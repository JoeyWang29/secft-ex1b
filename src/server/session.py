"""会话管理：登录后签发不透明随机令牌，绑定用户、证书指纹与序列号。

- token 由 secrets.token_hex 生成（128 bit），不可预测。
- 会话绑定客户端证书指纹，防止令牌被挪用到其他连接。
- 记录 last_seq 用于拒绝重放/乱序的旧请求（单调递增校验）。
- 空闲超时由服务器在心跳缺失时清理。
"""

from __future__ import annotations

import secrets
import threading
import time


class Session:
    __slots__ = ("token", "username", "info", "cert_fp", "last_seq", "created", "last_seen")

    def __init__(self, token: str, username: str, info: dict, cert_fp: str):
        self.token = token
        self.username = username
        self.info = info          # {"tier":..., "perm":...}
        self.cert_fp = cert_fp    # 客户端证书 SHA-256 指纹
        self.last_seq = 0
        self.created = time.time()
        self.last_seen = self.created


class SessionManager:
    def __init__(self):
        self.lock = threading.RLock()
        self.sessions: dict[str, Session] = {}

    def create(self, username: str, info: dict, cert_fp: str) -> Session:
        token = secrets.token_hex(16)
        sess = Session(token, username, info, cert_fp)
        with self.lock:
            self.sessions[token] = sess
        return sess

    def get(self, token: str, cert_fp: str | None = None) -> Session | None:
        """校验 token；若提供 cert_fp 则要求与会话绑定证书一致。"""
        if not token:
            return None
        with self.lock:
            sess = self.sessions.get(token)
            if sess is None:
                return None
            if cert_fp is not None and sess.cert_fp != cert_fp:
                return None
            sess.last_seen = time.time()
            return sess

    def check_seq(self, sess: Session, seq: int) -> bool:
        """会话内请求序号必须严格递增，直接拒绝重放。"""
        with self.lock:
            if not isinstance(seq, int) or seq <= sess.last_seq:
                return False
            sess.last_seq = seq
            return True

    def revoke(self, token: str) -> None:
        with self.lock:
            self.sessions.pop(token, None)

    def sweep(self, max_idle: float) -> None:
        """清理空闲超时会话。"""
        now = time.time()
        with self.lock:
            dead = [t for t, s in self.sessions.items() if now - s.last_seen > max_idle]
            for t in dead:
                del self.sessions[t]

    def count(self) -> int:
        with self.lock:
            return len(self.sessions)
