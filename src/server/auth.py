"""用户存储与认证：PBKDF2 口令验证 + 登录封禁（防爆破/防 DDoS）。

设计要点：
- 绝不存储明文口令。users.json 中只保存 PBKDF2-HMAC-SHA256 校验值（verifier）。
- 登录流程为挑战-应答：服务器下发盐值与一次性 nonce，客户端用
  X = PBKDF2(口令, salt, iter) 计算 proof = HMAC(X, nonce) 发回；
  服务器用本地存储的 X 重算 HMAC 比对。nonce 每次随机，重放的历史
  proof 无法再次通过验证。
- 登录连续失败达到阈值后按用户名封禁一段时间（可配置）。
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import threading
import time

PBKDF2_ITERATIONS = 200_000
PBKDF2_DKLEN = 32


def compute_verifier(password: str, salt: bytes, iterations: int = PBKDF2_ITERATIONS) -> bytes:
    """由口令推导校验值 X（客户端与服务器使用同一算法）。"""
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations, dklen=PBKDF2_DKLEN)


def compute_proof(verifier: bytes, nonce: bytes) -> bytes:
    """挑战应答：proof = HMAC-SHA256(X, nonce)。"""
    return hmac.new(verifier, nonce, hashlib.sha256).digest()


class UserStore:
    """线程安全的用户存储，数据落在 users.json。"""

    def __init__(self, path: str, max_fail: int = 5, ban_seconds: int = 600):
        self.path = path
        self.max_fail = max_fail
        self.ban_seconds = ban_seconds
        self.lock = threading.RLock()
        self.users: dict = {}
        self._load()

    def _load(self) -> None:
        if not os.path.exists(self.path):
            raise FileNotFoundError(f"用户文件不存在: {self.path}（请先运行 scripts/gen_users.py）")
        with open(self.path, "r", encoding="utf-8") as f:
            self.users = json.load(f)
        for name, info in self.users.items():
            info.setdefault("fail_count", 0)
            info.setdefault("banned_until", 0.0)

    def save(self) -> None:
        with self.lock:
            tmp = self.path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(self.users, f, ensure_ascii=False, indent=2)
            os.replace(tmp, self.path)

    def exists(self, username: str) -> bool:
        with self.lock:
            return username in self.users

    def is_banned(self, username: str) -> bool:
        with self.lock:
            info = self.users.get(username)
            return bool(info) and time.time() < info["banned_until"]

    def get_salt(self, username: str) -> bytes:
        with self.lock:
            return base64.b64decode(self.users[username]["salt"])

    def get_verifier(self, username: str) -> bytes:
        with self.lock:
            return base64.b64decode(self.users[username]["verifier"])

    def get_iterations(self, username: str) -> int:
        with self.lock:
            return int(self.users[username].get("iter", PBKDF2_ITERATIONS))

    def check_proof(self, username: str, proof: bytes, nonce: bytes) -> bool:
        """校验挑战应答，并维护失败计数与封禁状态。"""
        with self.lock:
            info = self.users.get(username)
            if info is None:
                return False
            now = time.time()
            if now < info["banned_until"]:
                return False
            expected = compute_proof(base64.b64decode(info["verifier"]), nonce)
            ok = hmac.compare_digest(expected, proof)
            if ok:
                info["fail_count"] = 0
                info["banned_until"] = 0.0
            else:
                info["fail_count"] += 1
                if info["fail_count"] >= self.max_fail:
                    info["banned_until"] = now + self.ban_seconds
                    info["fail_count"] = 0
            self.save()
            return ok

    def get_user_info(self, username: str) -> dict:
        """返回对客户端可见的用户信息（tier/perm），不含任何口令材料。"""
        with self.lock:
            info = self.users[username]
            return {
                "username": username,
                "tier": info.get("tier", "normal"),
                "perm": info.get("perm", "rw"),
            }
