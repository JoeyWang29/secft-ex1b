"""SecFT 客户端网络层：TLS 控制连接（长连接 + 心跳）与数据连接。"""

from __future__ import annotations

import base64
import hashlib
import hmac
import socket
import ssl
import threading
import time

from common.protocol import (MsgType, ProtocolError, ErrCode, make_header,
                             recv_frame, send_frame)


class SecFTError(Exception):
    """服务器返回错误或连接异常时抛出，携带错误码。"""

    def __init__(self, code: int, message: str = ""):
        super().__init__(message or ErrMsg.get(code, f"错误码 {code}"))
        self.code = code
        self.message = message or ErrMsg.get(code, f"错误码 {code}")


ErrMsg = {
    ErrCode.OK: "成功",
    ErrCode.AUTH_FAILED: "用户名或密码错误",
    ErrCode.PERMISSION_DENIED: "权限不足",
    ErrCode.PATH_VIOLATION: "路径越界",
    ErrCode.FILE_NOT_FOUND: "文件不存在",
    ErrCode.RATE_LIMITED: "请求过于频繁",
    ErrCode.PROTOCOL_ERROR: "协议错误",
    ErrCode.SERVER_BUSY: "服务器繁忙",
    ErrCode.SIZE_EXCEEDED: "文件大小超出限制",
    ErrCode.INVALID_STATE: "状态错误",
    ErrCode.INTERNAL: "服务器内部错误",
    ErrCode.EXISTS: "目标已存在",
    ErrCode.BANNED: "账号被临时封禁",
    ErrCode.CERT_MISMATCH: "客户端证书与用户名不匹配",
}


def build_client_ctx(ca_cert: str, client_cert: str | None = None) -> ssl.SSLContext:
    """客户端 TLS 上下文：以本地 CA 根证书校验服务器身份（防中间人），
    并加载客户端证书实现双向认证。"""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_verify_locations(cafile=ca_cert)   # 校验服务器证书链
    ctx.check_hostname = True                   # 校验证书域名
    if client_cert:
        ctx.load_cert_chain(client_cert)
    return ctx


class ControlConn:
    """TLS 控制连接：请求-响应 + 后台心跳线程保持长连接。"""

    def __init__(self, host: str, port: int, ca_cert: str, client_cert: str | None):
        self.host = host
        self.port = port
        self.ctx = build_client_ctx(ca_cert, client_cert)
        self.sock: ssl.SSLSocket | None = None
        self.seq = 0
        self.token = ""
        self.user_info: dict = {}
        self.chunk_size = 1024 * 1024
        self.server_cipher = ""
        self.rtt_ms = 0.0
        self._hb_stop = threading.Event()
        self._hb_thread: threading.Thread | None = None
        # 请求-响应必须原子执行：并发下载线程共用控制连接时，
        # 若 send/recv 分别加锁会导致两个线程交叉读取彼此的响应帧
        self._req_lock = threading.RLock()

    # ---------------------------------------------------------- 基础请求
    def _next_seq(self) -> int:
        self.seq += 1
        return self.seq

    def _request(self, mtype: str, meta: dict | None = None, token: str = "",
                 timeout: float = 30.0) -> tuple[dict, bytes]:
        """发送请求并等待同一条连接上的响应（带超时）。"""
        sock = self.sock
        if sock is None:
            raise SecFTError(ErrCode.PROTOCOL_ERROR, "连接未建立")
        seq = self._next_seq()
        header = make_header(mtype, seq=seq, token=token or self.token, meta=meta)
        old_timeout = sock.gettimeout()
        sock.settimeout(timeout)
        try:
            with self._req_lock:
                send_frame(sock, header)
                resp, payload = recv_frame(sock)
        finally:
            sock.settimeout(old_timeout)
        if resp.get("type") == MsgType.ERROR:
            meta_err = resp.get("meta") or {}
            raise SecFTError(int(meta_err.get("code", ErrCode.INTERNAL)),
                             str(meta_err.get("msg", "")))
        if resp.get("ack") != seq:
            raise ProtocolError(f"响应序号不匹配 ack={resp.get('ack')} 期望={seq}")
        return resp, payload

    # ---------------------------------------------------------- 连接与认证
    def connect(self) -> dict:
        raw = socket.create_connection((self.host, self.port), timeout=10)
        self.sock = self.ctx.wrap_socket(raw, server_hostname=self.host)
        self.server_cipher = self.sock.cipher()[0]
        resp, _ = self._request(MsgType.HELLO, timeout=15)
        return resp.get("meta", {})

    def auth(self, username: str, password: str) -> dict:
        """挑战-应答登录：绝不传输明文口令（PBKDF2 校验值 + HMAC(nonce)）。"""
        resp, _ = self._request(MsgType.AUTH_INIT, {"username": username})
        meta = resp.get("meta", {})
        salt = base64.b64decode(meta["salt"])
        nonce = base64.b64decode(meta["nonce"])
        iterations = int(meta.get("iter", 200000))
        verifier = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt,
                                       iterations, dklen=32)
        proof = hmac.new(verifier, nonce, hashlib.sha256).digest()
        resp, _ = self._request(MsgType.AUTH_PROOF, {"proof": base64.b64encode(proof).decode()})
        meta = resp.get("meta", {})
        self.token = resp.get("token", "")
        self.user_info = meta.get("user", {})
        self.chunk_size = int(meta.get("chunk_size", 1024 * 1024))
        self._start_heartbeat()
        return meta

    def logout(self) -> None:
        try:
            self._request(MsgType.LOGOUT, timeout=5)
        except Exception:
            pass
        self.close()

    # ---------------------------------------------------------- 心跳保活
    def _start_heartbeat(self) -> None:
        self._hb_stop.clear()
        self._hb_thread = threading.Thread(target=self._heartbeat_loop, daemon=True,
                                           name="heartbeat")
        self._hb_thread.start()

    def _heartbeat_loop(self) -> None:
        """每 15s 发送 PING；服务器空闲超时 75s，心跳缺失即被清理。
        客户端不主动关闭连接 —— 满足课程对长连接 keep-alive 的要求。"""
        while not self._hb_stop.wait(15):
            if self.sock is None:
                return
            try:
                t0 = time.time()
                resp, _ = self._request(MsgType.PING, timeout=10)
                self.rtt_ms = (time.time() - t0) * 1000
            except Exception:
                self.rtt_ms = -1  # 心跳失败，由调用方读取后提示

    def close(self) -> None:
        self._hb_stop.set()
        sock, self.sock = self.sock, None
        self.token = ""
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass

    @property
    def alive(self) -> bool:
        return self.sock is not None and self.rtt_ms >= 0

    # ---------------------------------------------------------- 目录操作
    def list_dir(self, path: str = "/") -> list[dict]:
        resp, _ = self._request(MsgType.LIST, {"path": path})
        return resp["meta"]["entries"]

    def mkdir(self, path: str) -> None:
        self._request(MsgType.MKDIR, {"path": path})

    def delete(self, path: str) -> None:
        self._request(MsgType.DELETE, {"path": path})

    def rename(self, src: str, dst: str) -> None:
        self._request(MsgType.RENAME, {"src": src, "dst": dst})

    # ---------------------------------------------------------- 传输任务
    def upload_init(self, filename: str, size: int, sha256: str, overwrite: bool) -> dict:
        resp, _ = self._request(MsgType.UPLOAD_INIT, {
            "filename": filename, "size": size, "sha256": sha256, "overwrite": overwrite})
        return resp["meta"]

    def download_init(self, filename: str, offset: int = 0) -> dict:
        resp, _ = self._request(MsgType.DOWNLOAD_INIT, {"filename": filename, "offset": offset})
        return resp["meta"]
