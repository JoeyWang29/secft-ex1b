"""SecFT 服务器：TLS 双向认证 + 多线程并发 + ACL 越狱防护 + 断点续传 + 分级限速。

通道模型（仿 FTP 的控制/数据分离，长连接）：
  控制通道 ctrl_port —— 认证、目录操作、传输任务建立；客户端心跳保持长连接，
                        服务器守护线程持续维护会话，直至客户端主动 LOGOUT。
  数据通道 data_port —— 每个上传/下载任务单独建立一条 TLS 连接，天然支持
                        多文件并发传输，避免控制通道队头阻塞。
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import socket
import ssl
import sys
import threading
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from common.helpers import PathViolation, safe_resolve, setup_logger, validate_name
from common.protocol import (DEFAULT_CHUNK_SIZE, ErrCode, MsgType, ProtocolError,
                             error_header, make_header, recv_frame, send_frame,
                             sha256_file, sha256_bytes)
from server.auth import UserStore
from server.ratelimit import TokenBucket
from server.session import SessionManager

USERNAME_RE = r"^[A-Za-z0-9_]{1,32}$"
PRE_AUTH_TYPES = {MsgType.HELLO, MsgType.AUTH_INIT, MsgType.AUTH_PROOF, MsgType.PING}


class Config:
    """读取并规范路径的配置封装。"""

    def __init__(self, path: str):
        with open(path, "r", encoding="utf-8") as f:
            self.raw = json.load(f)
        base = os.path.dirname(os.path.abspath(path))
        def _abs(p: str) -> str:
            return p if os.path.isabs(p) else os.path.normpath(os.path.join(base, "..", p))
        self.ctrl_port = int(self.raw["ctrl_port"])
        self.data_port = int(self.raw["data_port"])
        self.listen_host = self.raw.get("listen_host", "0.0.0.0")
        self.root_dir = _abs(self.raw["root_dir"])
        self.users_file = _abs(self.raw["users_file"])
        self.ca_cert = _abs(self.raw["tls"]["ca_cert"])
        self.server_cert = _abs(self.raw["tls"]["server_cert"])
        self.server_key = _abs(self.raw["tls"]["server_key"])
        self.require_client_cert = bool(self.raw["tls"].get("require_client_cert", True))
        ver_name = self.raw["tls"].get("min_tls_version", "TLSv1.2").replace(".", "_")
        self.min_tls = getattr(ssl.TLSVersion, ver_name)
        self.max_file_size = int(self.raw.get("max_file_size", 2 << 30))
        self.max_total_conns = int(self.raw.get("max_total_conns", 64))
        self.max_conns_per_ip = int(self.raw.get("max_conns_per_ip", 8))
        self.idle_timeout = int(self.raw.get("idle_timeout", 75))
        self.max_fail = int(self.raw.get("login", {}).get("max_fail", 5))
        self.ban_seconds = int(self.raw.get("login", {}).get("ban_seconds", 600))
        self.req_per_sec = float(self.raw.get("ctrl_rate", {}).get("req_per_sec", 20))
        self.rate_burst = float(self.raw.get("ctrl_rate", {}).get("burst", 30))
        self.bandwidth = self.raw.get("bandwidth", {"normal": 1048576, "vip": 8388608})
        self.chunk_size = int(self.raw.get("chunk_size", DEFAULT_CHUNK_SIZE))
        self.pending_timeout = int(self.raw.get("transfer_pending_timeout", 60))
        self.log_file = _abs(self.raw.get("log_file", "logs/server.log"))


class FTServer:
    """SecFT 文件传输服务器。"""

    def __init__(self, config_path: str):
        self.cfg = Config(config_path)
        os.makedirs(self.cfg.root_dir, exist_ok=True)
        self.log = setup_logger("secft.server", self.cfg.log_file)
        self.store = UserStore(self.cfg.users_file, self.cfg.max_fail, self.cfg.ban_seconds)
        self.sessions = SessionManager()
        self.pending: dict[str, dict] = {}          # 传输任务登记表
        self.pending_lock = threading.Lock()
        self.user_buckets: dict[str, TokenBucket] = {}  # 用户 -> 带宽桶（按 tier 限速）
        self.bucket_lock = threading.Lock()
        self.conn_lock = threading.Lock()
        self.conn_per_ip: dict[str, int] = {}
        self.total_conns = 0
        self.tls_ctx = self._build_tls_ctx()
        self.running = False

    # ------------------------------------------------------------------ TLS
    def _build_tls_ctx(self) -> ssl.SSLContext:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = self.cfg.min_tls
        ctx.load_cert_chain(self.cfg.server_cert, self.cfg.server_key)
        ctx.load_verify_locations(cafile=self.cfg.ca_cert)
        if self.cfg.require_client_cert:
            # 双向证书认证：服务器强制校验客户端证书（加分项）
            ctx.verify_mode = ssl.CERT_REQUIRED
        else:
            ctx.verify_mode = ssl.CERT_NONE
        self.log.info("TLS 上下文就绪: min=%s 双向认证=%s", self.cfg.min_tls, self.cfg.require_client_cert)
        return ctx

    @staticmethod
    def peer_fingerprint(tls_sock: ssl.SSLSocket) -> str:
        der = tls_sock.getpeercert(binary_form=True)
        return hashlib.sha256(der).hexdigest() if der else ""

    @staticmethod
    def peer_cn(tls_sock: ssl.SSLSocket) -> str:
        subj = tls_sock.getpeercert().get("subject", ())
        for rdn in subj:
            for key, val in rdn:
                if key == "commonName":
                    return str(val)
        return ""

    # ------------------------------------------------------------- 接入管理
    def _register_conn(self, ip: str) -> bool:
        """连接计数；超出总量或单 IP 上限则拒绝（防连接洪泛）。"""
        with self.conn_lock:
            if self.total_conns >= self.cfg.max_total_conns:
                return False
            if self.conn_per_ip.get(ip, 0) >= self.cfg.max_conns_per_ip:
                return False
            self.total_conns += 1
            self.conn_per_ip[ip] = self.conn_per_ip.get(ip, 0) + 1
            return True

    def _release_conn(self, ip: str) -> None:
        with self.conn_lock:
            self.total_conns = max(0, self.total_conns - 1)
            left = self.conn_per_ip.get(ip, 1) - 1
            if left <= 0:
                self.conn_per_ip.pop(ip, None)
            else:
                self.conn_per_ip[ip] = left

    def serve(self) -> None:
        self.running = True
        ctrl_sock = self._listen(self.cfg.ctrl_port, "控制通道")
        data_sock = self._listen(self.cfg.data_port, "数据通道")
        threading.Thread(target=self._accept_loop, args=(ctrl_sock, self._handle_control, "ctrl"),
                         daemon=True, name="accept-ctrl").start()
        threading.Thread(target=self._accept_loop, args=(data_sock, self._handle_data, "data"),
                         daemon=True, name="accept-data").start()
        threading.Thread(target=self._janitor, daemon=True, name="janitor").start()
        self.log.info("SecFT 服务器已启动  根目录=%s 用户数=%d", self.cfg.root_dir, len(self.store.users))
        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            self.log.info("收到 Ctrl+C，服务器退出")
        finally:
            self.running = False

    def _listen(self, port: int, label: str) -> socket.socket:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((self.cfg.listen_host, port))
        s.listen(32)
        self.log.info("%s监听 %s:%d", label, self.cfg.listen_host, port)
        return s

    def _accept_loop(self, lsock: socket.socket, handler, label: str) -> None:
        while self.running:
            try:
                raw, addr = lsock.accept()
            except OSError:
                break
            ip = addr[0]
            if not self._register_conn(ip):
                self.log.warning("拒绝连接（并发上限）%s:%d [%s]", ip, addr[1], label)
                raw.close()
                continue
            t = threading.Thread(target=self._wrap_conn, args=(raw, addr, handler, label),
                                 daemon=True)
            t.start()

    def _wrap_conn(self, raw: socket.socket, addr, handler, label: str) -> None:
        ip, port = addr
        try:
            raw.settimeout(10)
            try:
                tls = self.tls_ctx.wrap_socket(raw, server_side=True)
            except (ssl.SSLError, OSError) as exc:
                self.log.info("TLS 握手失败 %s:%d [%s] %s", ip, port, label, exc)
                return
            tls.settimeout(self.cfg.idle_timeout)
            handler(tls, (ip, port))
        except Exception as exc:  # 任何线程内异常都不能杀死服务器
            self.log.exception("连接处理异常 %s:%d [%s]: %r", ip, port, label, exc)
        finally:
            try:
                tls.close()
            except Exception:
                pass
            self._release_conn(ip)

    # ---------------------------------------------------------- 控制通道主循环
    def _handle_control(self, tls: ssl.SSLSocket, addr) -> None:
        ip, port = addr
        cert_fp = self.peer_fingerprint(tls)
        cert_cn = self.peer_cn(tls)
        self.log.info("控制连接建立 %s:%d 证书CN=%s", ip, port, cert_cn)
        sess = None
        bucket = TokenBucket(self.cfg.req_per_sec, self.cfg.rate_burst)
        rate_violations = 0
        auth_ctx = {}  # AUTH_INIT 暂存：username/nonce
        # 状态机: hello -> authing -> ready
        while True:
            try:
                header, payload = recv_frame(tls)
            except (ProtocolError, ConnectionError, ssl.SSLError, socket.timeout, OSError) as exc:
                self.log.info("控制连接断开 %s:%d: %s", ip, port, exc)
                return
            mtype = header.get("type", "")
            seq = header.get("seq", 0)
            meta = header.get("meta") or {}
            token = header.get("token", "")
            # 已认证会话：校验 token 绑定 + 序号单调递增（防重放）
            if sess is not None and mtype != MsgType.LOGOUT:
                if token != sess.token or not self.sessions.check_seq(sess, seq):
                    self._send_err(tls, ErrCode.PROTOCOL_ERROR, "会话令牌或序号非法", seq)
                    return
            if not bucket.consume():
                rate_violations += 1
                self.log.warning("限流触发 %s:%d 连续%d次", ip, port, rate_violations)
                self._send_err(tls, ErrCode.RATE_LIMITED, "", seq)
                if rate_violations > 10:
                    self.log.warning("持续超频，强制断开 %s:%d", ip, port)
                    return
                continue
            try:
                sess, reply = self._dispatch_ctrl(tls, sess, auth_ctx, mtype, seq, meta,
                                                  token, cert_fp, cert_cn, ip)
                if reply is not None:
                    send_frame(tls, reply)
                if mtype in (MsgType.LOGOUT,):
                    self.log.info("客户端主动登出 %s:%d", ip, port)
                    return
            except PathViolation as exc:
                self.log.warning("路径越界拦截 %s:%d: %s", ip, port, exc)
                self._send_err(tls, ErrCode.PATH_VIOLATION, str(exc), seq)
            except PermissionError as exc:
                self.log.warning("权限拒绝 %s:%d: %s", ip, port, exc)
                self._send_err(tls, ErrCode.PERMISSION_DENIED, str(exc), seq)
            except ProtocolError as exc:
                self.log.warning("协议错误 %s:%d: %s", ip, port, exc)
                self._send_err(tls, ErrCode.PROTOCOL_ERROR, str(exc), seq)
                return
            except (ConnectionError, ssl.SSLError, socket.timeout, OSError) as exc:
                self.log.info("发送失败 %s:%d: %s", ip, port, exc)
                return

    def _send_err(self, tls: ssl.SSLSocket, code: int, msg: str, ack: int = 0) -> None:
        try:
            send_frame(tls, error_header(code, msg, ack=ack))
        except OSError:
            pass

    def _dispatch_ctrl(self, tls, sess, auth_ctx, mtype, seq, meta, token, cert_fp, cert_cn, ip):
        """按消息类型分发；返回 (会话, 待回复报头 or None)。"""
        cfg = self.cfg
        # ---- 握手
        if mtype == MsgType.HELLO:
            return sess, make_header(MsgType.WELCOME, seq=0, ack=seq, meta={
                "ver": 1, "cipher": tls.cipher()[0], "server_time": time.time(),
                "require_client_cert": cfg.require_client_cert,
                "data_port": cfg.data_port})
        # ---- 认证
        if mtype == MsgType.AUTH_INIT:
            username = str(meta.get("username", ""))
            if sess is not None:
                return sess, error_header(ErrCode.INVALID_STATE, "已登录", ack=seq)
            import re
            if not re.match(USERNAME_RE, username):
                return sess, error_header(ErrCode.AUTH_FAILED, "用户名格式非法", ack=seq)
            if not self.store.exists(username):
                self.log.warning("认证失败（用户不存在）%s %s", ip, username)
                return sess, error_header(ErrCode.AUTH_FAILED, "", ack=seq)
            if self.store.is_banned(username):
                self.log.warning("封禁期内登录被拒 %s %s", ip, username)
                return sess, error_header(ErrCode.BANNED, "", ack=seq)
            if cfg.require_client_cert and cert_cn and cert_cn != username:
                self.log.warning("证书CN(%s)与用户名(%s)不匹配 %s", cert_cn, username, ip)
                return sess, error_header(ErrCode.CERT_MISMATCH,
                                          f"证书 CN={cert_cn}", ack=seq)
            nonce = secrets.token_bytes(16)
            auth_ctx.update({"username": username, "nonce": nonce,
                             "salt": self.store.get_salt(username),
                             "iter": self.store.get_iterations(username)})
            return sess, make_header(MsgType.AUTH_SALT, ack=seq, meta={
                "salt": base64.b64encode(auth_ctx["salt"]).decode(),
                "nonce": base64.b64encode(nonce).decode(),
                "iter": auth_ctx["iter"]})
        if mtype == MsgType.AUTH_PROOF:
            username = auth_ctx.get("username")
            if not username or sess is not None:
                return sess, error_header(ErrCode.INVALID_STATE, "", ack=seq)
            try:
                proof = base64.b64decode(meta.get("proof", ""))
            except Exception:
                proof = b""
            nonce = auth_ctx["nonce"]
            if self.store.check_proof(username, proof, nonce):
                info = self.store.get_user_info(username)
                sess = self.sessions.create(username, info, cert_fp)
                self.log.info("登录成功 %s -> %s [%s]", ip, username, info["tier"])
                return sess, make_header(MsgType.AUTH_RESULT, ack=seq, token=sess.token, meta={
                    "user": info, "chunk_size": cfg.chunk_size,
                    "root": "/"})
            self.log.warning("口令校验失败 %s %s", ip, username)
            return sess, error_header(ErrCode.AUTH_FAILED, "", ack=seq)
        # ---- 以下均为已认证操作
        if sess is None:
            return sess, error_header(ErrCode.AUTH_FAILED, "请先登录", ack=seq)
        if mtype == MsgType.PING:
            return sess, make_header(MsgType.PONG, ack=seq, token=sess.token,
                                     meta={"server_time": time.time()})
        if mtype == MsgType.LOGOUT:
            self.sessions.revoke(sess.token)
            return sess, make_header(MsgType.BYE, ack=seq, token=sess.token)
        if mtype == MsgType.LIST:
            return sess, self._op_list(sess, seq, meta)
        if mtype == MsgType.MKDIR:
            return sess, self._op_mkdir(sess, seq, meta)
        if mtype == MsgType.DELETE:
            return sess, self._op_delete(sess, seq, meta)
        if mtype == MsgType.RENAME:
            return sess, self._op_rename(sess, seq, meta)
        if mtype == MsgType.UPLOAD_INIT:
            return sess, self._op_upload_init(sess, seq, meta)
        if mtype == MsgType.DOWNLOAD_INIT:
            return sess, self._op_download_init(sess, seq, meta)
        return sess, error_header(ErrCode.PROTOCOL_ERROR, f"未知消息类型 {mtype}", ack=seq)

    # ------------------------------------------------------------ 目录操作
    def _user_root(self, sess) -> str:
        """每个用户隔离在自己的目录下（多用户隔离 + ACL 越狱防线）。"""
        return safe_resolve(self.cfg.root_dir, sess.username)

    def _require_write(self, sess) -> None:
        if sess.info.get("perm") != "rw":
            raise PermissionError("只读用户禁止写操作")

    def _op_list(self, sess, seq, meta) -> dict:
        rel = str(meta.get("path", "/"))
        target = safe_resolve(self._user_root(sess), rel)
        if not os.path.isdir(target):
            return error_header(ErrCode.FILE_NOT_FOUND, rel, ack=seq)
        entries = []
        for name in os.listdir(target):
            p = os.path.join(target, name)
            st = os.stat(p)
            entries.append({"name": name, "dir": os.path.isdir(p),
                            "size": st.st_size, "mtime": int(st.st_mtime)})
        entries.sort(key=lambda e: (not e["dir"], e["name"].lower()))
        return make_header(MsgType.LIST, ack=seq, token=sess.token,
                           meta={"path": rel, "entries": entries})

    def _op_mkdir(self, sess, seq, meta) -> dict:
        self._require_write(sess)
        rel = str(meta.get("path", "")).strip("/")
        validate_name(os.path.basename(rel))
        target = safe_resolve(self._user_root(sess), rel)
        if os.path.exists(target):
            return error_header(ErrCode.EXISTS, rel, ack=seq)
        os.makedirs(target, exist_ok=True)
        self.log.info("MKDIR %s -> %s", sess.username, rel)
        return make_header(MsgType.MKDIR, ack=seq, token=sess.token, meta={"path": rel})

    def _op_delete(self, sess, seq, meta) -> dict:
        self._require_write(sess)
        rel = str(meta.get("path", "")).strip("/")
        target = safe_resolve(self._user_root(sess), rel)
        if target == os.path.realpath(self._user_root(sess)):
            return error_header(ErrCode.PERMISSION_DENIED, "禁止删除用户根目录", ack=seq)
        if not os.path.exists(target):
            return error_header(ErrCode.FILE_NOT_FOUND, rel, ack=seq)
        if os.path.isdir(target):
            os.rmdir(target)  # 仅允许删除空目录，防误删整棵树
        else:
            os.remove(target)
        self.log.info("DELETE %s -> %s", sess.username, rel)
        return make_header(MsgType.DELETE, ack=seq, token=sess.token, meta={"path": rel})

    def _op_rename(self, sess, seq, meta) -> dict:
        self._require_write(sess)
        src = str(meta.get("src", "")).strip("/")
        dst = str(meta.get("dst", "")).strip("/")
        validate_name(os.path.basename(dst))
        s_path = safe_resolve(self._user_root(sess), src)
        d_path = safe_resolve(self._user_root(sess), dst)
        if not os.path.exists(s_path):
            return error_header(ErrCode.FILE_NOT_FOUND, src, ack=seq)
        if os.path.exists(d_path):
            return error_header(ErrCode.EXISTS, dst, ack=seq)
        os.rename(s_path, d_path)
        self.log.info("RENAME %s %s -> %s", sess.username, src, dst)
        return make_header(MsgType.RENAME, ack=seq, token=sess.token,
                           meta={"src": src, "dst": dst})

    # ------------------------------------------------------------ 传输任务建立
    def _op_upload_init(self, sess, seq, meta) -> dict:
        self._require_write(sess)
        rel = str(meta.get("filename", "")).strip("/")
        validate_name(os.path.basename(rel))
        size = int(meta.get("size", -1))
        want_sha = str(meta.get("sha256", ""))
        overwrite = bool(meta.get("overwrite", False))
        if size < 0 or size > self.cfg.max_file_size:
            return error_header(ErrCode.SIZE_EXCEEDED,
                                f"size={size} 上限={self.cfg.max_file_size}", ack=seq)
        final_path = safe_resolve(self._user_root(sess), rel)
        if os.path.exists(final_path) and not overwrite:
            return error_header(ErrCode.EXISTS, rel, ack=seq)
        part_path = final_path + ".secft_part"
        # 断点续传：已有半成品则从其长度继续
        offset = os.path.getsize(part_path) if os.path.exists(part_path) else 0
        if offset > size:
            offset = 0
            os.remove(part_path)
        upload_id = secrets.token_hex(12)
        with self.pending_lock:
            self.pending[upload_id] = {
                "kind": "upload", "user": sess.username, "token": sess.token,
                "final": final_path, "part": part_path, "size": size,
                "sha256": want_sha, "received": offset, "expires": time.time() + self.cfg.pending_timeout,
            }
        self.log.info("UPLOAD_INIT %s %s size=%d 续传偏移=%d", sess.username, rel, size, offset)
        return make_header(MsgType.UPLOAD_READY, ack=seq, token=sess.token, meta={
            "upload_id": upload_id, "chunk_size": self.cfg.chunk_size,
            "offset": offset, "resume": offset > 0, "data_port": self.cfg.data_port})

    def _op_download_init(self, sess, seq, meta) -> dict:
        rel = str(meta.get("filename", "")).strip("/")
        target = safe_resolve(self._user_root(sess), rel)
        if not os.path.isfile(target):
            return error_header(ErrCode.FILE_NOT_FOUND, rel, ack=seq)
        size = os.path.getsize(target)
        offset = int(meta.get("offset", 0))
        if offset < 0 or offset > size:
            return error_header(ErrCode.INVALID_STATE, "断点偏移非法", ack=seq)
        download_id = secrets.token_hex(12)
        with self.pending_lock:
            self.pending[download_id] = {
                "kind": "download", "user": sess.username, "token": sess.token,
                "path": target, "size": size, "offset": offset,
                "sha256": sha256_file(target) if offset == 0 else "",
                "expires": time.time() + self.cfg.pending_timeout,
            }
        self.log.info("DOWNLOAD_INIT %s %s size=%d 起始偏移=%d", sess.username, rel, size, offset)
        return make_header(MsgType.DOWNLOAD_READY, ack=seq, token=sess.token, meta={
            "download_id": download_id, "size": size, "offset": offset,
            "chunk_size": self.cfg.chunk_size, "data_port": self.cfg.data_port})

    # ------------------------------------------------------------ 数据通道
    def _user_bucket(self, username: str) -> TokenBucket:
        """按用户 tier 取全局带宽桶：同一用户所有连接共享配额。"""
        with self.bucket_lock:
            bucket = self.user_buckets.get(username)
            if bucket is None:
                tier = self.store.users[username].get("tier", "normal")
                rate = float(self.cfg.bandwidth.get(tier, self.cfg.bandwidth["normal"]))
                bucket = TokenBucket(rate, rate * 2)
                self.user_buckets[username] = bucket
            return bucket

    def _pop_pending(self, tid: str, token: str) -> dict:
        """绑定并弹出传输任务（防止同一任务被两条数据连接并发绑定）。"""
        with self.pending_lock:
            task = self.pending.get(tid)
            if not task or task["token"] != token:
                raise ProtocolError("传输任务不存在或已过期")
            del self.pending[tid]
            return task

    def _handle_data(self, tls: ssl.SSLSocket, addr) -> None:
        ip, port = addr
        tls.settimeout(30)
        try:
            header, _ = recv_frame(tls)
            if header.get("type") != MsgType.DATA_AUTH:
                self._send_err(tls, ErrCode.PROTOCOL_ERROR, "数据通道首帧必须为 DATA_AUTH")
                return
            token = header.get("token", "")
            tid = str((header.get("meta") or {}).get("transfer_id", ""))
            sess = self.sessions.get(token)
            if sess is None:
                self._send_err(tls, ErrCode.AUTH_FAILED, "会话无效")
                return
            try:
                task = self._pop_pending(tid, token)  # 绑定即弹出，天然互斥
            except ProtocolError as exc:
                self._send_err(tls, ErrCode.INVALID_STATE, str(exc))
                return
            kind = task["kind"]
            send_frame(tls, make_header(MsgType.DATA_OK, ack=header.get("seq", 0),
                                        token=token, meta={"kind": kind}))
            if kind == "upload":
                self._data_upload(tls, task)
            else:
                self._data_download(tls, task, sess.username)
        except (ProtocolError, ConnectionError, ssl.SSLError, socket.timeout, OSError) as exc:
            self.log.info("数据通道异常 %s:%d: %s", ip, port, exc)
        except Exception:
            self.log.exception("数据通道未处理异常 %s:%d", ip, port)

    def _data_upload(self, tls: ssl.SSLSocket, task: dict) -> None:
        """数据通道上传：分片校验 -> 追加 .part -> 累积确认 -> 整体哈希提交。

        提交阶段必须先关闭 .part 句柄再做 os.replace（Windows 下打开中的
        文件不允许改名/替换，会抛 WinError 32）。
        """
        bucket = self._user_bucket(task["user"])
        part_path, final_path = task["part"], task["final"]
        size, expected_sha = task["size"], task["sha256"]
        received = task["received"]
        commit_ok = False
        with open(part_path, "ab") as part:
            while True:
                header, payload = recv_frame(tls)
                mtype = header.get("type")
                meta = header.get("meta") or {}
                if mtype == MsgType.UPLOAD_CHUNK:
                    offset = int(meta.get("offset", -1))
                    if offset != received:
                        send_frame(tls, make_header(MsgType.UPLOAD_ACK, token=task["token"],
                                                    meta={"offset": received, "expect": received,
                                                          "error": f"偏移不匹配 收到={offset}"}))
                        raise ProtocolError("上传偏移不匹配")
                    if len(payload) <= 0 or received + len(payload) > size:
                        raise ProtocolError("分片长度非法")
                    # 分片哈希校验（中途损坏立即可发现）
                    if str(meta.get("sha256", "")) and meta["sha256"] != sha256_bytes(payload):
                        raise ProtocolError("分片哈希不匹配")
                    bucket.take_wait(len(payload))  # 按用户 tier 整形（ACK 延迟形成背压）
                    part.write(payload)
                    part.flush()
                    received += len(payload)
                    send_frame(tls, make_header(MsgType.UPLOAD_ACK, token=task["token"],
                                                meta={"offset": received}))
                elif mtype == MsgType.UPLOAD_COMMIT:
                    if received != size:
                        send_frame(tls, error_header(ErrCode.INVALID_STATE,
                                                     f"未收完 received={received}/{size}"))
                        raise ProtocolError("提交时数据不完整")
                    commit_ok = True
                    break  # 先退出 with 关闭文件句柄
                else:
                    raise ProtocolError(f"上传数据通道出现非法消息 {mtype}")
        # ---- 提交校验与原子落盘（句柄已关闭）
        if not commit_ok:
            raise ProtocolError("上传未提交即断开")
        actual = sha256_file(part_path)
        if expected_sha and actual != expected_sha:
            send_frame(tls, error_header(ErrCode.INVALID_STATE, "整文件哈希校验失败"))
            raise ProtocolError("整文件哈希不匹配")
        os.replace(part_path, final_path)
        self.log.info("UPLOAD_DONE %s %s sha256=%s", task["user"],
                      os.path.basename(final_path), actual[:16])
        send_frame(tls, make_header(MsgType.UPLOAD_DONE, token=task["token"],
                                    meta={"sha256": actual}))

    def _data_download(self, tls: ssl.SSLSocket, task: dict, username: str) -> None:
        """数据通道下载：按 chunk 流式推送，令牌桶整形带宽（VIP 分级限速）。"""
        bucket = self._user_bucket(username)
        path, size, offset = task["path"], task["size"], task["offset"]
        chunk_size = self.cfg.chunk_size
        sent = offset
        with open(path, "rb") as f:
            f.seek(offset)
            while sent < size:
                data = f.read(chunk_size)
                if not data:
                    break
                bucket.take_wait(len(data))
                send_frame(tls, make_header(MsgType.DOWNLOAD_CHUNK, token=task["token"],
                                            meta={"offset": sent,
                                                  "sha256": sha256_bytes(data)}), data)
                sent += len(data)
            send_frame(tls, make_header(MsgType.DATA_END, token=task["token"],
                                        meta={"sent": sent, "size": size, "ok": sent == size}))
        self.log.info("DOWNLOAD_DONE %s %s 字节=%d", username, os.path.basename(path), sent - offset)

    # ------------------------------------------------------------ 后台清理
    def _janitor(self) -> None:
        """守护线程：清理过期传输任务、空闲会话、无用带宽桶。"""
        while self.running:
            time.sleep(30)
            now = time.time()
            with self.pending_lock:
                dead = [k for k, v in self.pending.items() if v["expires"] < now]
                for k in dead:
                    del self.pending[k]
            self.sessions.sweep(self.cfg.idle_timeout * 2)


def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(description="SecFT 安全文件传输服务器")
    parser.add_argument("-c", "--config", default="config/server_config.json")
    args = parser.parse_args()
    server = FTServer(args.config)
    server.serve()


if __name__ == "__main__":
    main()
