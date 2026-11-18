"""SecFT 传输层：上传/下载 worker，支持断点续传、分片校验、多任务并发。

并发模型：每个传输任务独占一条 TLS 数据连接 + 一个工作线程，
控制连接只负责任务建立（UPLOAD_INIT / DOWNLOAD_INIT），
因此多个任务可以真正并行，且互不阻塞控制通道。

断点续传：任何网络中断都会触发「重新登记任务 -> 从服务器/本地已有
偏移继续」的自动重试循环，直至整文件哈希校验通过并原子落盘。
"""

from __future__ import annotations

import hashlib
import os
import secrets
import socket
import ssl
import threading
import time

from client.network import ControlConn, SecFTError, build_client_ctx
from common.protocol import (ErrCode, MsgType, ProtocolError, make_header,
                             recv_frame, send_frame, sha256_file)

FATAL_CODES = {ErrCode.PERMISSION_DENIED, ErrCode.PATH_VIOLATION, ErrCode.SIZE_EXCEEDED,
               ErrCode.AUTH_FAILED, ErrCode.CERT_MISMATCH}
MAX_RETRY = 5


class TransferTask:
    """一次上传或下载任务的运行时状态（GUI 据此渲染进度）。"""

    UPLOAD = "上传"
    DOWNLOAD = "下载"

    def __init__(self, kind: str, local_path: str, remote_path: str, size: int):
        self.kind = kind
        self.local_path = local_path
        self.remote_path = remote_path
        self.size = max(size, 1)
        self.done_bytes = 0
        self.status = "排队中"
        self.error = ""
        self.started = time.time()
        self.finished = time.time()
        self.speed = 0.0        # 字节/秒
        self.task_id = secrets.token_hex(4)
        self.resume_from = 0    # 断点续传起始偏移

    @property
    def percent(self) -> float:
        return min(100.0, self.done_bytes * 100.0 / self.size)

    @property
    def name(self) -> str:
        return os.path.basename(self.remote_path)


class TransferManager:
    """客户端传输管理器：维护任务队列并控制并发上限。"""

    def __init__(self, conn: ControlConn, host: str, data_port: int,
                 ca_cert: str, client_cert: str | None, max_parallel: int = 4):
        self.conn = conn
        self.host = host
        self.data_port = data_port
        self.ca_cert = ca_cert
        self.client_cert = client_cert
        self.tasks: dict[str, TransferTask] = {}
        self.lock = threading.Lock()
        self.semaphore = threading.Semaphore(max_parallel)
        self.listeners: list = []   # GUI 注册的进度回调

    def notify(self, task: TransferTask) -> None:
        for cb in list(self.listeners):
            try:
                cb(task)
            except Exception:
                pass

    def submit(self, task: TransferTask) -> None:
        with self.lock:
            self.tasks[task.task_id] = task
        threading.Thread(target=self._run, args=(task,), daemon=True,
                         name=f"xfer-{task.task_id}").start()

    def _run(self, task: TransferTask) -> None:
        self.semaphore.acquire()
        try:
            task.status = "传输中"
            self.notify(task)
            if task.kind == TransferTask.UPLOAD:
                self._do_upload(task)
            else:
                self._do_download(task)
            task.status = "已完成"
        except SecFTError as exc:
            task.status = "失败"
            task.error = exc.message
        except (ProtocolError, ConnectionError, OSError, ssl.SSLError) as exc:
            task.status = "失败"
            task.error = f"网络错误: {exc}"
        except Exception as exc:
            task.status = "失败"
            task.error = f"未知错误: {exc!r}"
        finally:
            task.finished = time.time()
            self._finish_speed(task)
            self.notify(task)
            self.semaphore.release()

    # ------------------------------------------------------------- 上传
    def _do_upload(self, task: TransferTask) -> None:
        local = task.local_path
        total = os.path.getsize(local)
        task.size = max(total, 1)
        sha = sha256_file(local)
        attempts = 0
        committed = False
        while not committed:
            meta = self.conn.upload_init(task.remote_path, total, sha, overwrite=False)
            resume = int(meta.get("offset", 0))
            task.resume_from = resume
            self.data_port = int(meta.get("data_port", self.data_port))
            if resume >= total:
                break  # 服务器端已收完（上次 commit 前断线也无需重传）
            try:
                self._upload_stream(task, meta, sha, total)
                committed = True
            except SecFTError as exc:
                if exc.code in FATAL_CODES:
                    raise
                attempts = self._retry_or_raise(task, attempts, exc)
            except (ProtocolError, ConnectionError, OSError, ssl.SSLError) as exc:
                attempts = self._retry_or_raise(task, attempts, exc)
        task.done_bytes = total

    def _upload_stream(self, task: TransferTask, meta: dict, sha: str, total: int) -> None:
        """单次尝试：数据连接 -> DATA_AUTH -> 逐片(停等+累积ACK) -> COMMIT。"""
        port = int(meta["data_port"])
        ctx = build_client_ctx(self.ca_cert, self.client_cert)
        raw = socket.create_connection((self.host, port), timeout=15)
        data_sock = ctx.wrap_socket(raw, server_hostname=self.host)
        try:
            send_frame(data_sock, make_header(MsgType.DATA_AUTH, token=self.conn.token,
                                              meta={"transfer_id": meta["upload_id"]}))
            resp, _ = recv_frame(data_sock)
            if resp.get("type") == MsgType.ERROR:
                m = resp["meta"]
                raise SecFTError(int(m["code"]), str(m["msg"]))
            offset = int(meta["offset"])
            chunk_size = int(meta.get("chunk_size", 1024 * 1024))
            with open(task.local_path, "rb") as f:
                f.seek(offset)
                sent = offset
                while sent < total:
                    data = f.read(chunk_size)
                    if not data:
                        break
                    send_frame(data_sock, make_header(
                        MsgType.UPLOAD_CHUNK,
                        meta={"offset": sent, "sha256": hashlib.sha256(data).hexdigest()}), data)
                    ack, _ = recv_frame(data_sock)
                    if ack.get("type") == MsgType.ERROR:
                        m = ack["meta"]
                        raise SecFTError(int(m["code"]), str(m["msg"]))
                    if int((ack.get("meta") or {}).get("offset", -1)) != sent + len(data):
                        raise ProtocolError("服务器确认偏移异常")
                    sent += len(data)
                    task.done_bytes = sent
                    self._tick_speed(task)
                    self.notify(task)
                send_frame(data_sock, make_header(MsgType.UPLOAD_COMMIT, meta={"sha256": sha}))
                done, _ = recv_frame(data_sock)
                if done.get("type") == MsgType.ERROR:
                    m = done["meta"]
                    raise SecFTError(int(m["code"]), str(m["msg"]))
                if done.get("type") != MsgType.UPLOAD_DONE:
                    raise ProtocolError("上传提交响应异常")
        finally:
            try:
                data_sock.close()
            except OSError:
                pass

    # ------------------------------------------------------------- 下载
    def _do_download(self, task: TransferTask) -> None:
        part = task.local_path + ".secft_part"
        meta: dict = {}
        attempts = 0
        finished = False
        while not finished:
            offset = os.path.getsize(part) if os.path.exists(part) else 0
            meta = self.conn.download_init(task.remote_path, offset)
            total = int(meta["size"])
            task.size = max(total, 1)
            task.resume_from = offset
            self.data_port = int(meta.get("data_port", self.data_port))
            if offset >= total:
                break  # 本地已收齐（例如上次校验前中断）
            try:
                self._download_stream(task, part, meta, total)
                finished = True
            except SecFTError as exc:
                if exc.code in FATAL_CODES:
                    raise
                attempts = self._retry_or_raise(task, attempts, exc)
            except (ProtocolError, ConnectionError, OSError, ssl.SSLError) as exc:
                attempts = self._retry_or_raise(task, attempts, exc)
        # 完整哈希校验后原子落盘
        actual = sha256_file(part)
        expect = str(meta.get("sha256", "")) or getattr(task, "sha256_downloaded", "")
        if expect and expect != actual:
            os.remove(part)
            raise ProtocolError("下载整文件哈希校验失败")
        os.replace(part, task.local_path)
        task.done_bytes = total

    def _download_stream(self, task: TransferTask, part: str, meta: dict, total: int) -> None:
        """单次尝试：数据连接 -> DATA_AUTH -> 接收分片（前缀纳入哈希） -> DATA_END。"""
        port = int(meta["data_port"])
        ctx = build_client_ctx(self.ca_cert, self.client_cert)
        raw = socket.create_connection((self.host, port), timeout=15)
        data_sock = ctx.wrap_socket(raw, server_hostname=self.host)
        hasher = hashlib.sha256()
        start = int(meta["offset"])
        try:
            send_frame(data_sock, make_header(MsgType.DATA_AUTH, token=self.conn.token,
                                              meta={"transfer_id": meta["download_id"]}))
            resp, _ = recv_frame(data_sock)
            if resp.get("type") == MsgType.ERROR:
                m = resp["meta"]
                raise SecFTError(int(m["code"]), str(m["msg"]))
            if os.path.exists(part):  # 已有前缀也要参与整体哈希
                with open(part, "rb") as pf:
                    while True:
                        b = pf.read(1024 * 1024)
                        if not b:
                            break
                        hasher.update(b)
            expect_pos = start
            with open(part, "ab" if start else "wb") as out:
                while True:
                    header, payload = recv_frame(data_sock)
                    mtype = header.get("type")
                    m = header.get("meta") or {}
                    if mtype == MsgType.DOWNLOAD_CHUNK:
                        if str(m.get("sha256", "")) and m["sha256"] != hashlib.sha256(payload).hexdigest():
                            raise ProtocolError("分片哈希不匹配")
                        if int(m.get("offset", -1)) != expect_pos:
                            raise ProtocolError("下载偏移错乱")
                        out.write(payload)
                        hasher.update(payload)
                        expect_pos += len(payload)
                        task.done_bytes = expect_pos
                        self._tick_speed(task)
                        self.notify(task)
                    elif mtype == MsgType.DATA_END:
                        if int(m.get("sent", -1)) != expect_pos:
                            raise ProtocolError("结束偏移不匹配")
                        task.sha256_downloaded = hasher.hexdigest()
                        meta["sha256"] = hasher.hexdigest()
                        return
                    elif mtype == MsgType.ERROR:
                        raise SecFTError(int(m.get("code", ErrCode.INTERNAL)), str(m.get("msg", "")))
                    else:
                        raise ProtocolError(f"下载数据通道非法消息 {mtype}")
        finally:
            try:
                data_sock.close()
            except OSError:
                pass

    # ------------------------------------------------------------- 重试与速率
    def _retry_or_raise(self, task: TransferTask, attempts: int, exc: Exception) -> int:
        attempts += 1
        if attempts >= MAX_RETRY:
            raise exc
        task.status = f"断线重连({attempts}/{MAX_RETRY})"
        self.notify(task)
        time.sleep(0.5 * attempts)
        task.status = "传输中"
        return attempts

    def _tick_speed(self, task: TransferTask) -> None:
        now = time.time()
        if not hasattr(task, "_speed_t0"):
            task._speed_t0 = now
            task._speed_b0 = task.done_bytes
        if now - task._speed_t0 >= 0.5:
            dt = now - task._speed_t0
            task.speed = (task.done_bytes - task._speed_b0) / dt if dt > 0 else 0.0
            task._speed_t0 = now
            task._speed_b0 = task.done_bytes

    def _finish_speed(self, task: TransferTask) -> None:
        dt = max(task.finished - task.started, 0.001)
        task.speed = task.done_bytes / dt
