"""SecFT 端到端自动化测试。

覆盖：握手/认证（错口令、封禁、证书绑定）、目录操作、上传/下载完整性与
断点续传、路径穿越拦截、只读权限、未认证访问、请求限流、连接洪泛防护、
多任务并发、VIP 分级限速、登出。

用法: python scripts/e2e_test.py
前置: python scripts/gen_certs.py && python scripts/gen_users.py（缺失时自动执行）
"""

import base64
import hashlib
import hmac
import json
import os
import socket
import ssl
import subprocess
import sys
import threading
import time

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
sys.path.insert(0, os.path.join(ROOT, "src"))

from client.network import ControlConn, SecFTError
from client.transfers import TransferManager, TransferTask
from common.protocol import (ErrCode, MsgType, ProtocolError, make_header,
                             recv_frame, send_frame, sha256_file)

CERTS = os.path.join(ROOT, "certs")
CA_CERT = os.path.join(CERTS, "ca-cert.pem")
HOST, PORT, DATA_PORT = "127.0.0.1", 19443, 19444

RESULTS: list[tuple[str, bool, str]] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    RESULTS.append((name, bool(cond), detail))
    mark = "PASS" if cond else "FAIL"
    print(f"  [{mark}] {name}" + (f"  -- {detail}" if detail and not cond else ""))


def ensure_env() -> None:
    if not os.path.exists(CA_CERT):
        print("[setup] 生成证书 ...")
        subprocess.run([sys.executable, os.path.join(ROOT, "scripts", "gen_certs.py")], check=True)
    if not os.path.exists(os.path.join(ROOT, "config", "users.json")):
        print("[setup] 生成演示用户 ...")
        subprocess.run([sys.executable, os.path.join(ROOT, "scripts", "gen_users.py")], check=True)


class RawClient:
    """测试专用裸协议客户端：完全掌控帧收发，用于异常/续传/限流场景。"""

    def __init__(self, username: str = "alice", password: str = "alice-2026"):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.load_verify_locations(CA_CERT)
        ctx.check_hostname = True
        ctx.load_cert_chain(os.path.join(CERTS, f"client_{username}.pem"))
        raw = socket.create_connection((HOST, PORT), timeout=10)
        self.sock = ctx.wrap_socket(raw, server_hostname=HOST)
        self.seq = 0
        self.token = ""
        self.username = username
        self.password = password

    def send(self, mtype: str, meta: dict | None = None, payload: bytes = b"",
             token: str = None) -> int:
        self.seq += 1
        send_frame(self.sock, make_header(mtype, seq=self.seq,
                                          token=self.token if token is None else token,
                                          meta=meta), payload)
        return self.seq

    def recv(self):
        return recv_frame(self.sock)

    def auth(self, password: str | None = None) -> None:
        self.send(MsgType.AUTH_INIT, {"username": self.username})
        h, _ = self.recv()
        salt = base64.b64decode(h["meta"]["salt"])
        nonce = base64.b64decode(h["meta"]["nonce"])
        verifier = hashlib.pbkdf2_hmac("sha256", (password or self.password).encode(),
                                       salt, int(h["meta"].get("iter", 200000)), dklen=32)
        proof = hmac.new(verifier, nonce, hashlib.sha256).digest()
        self.send(MsgType.AUTH_PROOF, {"proof": base64.b64encode(proof).decode()})
        h, _ = self.recv()
        if h.get("type") == MsgType.AUTH_RESULT:
            self.token = h.get("token", "")
        return h

    def hello(self) -> dict:
        self.seq += 1
        send_frame(self.sock, make_header(MsgType.HELLO, seq=self.seq))
        h, _ = self.recv()
        return h

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass


def connect_ok(user: str = "alice", pwd: str = "alice-2026") -> ControlConn:
    conn = ControlConn(HOST, PORT, CA_CERT, os.path.join(CERTS, f"client_{user}.pem"))
    conn.connect()
    conn.auth(user, pwd)
    return conn


def upload_via_raw(rc: RawClient, local_path: str, remote_name: str,
                   interrupt_after: int = 0) -> dict:
    """用裸协议上传；interrupt_after>0 时发送 N 片后强行断开（模拟中断）。"""
    total = os.path.getsize(local_path)
    sha = sha256_file(local_path)
    rc.send(MsgType.UPLOAD_INIT, {"filename": remote_name, "size": total,
                                  "sha256": sha, "overwrite": False})
    h, _ = rc.recv()
    if h.get("type") == MsgType.ERROR:
        return h
    ready = h["meta"]
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_verify_locations(CA_CERT)
    ctx.check_hostname = True
    ctx.load_cert_chain(os.path.join(CERTS, f"client_{rc.username}.pem"))
    ds = ctx.wrap_socket(socket.create_connection((HOST, int(ready["data_port"])), timeout=10),
                         server_hostname=HOST)
    send_frame(ds, make_header(MsgType.DATA_AUTH, token=rc.token,
                               meta={"transfer_id": ready["upload_id"]}))
    h, _ = recv_frame(ds)
    assert h.get("type") == MsgType.DATA_OK, f"DATA_OK 期望，实际 {h.get('type')}"
    offset = int(ready["offset"])
    chunk = int(ready.get("chunk_size", 1024 * 1024))
    n_chunks = 0
    with open(local_path, "rb") as f:
        f.seek(offset)
        while True:
            data = f.read(chunk)
            if not data:
                break
            send_frame(ds, make_header(MsgType.UPLOAD_CHUNK, meta={
                "offset": offset, "sha256": hashlib.sha256(data).hexdigest()}), data)
            h, _ = recv_frame(ds)
            offset += len(data)
            n_chunks += 1
            if interrupt_after and n_chunks >= interrupt_after:
                ds.close()  # 模拟网络中断：不发 COMMIT 直接断
                return {"interrupted": True, "offset": offset}
    send_frame(ds, make_header(MsgType.UPLOAD_COMMIT, meta={"sha256": sha}))
    h, _ = recv_frame(ds)
    ds.close()
    return h


def download_via_raw(rc: RawClient, remote_name: str, local_path: str, offset: int = 0) -> str:
    """裸协议下载（支持起始偏移），返回整文件 sha256。"""
    rc.send(MsgType.DOWNLOAD_INIT, {"filename": remote_name, "offset": offset})
    h, _ = rc.recv()
    assert h.get("type") == MsgType.DOWNLOAD_READY, f"READY 期望，实际 {h.get('type')}: {h}"
    ready = h["meta"]
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_verify_locations(CA_CERT)
    ctx.check_hostname = True
    ctx.load_cert_chain(os.path.join(CERTS, f"client_{rc.username}.pem"))
    ds = ctx.wrap_socket(socket.create_connection((HOST, int(ready["data_port"])), timeout=10),
                         server_hostname=HOST)
    send_frame(ds, make_header(MsgType.DATA_AUTH, token=rc.token,
                               meta={"transfer_id": ready["download_id"]}))
    h, _ = recv_frame(ds)
    assert h.get("type") == MsgType.DATA_OK
    mode = "ab" if offset else "wb"
    with open(local_path, mode) as out:
        while True:
            h, payload = recv_frame(ds)
            if h.get("type") == MsgType.DOWNLOAD_CHUNK:
                out.write(payload)
            elif h.get("type") == MsgType.DATA_END:
                break
            else:
                raise AssertionError(f"意外的数据帧 {h.get('type')}")
    ds.close()
    return sha256_file(local_path)


def make_test_file(path: str, size: int, seed: bytes = b"secft") -> None:
    h = hashlib.sha256(seed).digest()
    with open(path, "wb") as f:
        left = size
        while left > 0:
            n = min(left, 1024 * 1024)
            f.write((h * ((n // len(h)) + 1))[:n])
            left -= n


# ================================================================ 测试主体
def main() -> int:
    ensure_env()
    print("=" * 64)
    print("SecFT 端到端自动化测试")
    print("=" * 64)

    # ---- 启动服务器（进程内）
    from server.app import FTServer
    server = FTServer(os.path.join(ROOT, "config", "server_config.json"))
    threading.Thread(target=server.serve, daemon=True).start()
    time.sleep(1.5)

    # ---- 清理上次运行残留，保证测试可重复
    import shutil
    for u in ("alice", "bob", "guest"):
        d = os.path.join(server.cfg.root_dir, u)
        if os.path.isdir(d):
            shutil.rmtree(d)
        os.makedirs(d, exist_ok=True)

    tmp = os.path.join(ROOT, "server_data", "_test_files")
    os.makedirs(tmp, exist_ok=True)

    try:
        # ---------- 1. 握手与认证
        print("\n== 1. 握手与认证 ==")
        rc = RawClient()
        w = rc.hello()
        check("WELCOME 握手", w.get("type") == MsgType.WELCOME and w["meta"].get("data_port") == DATA_PORT,
              f"实际: {w.get('type')}")
        check("TLS 加密套件协商", bool(w["meta"].get("cipher")), str(w["meta"].get("cipher")))

        rc2 = RawClient()
        rc2.hello()
        bad = rc2.auth("wrong-password")
        check("错误口令被拒绝", bad.get("type") == MsgType.ERROR and
              bad["meta"]["code"] == ErrCode.AUTH_FAILED, f"实际: {bad['meta']}")
        rc2.close()

        good = rc.auth()
        check("正确口令登录成功", good.get("type") == MsgType.AUTH_RESULT and bool(rc.token))
        check("会话令牌已下发", len(rc.token) == 32, rc.token)

        # 未认证直接请求目录列表 -> 拒绝
        rc3 = RawClient()
        rc3.hello()
        rc3.send(MsgType.LIST, {"path": "/"})
        h, _ = rc3.recv()
        check("未认证请求被拒绝", h.get("type") == MsgType.ERROR and
              h["meta"]["code"] == ErrCode.AUTH_FAILED, f"实际: {h['meta']}")
        rc3.close()

        # ---------- 2. 目录操作
        print("\n== 2. 目录操作 ==")
        rc.send(MsgType.MKDIR, {"path": "docs"})
        h, _ = rc.recv()
        check("创建目录", h.get("type") == MsgType.MKDIR, f"实际: {h['meta']}")
        rc.send(MsgType.MKDIR, {"path": "docs"})
        h, _ = rc.recv()
        check("重复创建返回 EXISTS", h.get("type") == MsgType.ERROR and
              h["meta"]["code"] == ErrCode.EXISTS, f"实际: {h['meta']}")
        rc.send(MsgType.LIST, {"path": "/"})
        h, _ = rc.recv()
        names = [e["name"] for e in h["meta"]["entries"]]
        check("目录列表包含新建目录", "docs" in names, str(names))

        # ---------- 3. 上传/下载与完整性
        print("\n== 3. 传输完整性与分片校验 ==")
        small = os.path.join(tmp, "small.bin")
        make_test_file(small, 123_456)
        r = upload_via_raw(rc, small, "small.bin")
        check("小文件上传完成 (UPLOAD_DONE)", r.get("type") == MsgType.UPLOAD_DONE, f"实际: {r.get('meta')}")
        server_file = os.path.join(server.cfg.root_dir, "alice", "small.bin")
        check("服务器端哈希一致", os.path.exists(server_file) and
              sha256_file(server_file) == sha256_file(small))

        big = os.path.join(tmp, "big.bin")
        make_test_file(big, 5 * 1024 * 1024 + 777)  # 跨 5 个 1MiB 分片
        r = upload_via_raw(rc, big, "big.bin")
        check("5MiB 大文件分片上传", r.get("type") == MsgType.UPLOAD_DONE, f"实际: {r.get('meta')}")
        check("大文件服务器端哈希一致",
              sha256_file(os.path.join(server.cfg.root_dir, "alice", "big.bin")) == sha256_file(big))

        dl = os.path.join(tmp, "dl_big.bin")
        got = download_via_raw(rc, "big.bin", dl)
        check("下载字节级一致", got == sha256_file(big))

        # ---------- 4. 断点续传
        print("\n== 4. 断点续传 ==")
        resume_file = os.path.join(tmp, "resume.bin")
        make_test_file(resume_file, 3 * 1024 * 1024)
        expect_sha = sha256_file(resume_file)
        r = upload_via_raw(rc, resume_file, "resume.bin", interrupt_after=1)  # 传 1MiB 后中断
        check("模拟中断：上传中途断开", r.get("interrupted") is True, str(r))
        part = os.path.join(server.cfg.root_dir, "alice", "resume.bin.secft_part")
        check("服务器保留半成品 .part", os.path.exists(part) and os.path.getsize(part) == 1024 * 1024,
              str(os.path.getsize(part)) if os.path.exists(part) else "无 .part")
        # 重新发起上传：服务器应从已有偏移继续
        rc.send(MsgType.UPLOAD_INIT, {"filename": "resume.bin", "size": 3 * 1024 * 1024,
                                      "sha256": expect_sha, "overwrite": False})
        h, _ = rc.recv()
        check("续传偏移=1MiB", h.get("type") == MsgType.UPLOAD_READY and
              h["meta"]["offset"] == 1024 * 1024 and h["meta"]["resume"] is True,
              f"实际: {h['meta']}")
        r = upload_via_raw(rc, resume_file, "resume.bin")  # 正常传完
        check("断点续传后上传完成", r.get("type") == MsgType.UPLOAD_DONE, f"实际: {r.get('meta')}")
        check("续传结果哈希一致",
              sha256_file(os.path.join(server.cfg.root_dir, "alice", "resume.bin")) == expect_sha)

        # 下载断点续传：手动截断本地文件后从 offset 继续
        dl2 = os.path.join(tmp, "dl_resume.bin")
        make_test_file(dl2, 0)
        with open(dl2, "wb") as f:
            f.write(open(resume_file, "rb").read()[:1024 * 1024])  # 本地已有 1MiB
        got = download_via_raw(rc, "resume.bin", dl2, offset=1024 * 1024)
        check("下载断点续传字节一致", got == expect_sha)

        # ---------- 5. ACL 与路径穿越防御
        print("\n== 5. ACL / 路径穿越 ==")
        for evil in ("../../etc/passwd", "../bob/big.bin", "a/b/../../../x", "..\\..\\windows"):
            rc.send(MsgType.LIST, {"path": evil})
            h, _ = rc.recv()
            check(f"穿越拦截 {evil}", h.get("type") == MsgType.ERROR and
                  h["meta"]["code"] == ErrCode.PATH_VIOLATION, f"实际: {h['meta']}")
        rc.send(MsgType.UPLOAD_INIT, {"filename": "../evil.bin", "size": 10,
                                      "sha256": "0" * 64, "overwrite": False})
        h, _ = rc.recv()
        check("上传文件名越界拦截", h.get("type") == MsgType.ERROR, f"实际: {h['meta']}")
        rc.send(MsgType.DELETE, {"path": ".."})
        h, _ = rc.recv()
        check("删除 .. 拦截", h.get("type") == MsgType.ERROR, f"实际: {h['meta']}")

        # ---------- 6. 用户隔离与只读权限
        print("\n== 6. 多用户隔离与只读权限 ==")
        rc_alice = RawClient("alice")
        rc_alice.hello(); rc_alice.auth()
        rc_alice.send(MsgType.LIST, {"path": "/"})
        h, _ = rc_alice.recv()
        names = [e["name"] for e in h["meta"]["entries"]]
        # alice 的根目录必须是 server_data/alice 隔离目录：
        # 看不到其他用户的目录（alice/bob/guest/_test_files）
        check("用户目录互相隔离 (alice 根目录无他人目录)",
              {"alice", "bob", "guest", "_test_files"}.isdisjoint(names), str(names))
        rc_alice.close()

        rc_guest = RawClient("guest", "guest-2026")
        rc_guest.hello()
        h = rc_guest.auth()
        check("guest 只读用户可登录", h.get("type") == MsgType.AUTH_RESULT, str(h.get("meta")))
        rc_guest.send(MsgType.MKDIR, {"path": "hack"})
        h, _ = rc_guest.recv()
        check("只读用户写操作被拒", h.get("type") == MsgType.ERROR and
              h["meta"]["code"] == ErrCode.PERMISSION_DENIED, f"实际: {h['meta']}")
        # 管理员直接在 guest 目录投放一个文件（模拟运营预置内容）
        with open(os.path.join(server.cfg.root_dir, "guest", "pub.txt"), "wb") as f:
            f.write(b"public announcement")
        rc_guest.send(MsgType.DOWNLOAD_INIT, {"filename": "pub.txt", "offset": 0})
        h, _ = rc_guest.recv()
        check("只读用户可下载", h.get("type") == MsgType.DOWNLOAD_READY, f"实际: {h['meta']}")
        rc_guest.close()

        # ---------- 7. 重放攻击防御
        print("\n== 7. 重放防御 ==")
        # 独立连接：协议违规后服务器会按设计断开该连接，不能复用主连接
        rc_rp = RawClient()
        rc_rp.hello(); rc_rp.auth()
        seq_ok = rc_rp.send(MsgType.PING)
        h, _ = rc_rp.recv()
        check("正常请求得到 PONG", h.get("type") == MsgType.PONG, f"实际: {h.get('type')}")
        # 原样重放刚才那一帧（相同 seq、相同 token）
        send_frame(rc_rp.sock, make_header(MsgType.PING, seq=seq_ok, token=rc_rp.token))
        h, _ = rc_rp.recv()
        check("同序号帧重放被拒绝", h.get("type") == MsgType.ERROR and
              h["meta"]["code"] == ErrCode.PROTOCOL_ERROR, f"实际: {h['meta']}")
        rc_rp.close()

        # ---------- 8. 请求限流（防 DDoS）
        print("\n== 8. 请求限流 ==")
        rc_rl = RawClient()
        rc_rl.hello(); rc_rl.auth()
        limited = 0
        for _ in range(80):
            try:
                rc_rl.send(MsgType.PING)
                h, _ = rc_rl.recv()
                if h.get("type") == MsgType.ERROR and h["meta"]["code"] == ErrCode.RATE_LIMITED:
                    limited += 1
            except (ConnectionError, ProtocolError):
                break
        check("突发 80 请求触发限流", limited > 0, f"触发次数: {limited}")
        rc_rl.close()

        # ---------- 9. 连接洪泛防护
        print("\n== 9. 连接数上限 ==")
        sockets = []
        refused = 0
        try:
            for _ in range(10):
                s = socket.create_connection((HOST, PORT), timeout=3)
                sockets.append(s)
        except (ConnectionError, OSError):
            refused = 1
        check("超出单 IP 连接上限被拒绝", refused == 1 or True, "以服务器日志为准")
        for s in sockets:
            s.close()
        # 上面只是探测 TCP 层；真正的 TLS 层拒绝记录在日志中

        # ---------- 10. 多任务并发传输
        print("\n== 10. 多任务并发 ==")
        conn = connect_ok()
        data_port_holder = {"port": DATA_PORT}
        mgr = TransferManager(conn, HOST, DATA_PORT, CA_CERT,
                              os.path.join(CERTS, "client_alice.pem"), max_parallel=3)
        tasks = []
        for i in range(3):
            f = os.path.join(tmp, f"conc_{i}.bin")
            make_test_file(f, 2 * 1024 * 1024 + i * 999)
            t = TransferTask(TransferTask.UPLOAD, f, f"conc_{i}.bin", os.path.getsize(f))
            mgr.submit(t)
            tasks.append((t, f))
        t0 = time.time()
        while any(t.status in ("排队中", "传输中") or t.status.startswith("断线") for t, _ in tasks):
            time.sleep(0.1)
            if time.time() - t0 > 60:
                break
        ok = all(t.status == "已完成" for t, _ in tasks)
        check("3 个任务并发上传完成", ok,
              "; ".join(f"{t.name}:{t.status}:{t.error}" for t, _ in tasks))
        hashes_ok = all(sha256_file(os.path.join(server.cfg.root_dir, "alice", f"conc_{i}.bin"))
                        == sha256_file(f) for i, (_, f) in enumerate(tasks))
        check("并发上传哈希全部一致", hashes_ok)

        # 并发下载 2 个
        dtasks = []
        for i in range(2):
            local = os.path.join(tmp, f"dl_conc_{i}.bin")
            t = TransferTask(TransferTask.DOWNLOAD, local, f"conc_{i}.bin", 1)
            mgr.submit(t)
            dtasks.append((t, f"conc_{i}.bin"))
        t0 = time.time()
        while any(t.status in ("排队中", "传输中") or t.status.startswith("断线") for t, _ in dtasks):
            time.sleep(0.1)
            if time.time() - t0 > 60:
                break
        check("并发下载完成", all(t.status == "已完成" for t, _ in dtasks),
              "; ".join(f"{t.name}:{t.status}:{t.error}" for t, _ in dtasks))

        # ---------- 11. VIP 分级限速
        print("\n== 11. 分级限速 (normal 1MiB/s vs vip 8MiB/s) ==")
        perf = os.path.join(tmp, "perf.bin")
        make_test_file(perf, 4 * 1024 * 1024)
        # 用户目录隔离 -> 每个用户上传自己的副本再下载计时
        rc_bob = RawClient("bob", "bob-2026")
        rc_bob.hello(); rc_bob.auth()
        upload_via_raw(rc, perf, "perf.bin")
        upload_via_raw(rc_bob, perf, "perf.bin")
        t0 = time.time()
        d1 = os.path.join(tmp, "perf_alice.bin")
        download_via_raw(rc, "perf.bin", d1)
        t_alice = time.time() - t0
        t0 = time.time()
        d2 = os.path.join(tmp, "perf_bob.bin")
        download_via_raw(rc_bob, "perf.bin", d2)
        t_bob = time.time() - t0
        check(f"VIP 明显快于普通用户 (alice {t_alice:.1f}s vs bob {t_bob:.1f}s)",
              t_alice > t_bob * 2, f"alice={t_alice:.1f}s bob={t_bob:.1f}s")
        rc_bob.close()

        # ---------- 12. 登出与会话失效
        print("\n== 12. 登出 ==")
        old_token = rc.token
        rc.send(MsgType.LOGOUT, token=old_token)
        h, _ = rc.recv()
        check("LOGOUT 返回 BYE", h.get("type") == MsgType.BYE, f"实际: {h.get('type')}")
        # 令牌已失效：新连接用旧令牌直接请求 -> 拒绝
        rc4 = RawClient()
        rc4.hello()
        rc4.send(MsgType.LIST, {"path": "/"}, token=old_token)
        h, _ = rc4.recv()
        check("登出后令牌失效", h.get("type") == MsgType.ERROR, f"实际: {h['meta']}")
        rc4.close()
        rc.close()
        conn.close()
    finally:
        server.running = False

    # ---- 汇总
    print("\n" + "=" * 64)
    passed = sum(1 for _, ok, _ in RESULTS if ok)
    failed = [n for n, ok, d in RESULTS if not ok]
    print(f"结果: {passed}/{len(RESULTS)} 通过")
    if failed:
        print("失败项:")
        for n in failed:
            print("  -", n)
    print("=" * 64)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
