"""GUI 冒烟测试：进程内启动服务器，程序化登录并构建主窗口，验证界面可创建。

用法: python scripts/gui_smoke_test.py
说明：会短暂弹出一个窗口，验证后自动关闭。
"""

import os
import sys
import threading
import time

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
sys.path.insert(0, os.path.join(ROOT, "src"))

import tkinter as tk

from client.gui import LoginWindow, MainWindow, CERTS_DIR
from client.network import ControlConn

CA_CERT = os.path.join(CERTS_DIR, "ca-cert.pem")


def main() -> int:
    from server.app import FTServer
    server = FTServer(os.path.join(ROOT, "config", "server_config.json"))
    threading.Thread(target=server.serve, daemon=True).start()
    time.sleep(1.5)

    root = tk.Tk()
    root.withdraw()
    # 1) 登录窗口可构建
    login_holder = {}
    def on_success(conn, banner, info):
        login_holder["ok"] = True
    lw = LoginWindow(root, on_success)
    lw.var_host.set("127.0.0.1")
    lw.var_port.set("19443")
    lw.var_user.set("alice")
    lw.var_pwd.set("alice-2026")
    root.update()
    print("[OK] 登录窗口构建成功")
    lw._do_login()
    t0 = time.time()
    while "ok" not in login_holder and time.time() - t0 < 10:
        root.update()
        time.sleep(0.05)
    assert login_holder.get("ok"), "程序化登录失败"
    print("[OK] 程序化登录成功（TLS 双向认证 + 挑战应答）")

    # 2) 主窗口可构建
    conn = ControlConn("127.0.0.1", 19443, CA_CERT,
                       os.path.join(CERTS_DIR, "client_alice.pem"))
    banner = conn.connect()
    info = conn.auth("alice", "alice-2026")
    for w in root.winfo_children():
        w.destroy()
    mw = MainWindow(root, conn, banner, info)
    root.update()
    time.sleep(1.0)  # 等待远程列表刷新线程
    root.update()
    rows = mw.tree_remote.get_children()
    print(f"[OK] 主窗口构建成功，远程列表条目数={len(rows)}")
    rtt = conn.rtt_ms
    print(f"[OK] 心跳 RTT = {rtt:.1f} ms")

    conn.logout()
    root.destroy()
    server.running = False
    print("GUI 冒烟测试全部通过")
    return 0


if __name__ == "__main__":
    sys.exit(main())
