"""SecFT 客户端图形界面（Tkinter）：登录、远程浏览、多任务并发传输、状态监控。"""

from __future__ import annotations

import os
import queue
import threading
import time
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

from client.network import ControlConn, SecFTError
from client.transfers import TransferManager, TransferTask

PROJECT_ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", ".."))
CERTS_DIR = os.path.join(PROJECT_ROOT, "certs")
CA_CERT = os.path.join(CERTS_DIR, "ca-cert.pem")


def human_size(n: float) -> str:
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if abs(n) < 1024 or unit == "TiB":
            return f"{n:.1f} {unit}" if unit != "B" else f"{int(n)} B"
        n /= 1024
    return f"{n:.1f} TiB"


class LoginWindow:
    """登录窗口：服务器地址、账号、口令；客户端证书按用户名自动匹配。

    线程模型：网络 worker 线程只向 self.q 投递 (callable, args)，
    主线程每 100ms 轮询执行 —— Tkinter 只允许主线程触碰控件。
    """

    def __init__(self, root: tk.Tk, on_success):
        self.root = root
        self.on_success = on_success
        self.q: queue.Queue = queue.Queue()
        root.title("SecFT 安全文件传输客户端 - 登录")
        root.geometry("420x330")
        frm = ttk.Frame(root, padding=20)
        frm.pack(fill="both", expand=True)

        ttk.Label(frm, text="SecFT 安全文件传输", font=("Microsoft YaHei", 14, "bold")).pack(pady=(0, 12))
        grid = ttk.Frame(frm)
        grid.pack()
        self.var_host = tk.StringVar(value="127.0.0.1")
        self.var_port = tk.StringVar(value="19443")
        self.var_user = tk.StringVar(value="alice")
        self.var_pwd = tk.StringVar(value="")
        rows = [("服务器地址", self.var_host), ("端口", self.var_port),
                ("用户名", self.var_user), ("口令", self.var_pwd)]
        for i, (label, var) in enumerate(rows):
            ttk.Label(grid, text=label).grid(row=i, column=0, sticky="e", padx=4, pady=6)
            entry = ttk.Entry(grid, textvariable=var, width=26,
                              show="*" if var is self.var_pwd else "")
            entry.grid(row=i, column=1, pady=6)
        self.var_info = tk.StringVar(value="双向 TLS：客户端证书将按用户名自动加载")
        ttk.Label(frm, textvariable=self.var_info, foreground="#666").pack(pady=(8, 4))
        self.btn_login = ttk.Button(frm, text="连 接", command=self._do_login)
        self.btn_login.pack(pady=6, ipadx=20)
        tip = ("演示账号: alice/alice-2026 (普通)  bob/bob-2026 (VIP)\n"
               "guest/guest-2026 (只读)  ·  服务器需已启动")
        ttk.Label(frm, text=tip, foreground="#999", font=("Microsoft YaHei", 9)).pack(pady=8)
        root.after(100, self._poll)

    def _poll(self) -> None:
        """主线程轮询：执行 worker 线程投递的 UI 回调。"""
        try:
            while True:
                fn, args = self.q.get_nowait()
                fn(*args)
        except queue.Empty:
            pass
        self.root.after(100, self._poll)

    def _do_login(self) -> None:
        host = self.var_host.get().strip()
        try:
            port = int(self.var_port.get().strip())
        except ValueError:
            messagebox.showerror("错误", "端口必须是数字")
            return
        user = self.var_user.get().strip()
        pwd = self.var_pwd.get()
        self.btn_login.config(state="disabled")
        self.var_info.set("正在连接……")
        threading.Thread(target=self._login_worker, args=(host, port, user, pwd),
                         daemon=True).start()

    def _login_worker(self, host: str, port: int, user: str, pwd: str) -> None:
        try:
            if not os.path.exists(CA_CERT):
                raise SecFTError(0, "找不到 CA 证书 certs/ca-cert.pem，请先运行 scripts/gen_certs.py")
            client_cert = os.path.join(CERTS_DIR, f"client_{user}.pem")
            if not os.path.exists(client_cert):
                client_cert = None  # 未配置客户端证书时退化为单向认证
            conn = ControlConn(host, port, CA_CERT, client_cert)
            banner = conn.connect()
            info = conn.auth(user, pwd)
            self.q.put((self.on_success, (conn, banner, info)))
        except Exception as exc:
            msg = getattr(exc, "message", str(exc))
            self.q.put((self._login_failed, (msg,)))

    def _login_failed(self, msg: str) -> None:
        self.btn_login.config(state="normal")
        self.var_info.set(f"登录失败: {msg}")


class MainWindow:
    """主窗口：远程/本地双栏浏览 + 并发传输队列 + 连接状态栏。"""

    def __init__(self, root: tk.Tk, conn: ControlConn, banner: dict, info: dict):
        self.root = root
        self.conn = conn
        self.banner = banner
        self.remote_path = "/"
        self.local_cwd = os.path.join(PROJECT_ROOT, "local_downloads")
        os.makedirs(self.local_cwd, exist_ok=True)
        self.msg_q: queue.Queue = queue.Queue()

        data_port = int(banner.get("data_port", 19444))
        self.mgr = TransferManager(conn, conn.host, data_port, CA_CERT,
                                   os.path.join(CERTS_DIR, f"client_{conn.user_info.get('username','')}.pem"))
        self.mgr.listeners.append(lambda t: self.msg_q.put(("task", t)))
        self._build_ui()
        root.after(100, self._poll)
        threading.Thread(target=self._refresh_remote, daemon=True).start()

    # ------------------------------------------------------------ UI 构建
    def _build_ui(self) -> None:
        self.root.title("SecFT 安全文件传输客户端")
        self.root.geometry("980x640")
        user = self.conn.user_info
        # ---- 状态栏（顶部）
        top = ttk.Frame(self.root, padding=6)
        top.pack(fill="x")
        self.var_status = tk.StringVar(
            value=f"已登录: {user.get('username')}  等级: {user.get('tier')}  "
                  f"权限: {user.get('perm')}  密码套件: {self.conn.server_cipher}")
        ttk.Label(top, textvariable=self.var_status, foreground="#0a6").pack(side="left")
        ttk.Button(top, text="断开连接", command=self._disconnect).pack(side="right")
        self.var_rtt = tk.StringVar(value="心跳: -")
        ttk.Label(top, textvariable=self.var_rtt).pack(side="right", padx=12)
        # ---- 工具栏
        bar = ttk.Frame(self.root, padding=(6, 0))
        bar.pack(fill="x")
        ttk.Button(bar, text="上传选中文件", command=self._upload).pack(side="left", padx=2)
        ttk.Button(bar, text="下载选中文件", command=self._download).pack(side="left", padx=2)
        ttk.Button(bar, text="新建文件夹", command=self._mkdir).pack(side="left", padx=2)
        ttk.Button(bar, text="删除", command=self._delete).pack(side="left", padx=2)
        ttk.Button(bar, text="重命名", command=self._rename).pack(side="left", padx=2)
        ttk.Button(bar, text="刷新", command=lambda: threading.Thread(
            target=self._refresh_remote, daemon=True).start()).pack(side="left", padx=2)
        # ---- 双栏
        panes = ttk.PanedWindow(self.root, orient="horizontal")
        panes.pack(fill="both", expand=True, padx=6, pady=4)
        # 远程
        rfrm = ttk.LabelFrame(panes, text="远程文件 (用户隔离目录)", padding=4)
        cols = ("name", "type", "size", "mtime")
        self.tree_remote = ttk.Treeview(rfrm, columns=cols, show="headings", selectmode="extended")
        for c, w, t in (("name", 260, "名称"), ("type", 60, "类型"),
                        ("size", 90, "大小"), ("mtime", 130, "修改时间")):
            self.tree_remote.heading(c, text=t)
            self.tree_remote.column(c, width=w)
        self.tree_remote.pack(fill="both", expand=True)
        self.tree_remote.bind("<Double-1>", self._remote_open)
        rbar = ttk.Frame(rfrm); rbar.pack(fill="x")
        ttk.Button(rbar, text="上一级", command=self._remote_up).pack(side="left")
        self.var_rpath = tk.StringVar(value="/")
        ttk.Label(rbar, textvariable=self.var_rpath).pack(side="left", padx=8)
        panes.add(rfrm, weight=3)
        # 本地
        lfrm = ttk.LabelFrame(panes, text="本地文件", padding=4)
        self.tree_local = ttk.Treeview(lfrm, columns=cols, show="headings", selectmode="extended")
        for c, w, t in (("name", 260, "名称"), ("type", 60, "类型"),
                        ("size", 90, "大小"), ("mtime", 130, "修改时间")):
            self.tree_local.heading(c, text=t)
            self.tree_local.column(c, width=w)
        self.tree_local.pack(fill="both", expand=True)
        self.tree_local.bind("<Double-1>", self._local_open)
        lbar = ttk.Frame(lfrm); lbar.pack(fill="x")
        ttk.Button(lbar, text="上一级", command=self._local_up).pack(side="left")
        ttk.Button(lbar, text="切换目录", command=self._local_pick).pack(side="left", padx=4)
        self.var_lpath = tk.StringVar(value=self.local_cwd)
        ttk.Label(lbar, textvariable=self.var_lpath).pack(side="left", padx=8)
        panes.add(lfrm, weight=2)
        # ---- 传输队列
        tfrm = ttk.LabelFrame(self.root, text="传输任务（支持多任务并发 / 断点续传）", padding=4)
        tcols = ("name", "dir", "progress", "bytes", "speed", "state")
        self.tree_tasks = ttk.Treeview(tfrm, columns=tcols, show="headings", height=6)
        for c, w, t in (("name", 200, "文件"), ("dir", 60, "方向"), ("progress", 100, "进度"),
                        ("bytes", 140, "已传/总量"), ("speed", 100, "速度"),
                        ("state", 180, "状态")):
            self.tree_tasks.heading(c, text=t)
            self.tree_tasks.column(c, width=w)
        self.tree_tasks.pack(fill="both", expand=True)
        tfrm.pack(fill="x", padx=6, pady=(0, 4))
        # ---- 日志
        self.txt_log = tk.Text(self.root, height=4, state="disabled", font=("Consolas", 9))
        self.txt_log.pack(fill="x", padx=6, pady=(0, 6))
        self._log("欢迎。长连接已建立，心跳每 15 秒一次；关闭窗口前连接将持续保持。")
        self._refresh_local()
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    # ------------------------------------------------------------ 工具方法
    def _log(self, msg: str) -> None:
        self.txt_log.config(state="normal")
        self.txt_log.insert("end", f"[{time.strftime('%H:%M:%S')}] {msg}\n")
        self.txt_log.see("end")
        self.txt_log.config(state="disabled")

    def _poll(self) -> None:
        """主循环每 100ms 取队列消息刷新 UI（线程安全）。"""
        try:
            while True:
                kind, *args = self.msg_q.get_nowait()
                if kind == "task":
                    self._render_task(args[0])
                elif kind == "log":
                    self._log(args[0])
                elif kind == "entries":
                    self._paint_remote(args[0], args[1])
        except queue.Empty:
            pass
        rtt = self.conn.rtt_ms
        if rtt < 0:
            self.var_rtt.set("心跳: 超时!")
            self.var_status.set("连接异常：心跳超时，请检查网络")
        elif rtt:
            self.var_rtt.set(f"心跳: {rtt:.0f} ms")
        self.root.after(100, self._poll)

    def _render_task(self, task: TransferTask) -> None:
        iid = task.task_id
        vals = (task.name, task.kind, f"{task.percent:.1f}%",
                f"{human_size(task.done_bytes)}/{human_size(task.size)}",
                f"{human_size(task.speed)}/s" if task.speed else "-",
                task.status + (f": {task.error}" if task.error else ""))
        if self.tree_tasks.exists(iid):
            self.tree_tasks.item(iid, values=vals)
        else:
            self.tree_tasks.insert("", "end", iid=iid, values=vals)
        if task.status in ("已完成", "失败"):
            self._log(f"{task.kind} {task.name} -> {task.status}"
                      + (f" ({task.error})" if task.error else "")
                      + (f" [断点续传自 {human_size(task.resume_from)}]" if task.resume_from else ""))
        if task.status == "已完成" and task.kind == TransferTask.DOWNLOAD:
            self._refresh_local()

    # ------------------------------------------------------------ 远程浏览
    def _refresh_remote(self) -> None:
        try:
            entries = self.conn.list_dir(self.remote_path)
        except Exception as exc:
            self.msg_q.put(("log", f"刷新失败: {getattr(exc, 'message', exc)}"))
            return
        self.msg_q.put(("entries", entries, self.remote_path))

    def _paint_remote(self, entries: list, path: str) -> None:
        """主线程渲染远程文件列表。"""
        self.tree_remote.delete(*self.tree_remote.get_children())
        for e in entries:
            self.tree_remote.insert("", "end", values=(
                e["name"], "目录" if e["dir"] else "文件",
                human_size(e["size"]) if not e["dir"] else "-",
                time.strftime("%Y-%m-%d %H:%M", time.localtime(e["mtime"]))))
        self.var_rpath.set("远程: " + path)

    def _remote_open(self, _event) -> None:
        sel = self.tree_remote.selection()
        if not sel:
            return
        vals = self.tree_remote.item(sel[0], "values")
        if vals[1] == "目录":
            name = vals[0]
            self.remote_path = (self.remote_path.rstrip("/") + "/" + name) if self.remote_path != "/" else "/" + name
            threading.Thread(target=self._refresh_remote, daemon=True).start()

    def _remote_up(self) -> None:
        if self.remote_path == "/":
            return
        parent = self.remote_path.rstrip("/").rsplit("/", 1)[0]
        self.remote_path = parent or "/"
        threading.Thread(target=self._refresh_remote, daemon=True).start()

    # ------------------------------------------------------------ 本地浏览
    def _refresh_local(self) -> None:
        self.tree_local.delete(*self.tree_local.get_children())
        try:
            for name in sorted(os.listdir(self.local_cwd)):
                p = os.path.join(self.local_cwd, name)
                st = os.stat(p)
                self.tree_local.insert("", "end", values=(
                    name, "目录" if os.path.isdir(p) else "文件",
                    human_size(st.st_size) if os.path.isfile(p) else "-",
                    time.strftime("%Y-%m-%d %H:%M", time.localtime(st.st_mtime))))
        except OSError:
            pass
        self.var_lpath.set("本地: " + self.local_cwd)

    def _local_open(self, _event) -> None:
        sel = self.tree_local.selection()
        if not sel:
            return
        vals = self.tree_local.item(sel[0], "values")
        p = os.path.join(self.local_cwd, vals[0])
        if os.path.isdir(p):
            self.local_cwd = p
            self._refresh_local()

    def _local_up(self) -> None:
        parent = os.path.dirname(self.local_cwd)
        if os.path.isdir(parent):
            self.local_cwd = parent
            self._refresh_local()

    def _local_pick(self) -> None:
        d = filedialog.askdirectory(initialdir=self.local_cwd)
        if d:
            self.local_cwd = d
            self._refresh_local()

    # ------------------------------------------------------------ 操作
    def _upload(self) -> None:
        files = filedialog.askopenfilenames(initialdir=self.local_cwd,
                                            title="选择要上传的文件（可多选）")
        if not files:
            return
        for f in files:
            name = os.path.basename(f)
            remote = (self.remote_path.rstrip("/") + "/" + name)
            task = TransferTask(TransferTask.UPLOAD, f, remote.lstrip("/") or name,
                                os.path.getsize(f))
            self.mgr.submit(task)
        self._log(f"已加入 {len(files)} 个上传任务（并发上限 4）")

    def _download(self) -> None:
        sel = self.tree_remote.selection()
        if not sel:
            messagebox.showinfo("提示", "请先在远程列表中选择要下载的文件")
            return
        for iid in sel:
            vals = self.tree_remote.item(iid, "values")
            name, typ = vals[0], vals[1]
            if typ == "目录":
                continue
            remote = (self.remote_path.rstrip("/") + "/" + name).lstrip("/")
            local = os.path.join(self.local_cwd, name)
            self.mgr.submit(TransferTask(TransferTask.DOWNLOAD, local, remote, 1))
        self._log("已加入下载任务")

    def _mkdir(self) -> None:
        name = self._ask_str("新建文件夹", "请输入文件夹名称：")
        if not name:
            return
        try:
            self.conn.mkdir(name)
            self._log(f"已创建目录 {name}")
            threading.Thread(target=self._refresh_remote, daemon=True).start()
        except Exception as exc:
            messagebox.showerror("失败", getattr(exc, "message", str(exc)))

    def _delete(self) -> None:
        sel = self.tree_remote.selection()
        if not sel:
            return
        if not messagebox.askyesno("确认", f"确定删除选中的 {len(sel)} 项？"):
            return
        for iid in sel:
            vals = self.tree_remote.item(iid, "values")
            path = (self.remote_path.rstrip("/") + "/" + vals[0]).lstrip("/")
            try:
                self.conn.delete(path)
                self._log(f"已删除 {path}")
            except Exception as exc:
                messagebox.showerror("删除失败", f"{vals[0]}: {getattr(exc, 'message', exc)}")
        threading.Thread(target=self._refresh_remote, daemon=True).start()

    def _rename(self) -> None:
        sel = self.tree_remote.selection()
        if len(sel) != 1:
            messagebox.showinfo("提示", "请选择一项进行重命名")
            return
        old = self.tree_remote.item(sel[0], "values")[0]
        new = self._ask_str("重命名", f"将 {old} 重命名为：")
        if not new or new == old:
            return
        base = "" if self.remote_path == "/" else self.remote_path.strip("/")
        try:
            self.conn.rename(f"{base}/{old}".lstrip("/"), f"{base}/{new}".lstrip("/"))
            self._log(f"已重命名 {old} -> {new}")
            threading.Thread(target=self._refresh_remote, daemon=True).start()
        except Exception as exc:
            messagebox.showerror("失败", getattr(exc, "message", str(exc)))

    def _ask_str(self, title: str, prompt: str) -> str | None:
        win = tk.Toplevel(self.root)
        win.title(title)
        win.geometry("320x120")
        win.transient(self.root)
        var = tk.StringVar()
        ttk.Label(win, text=prompt, padding=8).pack()
        entry = ttk.Entry(win, textvariable=var, width=30)
        entry.pack(pady=4)
        result = {"v": None}
        def ok(_e=None):
            result["v"] = var.get().strip()
            win.destroy()
        entry.bind("<Return>", ok)
        ttk.Button(win, text="确定", command=ok).pack(pady=6)
        entry.focus_set()
        win.grab_set()
        self.root.wait_window(win)
        return result["v"]

    # ------------------------------------------------------------ 会话
    def _disconnect(self) -> None:
        if messagebox.askyesno("断开", "确定断开与服务器的连接？"):
            self._on_close()

    def _on_close(self) -> None:
        try:
            self.conn.logout()
        except Exception:
            self.conn.close()
        self.root.destroy()


def run() -> None:
    root = tk.Tk()
    try:
        style = ttk.Style(root)
        if "vista" in style.theme_names():
            style.theme_use("vista")
    except Exception:
        pass

    def on_success(conn, banner, info):
        for w in root.winfo_children():
            w.destroy()
        MainWindow(root, conn, banner, info)

    LoginWindow(root, on_success)
    root.mainloop()
