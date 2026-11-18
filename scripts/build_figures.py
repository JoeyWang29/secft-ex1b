"""生成实验报告插图（matplotlib -> docs/figures/*.png）。

包含：系统架构图、协议帧格式图、认证/上传(断点续传)/下载时序图、
安全防御体系图、心跳长连接示意图。
"""

import os

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch

# 中文字体（Windows: 微软雅黑）
plt.rcParams["font.sans-serif"] = ["Microsoft YaHei", "SimHei"]
plt.rcParams["axes.unicode_minus"] = False

FIGS = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                    "docs", "figures")
os.makedirs(FIGS, exist_ok=True)

C_BLUE = "#2b6cb0"
C_LIGHT = "#ebf4ff"
C_GREEN = "#2f855a"
C_LGREEN = "#f0fff4"
C_ORANGE = "#c05621"
C_LORANGE = "#fffaf0"
C_RED = "#c53030"
C_GRAY = "#4a5568"


def box(ax, x, y, w, h, text, fc=C_LIGHT, ec=C_BLUE, fs=10, weight="normal"):
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.02",
                                fc=fc, ec=ec, lw=1.4))
    ax.text(x + w / 2, y + h / 2, text, ha="center", va="center",
            fontsize=fs, fontweight=weight, color="#1a202c")


def arrow(ax, x1, y1, x2, y2, text="", color=C_GRAY, fs=9, style="-|>", ls="-", dy=0.15):
    ax.add_patch(FancyArrowPatch((x1, y1), (x2, y2), arrowstyle=style,
                                 mutation_scale=14, color=color, lw=1.6, ls=ls))
    if text:
        ax.text((x1 + x2) / 2, (y1 + y2) / 2 + dy, text, ha="center", va="bottom",
                fontsize=fs, color=color)


def save(fig, name):
    path = os.path.join(FIGS, name)
    fig.savefig(path, dpi=150, bbox_inches="tight", facecolor="white")
    plt.close(fig)
    print("生成", name)


# ================================================================ 1. 系统架构
def fig_architecture():
    fig, ax = plt.subplots(figsize=(10, 7))
    ax.set_xlim(0, 10)
    ax.set_ylim(0, 7)
    ax.axis("off")

    # 客户端 / 服务器两大框
    box(ax, 0.4, 3.9, 3.0, 2.6, "", fc="#f7fafc", ec=C_BLUE)
    ax.text(1.9, 6.2, "客户端（Tkinter GUI）", ha="center", fontsize=11, fontweight="bold", color=C_BLUE)
    box(ax, 0.6, 5.5, 2.6, 0.55, "远程浏览 / 本地浏览\n上传下载 / 任务队列", fs=8.5)
    box(ax, 0.6, 4.8, 2.6, 0.55, "TransferManager\n多任务并发 + 断点续传", fs=8.5)
    box(ax, 0.6, 4.1, 2.6, 0.55, "ControlConn\n心跳保活(15s) / 挑战应答", fs=8.5)

    box(ax, 6.6, 3.9, 3.0, 2.6, "", fc="#f7fafc", ec=C_GREEN)
    ax.text(8.1, 6.2, "服务器（多线程）", ha="center", fontsize=11, fontweight="bold", color=C_GREEN)
    box(ax, 6.8, 5.5, 2.6, 0.55, "控制线程池\n每连接一线程", fs=8.5)
    box(ax, 6.8, 4.8, 2.6, 0.55, "SessionManager 会话管理\nseq 防重放", fs=8.5)
    box(ax, 6.8, 4.1, 2.6, 0.55, "UserStore (PBKDF2)\nACL 越狱防护 / 令牌桶", fs=8.5)

    # 数据通道（上）
    arrow(ax, 3.4, 5.9, 6.6, 5.9, "数据通道 TLS :19444", color=C_ORANGE, fs=10)
    ax.text(5.0, 5.72, "每任务一条独立连接\n分片 + SHA-256 校验", ha="center", va="top",
            fontsize=8, color=C_ORANGE)
    # 控制通道（下）
    arrow(ax, 3.4, 4.72, 6.6, 4.72, "控制通道 TLS :19443", color=C_BLUE, fs=10)
    ax.text(5.0, 4.54, "长连接 + PING 心跳\n认证 / 目录操作 / 任务建立", ha="center", va="top",
            fontsize=8, color=C_BLUE)

    # 底部支撑组件
    box(ax, 0.4, 1.3, 3.0, 1.0, "PKI: ca-cert + server-cert\n+ client_<user>.pem\n(双向认证)",
        fc=C_LORANGE, ec=C_ORANGE, fs=8)
    box(ax, 6.6, 1.3, 1.4, 1.0, "users.json\nPBKDF2 口令\n封禁/分级", fc=C_LGREEN, ec=C_GREEN, fs=8)
    box(ax, 8.2, 1.3, 1.4, 1.0, "server_data/\nalice/ bob/ guest/\n用户隔离目录", fc=C_LGREEN, ec=C_GREEN, fs=8)
    arrow(ax, 1.9, 2.35, 1.9, 3.85, "", color=C_ORANGE, ls=":")
    arrow(ax, 7.3, 2.35, 7.3, 3.85, "", color=C_GREEN, ls=":")
    arrow(ax, 8.9, 2.35, 8.9, 3.85, "", color=C_GREEN, ls=":")
    ax.text(5.0, 0.55, "TLS 1.2+ 全链路加密 · 双向证书认证 · 完整性 SHA-256 · 分级限速(VIP)",
            ha="center", fontsize=9.5, color=C_GRAY)
    save(fig, "fig_architecture.png")


# ================================================================ 2. 帧格式
def fig_frame():
    fig, ax = plt.subplots(figsize=(11, 3.4))
    ax.set_xlim(0, 11)
    ax.set_ylim(0, 3.4)
    ax.axis("off")
    # 三个区段
    box(ax, 0.2, 1.2, 1.2, 1.0, "header_len\n(u32 BE)\n4 字节", fc=C_LORANGE, ec=C_ORANGE, fs=9)
    box(ax, 1.4, 1.2, 4.6, 1.0, "JSON 报头（UTF-8，可变长）", fc=C_LIGHT, ec=C_BLUE, fs=11)
    box(ax, 6.0, 1.2, 4.6, 1.0, "载荷 payload（二进制，文件分片数据）", fc=C_LGREEN, ec=C_GREEN, fs=10)
    # JSON 字段细分
    fields = [("ver", 1.55), ("type", 2.45), ("seq", 3.25), ("ack", 3.9), ("token", 4.55), ("plen", 5.25), ("meta", 5.85)]
    for name, x in fields:
        ax.text(x, 1.95, name, ha="center", fontsize=9, color=C_BLUE, fontweight="bold")
        ax.plot([x - 0.32, x - 0.32], [1.2, 2.2], color="#bee3f8", lw=0.8)
    ax.text(3.7, 0.55, "报头自描述长度 plen → 接收方先读 4B 长度，再读 JSON，再按 plen 读载荷\n"
                       "（对应课程要求的 sizeof(json) ‖ json ‖ payload 编码）",
            ha="center", fontsize=9.5, color=C_GRAY)
    ax.text(8.3, 0.85, "文件分片 ≤ chunk_size(默认1MiB)", ha="center", fontsize=8.5, color=C_GREEN)
    save(fig, "fig_frame.png")


# ================================================================ 3. 时序图
def seq_diag(name, title, lifelines, steps, figsize=(9, None)):
    """lifelines: [(label, x)]; steps: (x_from, x_to, label, color, dashed|note)"""
    n = len(lifelines)
    h = 1.2 + len(steps) * 0.52 + 0.6
    fig, ax = plt.subplots(figsize=(figsize[0], h))
    ax.set_xlim(-0.6, n + 0.6)
    ax.set_ylim(0, h)
    ax.axis("off")
    for label, x in lifelines:
        box(ax, x - 0.72, h - 0.62, 1.44, 0.5, label, fs=10, weight="bold")
        ax.plot([x, x], [0.3, h - 0.62], color="#a0aec0", lw=1.2, ls="--")
    y = h - 1.0
    for st in steps:
        if st[0] == "note":
            _, text, color = st
            ax.text(0.05, y, text, fontsize=8.5, color=color, style="italic")
            y -= 0.34
            continue
        x1, x2, text, color = st[0], st[1], st[2], st[3]
        dashed = len(st) > 4 and st[4]
        arrow(ax, x1, y, x2, y - 0.12, text, color=color, fs=8.5,
              style="-|>" if not dashed else "-|>", ls="--" if dashed else "-")
        y -= 0.52
    save(fig, name)


def fig_seq_auth():
    seq_diag("fig_seq_auth.png", "认证时序",
             [("客户端", 1), ("服务器", 3)],
             [
                 (1, 3, "HELLO (ver=1)", C_BLUE),
                 (3, 1, "WELCOME (cipher, data_port)", C_GREEN, True),
                 (1, 3, "AUTH_INIT {username}", C_BLUE),
                 ("note", "服务器检查用户存在/封禁/证书CN绑定", C_ORANGE),
                 (3, 1, "AUTH_SALT {salt, nonce, iter}", C_GREEN, True),
                 ("note", "客户端计算 X=PBKDF2(口令,salt,iter)，proof=HMAC(X,nonce)", C_GRAY),
                 (1, 3, "AUTH_PROOF {proof}", C_BLUE),
                 ("note", "服务器重算 HMAC 比对（compare_digest 防时序侧信道）", C_GRAY),
                 (3, 1, "AUTH_RESULT {token, tier, perm}", C_GREEN, True),
                 ("note", "后续请求携带 token，seq 单调递增防重放", C_GRAY),
             ])


def fig_seq_upload():
    seq_diag("fig_seq_upload.png", "上传时序（含断点续传）",
             [("客户端", 1), ("控制通道", 2), ("数据通道", 3), ("服务器", 4)],
             [
                 (1, 4, "UPLOAD_INIT {filename,size,sha256,overwrite}", C_BLUE),
                 (4, 1, "UPLOAD_READY {upload_id, chunk, offset}", C_GREEN, True),
                 ("note", "服务器存在 .secft_part 半成品 → offset=已有长度（断点续传）", C_ORANGE),
                 (1, 3, "新开 TLS 数据连接: DATA_AUTH {upload_id}", C_ORANGE),
                 (3, 1, "DATA_OK", C_GREEN, True),
                 (1, 3, "UPLOAD_CHUNK {offset, sha256} + 1MiB 分片", C_BLUE),
                 (3, 1, "UPLOAD_ACK {offset}（累积确认，ACK 延迟=背压限速）", C_GREEN, True),
                 ("note", "分片哈希即时校验；停等协议保证偏移严格对齐", C_GRAY),
                 (1, 3, "UPLOAD_COMMIT {sha256}", C_ORANGE),
                 (3, 1, "校验整文件 SHA-256 → 原子改名落盘", C_GRAY, True),
                 (3, 1, "UPLOAD_DONE {sha256}", C_GREEN, True),
                 ("note", "任一环节断线：客户端自动重连并从服务器 .part 偏移继续", C_RED),
             ])


def fig_seq_download():
    seq_diag("fig_seq_download.png", "下载时序（支持断点续传）",
             [("客户端", 1), ("控制通道", 2), ("数据通道", 3), ("服务器", 4)],
             [
                 (1, 4, "DOWNLOAD_INIT {filename, offset=本地.part长度}", C_BLUE),
                 (4, 1, "DOWNLOAD_READY {download_id, size, sha256}", C_GREEN, True),
                 (1, 3, "新开 TLS 数据连接: DATA_AUTH {download_id}", C_ORANGE),
                 (3, 1, "DATA_OK", C_GREEN, True),
                 (3, 1, "DOWNLOAD_CHUNK {offset, sha256} + 分片（令牌桶整形带宽）", C_GREEN, True),
                 (3, 1, "…… 流式推送至文件尾 ……", C_GRAY, True),
                 (3, 1, "DATA_END {sent, ok}", C_ORANGE, True),
                 ("note", "客户端合并前缀 + 新数据，整文件 SHA-256 校验后原子落盘", C_GRAY),
                 ("note", "VIP=8MiB/s / normal=1MiB/s：服务器令牌桶按用户全局限速", C_RED),
             ])


def fig_seq_heartbeat():
    seq_diag("fig_seq_heartbeat.png", "长连接与心跳保活",
             [("客户端", 1), ("服务器守护进程", 3)],
             [
                 ("note", "客户端不主动关闭连接（课程要求 keep-alive），由以下机制维持", C_GRAY),
                 (1, 3, "PING (每 15 秒)", C_BLUE),
                 (3, 1, "PONG {server_time}", C_GREEN, True),
                 ("note", "服务器空闲超时 75 秒：无任何帧则回收连接与会话", C_ORANGE),
                 ("note", "Janitor 守护线程定期清理过期会话/传输任务/带宽桶", C_ORANGE),
                 (1, 3, "LOGOUT（用户主动退出）", C_BLUE),
                 (3, 1, "BYE + 会话令牌吊销", C_GREEN, True),
             ])


# ================================================================ 4. 安全体系
def fig_security():
    fig, ax = plt.subplots(figsize=(10, 5.6))
    ax.set_xlim(0, 10)
    ax.set_ylim(0, 5.6)
    ax.axis("off")
    ax.text(5, 5.25, "三层纵深防御体系", ha="center", fontsize=13, fontweight="bold", color="#1a365d")

    box(ax, 0.3, 3.6, 3.0, 1.35, "① 传输层：防中间人\nTLS1.2+/1.3 · 自建CA证书链\n双向证书认证(加分项)\n证书CN与用户名绑定", fc=C_LIGHT, ec=C_BLUE, fs=9)
    box(ax, 3.5, 3.6, 3.0, 1.35, "② 协议层：防重放/防爆破\n挑战-应答(PBKDF2+HMAC)\nseq 单调递增防重放\nPBKDF2-200k 落盘存储", fc=C_LGREEN, ec=C_GREEN, fs=9)
    box(ax, 6.7, 3.6, 3.0, 1.35, "③ 业务层：防滥用/防注入\n请求限流(令牌桶)\n连接数/封禁/帧长上限\n路径越狱拦截+白名单", fc=C_LORANGE, ec=C_ORANGE, fs=9)

    box(ax, 0.3, 1.7, 4.5, 1.3, "防 SQL 注入：不使用 SQL，用户凭据存 JSON+\nPBKDF2 校验值；全部文件操作经\nrealpath 越狱检查（. .. 绝对路径 拒绝）", fc="#fff5f5", ec=C_RED, fs=9)
    box(ax, 5.2, 1.7, 4.5, 1.3, "防 DDoS：总连接数/单IP连接上限\n登录5次失败封禁10分钟\n超频>10次强制断开\n文件/帧大小上限", fc="#fff5f5", ec=C_RED, fs=9)

    box(ax, 0.3, 0.35, 9.4, 0.95, "完整性保证：分片 SHA-256 即时校验 + 整文件 SHA-256 提交校验 + os.replace 原子落盘\n"
                               "分级限速：normal 1MiB/s / VIP 8MiB/s（令牌桶按用户全局整形）",
        fc="#f7fafc", ec=C_GRAY, fs=9.5)
    save(fig, "fig_security.png")


if __name__ == "__main__":
    fig_architecture()
    fig_frame()
    fig_seq_auth()
    fig_seq_upload()
    fig_seq_download()
    fig_seq_heartbeat()
    fig_security()
    print("全部插图生成完毕 ->", FIGS)
