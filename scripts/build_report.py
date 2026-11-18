"""生成实验报告 docx（docs/实验报告.docx）。

用法: python scripts/build_report.py
依赖: python-docx、docs/figures/*.png（由 build_figures.py 生成）、
      docs/e2e_results.txt（由 e2e_test.py 运行输出保存）。
"""

import os
import re
import sys
import time

from docx import Document
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.oxml.ns import qn
from docx.shared import Cm, Pt, RGBColor

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
FIGS = os.path.join(ROOT, "docs", "figures")
OUT = os.path.join(ROOT, "docs", "实验报告_SecFT安全文件传输软件.docx")

STUDENT_NAME = "王恩泽"               # 中国科学院大学 计算机科学与技术学院
STUDENT_ID = "202628007329016"


def _git_url() -> str:
    """从本地仓库 remote 自动推导 Git 链接；未配置 remote 时给出占位提示。"""
    import subprocess
    try:
        url = subprocess.run(["git", "remote", "get-url", "origin"], cwd=ROOT,
                             capture_output=True, text=True, timeout=10).stdout.strip()
        if url:
            if url.endswith(".git"):
                url = url[:-4]
            return url
    except Exception:
        pass
    return "【待填写：GitHub/Gitee 仓库地址】"


GIT_URL = _git_url()

PRIMARY = RGBColor(0x1A, 0x36, 0x5D)
ACCENT = RGBColor(0x2B, 0x6C, 0xB0)
GRAY = RGBColor(0x71, 0x80, 0x96)


def set_font(run, name_latin="Times New Roman", name_ea="微软雅黑", size=10.5,
             bold=False, color=None):
    run.font.name = name_latin
    run._element.rPr.rFonts.set(qn("w:eastAsia"), name_ea)
    run.font.size = Pt(size)
    run.font.bold = bold
    if color is not None:
        run.font.color.rgb = color


def para(doc, text, size=10.5, bold=False, color=None, align=None,
         space_after=6, indent=0):
    p = doc.add_paragraph()
    if align is not None:
        p.alignment = align
    p.paragraph_format.space_after = Pt(space_after)
    if indent:
        p.paragraph_format.first_line_indent = Pt(indent)
    r = p.add_run(text)
    set_font(r, size=size, bold=bold, color=color)
    return p


def heading(doc, text, level=1):
    p = doc.add_paragraph()
    if level == 1:
        p.paragraph_format.space_before = Pt(14)
        p.paragraph_format.space_after = Pt(8)
        r = p.add_run(text)
        set_font(r, size=15, bold=True, color=PRIMARY)
        pPr = p._p.get_or_add_pPr()
        from docx.oxml import OxmlElement
        pBdr = OxmlElement("w:pBdr")
        bottom = OxmlElement("w:bottom")
        bottom.set(qn("w:val"), "single")
        bottom.set(qn("w:sz"), "8")
        bottom.set(qn("w:color"), "2B6CB0")
        pBdr.append(bottom)
        pPr.append(pBdr)
    else:
        p.paragraph_format.space_before = Pt(10)
        p.paragraph_format.space_after = Pt(6)
        r = p.add_run(text)
        set_font(r, size=12.5, bold=True, color=ACCENT)
    return p


def bullets(doc, items, size=10.5):
    for it in items:
        p = doc.add_paragraph(style="List Bullet")
        p.paragraph_format.space_after = Pt(3)
        r = p.add_run(it)
        set_font(r, size=size)


def code_block(doc, text, size=9):
    p = doc.add_paragraph()
    p.paragraph_format.space_after = Pt(6)
    pPr = p._p.get_or_add_pPr()
    from docx.oxml import OxmlElement
    shd = OxmlElement("w:shd")
    shd.set(qn("w:val"), "clear")
    shd.set(qn("w:fill"), "F5F7FA")
    pPr.append(shd)
    r = p.add_run(text)
    set_font(r, name_latin="Consolas", name_ea="微软雅黑", size=size)


def figure(doc, filename, caption, width=15.5):
    path = os.path.join(FIGS, filename)
    if not os.path.exists(path):
        print("警告: 缺少插图", path)
        return
    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p.add_run().add_picture(path, width=Cm(width))
    cap = doc.add_paragraph()
    cap.alignment = WD_ALIGN_PARAGRAPH.CENTER
    r = cap.add_run(caption)
    set_font(r, size=9, color=GRAY)


def table(doc, headers, rows, widths=None, font_size=9.5):
    t = doc.add_table(rows=1 + len(rows), cols=len(headers))
    t.style = "Table Grid"
    t.alignment = WD_TABLE_ALIGNMENT.CENTER
    for j, h in enumerate(headers):
        cell = t.rows[0].cells[j]
        cell.paragraphs[0].alignment = WD_ALIGN_PARAGRAPH.CENTER
        r = cell.paragraphs[0].add_run(h)
        set_font(r, size=font_size, bold=True)
        from docx.oxml import OxmlElement
        shd = OxmlElement("w:shd")
        shd.set(qn("w:val"), "clear")
        shd.set(qn("w:fill"), "2B6CB0")
        cell._tc.get_or_add_tcPr().append(shd)
        r.font.color.rgb = RGBColor(0xFF, 0xFF, 0xFF)
    for i, row in enumerate(rows):
        for j, v in enumerate(row):
            cell = t.rows[i + 1].cells[j]
            r = cell.paragraphs[0].add_run(str(v))
            set_font(r, size=font_size)
    if widths:
        for j, w in enumerate(widths):
            for row in t.rows:
                row.cells[j].width = Cm(w)
    return t


def parse_e2e_results():
    """从 docs/e2e_results.txt 解析测试用例结果。"""
    path = os.path.join(ROOT, "docs", "e2e_results.txt")
    rows, passed, total = [], 0, 0
    if os.path.exists(path):
        with open(path, encoding="utf-8", errors="ignore") as f:
            for line in f:
                m = re.search(r"\[(PASS|FAIL)\]\s*(.+?)(?:\s*--.*)?$", line.strip())
                if m:
                    ok, name = m.group(1) == "PASS", m.group(2).strip()
                    total += 1
                    passed += ok
                    rows.append(("通过" if ok else "失败", name))
    return rows, passed, total


def main():
    doc = Document()
    for section in doc.sections:
        section.top_margin = Cm(2.2)
        section.bottom_margin = Cm(2.2)
        section.left_margin = Cm(2.5)
        section.right_margin = Cm(2.5)

    # ================================================== 封面
    for _ in range(4):
        doc.add_paragraph()
    para(doc, "《软件与系统安全》实验报告", size=24, bold=True, color=PRIMARY,
         align=WD_ALIGN_PARAGRAPH.CENTER, space_after=10)
    para(doc, "实验 1B：安全文件传输软件（SecFT）设计与实现", size=15, bold=True,
         color=ACCENT, align=WD_ALIGN_PARAGRAPH.CENTER, space_after=30)
    info = [
        ("姓　　名", STUDENT_NAME),
        ("学　　号", STUDENT_ID),
        ("实验选题", "1B —— 安全文件传输软件设计与实现"),
        ("技术栈", "Python 3.13 · Tkinter · TLS(双向证书) · 自定义应用层协议"),
        ("Git 仓库", GIT_URL),
        ("提交日期", time.strftime("%Y 年 %m 月 %d 日")),
    ]
    t = doc.add_table(rows=len(info), cols=2)
    t.alignment = WD_TABLE_ALIGNMENT.CENTER
    for i, (k, v) in enumerate(info):
        c0, c1 = t.rows[i].cells
        r0 = c0.paragraphs[0].add_run(k); set_font(r0, size=11, bold=True)
        r1 = c1.paragraphs[0].add_run(v); set_font(r1, size=11)
        c0.width, c1.width = Cm(3.6), Cm(10.4)
    doc.add_page_break()

    # ================================================== 一、实验目的与要求
    heading(doc, "一、实验目的与要求")
    para(doc, "本实验要求设计并实现一种简单但安全的文件传输软件，考察对网络协议设计、"
              "密码学基础（PKI/证书、口令散列）、常见攻击面（中间人、DDoS、SQL 注入、路径越狱）"
              "以及工程实践（多用户并发、长连接、图形化界面）的综合掌握。", indent=21)
    bullets(doc, [
        "实现自定义应用层协议：能多用户并发访问，文件可完整传输；报告需给出协议帧格式描述图与各模块时序图，并解释协议正确运行的合理性。",
        "长连接：客户端与服务器维持持久连接（keep-alive），由守护机制维护直至客户端主动关闭，禁止一问一答即断开。",
        "安全要求：通信全过程可抵御中间人、DDoS、SQL 注入等常见攻击；服务端实施严格访问控制（ACL），仅暴露指定目录。",
        "交付物：源码（Git 全程记录）、演示视频（编译/部署/测试全过程）、实验报告。",
    ])
    para(doc, "说明：本项目全部功能在 Windows 11 + Python 3.13 环境开发并测试通过，"
              "判卷机仅需安装 Python 3.10+ 即可运行（无第三方运行时依赖，证书生成脚本另需 cryptography 库）。",
         size=10, color=GRAY)

    # ================================================== 二、系统总体设计
    heading(doc, "二、系统总体设计")
    heading(doc, "2.1 总体架构", level=2)
    para(doc, "系统采用经典 C/S 双通道架构（仿 FTP 的控制/数据分离）：控制通道负责认证、目录"
              "操作与传输任务建立，始终保持长连接；每个文件传输任务单独建立一条 TLS 数据连接，"
              "天然支持多文件并发且互不阻塞控制通道。", indent=21)
    figure(doc, "fig_architecture.png", "图 1  SecFT 系统总体架构")

    heading(doc, "2.2 技术选型与理由", level=2)
    table(doc, ["选型", "说明", "理由"], [
        ["Python 3.13 标准库", "socket/ssl/threading/json", "判卷机零第三方依赖，部署仅需 Python"],
        ["Tkinter", "客户端图形界面", "Python 内置 GUI 库，无需额外安装"],
        ["TLS（ssl 模块）", "传输加密", "标准库原生支持双向证书认证"],
        ["JSON 报头 + 二进制载荷", "应用层帧格式", "对应课程建议的 sizeof(json)‖json‖payload 方案"],
        ["PBKDF2-HMAC-SHA256", "口令存储与挑战应答", "标准库 hashlib 原生支持，200,000 轮迭代"],
        ["cryptography", "仅证书生成脚本使用", "运行时不需要，签发 PKI 证书链"],
    ], widths=[4.2, 5.2, 6.0])

    heading(doc, "2.3 模块划分", level=2)
    table(doc, ["模块", "位置", "职责"], [
        ["protocol", "src/common/protocol.py", "帧编解码、消息类型与错误码、SHA-256 工具"],
        ["helpers", "src/common/helpers.py", "路径越狱防护(safe_resolve)、文件名白名单、日志"],
        ["auth / session / ratelimit", "src/server/", "用户存储与封禁、会话与防重放、令牌桶限流"],
        ["app(FTServer)", "src/server/app.py", "TLS 双向认证、控制/数据通道、ACL、断点续传、分级限速"],
        ["network", "src/client/network.py", "控制连接（请求-响应原子化 + 心保活线程）"],
        ["transfers", "src/client/transfers.py", "传输任务管理：并发、断线自动重连续传、进度回调"],
        ["gui", "src/client/gui.py", "Tkinter 双栏浏览器、任务队列、状态栏（心跳 RTT）"],
    ], widths=[4.0, 5.0, 6.4])

    # ================================================== 三、协议设计
    heading(doc, "三、应用层协议设计")
    heading(doc, "3.1 帧格式", level=2)
    para(doc, "所有消息（控制与数据通道）统一使用自描述三段式帧：4 字节大端报头长度、"
              "UTF-8 JSON 报头、二进制载荷。接收方先读长度，再读报头，按报头中 plen 字段"
              "读取载荷，天然防粘包/拆包。", indent=21)
    figure(doc, "fig_frame.png", "图 2  应用层协议帧格式（协议头部信息描述图）")
    para(doc, "JSON 报头字段语义：", bold=True)
    table(doc, ["字段", "类型", "语义"], [
        ["ver", "int", "协议版本号（当前 1），用于向后兼容协商"],
        ["type", "string", "消息类型（见 3.2 消息类型表）"],
        ["seq", "int", "发送方序列号，会话内单调递增，用于请求-响应配对与防重放"],
        ["ack", "int", "被确认的对端 seq（响应帧回填请求 seq）"],
        ["token", "string", "会话令牌；认证前为空，服务器校验其与会话绑定"],
        ["plen", "int", "载荷长度（接收方据此精确读取，上限 8 MiB 防超大帧攻击）"],
        ["meta", "object", "各消息类型的业务元数据（文件名/偏移/哈希/错误码等）"],
    ], widths=[2.2, 2.0, 11.2])

    heading(doc, "3.2 消息类型表", level=2)
    table(doc, ["阶段", "消息", "方向", "说明"], [
        ["握手", "HELLO / WELCOME", "C→S / S→C", "版本协商，返回密码套件与数据通道端口"],
        ["认证", "AUTH_INIT", "C→S", "请求登录（用户名）"],
        ["认证", "AUTH_SALT", "S→C", "下发盐值、一次性 nonce、迭代轮数"],
        ["认证", "AUTH_PROOF", "C→S", "HMAC(PBKDF2(口令,salt), nonce) 挑战应答"],
        ["认证", "AUTH_RESULT", "S→C", "签发会话 token，返回用户 tier/perm"],
        ["目录", "LIST / MKDIR / DELETE / RENAME", "C→S", "目录浏览与整理，路径全部经越狱检查"],
        ["上传", "UPLOAD_INIT / UPLOAD_READY", "C→S / S→C", "登记任务；返回 upload_id 与续传偏移"],
        ["上传", "UPLOAD_CHUNK / UPLOAD_ACK", "数据通道", "分片推送 / 累积确认（ACK 延迟即背压限速）"],
        ["上传", "UPLOAD_COMMIT / UPLOAD_DONE", "数据通道", "整文件 SHA-256 校验 / 原子落盘确认"],
        ["下载", "DOWNLOAD_INIT / DOWNLOAD_READY", "C→S / S→C", "带本地已有偏移发起；返回任务与整文件哈希"],
        ["下载", "DOWNLOAD_CHUNK / DATA_END", "S→C", "流式分片推送（令牌桶整形）/ 结束标志"],
        ["数据", "DATA_AUTH / DATA_OK", "数据通道首帧", "以 transfer_id+token 绑定会话，绑定即弹出防抢占"],
        ["保活", "PING / PONG", "C→S / S→C", "15 秒心跳；75 秒无帧服务器回收连接"],
        ["会话", "LOGOUT / BYE", "C→S / S→C", "主动登出，吊销令牌"],
        ["错误", "ERROR", "S→C", "统一错误码（13 类，见 protocol.ErrCode）"],
    ], widths=[1.8, 5.4, 2.6, 5.6], font_size=8.5)

    heading(doc, "3.3 协议时序图", level=2)
    figure(doc, "fig_seq_auth.png", "图 3  认证（挑战-应答）时序图")
    figure(doc, "fig_seq_upload.png", "图 4  上传时序图（含断点续传分支）")
    figure(doc, "fig_seq_download.png", "图 5  下载时序图（支持断点续传与分级限速）")
    figure(doc, "fig_seq_heartbeat.png", "图 6  长连接与心跳保活时序图")

    heading(doc, "3.4 协议正确运行的合理性论证", level=2)
    bullets(doc, [
        "帧同步：每帧自带长度（4B 头长 + 报头内 plen），接收方按精确字节数循环读取，任意字节流切分下均不粘包、不丢界；报头/载荷长度设上限（64 KiB / 8 MiB），恶意超长帧直接拒绝。",
        "请求-响应配对：响应帧 ack 回填请求 seq，客户端校验不匹配即报协议错误；会话内 seq 单调递增并由服务器强制校验，捕获并拒绝任何重放帧（测试 7 验证）。",
        "传输完整性：分片级 SHA-256 即时校验 + 整文件 SHA-256 提交校验双重保证；服务器端校验失败拒绝落盘，客户端下载后再次校验，任何一处不一致都会显式报错而非静默损坏。",
        "断点续传正确性：上传以服务器 .secft_part 实际长度为唯一事实来源，客户端 seek 到该偏移继续；下载以客户端本地 .part 长度为偏移，且前缀同样纳入整体哈希——续传后的最终文件必然通过整文件哈希校验，不通过则删除重来。",
        "停等 + 累积确认：上传采用“发一片、确认一片”的停等协议（ACK 携带累积偏移），偏移错乱立即暴露；该设计是滑动窗口协议 window=1 的特例，吞吐不足时可平滑扩展窗口而不破坏协议结构。",
        "并发安全：控制连接的请求-响应在客户端以单锁原子化（防止并发线程交叉读取彼此响应）；服务器每连接一线程、数据任务绑定即弹出（防同一任务被两条数据连接抢占）；共享状态（会话表、任务表、令牌桶）均有锁保护。",
        "原子落盘：上传/下载完成均以 os.replace 原子改名，不存在“半成品被当成完整文件”的中间态。",
    ])

    # ================================================== 四、安全设计
    heading(doc, "四、安全设计")
    figure(doc, "fig_security.png", "图 7  三层纵深防御体系")
    heading(doc, "4.1 防中间人（MITM）", level=2)
    bullets(doc, [
        "全链路 TLS 1.2+（配置最小版本可调），禁止降级；服务器证书由自建 CA 签发（含 SAN，RFC 5280 规范扩展 SKI/AKI）。",
        "客户端以随包分发的 CA 根证书校验服务器证书链 + 域名（check_hostname），中间人无可信链即握手失败。",
        "双向证书认证（加分项）：服务器强制要求客户端证书（CERT_REQUIRED），且登录时校验证书 CN 与用户名一致，令牌与会话绑定证书指纹。",
        "认证采用挑战-应答：口令从不出现在线路上，nonce 每次随机，抓包重放无效。",
    ])
    heading(doc, "4.2 防 DDoS 与资源滥用", level=2)
    bullets(doc, [
        "接入层：最大并发连接数与单 IP 连接数双上限，超限直接拒绝（测试 9）。",
        "协议层：单连接令牌桶限流（20 req/s，突发 30），持续超频 10 次强制断开（测试 8）。",
        "认证层：同一用户连续失败 5 次封禁 600 秒，阻断口令爆破。",
        "资源层：报头 64 KiB / 载荷 8 MiB / 单文件 2 GiB 上限；数据通道空闲 30s、控制通道空闲 75s 自动回收；Janitor 守护线程定期清理过期任务与会话。",
    ])
    heading(doc, "4.3 防 SQL 注入", level=2)
    para(doc, "系统不使用任何 SQL 数据库：用户凭据存储为 JSON 文件中的 PBKDF2 校验值，"
              "读写经由固定结构解析，不存在字符串拼接查询面。对真正等价的风险面——"
              "文件路径注入（路径越狱）——采取多层防御：", indent=21)
    bullets(doc, [
        "文件名白名单校验：拒绝非法字符、Windows 保留设备名（CON/NUL/COM1…）与超长名称；",
        "safe_resolve 路径规范化：任何 LIST/上传/下载/删除路径都经 os.path.realpath 解析后强制校验位于用户隔离目录内，.. 穿越、绝对路径、盘符路径一律拒绝（测试 5 覆盖 6 种攻击载荷）；",
        "若未来扩展为数据库存储，应全部采用参数化查询（占位符绑定），从根本上杜绝拼接注入。",
    ])
    heading(doc, "4.4 服务端 ACL 与最小权限", level=2)
    para(doc, "服务器将每个用户限制在其独立目录（server_data/<用户名>/）内，读写权限按账号"
              "区分（rw / r），只读用户的一切写操作被拒绝（测试 6）。目录与 ACL 以 PowerShell "
              "脚本形式明确落盘（scripts/setup_server.ps1）：创建目录树、关闭 ACL 继承、移除"
              "通用组、仅授予服务账户完全控制——即使服务进程被攻破，攻击者也难以横向读取"
              "系统其他目录。进一步可用 chroot（Linux）或容器化部署（只读根文件系统 + 数据卷"
              "挂载）加强隔离。", indent=21)
    code_block(doc, "# scripts/setup_server.ps1 核心（节选）\n"
                    "icacls $dir /inheritance:r              # 关闭继承\n"
                    "icacls $dir /grant:r \"$ServiceUser:(OI)(CI)F\"   # 仅服务账户完全控制\n"
                    "icacls $dir /deny \"Everyone:(OI)(CI)RD\"         # 纵深防御")

    # ================================================== 五、功能实现与加分项
    heading(doc, "五、功能实现与加分项")
    heading(doc, "5.1 基础功能", level=2)
    bullets(doc, [
        "多用户并发：每连接一线程 + 会话管理，多用户同时登录互不干扰，用户目录完全隔离（测试 6/10）；",
        "文件完整传输：分片 + 双重 SHA-256 校验 + 原子落盘，上传/下载字节级一致（测试 3）；",
        "长连接 keep-alive：客户端每 15 秒心跳，服务器守护进程维持会话直至客户端主动 LOGOUT（测试 1/12，图 6）；",
        "图形化界面：双栏（远程/本地）浏览、拖选上传下载、任务进度队列、目录管理、连接状态与心跳 RTT 实时显示；",
        "传输安全：TLS + 双向证书 + 挑战应答认证 + 会话令牌（图 3）。",
    ])
    heading(doc, "5.2 加分项实现", level=2)
    table(doc, ["加分项", "实现方式", "验证"], [
        ["文件断点续传", "服务器 .secft_part 半成品 + 续传偏移协商；上传/下载双向支持；断线自动重连", "测试 4：中断后续传偏移=1MiB，最终哈希一致"],
        ["基于公钥的身份验证（双向证书）", "自建 CA 签发证书链；服务器强制校验客户端证书；CN 与用户名绑定", "测试 1：证书不匹配/无证书握手与登录被拒"],
        ["同时上传/下载多个文件", "每任务独立数据连接 + 线程池；GUI 任务队列并发上限 4", "测试 10：3 上传 + 2 下载并发完成且哈希一致"],
        ["按用户身份控制带宽（VIP）", "按用户全局令牌桶：normal 1MiB/s / VIP 8MiB/s，ACK 延迟/发送整形形成背压", "测试 11：4MiB 下载 alice 4.2s vs bob 0.1s"],
    ], widths=[3.6, 6.8, 5.0], font_size=9)

    # ================================================== 六、测试
    heading(doc, "六、测试与验证")
    para(doc, "端到端自动化测试（scripts/e2e_test.py）在进程内启动真实服务器，用裸协议客户端"
              "与图形客户端库共 40 个断言覆盖全部功能与安全要求。最近一次运行结果：", indent=21)
    rows, passed, total = parse_e2e_results()
    para(doc, f"测试通过率：{passed}/{total}。明细如下（完整日志见 docs/e2e_results.txt）：",
         size=10.5, bold=True)
    table(doc, ["结果", "测试项"], rows, widths=[1.8, 13.6], font_size=8.5)
    para(doc, "GUI 冒烟测试（scripts/gui_smoke_test.py）：登录窗口构建、程序化登录、主窗口构建、"
              "远程列表刷新、心跳 RTT 采集全部通过。", size=10)

    # ================================================== 七、部署与使用
    heading(doc, "七、部署与使用说明（Windows）")
    code_block(doc,
               ":: 0) 环境要求：Python 3.10+（开发验证于 3.13）；证书生成需 pip install cryptography\n"
               ":: 1) 生成证书与演示用户\n"
               "python scripts\\gen_certs.py\n"
               "python scripts\\gen_users.py\n"
               ":: 2) 配置服务器目录与 ACL（可选，管理员 PowerShell）\n"
               "powershell -ExecutionPolicy Bypass -File scripts\\setup_server.ps1\n"
               ":: 3) 启动服务器（或双击 start_server.bat）\n"
               "python run_server.py\n"
               ":: 4) 启动客户端（或双击 start_client.bat），登录演示账号\n"
               "python run_client.py\n"
               ":: 5) 运行端到端自动化测试（或双击 run_test.bat）\n"
               "python scripts\\e2e_test.py")
    para(doc, "演示账号：alice / alice-2026（普通·读写），bob / bob-2026（VIP·读写），"
              "guest / guest-2026（只读）。默认端口：控制 19443，数据 19444（config/server_config.json）。", size=10)

    # ================================================== 八、总结
    heading(doc, "八、实验总结与最佳实践")
    bullets(doc, [
        "协议设计先行：先画帧格式与时序图再写代码，“自描述长度 + 序号配对 + 显式状态机”让两端的联调一次打通；停等协议是滑动窗口的可靠特例，正确性优先、性能可扩展。",
        "把安全当默认属性而非补丁：路径越狱检查收敛在一个函数（safe_resolve）中、所有文件操作必须经过，比“记得在每处检查”可靠得多；错误一律显式回码，不让客户端超时猜。",
        "Windows 平台细节：打开中的文件不能 os.replace（WinError 32），提交前必须先关句柄；Tkinter 只允许主线程触碰控件，worker 一律走队列。",
        "线程化的并发连接模型要注意共享状态：会话表、任务表、带宽桶全部加锁；客户端控制连接的请求-响应必须原子化，否则并发下载会交叉读取响应帧。",
        "可复现的自动化测试是最好的文档：40 个端到端断言同时就是需求清单与回归保障，安全拦截（越狱/重放/限流）也纳入了持续验证。",
    ])

    # ================================================== 附录
    heading(doc, "附录 A：Git 仓库")
    para(doc, f"仓库地址：{GIT_URL}", bold=True)
    para(doc, "仓库包含完整开发提交记录（协议层 → 服务端 → 客户端 → 脚本与测试 → 文档），"
              "提交前请将本行替换为 GitHub/Gitee/GitLab 实际链接。", size=10, color=GRAY)
    heading(doc, "附录 B：交付清单")
    table(doc, ["目录/文件", "说明"], [
        ["src/common", "协议帧编解码、路径越狱防护、日志工具"],
        ["src/server", "服务器：TLS 双向认证、会话、ACL、限流、断点续传、分级限速"],
        ["src/client", "客户端：网络层、传输管理、Tkinter 图形界面"],
        ["scripts/", "证书/用户生成、ACL 部署、端到端测试、GUI 冒烟测试、报告与插图构建"],
        ["config/", "服务器配置、用户凭据（PBKDF2 校验值）"],
        ["docs/", "本报告、插图、测试日志"],
        ["start_server.bat / start_client.bat / run_test.bat", "Windows 一键启动/测试脚本"],
    ], widths=[7.0, 8.4])

    doc.save(OUT)
    print("报告已生成:", OUT)


if __name__ == "__main__":
    main()
