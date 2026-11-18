# SecFT —— 安全文件传输软件（《软件与系统安全》实验 1B）

基于 **Python 3 标准库** 实现的带图形界面的安全文件传输系统：
自定义应用层协议（JSON 报头 + 二进制载荷）+ TLS 双向证书认证，
支持多用户并发、长连接心跳保活、断点续传、多任务并发传输与 VIP 分级限速。

> 实验报告详见 `docs/实验报告_SecFT安全文件传输软件.docx`
> （协议帧格式图、认证/上传/下载/心跳时序图、安全设计与 40 项端到端测试明细）

## 功能一览

| 类别 | 内容 |
|------|------|
| 传输 | 上传 / 下载 / 断点续传（双向）/ 多任务并发 / 分片与整文件双重 SHA-256 校验 / 原子落盘 |
| 安全 | TLS 1.2+ 双向证书认证 · 挑战-应答认证（PBKDF2+HMAC，口令不上线路径） · seq 防重放 · 路径越狱拦截 · 请求限流 · 登录封禁 · 连接数上限 |
| 管理 | 多用户隔离目录 · 只读/读写权限 · VIP 分级限速（normal 1MiB/s / VIP 8MiB/s） · ACL 部署脚本 |
| 界面 | Tkinter 双栏浏览、任务进度队列、心跳 RTT 状态栏 |

## 快速开始（Windows）

```bat
:: 环境要求：Python 3.10+；生成证书需 pip install cryptography
python scripts\gen_certs.py        :: 1) 生成 CA / 服务器 / 客户端证书链
python scripts\gen_users.py        :: 2) 生成演示用户（PBKDF2 存储）
python run_server.py               :: 3) 启动服务器（或 start_server.bat）
python run_client.py               :: 4) 启动客户端（或 start_client.bat）
python scripts\e2e_test.py         :: 5) 端到端自动化测试（40 断言）
```

演示账号：`alice / alice-2026`（普通·读写）、`bob / bob-2026`（VIP·读写）、
`guest / guest-2026`（只读）。默认端口：控制 19443 / 数据 19444。

## 目录结构

```
src/common    协议帧编解码、消息类型/错误码、路径越狱防护、日志
src/server    TLS 双向认证、会话管理、ACL、令牌桶限流、断点续传、分级限速
src/client    控制连接（心跳保活）、传输管理（并发/自动续传）、Tkinter 界面
scripts       证书/用户生成、ACL 部署、端到端测试、GUI 冒烟测试、报告构建
config        服务器配置、用户凭据（仅存 PBKDF2 校验值）
docs          实验报告、插图、测试日志
```

## 安全设计要点

- **防中间人**：自建 CA 证书链，客户端校验服务器证书 + 域名；服务器强制校验客户端证书（双向认证），证书 CN 与用户名绑定。
- **防重放/防爆破**：挑战-应答（随机 nonce）+ 会话 seq 单调递增校验；登录失败 5 次封禁 10 分钟。
- **防 DDoS**：总/单 IP 连接上限、令牌桶请求限流（超频强制断开）、帧长/文件大小上限、空闲回收。
- **防 SQL 注入/路径注入**：不使用 SQL（JSON + PBKDF2 存储）；全部路径经 realpath 越狱检查 + 文件名白名单（含 Windows 保留设备名）。
- **服务端 ACL**：用户隔离目录 + 读写权限分级 + `scripts/setup_server.ps1` 显式配置 Windows 目录 ACL（最小权限）。
