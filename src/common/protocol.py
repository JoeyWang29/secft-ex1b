"""SecFT 自定义应用层协议：帧编解码、消息类型、错误码。

帧格式（大端序），对应课程要求的 sizeof(json) || json || payload 方案：

    +------------------+--------------------+------------------+
    | 4 字节            | header_len 字节     | payload_len 字节  |
    | header_len (u32) | JSON 报头 (UTF-8)   | 二进制载荷         |
    +------------------+--------------------+------------------+

JSON 报头字段：
    ver    协议版本号
    type   消息类型字符串
    seq    发送方序列号（单调递增，防重放）
    ack    对端被确认的 seq（请求-响应配对）
    token  会话令牌（认证后必填，预认证阶段为空串）
    plen   载荷长度（接收方据此读取载荷）
    meta   与消息类型相关的元数据字典
"""

from __future__ import annotations

import hashlib
import json
import struct
from typing import Tuple

PROTOCOL_VERSION = 1

MAX_HEADER_LEN = 65535          # JSON 报头长度上限 64 KiB
MAX_PAYLOAD_LEN = 8 * 1024 * 1024   # 单帧载荷上限 8 MiB（防超大帧耗尽内存）
DEFAULT_CHUNK_SIZE = 1024 * 1024    # 文件分片默认 1 MiB

TOKEN_LEN = 32                  # 会话令牌字节数


class ProtocolError(Exception):
    """协议编解码或字段校验失败。"""


class MsgType:
    """全部消息类型。控制通道与数据通道共用一套帧格式。"""

    # 握手
    HELLO = "HELLO"
    WELCOME = "WELCOME"
    # 认证
    AUTH_INIT = "AUTH_INIT"        # 客户端 -> 服务器：请求登录（携带用户名）
    AUTH_SALT = "AUTH_SALT"        # 服务器 -> 客户端：下发盐值与一次性 nonce
    AUTH_PROOF = "AUTH_PROOF"      # 客户端 -> 服务器：挑战应答证明
    AUTH_RESULT = "AUTH_RESULT"    # 服务器 -> 客户端：登录结果 + 会话令牌
    # 目录操作
    LIST = "LIST"
    MKDIR = "MKDIR"
    DELETE = "DELETE"
    RENAME = "RENAME"
    # 上传（控制通道建立任务，数据通道传输内容）
    UPLOAD_INIT = "UPLOAD_INIT"
    UPLOAD_READY = "UPLOAD_READY"
    UPLOAD_CHUNK = "UPLOAD_CHUNK"  # 数据通道
    UPLOAD_ACK = "UPLOAD_ACK"      # 数据通道，累积确认
    UPLOAD_COMMIT = "UPLOAD_COMMIT"
    UPLOAD_DONE = "UPLOAD_DONE"
    # 下载
    DOWNLOAD_INIT = "DOWNLOAD_INIT"
    DOWNLOAD_READY = "DOWNLOAD_READY"
    DOWNLOAD_CHUNK = "DOWNLOAD_CHUNK"  # 数据通道
    DATA_END = "DATA_END"              # 数据通道结束标志
    # 数据通道准入
    DATA_AUTH = "DATA_AUTH"
    DATA_OK = "DATA_OK"
    # 保活与会话
    PING = "PING"
    PONG = "PONG"
    LOGOUT = "LOGOUT"
    BYE = "BYE"
    # 错误
    ERROR = "ERROR"

    # 允许在未认证状态下出现的消息（其余消息一律要求有效 token）
    PRE_AUTH_TYPES = {HELLO, AUTH_INIT, AUTH_PROOF, ERROR, BYE}
    # 数据通道首帧
    DATA_ENTRY_TYPES = {DATA_AUTH, ERROR, DATA_END}


class ErrCode:
    """错误码。0 表示成功。"""

    OK = 0
    AUTH_FAILED = 1          # 用户名或密码错误
    PERMISSION_DENIED = 2    # 权限不足（只读用户尝试写操作等）
    PATH_VIOLATION = 3       # 路径越界（ACL 越狱尝试）
    FILE_NOT_FOUND = 4
    RATE_LIMITED = 5         # 触发速率限制（防 DDoS）
    PROTOCOL_ERROR = 6
    SERVER_BUSY = 7          # 并发连接/任务数超限（防 DDoS）
    SIZE_EXCEEDED = 8        # 文件大小超限
    INVALID_STATE = 9        # 状态机不匹配的请求
    INTERNAL = 10            # 服务器内部错误
    EXISTS = 11              # 目标已存在
    BANNED = 12              # 登录失败次数过多，被临时封禁
    CERT_MISMATCH = 13       # 客户端证书 CN 与登录用户名不匹配


ERR_MSG = {
    ErrCode.OK: "成功",
    ErrCode.AUTH_FAILED: "用户名或密码错误",
    ErrCode.PERMISSION_DENIED: "权限不足",
    ErrCode.PATH_VIOLATION: "路径越界，已拒绝",
    ErrCode.FILE_NOT_FOUND: "文件不存在",
    ErrCode.RATE_LIMITED: "请求过于频繁，已限流",
    ErrCode.PROTOCOL_ERROR: "协议错误",
    ErrCode.SERVER_BUSY: "服务器繁忙",
    ErrCode.SIZE_EXCEEDED: "文件大小超出限制",
    ErrCode.INVALID_STATE: "请求与当前会话状态不符",
    ErrCode.INTERNAL: "服务器内部错误",
    ErrCode.EXISTS: "目标已存在",
    ErrCode.BANNED: "失败次数过多，账号被临时封禁",
    ErrCode.CERT_MISMATCH: "客户端证书与用户名不匹配",
}


def _recv_exact(sock, n: int) -> bytes:
    """从 socket 精确读取 n 字节；对端关闭则抛 ConnectionError。"""
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(min(n - len(buf), 262144))
        if not chunk:
            raise ConnectionError("对端已关闭连接")
        buf.extend(chunk)
    return bytes(buf)


def send_frame(sock, header: dict, payload: bytes = b"") -> None:
    """按帧格式发送一条消息。header 中自动注入 plen。"""
    if not isinstance(header, dict):
        raise ProtocolError("header 必须是字典")
    header = dict(header)
    payload = bytes(payload)
    header["plen"] = len(payload)
    body = json.dumps(header, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if len(body) > MAX_HEADER_LEN:
        raise ProtocolError("报头超长")
    sock.sendall(struct.pack(">I", len(body)) + body + payload)


def recv_frame(sock) -> Tuple[dict, bytes]:
    """按帧格式接收一条消息，返回 (header, payload)。"""
    (hlen,) = struct.unpack(">I", _recv_exact(sock, 4))
    if hlen <= 0 or hlen > MAX_HEADER_LEN:
        raise ProtocolError(f"非法报头长度: {hlen}")
    raw = _recv_exact(sock, hlen)
    try:
        header = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProtocolError(f"报头 JSON 解析失败: {exc}")
    if not isinstance(header, dict):
        raise ProtocolError("报头必须是 JSON 对象")
    plen = header.get("plen", 0)
    if not isinstance(plen, int) or plen < 0 or plen > MAX_PAYLOAD_LEN:
        raise ProtocolError(f"非法载荷长度: {plen}")
    payload = _recv_exact(sock, plen) if plen else b""
    return header, payload


def make_header(msg_type: str, seq: int = 0, ack: int = 0, token: str = "",
                meta: dict | None = None) -> dict:
    """构造统一格式的 JSON 报头。"""
    return {
        "ver": PROTOCOL_VERSION,
        "type": msg_type,
        "seq": seq,
        "ack": ack,
        "token": token,
        "meta": meta or {},
    }


def error_header(code: int, message: str = "", ack: int = 0) -> dict:
    """构造 ERROR 报头；message 缺省时使用内置错误描述。"""
    return {
        "ver": PROTOCOL_VERSION,
        "type": MsgType.ERROR,
        "seq": 0,
        "ack": ack,
        "token": "",
        "plen": 0,
        "meta": {"code": code, "msg": message or ERR_MSG.get(code, "未知错误")},
    }


def sha256_file(path: str, chunk: int = 1024 * 1024) -> str:
    """流式计算整文件 SHA-256，避免大文件占满内存。"""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            data = f.read(chunk)
            if not data:
                break
            h.update(data)
    return h.hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def parse_frame_or_error(sock) -> Tuple[dict, bytes]:
    """接收帧；协议错误统一包装为 ProtocolError 由调用方处理。"""
    return recv_frame(sock)
