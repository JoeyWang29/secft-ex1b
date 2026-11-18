"""SecFT 通用工具：路径越界防护（ACL 越狱防御）与日志配置。"""

from __future__ import annotations

import logging
import os
import re
import sys

# Windows 保留设备名，作为文件名一律拒绝（防 DoS/设备劫持）
WINDOWS_RESERVED = {
    "CON", "PRN", "AUX", "NUL",
    *(f"COM{i}" for i in range(1, 10)),
    *(f"LPT{i}" for i in range(1, 10)),
}

NAME_PATTERN = re.compile(r'^[^\\/:*?"<>|\x00-\x1f]+$')  # 文件名合法字符白名单
MAX_NAME_LEN = 255


class PathViolation(Exception):
    """路径越界或名称非法。"""


def validate_name(name: str) -> str:
    """校验单个文件/目录名：长度、非法字符、Windows 保留名。"""
    if not name or len(name) > MAX_NAME_LEN:
        raise PathViolation("文件名长度非法")
    if name in (".", ".."):
        raise PathViolation("非法文件名")
    if not NAME_PATTERN.match(name):
        raise PathViolation("文件名包含非法字符")
    stem = name.split(".")[0].upper()
    if stem in WINDOWS_RESERVED:
        raise PathViolation(f"Windows 保留设备名: {stem}")
    return name


def safe_resolve(root: str, rel: str) -> str:
    """将相对路径规范化并强制约束在 root 之内（服务器端 ACL 核心防线）。

    任何 .. 穿越、绝对路径、符号链接逃逸都会抛出 PathViolation。
    协议层的虚拟根目录（"/"、""、"."）一律映射到 root 本身。
    """
    root_real = os.path.realpath(root)
    rel = str(rel).replace("\\", "/").strip("/")
    if not rel or rel == ".":
        return root_real
    if os.path.isabs(rel):
        raise PathViolation("拒绝绝对路径")
    candidate = os.path.realpath(os.path.join(root_real, rel))
    if candidate == root_real:
        return candidate
    if not candidate.startswith(root_real + os.sep):
        raise PathViolation(f"路径越界: {rel}")
    return candidate


def setup_logger(name: str, log_file: str | None = None) -> logging.Logger:
    """统一日志：控制台 + 可选文件，安全事件全程留痕。"""
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger
    logger.setLevel(logging.INFO)
    fmt = logging.Formatter(
        "%(asctime)s [%(threadName)s] %(levelname)s %(message)s", "%Y-%m-%d %H:%M:%S"
    )
    sh = logging.StreamHandler(sys.stdout)
    sh.setFormatter(fmt)
    logger.addHandler(sh)
    if log_file:
        try:
            os.makedirs(os.path.dirname(log_file), exist_ok=True)
            fh = logging.FileHandler(log_file, encoding="utf-8")
            fh.setFormatter(fmt)
            logger.addHandler(fh)
        except OSError:
            logger.warning("日志文件不可用，仅输出到控制台")
    return logger
