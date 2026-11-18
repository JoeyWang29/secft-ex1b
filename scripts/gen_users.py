"""生成 users.json：PBKDF2 校验值存储，绝不保存明文口令。

用法: python scripts/gen_users.py                # 创建默认演示用户
      python scripts/gen_users.py 名 口令 等级 权限   # 追加自定义用户
等级: normal / vip（对应服务器带宽限制）；权限: rw / r
"""

import base64
import json
import os
import secrets
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from server.auth import compute_verifier, PBKDF2_ITERATIONS

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
USERS_FILE = os.path.join(ROOT, "config", "users.json")

DEFAULT_USERS = [
    ("alice", "alice-2026", "normal", "rw"),
    ("bob",   "bob-2026",   "vip",    "rw"),
    ("guest", "guest-2026", "normal", "r"),
]


def add_user(users: dict, name: str, password: str, tier: str, perm: str) -> None:
    salt = secrets.token_bytes(16)
    verifier = compute_verifier(password, salt)
    users[name] = {
        "salt": base64.b64encode(salt).decode(),
        "verifier": base64.b64encode(verifier).decode(),
        "iter": PBKDF2_ITERATIONS,
        "tier": tier,
        "perm": perm,
        "fail_count": 0,
        "banned_until": 0.0,
    }


def main() -> None:
    os.makedirs(os.path.dirname(USERS_FILE), exist_ok=True)
    users: dict = {}
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE, "r", encoding="utf-8") as f:
            users = json.load(f)
    args = sys.argv[1:]
    if args:
        if len(args) != 4:
            print("用法: gen_users.py 名 口令 等级 权限")
            sys.exit(1)
        name, password, tier, perm = args
        add_user(users, name, password, tier, perm)
        print(f"已添加用户 {name} (tier={tier}, perm={perm})")
    else:
        for name, password, tier, perm in DEFAULT_USERS:
            add_user(users, name, password, tier, perm)
            print(f"已创建演示用户 {name}/{password} (tier={tier}, perm={perm})")
    with open(USERS_FILE, "w", encoding="utf-8") as f:
        json.dump(users, f, ensure_ascii=False, indent=2)
    print("用户文件:", USERS_FILE)


if __name__ == "__main__":
    main()
