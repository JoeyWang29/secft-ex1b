"""SecFT 客户端启动入口。用法: python run_client.py"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def main() -> None:
    from client.gui import run
    run()


if __name__ == "__main__":
    main()
