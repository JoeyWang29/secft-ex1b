"""SecFT 服务器启动入口。用法: python run_server.py [-c 配置文件]"""

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def main() -> None:
    parser = argparse.ArgumentParser(description="SecFT 安全文件传输服务器（实验 1B）")
    parser.add_argument("-c", "--config", default=os.path.join("config", "server_config.json"),
                        help="服务器配置文件路径")
    args = parser.parse_args()
    from server.app import FTServer
    FTServer(args.config).serve()


if __name__ == "__main__":
    main()
