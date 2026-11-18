"""SecFT 客户端启动入口。用法: python run_client.py"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "src"))


def main() -> None:
    try:
        from client.gui import run
        run()
    except Exception:
        import os
        import traceback
        os.makedirs("logs", exist_ok=True)
        with open(os.path.join("logs", "client_error.log"), "w", encoding="utf-8") as f:
            f.write(traceback.format_exc())
        raise


if __name__ == "__main__":
    main()
