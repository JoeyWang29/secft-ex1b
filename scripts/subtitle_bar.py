"""演示视频字幕条：置顶小窗轮询显示 scripts/.subtitle 文本内容。

用法: python scripts/subtitle_bar.py
字幕内容写入 scripts/.subtitle（UTF-8），工具 0.4s 刷新一次；
文件为空或不存在时显示空白。录屏时可将其拖至屏幕底部。
"""

import os
import sys
import tkinter as tk

WATCH = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".subtitle")


def main() -> None:
    root = tk.Tk()
    root.overrideredirect(True)          # 无边框
    root.attributes("-topmost", True)
    sw, sh = root.winfo_screenwidth(), root.winfo_screenheight()
    root.geometry(f"{sw - 240}x64+120+{sh - 110}")
    root.attributes("-alpha", 0.88)
    lbl = tk.Label(root, text="准备中…", font=("Microsoft YaHei", 15, "bold"),
                   fg="white", bg="#1a365d", wraplength=sw - 280, justify="center")
    lbl.pack(fill="both", expand=True, padx=2, pady=2)

    def poll():
        try:
            with open(WATCH, encoding="utf-8") as f:
                text = f.read().strip()
        except OSError:
            text = ""
        if text and text != lbl.cget("text"):
            lbl.config(text=text)
        root.after(400, poll)

    poll()
    root.mainloop()


if __name__ == "__main__":
    main()
