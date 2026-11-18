"""按窗口标题移动/缩放窗口（演示布局工具）。

用法: python scripts/set_window_rect.py <标题子串> <x> <y> <宽> <高>
"""

import ctypes
import sys

user32 = ctypes.windll.user32
EnumWindows = user32.EnumWindows
GetWindowTextW = user32.GetWindowTextW
SetWindowPos = user32.SetWindowPos
IsWindowVisible = user32.IsWindowVisible

WNDPROCENUMPROC = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_void_p)


def find_hwnd(title_substr: str):
    found = []

    def cb(hwnd, _):
        buf = ctypes.create_unicode_buffer(256)
        GetWindowTextW(hwnd, buf, 256)
        if title_substr in buf.value and IsWindowVisible(hwnd):
            found.append(hwnd)
        return True

    EnumWindows(WNDPROCENUMPROC(cb), 0)
    return found[0] if found else None


def main() -> None:
    title, x, y, w, h = sys.argv[1], *map(int, sys.argv[2:6])
    hwnd = find_hwnd(title)
    if not hwnd:
        print(f"未找到窗口: {title}")
        sys.exit(1)
    # SWP_NOZORDER=4; 顶层窗口
    SetWindowPos(hwnd, 0, x, y, w, h, 0x0004)
    print(f"已定位 [{title}] -> ({x},{y}) {w}x{h}")


if __name__ == "__main__":
    main()
