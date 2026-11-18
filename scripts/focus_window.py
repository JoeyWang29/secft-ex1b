"""把指定标题子串的窗口置前台（不移动鼠标，避免首次点击被吞）。

用法: python scripts/focus_window.py <标题子串>
"""
import ctypes
import sys

user32 = ctypes.windll.user32
ENUMPROC = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_void_p)


def find_hwnd(title_substr: str):
    found = []

    def cb(hwnd, _):
        if not user32.IsWindowVisible(hwnd):
            return True
        buf = ctypes.create_unicode_buffer(256)
        user32.GetWindowTextW(hwnd, buf, 256)
        if title_substr in buf.value:
            found.append(hwnd)
        return True

    user32.EnumWindows(ENUMPROC(cb), 0)
    return found[0] if found else None


def main() -> None:
    title = sys.argv[1]
    hwnd = find_hwnd(title)
    if not hwnd:
        print(f"未找到窗口: {title}")
        sys.exit(1)
    user32.ShowWindow(hwnd, 9)      # SW_RESTORE
    user32.SetForegroundWindow(hwnd)
    print(f"已置前台: {title} hwnd={hwnd}")


if __name__ == "__main__":
    main()
