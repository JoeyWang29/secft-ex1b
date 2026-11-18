"""最小化指定标题子串的窗口（录屏清场用）。

用法: python scripts/minimize_windows.py <标题子串1> [标题子串2 ...]
"""
import ctypes
import sys

user32 = ctypes.windll.user32
SW_MINIMIZE = 6
ENUMPROC = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_void_p)


def minimize_matching(substrings):
    hits = []

    def cb(hwnd, _):
        if not user32.IsWindowVisible(hwnd):
            return True
        buf = ctypes.create_unicode_buffer(256)
        user32.GetWindowTextW(hwnd, buf, 256)
        title = buf.value
        for s in substrings:
            if s.lower() in title.lower():
                user32.ShowWindow(hwnd, SW_MINIMIZE)
                hits.append(title)
                break
        return True

    user32.EnumWindows(ENUMPROC(cb), 0)
    return hits


if __name__ == "__main__":
    print("已最小化:", minimize_matching(sys.argv[1:]))
