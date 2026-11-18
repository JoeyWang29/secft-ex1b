"""屏幕录制器 v2：mss 抓帧 + numpy 光标/点击叠加 + ffmpeg 管道直写 H.264。

用法: python scripts/screen_recorder.py 输出.mp4 [帧率=20]
停止：向 scripts/.rec_stop 写入任意内容，或 Ctrl+C。
性能：2520x1680@20fps 实时（PIL 版仅 ~7fps，故改用纯 numpy 与管道编码）。
"""

import ctypes
import os
import subprocess
import sys
import time

import imageio_ffmpeg
import mss
import numpy as np

STOP_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".rec_stop")
user32 = ctypes.windll.user32


class PPoint(ctypes.Structure):
    _fields_ = [("x", ctypes.c_long), ("y", ctypes.c_long)]


def cursor_pos():
    pt = PPoint()
    user32.GetCursorPos(ctypes.byref(pt))
    return pt.x, pt.y


def left_pressed() -> bool:
    return bool(user32.GetAsyncKeyState(0x01) & 0x8000)


def draw_disk(img, cx, cy, r, color):
    """在 BGR 图像上画实心圆（切片 + 圆形掩码，避免 PIL 开销）。"""
    h, w = img.shape[:2]
    x0, x1 = max(0, cx - r), min(w, cx + r + 1)
    y0, y1 = max(0, cy - r), min(h, cy + r + 1)
    if x0 >= x1 or y0 >= y1:
        return
    yy, xx = np.ogrid[y0:y1, x0:x1]
    mask = (xx - cx) ** 2 + (yy - cy) ** 2 <= r * r
    img[y0:y1, x0:x1][mask] = color


def draw_ring(img, cx, cy, r, color, thick=3):
    h, w = img.shape[:2]
    x0, x1 = max(0, cx - r), min(w, cx + r + 1)
    y0, y1 = max(0, cy - r), min(h, cy + r + 1)
    if x0 >= x1 or y0 >= y1:
        return
    yy, xx = np.ogrid[y0:y1, x0:x1]
    dist = np.abs(np.sqrt((xx - cx) ** 2 + (yy - cy) ** 2) - r)
    img[y0:y1, x0:x1][dist <= thick] = color


def main() -> None:
    out = sys.argv[1] if len(sys.argv) > 1 else "demo.mp4"
    fps = int(sys.argv[2]) if len(sys.argv) > 2 else 20
    if os.path.exists(STOP_FILE):
        os.remove(STOP_FILE)

    with mss.mss() as sct:
        mon = sct.monitors[1]  # 主显示器
        w, h = mon["width"], mon["height"]
        ff = imageio_ffmpeg.get_ffmpeg_exe()
        cmd = [ff, "-y", "-f", "rawvideo", "-pix_fmt", "bgr24",
               "-s", f"{w}x{h}", "-r", str(fps), "-i", "pipe:",
               "-c:v", "libx264", "-preset", "ultrafast", "-crf", "22",
               "-pix_fmt", "yuv420p", "-movflags", "+faststart", out]
        proc = subprocess.Popen(cmd, stdin=subprocess.PIPE,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print(f"录制开始 {w}x{h}@{fps}fps -> {out}")
        clicks = []
        target_dt = 1.0 / fps
        n = 0
        t_start = time.time()
        try:
            while True:
                t0 = time.time()
                if os.path.exists(STOP_FILE):
                    os.remove(STOP_FILE)
                    break
                frame = np.asarray(sct.grab(mon))[:, :, :3].copy()  # BGRA->BGR
                now = time.time()
                if left_pressed():
                    clicks.append((cursor_pos(), now))
                clicks = [c for c in clicks if now - c[1] < 0.35]
                for (cx, cy), t_click in clicks:
                    draw_ring(frame, cx, cy, 10 + int((now - t_click) * 45),
                              (0, 215, 255), thick=3)
                cx, cy = cursor_pos()
                draw_disk(frame, cx, cy, 5, (80, 80, 255))        # 红点（BGR）
                draw_ring(frame, cx, cy, 7, (255, 255, 255), 1)
                try:
                    proc.stdin.write(frame.tobytes())
                except (BrokenPipeError, OSError):
                    break
                n += 1
                dt = time.time() - t0
                if dt < target_dt:
                    time.sleep(target_dt - dt)
        except KeyboardInterrupt:
            pass
        finally:
            try:
                proc.stdin.close()
            except OSError:
                pass
            proc.wait(timeout=15)
    print(f"录制结束: {n} 帧, {time.time() - t_start:.1f}s -> {out}")


if __name__ == "__main__":
    main()
