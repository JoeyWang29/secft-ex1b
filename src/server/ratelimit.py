"""令牌桶限流：控制通道请求限速（防 DDoS）与数据通道带宽限制（VIP 分级）。"""

from __future__ import annotations

import threading
import time


class TokenBucket:
    """经典令牌桶。rate=每秒补充令牌数，capacity=桶容量（突发上限）。

    consume(n) 立即判断并扣除；take_wait(n) 阻塞等待直到取到（用于带宽整形）。
    """

    def __init__(self, rate: float, capacity: float):
        self.rate = float(rate)
        self.capacity = float(capacity)
        self.tokens = float(capacity)
        self.updated = time.monotonic()
        self.lock = threading.Lock()

    def _refill(self) -> None:
        now = time.monotonic()
        self.tokens = min(self.capacity, self.tokens + (now - self.updated) * self.rate)
        self.updated = now

    def consume(self, n: float = 1.0) -> bool:
        with self.lock:
            self._refill()
            if self.tokens >= n:
                self.tokens -= n
                return True
            return False

    def take_wait(self, n: float, poll_interval: float = 0.02) -> None:
        """阻塞直到取到 n 个令牌（n 不超过 capacity）。"""
        n = min(n, self.capacity)
        while True:
            with self.lock:
                self._refill()
                if self.tokens >= n:
                    self.tokens -= n
                    return
                deficit = (n - self.tokens) / self.rate
            time.sleep(min(max(deficit, poll_interval), 0.2))
