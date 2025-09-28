import numpy as np
import mss
import threading
import queue

import pyautogui


class Video:
    def __init__(self):
        self.frame_queue = queue.Queue(maxsize=5)
        self._running = False
        self._thread = None

        screen_width, screen_height = pyautogui.size()
        self.monitor = {
            "top": 0,
            "left": 0,
            "width": screen_width,
            "height": screen_height
        }

    def start(self):
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._capture_worker, daemon=True)
        self._thread.start()

    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=1)
            self._thread = None

    def _capture_worker(self):
        with mss.mss() as sct:
            while self._running:
                sct_img = sct.grab(self.monitor)

                frame = np.frombuffer(sct_img.rgb, dtype=np.uint8)
                frame = frame.reshape((sct_img.height, sct_img.width, 3))
                try:
                    self.frame_queue.put(frame, timeout=0.1)
                except queue.Full:
                    pass  # drop frame if queue is full

    def get_frame(self, timeout: float = 0.1):
        """Return latest frame or None if not available"""
        try:
            return self.frame_queue.get(timeout=timeout)
        except queue.Empty:
            return None