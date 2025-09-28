import cv2
import numpy as np
import mss
import threading
import queue

class Video:
    def __init__(self, monitor: dict):
        self.monitor = monitor
        self.frame_queue = queue.Queue(maxsize=5)
        self._running = False
        self._thread = None

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
                frame = np.array(sct.grab(self.monitor))[:, :, :3]
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