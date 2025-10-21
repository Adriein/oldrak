import time

import keyboard

from oldrak.shared import EngineState, EngineCommand
from oldrak.os import Process, Memory, Network, Debugger, Video
from oldrak.engine.session import GameSession, SessionDebugger


class Engine:
    def __init__(self):
        self._game = Process(Memory(), Network(), Debugger(Memory()), Video())
        self._state = None

    def start(self):
        self._state = EngineState.Running

        self._set_stop_handler()

        self._game.hook()

        while self._game.pid is None:
            print("Tibia is not running...")

            self._game.hook()

            time.sleep(0.5)

        tcp_stream = self._game.spy_network()

        session = GameSession(tcp_stream)
        # video_stream = self._game.capture_video()

        while self._state is EngineState.Running:
            time.sleep(0.01)

        print("Flushing session.")
        session.flush(record=True)

        print("Save decrypt keys.")
        self._game.write_decrypt_keys()

        # debugger = SessionDebugger()
        #
        # debugger.replay("20251019")

        print("Oldrak engine stopped.")

    def _set_stop_handler(self):
        keyboard.add_hotkey(EngineCommand.Stop.value, self._shutdown)

    def _shutdown(self):
        print(f"The {EngineCommand.Stop.value} key was pressed. Stopping oldrak engine...")
        self._state = EngineState.Stopped
        self._game.abort_spy_network()
