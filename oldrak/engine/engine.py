import time

import keyboard

from oldrak.shared import EngineState, EngineCommand
from oldrak.os import Process, Memory, Network, Debugger, Video


class Engine:
    def __init__(self):
        self._game = Process(Memory(), Network(), Debugger(Memory()), Video())
        self._state = None

    def start(self):
        self._state = EngineState.Running

        self._set_stop_handler()

        self._game.hook()

        while self._state is EngineState.Running:
            if self._game.pid is None:
                print("Tibia is not running...")

                self._game.hook()

                time.sleep(0.5)

                continue

            self._game.spy_network()
            self._game.capture_video()



        print("Oldrak engine stopped.")

    def _set_stop_handler(self):
        keyboard.add_hotkey(EngineCommand.Stop.value, self._shutdown)

    def _shutdown(self):
        print(f"The {EngineCommand.Stop.value} key was pressed. Stopping oldrak engine...")
        self._state = EngineState.Stopped
        self._game.abort_spy_network()
