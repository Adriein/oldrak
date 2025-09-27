import time

import keyboard

from oldrak.os.os import Memory, Network, Debugger
from oldrak.shared import EngineState, EngineCommand
from oldrak.os import Process


class Engine:
    def __init__(self):
        memory = Memory()
        self._game = Process(memory, Network(), Debugger(memory))
        self._state = None

    def start(self):
        self._state = EngineState.Running

        is_hooked = self._game.hook()

        keyboard.add_hotkey(EngineCommand.Stop.value, self._shutdown)

        while self._state is EngineState.Running:
            if not is_hooked:
                is_hooked = self._game.hook()

                print("Tibia is not running...")

                time.sleep(0.5)

                continue

            self._game.spy_network()


        print("Oldrak engine stopped.")

    def _shutdown(self):
        print(f"The {EngineCommand.Stop.value} key was pressed. Stopping oldrak engine...")
        self._state = EngineState.Stopped
