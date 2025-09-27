import time

import keyboard

from oldrak.os.os import Memory, Network, Debugger
from oldrak.shared import EngineState, EngineCommand, TIBIA
from oldrak.os import Process


class Engine:
    def __init__(self):
        memory = Memory()
        self._process = Process(memory, Network(), Debugger(memory))
        self._state = None

    def start(self):
        self._state = EngineState.Running

        is_hooked = self._process.hook_to(TIBIA)

        keyboard.add_hotkey(EngineCommand.Stop.value, self._shutdown)

        while self._state is EngineState.Running:
            if not is_hooked:
                is_hooked = self._process.hook_to(TIBIA)

                print("Tibia is not running...")

                time.sleep(0.5)

                continue


        print("Oldrak engine stopped.")

    def _shutdown(self):
        print(f"The {EngineCommand.Stop.value} key was pressed. Stopping oldrak engine...")
        self._state = EngineState.Stopped
