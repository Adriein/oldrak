import keyboard

from oldrak.shared import EngineState, EngineCommand
from oldrak.os import Process, Network


class Engine:
    def __init__(self):
        self._state = None
        self._game = Process("Tibia")

    def start(self):
        self._state = EngineState.Running.value

        return

        # proxy = Network()

        # proxy.sniff()

        while self._state is EngineState.Running.value:
            if keyboard.is_pressed(EngineCommand.Stop.value):
                print(f"The {EngineCommand.Stop.value} key was pressed. Stopping the program...")

                self._state = EngineState.Stopped.value

                break


        print("Game has ended.")
