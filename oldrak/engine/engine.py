import keyboard

from oldrak.shared import EngineState, EngineCommand
from oldrak.os import Process


class Engine:
    def __init__(self):
        self._state = None
        self._game = Process("Tibia")

    def start(self):
        self._state = EngineState.Running

        while self._state is EngineState.Running:
            if keyboard.is_pressed(EngineCommand.Stop.value):
                print("The 'p' key was pressed. Exiting the loop...")
                self._state = EngineState.Stopped
                break

            print(self._game.pid)

        print("Game has ended.")
