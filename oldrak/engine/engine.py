import keyboard

from oldrak.shared import EngineState, EngineCommand
from oldrak.os import Process

class Engine:
    def __init__(self):
        self.__state = EngineState.Running.value

    def start(self):
        while self.__state is EngineState.Running.value:
            if keyboard.is_pressed(EngineCommand.Stop.value):
                print("The 'p' key was pressed. Exiting the loop...")
                self.__state = EngineState.Stopped.value
                break

            process = Process("Tibia")

            print(process.pid())

        print("Game has ended.")