import keyboard

from oldrak.shared import EngineState, EngineCommand

class Engine:
    def __init__(self):
        self.__state = EngineState.Running.value

    def start(self):
        while self.__state == EngineState.Running.value:
            if keyboard.is_pressed(EngineCommand.Stop.value):
                print("The 'p' key was pressed. Exiting the loop...")
                self.__state = EngineState.Stopped.value
                break

            print("Game loop is running...")

        print("Game has ended.")