import asyncio

import keyboard

from oldrak.shared import EngineState, EngineCommand
from oldrak.os import Process, Network, Proxy


class Engine:
    def __init__(self):
        self._state = None
        self._game = Process("Tibia")

    async def start(self):
        self._state = EngineState.Running.value

        proxy = Proxy(Network())

        proxy.run()

        while self._state is EngineState.Running.value:
            if keyboard.is_pressed(EngineCommand.Stop.value):
                print(f"The {EngineCommand.Stop.value} key was pressed. Stopping the program...")

                self._state = EngineState.Stopped.value

                proxy.handle.cancel()

                break

            await asyncio.sleep(0.1)


        print("Game has ended.")
