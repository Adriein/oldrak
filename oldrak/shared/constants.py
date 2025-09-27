from enum import Enum

class EngineState(Enum):
    Running = 1
    Paused = 2
    Stopped = 3

class EngineCommand(Enum):
    Stop = 'p'