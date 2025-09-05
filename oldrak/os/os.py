import os

class Memory:
    def get_pid_by_name(self, name: str) -> int|None:
        for pid in os.listdir('/proc'):
            if not pid.isdigit():
                continue

            try:
                with open(os.path.join('/proc', pid, 'cmdline'), 'r') as buff:
                    if name in buff.read().strip():
                        return int(pid)

            except (IOError, FileNotFoundError):
                continue

        return None


class Process:
    def __init__(self, name: str):
        self.__memory = Memory()
        self.__process_name = name

    def pid(self) -> int|None:
        return self.__memory.get_pid_by_name(self.__process_name)