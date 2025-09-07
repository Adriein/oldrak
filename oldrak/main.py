import asyncio

from oldrak.engine import Engine

async def main():
    engine = Engine()

    await engine.start()

if __name__ == "__main__":
    asyncio.run(main())