#!/usr/bin/env python3
#
#  wsclient.py
#
#  Copyright (c) 2025 Florian Albrechtskirchinger. All rights reserved.
#  MIT License
#

import asyncio
import websockets


async def client():
    # Connect to the server
    async with websockets.connect("ws://localhost:8080/endpoint") as websocket:
        # Send the message
        message = "Hello, WebSockets!"
        await websocket.send(message)
        print(f"Sent: {message}")

        # Wait
        await asyncio.sleep(3)

        # Close the connection
        await websocket.close()
        print("Connection closed")


async def main():
    await client()


if __name__ == "__main__":
    asyncio.run(main())
