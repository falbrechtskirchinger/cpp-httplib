#!/usr/bin/env python3
#
#  wsclient.py
#
#  Copyright (c) 2025 Florian Albrechtskirchinger. All rights reserved.
#  MIT License
#

import asyncio
import logging
import websockets


async def echo(websocket):
    try:
        async for message in websocket:
            # Echo each message back to the client
            await websocket.send(message)
            print(f"Received and echoed: {message}")
    except websockets.exceptions.ConnectionClosedOK:
        print("Client disconnected normally")
    except Exception as e:
        print(f"Error in connection: {e}")


async def main():
    # Start the server on localhost at port 8080
    server = await websockets.serve(echo, "localhost", 8080, ping_interval=2)
    print("WebSocket Echo Server started on ws://localhost:8080")
    await server.wait_closed()


if __name__ == "__main__":
    logging.basicConfig(
        format="%(message)s",
        level=logging.DEBUG,
    )
    asyncio.run(main())
