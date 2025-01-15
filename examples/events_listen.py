#!/usr/bin/env python

import asyncio
import os
import sys
from aiostem import Controller

def on_event(event):
    print(event)

async def main():
    password = os.environ.get('AIOSTEM_PASS', 'password')
    host = os.environ.get('AIOSTEM_HOST', 'localhost')
    port = os.environ.get('AIOSTEM_PORT', 9051)

    print(f'[>] Connecting to {host} on port {port}')
    async with Controller.from_port(host, int(port)) as ctrl:
        reply = await ctrl.authenticate(password)
        reply.raise_for_status()

        for name in sys.argv[1:]:
            print(f'Listening for {name}')
            await ctrl.add_event_handler(name, on_event)

        while True:
            await asyncio.sleep(3600.0)

if __name__ == '__main__':
    asyncio.run(main())
