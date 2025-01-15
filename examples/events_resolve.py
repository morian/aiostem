#!/usr/bin/env python

import asyncio
import os
import sys
from aiostem import Controller
from aiostem.event import EventAddrMap
from functools import partial

def on_addrmap(done, event):
    if isinstance(event, EventAddrMap):
        print(f'{event.original} is located at {event.replacement}')
        done.set()

async def main():
    password = os.environ.get('AIOSTEM_PASS', 'password')
    host = os.environ.get('AIOSTEM_HOST', 'localhost')
    port = os.environ.get('AIOSTEM_PORT', 9051)

    # Simple asyncio event to exit when the event has been received.
    done = asyncio.Event()

    print(f'[>] Connecting to {host} on port {port}')
    async with Controller.from_port(host, int(port)) as ctrl:
        reply = await ctrl.authenticate(password)
        reply.raise_for_status()

        await ctrl.add_event_handler('ADDRMAP', partial(on_addrmap, done))
        reply = await ctrl.resolve(sys.argv[1:])
        reply.raise_for_status()

        # Wait until the address is resolved.
        await done.wait()

if __name__ == '__main__':
    asyncio.run(main())
