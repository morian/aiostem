#!/usr/bin/env python

import asyncio
import os
from functools import partial
from aiostem import Controller
from aiostem.event import EventAddrMap

def on_addrmap_event(done, event):
    if isinstance(event, EventAddrMap):
        print(f'{event.original} is at {event.replacement}')
        done.set()

async def main():
    password = os.environ.get('AIOSTEM_PASS', 'password')
    host = os.environ.get('AIOSTEM_HOST', 'localhost')
    port = os.environ.get('AIOSTEM_PORT', 9051)

    # Simple asyncio event to exit when the event has been received.
    done = asyncio.Event()

    # Create a new controller with the default port (9051).
    async with Controller.from_port(host, int(port)) as ctrl:
        # Authenticate automatically with a secure method (on localhost only).
        reply = await ctrl.authenticate(password)
        reply.raise_for_status()

        # Register a callback for ``ADDRMAP`` events.
        await ctrl.add_event_handler('ADDRMAP', partial(on_addrmap_event, done))

        # Request DNS resolution for ``github.com``.
        # The output here is received as an ``ADDRMAP`` event.
        reply = await ctrl.resolve(['github.com'])
        reply.raise_for_status()

        # Wait until the address is resolved.
        await done.wait()


if __name__ == '__main__':
    asyncio.run(main())
