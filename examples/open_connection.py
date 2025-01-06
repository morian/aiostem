#!/usr/bin/env python

import asyncio
import os
from aiostem import Controller

async def main():
    host = os.environ.get('AIOSTEM_HOST', 'localhost')
    port = int(os.environ.get('AIOSTEM_PORT', 9051))

    print(f'[>] Connecting to {host} on port {port}')
    async with Controller.from_port(host, port) as ctrl:
        reply = await ctrl.protocol_info()
        reply.raise_for_status()
        print(f'[+] Connected to Tor v{reply.data.tor_version}')

if __name__ == '__main__':
    asyncio.run(main())
