#!/usr/bin/env python

import asyncio
import os
from aiostem import Controller

async def main():
    password = os.environ.get('AIOSTEM_PASS', 'password')
    host = os.environ.get('AIOSTEM_HOST', 'localhost')
    port = os.environ.get('AIOSTEM_PORT', 9051)

    print(f'[>] Connecting to {host} on port {port}')
    async with Controller.from_port(host, int(port)) as ctrl:
        reply = await ctrl.authenticate(password)
        reply.raise_for_status()

        print('[+] Authentication successful!')

if __name__ == '__main__':
    asyncio.run(main())
