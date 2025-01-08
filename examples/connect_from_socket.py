#!/usr/bin/env python

import asyncio
import os
from aiostem import Controller

async def main():
    path = os.environ.get('AIOSTEM_PATH', '/run/tor/control')
    print(f'[>] Connecting to {path}')
    async with Controller.from_path(path) as ctrl:
        reply = await ctrl.protocol_info()
        reply.raise_for_status()
        print(f'[+] Connected to Tor v{reply.data.tor_version}')

if __name__ == '__main__':
    asyncio.run(main())
