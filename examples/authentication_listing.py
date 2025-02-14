#!/usr/bin/env python

import asyncio
import os
from aiostem import Controller

async def main():
    host = os.environ.get('AIOSTEM_HOST', 'localhost')
    port = os.environ.get('AIOSTEM_PORT', 9051)

    print(f'[>] Connecting to {host} on port {port}')
    async with Controller.from_port(host, int(port)) as ctrl:
        reply = await ctrl.protocol_info()
        reply.raise_for_status()

        print('[+] List of allowed authentication methods:')
        for method in reply.data.auth_methods:
            print(f' * {method}')
        if reply.data.auth_cookie_file is not None:
            print(f'[+] Path to the cookie file: {reply.data.auth_cookie_file}')

if __name__ == '__main__':
    asyncio.run(main())
