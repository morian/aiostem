AioStem
=======

Asynchronous Tor controller library for asyncio and Python.

[[_TOC_]]


# What is this all about?

`Aiostem` is a python library that aims to provide an asynchronous control library
for Tor. This goal is already fulfilled by `stem`, maintained by the Tor community.
`Stem` is not meant to be used in asynchronous python, and the un-released patches
does not seem to really implement the protocol in an asynchronous fashion.

Instead it seems to communicate with a synchronous instance spawned in another thread.
The initial goal of this library is to offer a better support for the streaming of events,
that can be generated while fetching hidden service descriptors for example.

`Stem` was not meant to support huge massive and concurrent event streaming and fails
miserably at this game.

`Aiostem` currently offers the following features:
* A controller similar to the one used by `Stem`, with support for all authentication methods
* Subscribe or un-subscribe to events (using async callbacks)
* Gathering protocol information
* Sending signals to the daemon
* Exiting the controller

On the event side, the following ones are parsed in dedicated structures:
* `HS_DESC`, `HS_DESC_CONTENT` used to gather hidden service descriptors
* `NETWORK_LIVENESS` to be notified when the network goes down
* `SIGNAL` to be notified when a signal has been processed
* `STATUS_GENERAL`, `STATUS_CLIENT`, `STATUS_SERVER` for miscellaneous status information

Additionally, a helper is provided to allow for fast hidden service descriptor fetching in
package `aiostem.extra`. An example application is provided in `aiostem-hsscan`.

Do note that for convenience, this package uses `stem` to parse descriptors.
This is already something that cannot block, which means there is little interest to reinvent
what already exists (and this is not the funny part, trust me).

On compatibility, just ensure you have a recent version of Tor (something like 0.4.1 or greater).


# Installation

Aiostem was tested successfully from Python 3.9 to Python 3.13.

The best way to install it is by creating a dedicated `venv` using the `venv` package from python.
Note that this might require the installation of distribution specific packages such as
`python3-venv` and `python3-pip`.

First create the target `venv` and source the environment:
```console
$ python3 -m venv venv
$ source venv/bin/activate
```

Then you can install Aiostem inside the environment from the wheel package, source distribution
or from sources using `setup.py` (provided):

```console
(venv) $ pip install dist/aiostem-*.whl
```

```console
(venv) $ pip install .
```

# Getting started

This simple example shows how to use the controller in asynchronous python.
No extra thread is involved here, everything runs in the event loop.

```python
import asyncio

from aiostem import Controller


async def aio_hs_callback(event):
    print(event.address)
    print(event.descriptor)

async def main():
    # Create a new controller with the default port (9051).
    async with Controller.from_port() as controller:
        # Authenticate automatically with a secure method.
        await controller.authenticate()

        # Be notified when hidden service descriptor content is available.
        await controller.event_subscribe('HS_DESC_CONTENT', aio_hs_callback)

        # Request a new identity (flush lots of caches).
        await controller.signal('NEWNYM')

        # Perform a descriptor request for this onion domain.
        await controller.hs_fetch('reconponydonugup.onion')

        # Wait a little bit until the descriptor is fetched.
        await asyncio.sleep(10)

if __name__ == '__main__':
    asyncio.run(main())
```


# Using `aiostem-hsscan`

The goal of this tool is to provide a way to rescan a huge list of onion domains provided
in `--input` through Tor's controller located at `--control` (authenticated with `--password`).
All the descriptors related to these onion domains are scanned concurrently with a maximum
of `--workers`, each with a timeout of `--timeout`. Successful domains (the ones alive) are
reported to `--output`.

We advise not to increase `--workers` too much as Tor seems to use a lot of CPU when this
value is too high (we recommend 10 workers).

```console
(venv) $ aiostem-hsscan --help
aiostem-hsscan [-h] -i FILE [-o FILE] [-c SOCK] [-p PASS] [-t SECS] [-w NUM] [-f]

Check onion domains liveness by requesting directories.

optional arguments:
  -h, --help                show this help message and exit
  -i FILE, --input FILE     input onion domains to scan (one per line)
  -o FILE, --output FILE    output list of successfully scanned domains
  -c SOCK, --control SOCK   location of Tor's controller (ip:port or path)
  -p PASS, --password PASS  optional password to connect to Tor's controller
  -t SECS, --timeout SECS   how long to wait for each descriptor to be fetched
  -w NUM, --workers NUM     maximum number of concurrent descriptor fetches
  -f, --flush               flush to output file after each write
```
