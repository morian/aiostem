AioStem
=======

|coverage| |docs|

.. |coverage| image:: https://codecov.io/github/morian/aiostem/graph/badge.svg
   :target: https://app.codecov.io/github/morian/aiostem

.. |docs| image:: https://img.shields.io/readthedocs/aiostem.svg
   :target: https://aiostem.readthedocs.io/en/latest/


``aiostem`` is an `asyncio`_ python library that provides a controller to connect
and interact with the Tor control port. It therefore acts as an alternative to the
community-maintained `stem`_ controller.

.. _asyncio: https://docs.python.org/3/library/asyncio.html
.. _stem: https://stem.torproject.org/


Why should we have another library?
-----------------------------------

``Stem`` is not meant to be used in asynchronous python and the (today) unreleased patches
does not seem to really implement the core protocol in an asynchronous fashion.
Instead it seems to communicate with a synchronous instance spawned in another thread.

The initial goal of ``aiostem`` is to offer better support for events, as there can be many
of them coming at a high rate. Moreover, I feel like `stem`_ has become too complex and
too bloated with legacy support, while Tor ``v0.4.x`` is out for many years now.

This is also why this library can only connect to ``Tor v0.4.5`` and later.


Current development status
--------------------------

All commands and replies were implemented from the protocol point of view, but only a few
events are currently parsed appropriately. There is still work in progress on this side.


Installation
------------

This package requires Python ≥ 3.11 and pulls a few other packages as dependencies.

To install the latest version use the following command:

.. code-block:: console

   python -m pip install aiostem


Use example
-----------

This simple example shows how to use the controller in asynchronous python.
No extra thread is involved here, everything runs in the event loop.

.. code-block:: python

   import asyncio
   from aiostem import Controller

   async def on_hs_desc_content(event):
       print(event.address)
       print(event.descriptor)

   async def main():
       # Create a new controller with the default port (9051).
       async with Controller.from_port() as controller:
           # Authenticate automatically with a secure method.
           await controller.authenticate()

           # Be notified when hidden service descriptor content is available.
           await controller.add_event_handler('HS_DESC_CONTENT', on_hs_desc_content)

           # Request a new identity from the controller (this flushes caches).
           await controller.signal('NEWNYM')

           # Perform a descriptor request for this onion domain.
           await controller.hs_fetch('reconponydonugup.onion')

           # Wait a little bit until the descriptor is fetched.
           await asyncio.sleep(10)

   if __name__ == '__main__':
       asyncio.run(main())
