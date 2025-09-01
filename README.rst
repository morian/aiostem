AioStem
=======

|licence| |version| |pyversions| |coverage| |docs|

.. |licence| image:: https://img.shields.io/pypi/l/aiostem.svg
   :target: https://pypi.org/project/aiostem/

.. |version| image:: https://img.shields.io/pypi/v/aiostem.svg
   :target: https://pypi.org/project/aiostem/

.. |pyversions| image:: https://img.shields.io/pypi/pyversions/aiostem.svg
   :target: https://pypi.org/project/aiostem/

.. |coverage| image:: https://codecov.io/github/morian/aiostem/graph/badge.svg
   :target: https://app.codecov.io/github/morian/aiostem

.. |docs| image:: https://img.shields.io/readthedocs/aiostem.svg
   :target: https://aiostem.readthedocs.io/en/latest/


``aiostem`` is an `asyncio`_ python library that provides a controller to connect
and interact with the Tor control port. It therefore acts as an alternative to the
community-maintained `stem`_ controller.

.. _asyncio: https://docs.python.org/3/library/asyncio.html
.. _stem: https://stem.torproject.org/


What about Stem?
----------------

``Stem`` was not meant to be used with asynchronous python and despite `an attempt`_
to support this framework, it has `never really worked`_ well and was never merged.
Additionally it does not use a true asynchronous connection but instead uses
worker threads in order not to break existing codes.

.. _an attempt: https://gitlab.torproject.org/legacy/trac/-/issues/22627
.. _never really worked: https://github.com/torproject/stem/issues/77

The initial goal of ``aiostem`` was to offer better support for events, as there can be many
of them coming at a high rate and I noticed that ``stem`` quickly ran into deadlocks and high
CPU usage. Moreover, I feel like `stem`_ provides too many high level APIs and it is hard to
know exactly what is performed under the hood. It has also become too complex and bloated with
legacy code, both for a large range of Python versions and support for old versions of Tor.

``Tor v0.4.x`` has been released for many years now, therefore ``aiostem`` focuses the support
for ``Tor v0.4.5`` and later, as well as Python 3.10 and later.

Additionally, ``stem`` does not provide a low-level API around the control protocol, which
means that there is time waster registering and unregistering events all around. ``aistem``
focuses on a clean implementation of the low level protocol, providing far better performances
when dealing with a higher number of events.

However, ``aiostem`` is not a drop-in replacement for ``stem`` since we do not handle the
following features:

- Parsing of server and relay descriptors as in ``stem.descriptor`` (we have HS descriptors).
- Higher (and easier) level APIs mixing commands and events in a single call.
- Run a Tor daemon from library calls as in ``stem.process``.
- Download server descriptors as in ``stem.descriptor.remote``.
- Command line interpreter as in ``stem.interpreter``.
- Support for older versions of Tor and Python.


Installation
------------

This package requires Python ≥ 3.10 and pulls a few other packages as dependencies
such as pydantic_ for serialization, deserialization and validation of received data,
and cryptography_ to deal with the various keys used by Tor.

To install the latest version use the following command:

.. _cryptography: https://github.com/pyca/cryptography
.. _pydantic: https://github.com/pydantic/pydantic

.. code-block:: console

   python -m pip install aiostem


Usage
-----

This simple example shows how to use the controller in asynchronous python.
No extra thread is involved here, everything runs in the event loop.

It shows how to open a controller, authenticate, subscribe to an event, run a
command and wait for the DNS resolution event to complete.

.. code-block:: python

   #!/usr/bin/env python

   import asyncio
   from functools import partial
   from aiostem import Controller
   from aiostem.event import EventAddrMap

   def on_addrmap_event(done, event):
       if isinstance(event, EventAddrMap):
           print(f'{event.original} is at {event.replacement}')
           done.set()

   async def main():
       # Simple asyncio event to exit when the event has been received.
       done = asyncio.Event()

       # Create a new controller with the default port (9051).
       async with Controller.from_port() as ctrl:
           # Authenticate automatically with a secure method (on localhost only).
           reply = await ctrl.authenticate()
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


This code, when executed displays the following output:

.. code-block:: console

   $ python examples/usage.py
   github.com is at 140.82.121.4


For further details, please refer to the documentation_.

.. _documentation: https://aiostem.readthedocs.io/en/latest/


Contributing
------------

Contributions, bug reports and feedbacks are very welcome, feel free to open
an issue_, send a `pull request`_. or `start a discussion`_.

Participants must uphold the `code of conduct`_.

.. _issue: https://github.com/morian/aiostem/issues/new
.. _pull request: https://github.com/morian/aiostem/compare/
.. _start a discussion: https://github.com/morian/aiostem/discussions
.. _code of conduct: https://github.com/morian/aiostem/blob/master/CODE_OF_CONDUCT.md

``aiostem`` is released under the `MIT license`_.

.. _MIT license: https://github.com/morian/aiostem/blob/master/LICENSE
