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

``Stem`` was not meant to be used with asynchronous python and despite `an attempt`_
to provide this feature, it has `never really worked`_ well and was never merged.
Additionally it does not use a true asynchronous connection but instead uses
worker threads in order not to break existing codes.

.. _an attempt: https://gitlab.torproject.org/legacy/trac/-/issues/22627
.. _never really worked: https://github.com/torproject/stem/issues/77

The initial goal of ``aiostem`` was to offer better support for events, as there can be many
of them coming at a high rate and I noticed that ``stem`` quickly ran into deadlocks and high
CPU usage. Moreover, I feel like `stem`_ has become too complex and bloated with legacy support,
both for a large range of Python versions and support for older versions of Tor.

``Tor v0.4.x`` has been released for many years now, therefore ``aiostem`` focuses the support for 
``Tor v0.4.5`` and later, as well as Python 3.11 and later.


Installation
------------

This package requires Python ≥ 3.11 and pulls a few other packages as dependencies
such as pydantic_ for serialization, deserialization and validation of received data,
and cryptography_ to deal with the various keys used by Tor.

To install the latest version use the following command:

.. _cryptography: https://github.com/pyca/cryptography
.. _pydantic: https://github.com/pydantic/pydantic

.. code-block:: console

   python -m pip install aiostem


Use example
-----------

This simple example shows how to use the controller in asynchronous python.
No extra thread is involved here, everything runs in the event loop.

.. code-block:: python

   #!/usr/bin/env python

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
