:tocdepth: 3

Utilities
=========

This page describe internal utility classes use to parse or help with converting
data from Tor to python structures. Most of these classes heavily rely on
`pydantic`_ to handle the heavy lifting.

.. _pydantic: https://github.com/pydantic/pydantic

.. currentmodule:: aiostem.protocol.utils


Generic decoders
----------------

These are helpers used to encode/decode encoded strings to something else like :class:`bytes`.

.. autotypevar:: T

.. autoclass:: EncoderProtocol
   :members:
.. autoclass:: Base32Encoder
   :members:
.. autoclass:: Base64Encoder
   :members:
.. autoclass:: HexEncoder
   :members:

.. autoclass:: EncodedBase
   :members:

.. autoclass:: EncodedBytes
   :members:


Hidden services
---------------

.. autoclass:: HiddenServiceVersion
   :undoc-members:
   :members:

.. autoclass:: BaseHiddenServiceAddress
   :members:
.. autoclass:: HiddenServiceAddressV2
   :members:
.. autoclass:: HiddenServiceAddressV3
   :members:

.. autodata:: HiddenServiceAddress


Data transformers
-----------------

.. autoclass:: LogSeverityTransformer
   :members:
.. autoclass:: StringSequence
   :members:
.. autoclass:: TimedeltaTransformer
   :members:
