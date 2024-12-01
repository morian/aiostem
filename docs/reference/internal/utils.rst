:tocdepth: 3

Utilities
=========

This page describe internal utility classes use to parse or help with converting
data from Tor to python structures. Most of these classes heavily rely on
`pydantic`_ to handle the heavy lifting.

.. _pydantic: https://github.com/pydantic/pydantic

.. currentmodule:: aiostem.protocol.utils


Type aliases
------------

These are helper types used to describe common types encountered throughout his library.

.. autodata:: AnyHost


Generic decoders
----------------

These are helpers used to encode/decode encoded strings to something else like :class:`bytes`.

.. autotypevar:: T
   :no-type:

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
   :no-show-inheritance:
   :members:
.. autoclass:: StringSequence
   :no-show-inheritance:
   :members:
.. autoclass:: TimedeltaTransformer
   :no-show-inheritance:
   :members:
