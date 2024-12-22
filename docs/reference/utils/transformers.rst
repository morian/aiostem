Transformers
============

This page describe internal utility classes use to parse or help with converting
data from Tor to python structures. Most of these classes rely on `pydantic`_ to
handle the heavy lifting.

.. _pydantic: https://github.com/pydantic/pydantic

.. currentmodule:: aiostem.utils.transformers

.. autoclass:: TrAfterAsTimezone
   :no-show-inheritance:
   :members:

.. autoclass:: TrBeforeSetToNone
   :no-show-inheritance:
   :members:

.. autoclass:: TrBeforeStringSplit
   :no-show-inheritance:
   :members:

.. autoclass:: TrBeforeTimedelta
   :no-show-inheritance:
   :members:

.. autoclass:: TrCast
   :no-show-inheritance:
   :members:

.. autoclass:: TrEd25519PrivateKey
   :no-show-inheritance:
   :members:

.. autoclass:: TrEd25519PublicKey
   :no-show-inheritance:
   :members:

.. autoclass:: TrX25519PrivateKey
   :no-show-inheritance:
   :members:

.. autoclass:: TrX25519PublicKey
   :no-show-inheritance:
   :members:
