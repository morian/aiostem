:tocdepth: 3

Commands
========

.. currentmodule:: aiostem.command


These commands could be built by the end-user along with :meth:`.Controller.request`
but the faster way is to use the corresponding wrapper provided on the :class:`.Controller`.


Base command class
------------------

.. autoclass:: Command
   :undoc-members:
   :members:


Authentication commands
-----------------------

.. autoclass:: CommandAuthenticate
   :undoc-members:
   :members:

.. autoclass:: CommandAuthChallenge
   :undoc-members:
   :members:


Configuration commands
----------------------

.. autoclass:: CommandGetConf
   :undoc-members:
   :members:

.. autoclass:: CommandLoadConf
   :undoc-members:
   :members:

.. autoclass:: CommandResetConf
   :undoc-members:
   :members:

.. autoclass:: CommandSaveConf
   :undoc-members:
   :members:

.. autoclass:: CommandSetConf
   :undoc-members:
   :members:


Hidden services commands
------------------------

.. autoclass:: CommandAddOnion
   :undoc-members:
   :members:

.. autoclass:: CommandDelOnion
   :undoc-members:
   :members:

.. autoclass:: CommandHsFetch
   :undoc-members:
   :members:

.. autoclass:: CommandHsPost
   :undoc-members:
   :members:

.. autoclass:: CommandOnionClientAuthAdd
   :undoc-members:
   :members:

.. autoclass:: CommandOnionClientAuthRemove
   :undoc-members:
   :members:

.. autoclass:: CommandOnionClientAuthView
   :undoc-members:
   :members:


Streams and circuits
--------------------

.. autoclass:: CommandAttachStream
   :undoc-members:
   :members:

.. autoclass:: CommandCloseCircuit
   :undoc-members:
   :members:

.. autoclass:: CommandCloseStream
   :undoc-members:
   :members:

.. autoclass:: CommandDropGuards
   :undoc-members:
   :members:

.. autoclass:: CommandExtendCircuit
   :undoc-members:
   :members:

.. autoclass:: CommandRedirectStream
   :undoc-members:
   :members:

.. autoclass:: CommandSetCircuitPurpose
   :undoc-members:
   :members:


Control commands
----------------

These commands have near to no side effect on the network but are used internally.

.. autoclass:: CommandDropOwnership
   :undoc-members:
   :members:

.. autoclass:: CommandDropTimeouts
   :undoc-members:
   :members:

.. autoclass:: CommandGetInfo
   :undoc-members:
   :members:

.. autoclass:: CommandMapAddress
   :undoc-members:
   :members:

.. autoclass:: CommandProtocolInfo
   :undoc-members:
   :members:

.. autoclass:: CommandQuit
   :undoc-members:
   :members:

.. autoclass:: CommandResolve
   :undoc-members:
   :members:

.. autoclass:: CommandSetEvents
   :undoc-members:
   :members:

.. autoclass:: CommandSignal
   :undoc-members:
   :members:

.. autoclass:: CommandTakeOwnership
   :undoc-members:
   :members:

.. autoclass:: CommandUseFeature
   :undoc-members:
   :members:


Bridge commands
---------------

.. autoclass:: CommandPostDescriptor
   :undoc-members:
   :members:


Command serializer
------------------

.. autoclass:: CommandSerializer
   :no-show-inheritance:
   :undoc-members:
   :members:

   .. automethod:: __init__


Command names
-------------

.. autoclass:: CommandWord
   :undoc-members:
   :members:
