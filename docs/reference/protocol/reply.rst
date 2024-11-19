:tocdepth: 3

Replies
=======

.. currentmodule:: aiostem.protocol.reply

These reply structures are built from :class:`.Message` received by the controller
and provided back by the :class:`.Controller` to the end-user.

All replies statuses should be checked, either directly or by using :attr:`~BaseReply.status`,
:attr:`~BaseReply.is_success` or through :meth:`~BaseReply.raise_for_status`.


Base classes
------------

.. autoclass:: BaseReply
   :undoc-members:
   :members:

.. autoclass:: Reply
   :undoc-members:
   :members:

.. autoclass:: ReplySimple
   :undoc-members:
   :members: status, status_text

.. autoclass:: ReplyGetMap
   :undoc-members:
   :members:


Authentication replies
----------------------

.. autoclass:: ReplyAuthenticate
   :undoc-members:
   :members:

.. autoclass:: ReplyAuthChallenge
   :exclude-members: SYNTAX, __init__, from_message
   :undoc-members:
   :members:


Configuration replies
---------------------

.. autoclass:: ReplyGetConf
   :exclude-members: SYNTAX, __init__, from_message
   :undoc-members:
   :members:

.. autoclass:: ReplyLoadConf
   :undoc-members:
   :members:

.. autoclass:: ReplyResetConf
   :undoc-members:
   :members:

.. autoclass:: ReplySaveConf
   :undoc-members:
   :members:

.. autoclass:: ReplySetConf
   :undoc-members:
   :members:


Hidden services replies
-----------------------

.. autoclass:: ReplyAddOnion
   :exclude-members: SYNTAX, __init__, from_message
   :undoc-members:
   :members:

.. autoclass:: ReplyDelOnion
   :undoc-members:
   :members:

.. autoclass:: ReplyHsFetch
   :undoc-members:
   :members:

.. autoclass:: ReplyHsPost
   :undoc-members:
   :members:

.. autoclass:: ReplyOnionClientAuthAdd
   :undoc-members:
   :members:

.. autoclass:: ReplyOnionClientAuthRemove
   :undoc-members:
   :members:

.. autoclass:: ReplyOnionClientAuthView
   :exclude-members: SYNTAXES, __init__, from_message
   :undoc-members:
   :members:


Streams and circuits
--------------------

.. autoclass:: ReplyAttachStream
   :undoc-members:
   :members:

.. autoclass:: ReplyCloseCircuit
   :undoc-members:
   :members:

.. autoclass:: ReplyCloseStream
   :undoc-members:
   :members:

.. autoclass:: ReplyDropGuards
   :undoc-members:
   :members:

.. autoclass:: ReplyExtendCircuit
   :exclude-members: SYNTAX, __init__, from_message
   :undoc-members:
   :members:

.. autoclass:: ReplyRedirectStream
   :undoc-members:
   :members:

.. autoclass:: ReplySetCircuitPurpose
   :undoc-members:
   :members:


Other replies
-------------

.. autoclass:: ReplyDropOwnership
   :undoc-members:
   :members:

.. autoclass:: ReplyDropTimeouts
   :undoc-members:
   :members:

.. autoclass:: ReplyGetInfo
   :exclude-members: SYNTAX, __init__, from_message
   :undoc-members:
   :members:

.. autoclass:: ReplyMapAddressItem
   :exclude-members: SYNTAX, __init__
   :undoc-members:
   :members:

.. autoclass:: ReplyMapAddress
   :exclude-members: __init__, from_message
   :undoc-members:
   :members:

.. autoclass:: ReplyProtocolInfo
   :exclude-members: SYNTAXES, __init__, from_message
   :undoc-members:
   :members:

.. autoclass:: ReplyQuit
   :undoc-members:
   :members:

.. autoclass:: ReplyResolve
   :undoc-members:
   :members:

.. autoclass:: ReplySetEvents
   :undoc-members:
   :members:

.. autoclass:: ReplySignal
   :undoc-members:
   :members:

.. autoclass:: ReplyTakeOwnership
   :undoc-members:
   :members:

.. autoclass:: ReplyUseFeature
   :undoc-members:
   :members:


Bridge replies
--------------

.. autoclass:: ReplyPostDescriptor
   :undoc-members:
   :members:
