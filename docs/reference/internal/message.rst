Messages
========

.. currentmodule:: aiostem.protocol.message

This page describes how we parse all received data from the :class:`~asyncio.StreamReader`
that lies under the :class:`.Controller`. These messages are then parsed either as a
:class:`.Reply` or as an :class:`.Event` depending on whether :attr:`BaseMessage.is_event`
is :obj:`False` or not (which means that :attr:`BaseMessage.status` equals ``650``).

Note that a :class:`Message` can contain multiple sub-messages, each with their own
status and header content. Additionally a sub-message can also contain a body.


Main class
----------

.. autoclass:: Message
   :undoc-members:
   :members:


Message items
-------------

.. autoclass:: MessageLine
   :undoc-members:
   :members:

.. autoclass:: MessageData
   :undoc-members:
   :members:


Base class
----------

.. autoclass:: BaseMessage
   :undoc-members:
   :members:


Helpers
-------

.. autofunction:: messages_from_stream
