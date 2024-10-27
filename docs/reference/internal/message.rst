Message
=======

A message is an internal representation of a received message.
It can either be an event or a reply to some other user-supplied query.

.. currentmodule:: aiostem.message

The message itself
------------------

.. autoclass:: Message
   :no-show-inheritance:
   :members:

   .. automethod:: __init__


Message helpers
---------------

.. autoclass:: MessageData
   :no-show-inheritance:
   :members:

.. autoclass:: MessageLineParser
   :no-show-inheritance:
   :members:

   .. automethod:: __init__
   .. automethod:: __str__
