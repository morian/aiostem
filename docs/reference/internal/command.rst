Commands
========

.. currentmodule:: aiostem.command

All queries performed against the controller are first converted into a :class:`Command`
which itself can contain multiple arguments and data blobs.

.. autoclass:: Command
   :no-show-inheritance:
   :members:

   .. automethod:: __init__
   .. automethod:: __str__
