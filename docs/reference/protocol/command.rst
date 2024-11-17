:tocdepth: 3

Commands
========

.. currentmodule:: aiostem.protocol.command


Base class
----------

.. autoclass:: Command
   :undoc-members:
   :members:


Command classes
---------------

These commands could be built by the end-user along with :meth:`.Controller.request`
but the faster way is to use the corresponding wrapper provided on the :class:`.Controller`.

.. autoclass:: CommandSetConf
   :undoc-members:
   :members:

.. autoclass:: CommandResetConf
   :undoc-members:
   :members:


Command names
-------------

.. autoclass:: CommandWord
   :undoc-members:
   :members:
