Arguments
=========

.. currentmodule:: aiostem.protocol.argument

These classes are used internally by :class:`.Command` and :class:`.CommandSerializer`
to serialize its parameters to the format expected by Tor.


Base class
----------

.. autoclass:: BaseArgument
   :members: __str__


Argument classes
----------------

.. autoclass:: ArgumentKeyword
   :undoc-members:
   :members:

   .. automethod:: __init__
   .. automethod:: __str__

.. autoclass:: ArgumentString
   :undoc-members:
   :members:

   .. automethod:: __init__
   .. automethod:: __str__


Helpers
-------

.. autoclass:: QuoteStyle
   :undoc-members:
   :members:
