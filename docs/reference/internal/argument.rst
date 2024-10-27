Arguments
=========

.. currentmodule:: aiostem.argument

These classes are used to parse and contain command and reply arguments.

Base class
----------

.. autoclass:: BaseArgument
   :no-show-inheritance:
   :members:

   .. automethod:: __str__


Positional argument
-------------------

.. autoclass:: SingleArgument
   :members:

   .. automethod:: __init__
   .. automethod:: __str__


Keyword argument
----------------

.. autoclass:: KeywordArgument
   :members:

   .. automethod:: __init__
   .. automethod:: __str__
