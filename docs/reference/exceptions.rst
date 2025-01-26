Exceptions
==========

.. currentmodule:: aiostem.exceptions

This page describes all the internal exceptions raised by this library.

Note that other exceptions such as :exc:`~pydantic_core.ValidationError` can also be raised
and these are not wrapped (yet?) by this library.


Exception hierarchy
-------------------

.. automodule:: aiostem.exceptions

Naming things is hard, but a short description of every exception is provided below.


Base exception
--------------

.. autoexception:: AiostemError


Effective exception
-------------------

.. autoexception:: ControllerError
.. autoexception:: CryptographyError
.. autoexception:: ProtocolError

Protocol exceptions
-------------------

.. autoexception:: CommandError
.. autoexception:: MessageError
.. autoexception:: ReplyError

Reply exceptions
----------------

.. autoexception:: ReplyStatusError

   .. automethod:: __init__
   .. autoproperty:: code

.. autoexception:: ReplySyntaxError
