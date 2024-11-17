Syntax parser
=============

.. currentmodule:: aiostem.protocol.syntax

This class helps with the parsing of a single :class:`.BaseMessage` using its header
and optionally its body content (for :class:`.MessageData`). A syntax describes how
positional and keyword values are extracted to a dictionary that can then be used as
the base values to build a :class:`.Reply` or an :class:`.Event`.

.. autoclass:: ReplySyntax
   :no-show-inheritance:
   :undoc-members:
   :members:

.. autoclass:: ReplySyntaxFlag
   :members:
