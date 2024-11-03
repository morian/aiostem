"""
:mod:`aiostem.exceptions` defines the following hierarchy of exceptions.

* :exc:`AiostemError`
   * :exc:`ControllerError`
   * :exc:`ProtocolError`
      * :exc:`CommandError`
      * :exc:`MessageError`
      * :exc:`ReplyStatusError`
"""

from __future__ import annotations


class AiostemError(Exception):
    """Base error for all exceptions raised by this library."""


class ControllerError(AiostemError):
    """Raised when the controller encountered an error."""


class ProtocolError(AiostemError):
    """Raises when a bad command or a bad reply was encountered."""


class CommandError(ProtocolError):
    """
    An error occurred while building a new command.

    This is a typical outcome when invalid arguments or argument combination are provided.
    It can also be the result of a detected command injection.
    """


class MessageError(ProtocolError):
    """Raised as a result of a bad manipulation of a received :class:`.Message`."""


class ReplyStatusError(ProtocolError):
    """Raised when a reply status code is invalid."""

    def __init__(self, message: str, *, code: int | None = None) -> None:
        """
        Create a new :class:`ReplyStatusError`.

        Args:
            message: the original message received from Tor if possible
            code: the status code associated with this message

        """
        super().__init__(message)
        self._code = code

    @property
    def code(self) -> int | None:
        """Get the status code that generated this exception."""
        return self._code
