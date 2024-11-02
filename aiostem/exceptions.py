"""
:mod:`aiostem.exceptions` defines the following hierarchy of exceptions.

* :exc:`AiostemError`
   * :exc:`ControllerError`
   * :exc:`ProtocolError`
      * :exc:`CommandError`
      * :exc:`MessageError`
      * :exc:`ResponseError`
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


class ResponseError(ProtocolError):
    """Raised when the response message received by the controller is an error."""

    def __init__(self, status: int, message: str) -> None:
        """
        Create a new response error message.

        Args:
            status: status code received as part of the message
            message: textual representation of the error message

        """
        super().__init__(message)
        self._status = status

    @property
    def status(self) -> int:
        """Get the response status code responsible for this error."""
        return self._status
