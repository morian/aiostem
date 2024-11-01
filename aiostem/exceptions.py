"""
:mod:`aiostem.exception` defines the following hierarchy of exceptions.

* :exc:`AiostemError`
   * :exc:`ControllerError`
   * :exc:`MessageError`
   * :exc:`ProtocolError`
      * :exc:`CommandError`
      * :exc:`ResponseError`
"""

from __future__ import annotations


class AiostemError(Exception):
    """Base error for all exceptions raised by this library."""


class ControllerError(AiostemError):
    """Raised when the controller encountered an error."""


class ProtocolError(AiostemError):
    """Raised when a protocol issue occur between the controller and Tor."""


class CommandError(ProtocolError):
    """An invalid command argument was provided."""


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
