"""
:mod:`aiostem.exceptions` defines the following hierarchy of exceptions.

* :exc:`AiostemError`
   * :exc:`ControllerError`
   * :exc:`CryptographyError`
   * :exc:`ProtocolError`
      * :exc:`CommandError`
      * :exc:`MessageError`
      * :exc:`ReplyError`
         * :exc:`ReplyStatusError`
         * :exc:`ReplySyntaxError`
"""

from __future__ import annotations


class AiostemError(Exception):
    """
    Base error for all exceptions raised by this library.

    Use this when you want to catch any other exception from the library.

    Note:
        No exception is raised with this sole class.

    """


class CryptographyError(AiostemError):
    """
    Any error raised due to an invalid cryptography check.

    This is typically raised while deciphering a descriptor or when
    an incorrect hash was computed during :attr:`~.CommandWord.AUTHCHALLENGE`.

    """


class ControllerError(AiostemError):
    """
    Raised when the controller encountered an error.

    This indicates that a fatal error has occurred, and the controller should be
    closed, no other action will be possible afterward.

    It happens when the link to the controlled breaks, or when no compatible
    authentication method was found.

    """


class ProtocolError(AiostemError):
    """
    Raised when a bad command, reply or event was encountered.

    When raised without a sub-class, this hints to a serious issue with the core protocol
    itself. This could occur for example if Tor would mess with the protocol so bad that
    we could not known what to do next.

    Otherwise it is the base exception for all more common errors (see below).

    """


class CommandError(ProtocolError):
    """
    An error occurred while building a new command.

    This is a typical outcome when an invalid argument or argument combination has been
    provided to a command (generally caught during serialization).

    It can also hint to a possible command injection, when the provided data, once
    serialized contains line-feed characters that would break the core protocol.

    No command was sent to Tor when this occurs.

    """


class MessageError(ProtocolError):
    """
    Raised as a result of a bad manipulation of a received :class:`.Message`.

    This error is currently only raised when a reply message gets incorrectly routed
    to the event processing part of the library.

    As a user, you will never see this error.

    """


class ReplyError(ProtocolError):
    """
    Raised when something went wrong with a reply or an event.

    This is never raised without a subclass.

    """


class ReplyStatusError(ReplyError):
    """
    Raised when the reply status code is an error.

    Can only be raised by :meth:`.BaseReply.raise_for_status`, which is generally
    called by the end user.

    The underlying protocol follows the semantic of SMTP or HTTP status codes.

    See Also:
        https://spec.torproject.org/control-spec/replies.html#replies

    """

    def __init__(self, message: str, *, code: int | None = None) -> None:
        """
        Create a new :class:`ReplyStatusError`.

        Args:
            message: The original error message received from Tor.
            code: The status code associated with this message.

        """
        super().__init__(message)
        self._code = code

    @property
    def code(self) -> int | None:
        """Get the status code that generated this exception."""
        return self._code


class ReplySyntaxError(ReplyError):
    """
    Raised when encountering an invalid syntax in a received message.

    The message was properly received, but could not be parsed appropriately
    according to the syntax we expected. If you ever happen to get or see this,
    please feel free to open an issue, ideally with the full backtrace.

    """
