from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar

from ..message import Message, MessageLineParser
from ..reply.base import Event

if TYPE_CHECKING:
    from collections.abc import Mapping


class BaseStatusEvent(Event):
    """Parent class for all status-like events."""

    def __init__(self, message: Message) -> None:
        """
        Create a new status-like event out of the received message.

        See Also:
            https://spec.torproject.org/control-spec/replies.html#STATUS

        Args:
            message: the message event we just received.

        """
        self._action = ''  # type: str
        self._severity = ''  # type: str
        super().__init__(message)

    def _message_parse(self, message: Message) -> None:
        """
        Parse this event message.

        Args:
            message: the event message we just received.

        """
        super()._message_parse(message)

        parser = MessageLineParser(message.status_line)
        parser.pop_arg_checked(self.EVENT_NAME)

        self._severity = parser.pop_arg()
        self._action = parser.pop_arg()
        self._arguments = self._keyword_parse(parser)

    @property
    def action(self) -> str:
        """Get the action string."""
        return self._action

    @property
    def arguments(self) -> Mapping[str, str]:
        """Get a map of generic keyword arguments."""
        return self._arguments

    @property
    def severity(self) -> str:
        """
        Get the message severity.

        Note:
            This can be `NOTICE`, `WARN`, `ERR`.

        """
        return self._severity


class StatusGeneralEvent(BaseStatusEvent):
    """General status event."""

    EVENT_NAME: ClassVar[str] = 'STATUS_GENERAL'


class StatusClientEvent(BaseStatusEvent):
    """Client status event."""

    EVENT_NAME: ClassVar[str] = 'STATUS_CLIENT'


class StatusServerEvent(BaseStatusEvent):
    """Server status event."""

    EVENT_NAME: ClassVar[str] = 'STATUS_SERVER'
