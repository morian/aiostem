from __future__ import annotations

from typing import Any, ClassVar, Dict

from aiostem.message import Message, MessageLineParser
from aiostem.response.base import Event


class BaseStatusEvent(Event):
    """Parent class for all status events."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Build any kind of status event."""
        self._action = ''  # type: str
        self._severity = ''  # type: str
        super().__init__(*args, **kwargs)

    def _message_parse(self, message: Message) -> None:
        """Parse this kind of event messages."""
        super()._message_parse(message)

        parser = MessageLineParser(message.endline)
        parser.pop_arg_checked(self.EVENT_NAME)

        self._severity = parser.pop_arg()
        self._action = parser.pop_arg()
        self._arguments = self._keyword_parse(parser)

    @property
    def action(self) -> str:
        """Get the action string."""
        return self._action

    @property
    def arguments(self) -> Dict[str, str]:
        """Get the list of generic keyword arguments."""
        return self._arguments

    @property
    def severity(self) -> str:
        """Get the message severity.

        This can be NOTICE, WARN, ERR.
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
