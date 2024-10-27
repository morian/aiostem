from __future__ import annotations

from typing import ClassVar

from ..message import Message, MessageLineParser
from ..reply.base import Event


class SignalEvent(Event):
    """
    Parse a signal events.

    See Also:
        https://spec.torproject.org/control-spec/replies.html#SIGNAL

    """

    EVENT_NAME: ClassVar[str] = 'SIGNAL'

    def __repr__(self) -> str:
        """Representation of this Signal event."""
        return f"<{type(self).__name__} '{self.signal}'>"

    def _message_parse(self, message: Message) -> None:
        """
        Parse this event message.

        Args:
            message: the event message we just received.

        """
        super()._message_parse(message)

        parser = MessageLineParser(message.status_line)
        parser.pop_arg_checked(self.EVENT_NAME)
        self._signal = parser.pop_arg()

    @property
    def signal(self) -> str:
        """Get the name of the signal received."""
        return self._signal
