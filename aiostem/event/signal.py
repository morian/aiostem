from aiostem.message import Message, MessageLine
from aiostem.response.base import Event


class SignalEvent(Event):
    """Parse signal events."""

    EVENT_NAME: str = 'SIGNAL'

    def __repr__(self) -> str:
        """Representation of this Signal event."""
        return "<{} '{}'>".format(type(self).__name__, self.signal)

    def _message_parse(self, message: Message) -> None:
        """Handle parsing on the signal event."""
        super()._message_parse(message)

        parser = MessageLine(message.endline)
        parser.pop_arg_checked(self.EVENT_NAME)
        self._signal = parser.pop_arg()

    @property
    def signal(self) -> str:
        """Name of the signal received in this event."""
        return self._signal
