from aiostem.message import Message
from aiostem.response.base import Reply


class SimpleReply(Reply):
    """Base class for simple replies (a single line)."""

    def __init__(self, *args, **kwargs) -> None:
        self._status_text = ''  # type: str
        super().__init__(*args, **kwargs)

    def __repr__(self) -> str:
        """Representation of this reply."""
        return "<{} status='{}' text='{}'>".format(
            type(self).__name__, self.status, self.status_text
        )

    def _message_parse(self, message: Message) -> None:
        """Parse the whole message."""
        super()._message_parse(message)
        self._status_text = message.endline

    @property
    def status_text(self) -> str:
        """Text version of the `status` code."""
        return self._status_text


class QuitReply(SimpleReply):
    """A reply parser for the QUIT command."""


class SignalReply(SimpleReply):
    """A reply parser for the SIGNAL command."""


class HsFetchReply(SimpleReply):
    """A reply parser for the HSFETCH command."""


class SetEventsReply(SimpleReply):
    """A reply parser for the SETEVENTS command."""
