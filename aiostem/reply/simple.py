from __future__ import annotations

from typing import Any

from aiostem.message import Message

from .base import Reply


class SimpleReply(Reply):
    """Base class for simple replies (a single line)."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Initialize any kind of simple replies."""
        self._status_text = ''  # type: str
        super().__init__(*args, **kwargs)

    def __repr__(self) -> str:
        """Get the representation of this reply."""
        return "<{} status='{}' text='{}'>".format(
            type(self).__name__, self.status, self.status_text
        )

    def _message_parse(self, message: Message) -> None:
        """Parse the whole message."""
        super()._message_parse(message)
        self._status_text = message.status_line

    @property
    def status_text(self) -> str:
        """Get the text version of the `status` code."""
        return self._status_text


class DropGuardsReply(SimpleReply):
    """A reply parser for the DROPGUARDS command."""


class HsFetchReply(SimpleReply):
    """A reply parser for the HSFETCH command."""


class QuitReply(SimpleReply):
    """A reply parser for the QUIT command."""


class SetConfReply(SimpleReply):
    """A reply parser for the SETCONF command."""


class SetEventsReply(SimpleReply):
    """A reply parser for the SETEVENTS command."""


class SignalReply(SimpleReply):
    """A reply parser for the SIGNAL command."""
