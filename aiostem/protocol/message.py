from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import MutableSequence
from dataclasses import dataclass, field
from typing import Final


class BaseMessage(ABC):
    """Base class for the whole message and message items."""

    #: The end of line applied while serializing messages.
    END_OF_LINE: Final[str] = '\r\n'

    #: Status code of the whole message.
    status: int
    #: Text that comes along with the status.
    header: str

    @abstractmethod
    def serialize(self) -> str:
        """Serialize this message to text that could have been sent."""


@dataclass(kw_only=True)
class MessageData(BaseMessage):
    """A sub-message with only a single line."""

    data: str

    def serialize(self) -> str:
        """Serialize this data sub-message to a string."""
        lines = [f'{self.status:03d}+{self.header}']
        for line in self.data.split('\n'):
            line = line.rstrip('\r')
            if line.startswith('.'):
                line = '.' + line
            lines.append(line)
        lines.append('.')
        return self.END_OF_LINE.join(lines) + self.END_OF_LINE


@dataclass(kw_only=True)
class MessageLine(BaseMessage):
    """A sub-message with only a single line."""

    def serialize(self) -> str:
        """Serialize this line sub-message to a string."""
        return f'{self.status:03d}-{self.header}\r\n'


@dataclass(kw_only=True)
class Message(BaseMessage):
    """Utility class used to parse any received message."""

    #: List of sub-messages received within this message.
    items: MutableSequence[MessageLine | MessageData] = field(default_factory=list)

    def serialize(self) -> str:
        """Serialize this message to a string."""
        text = ''
        for item in self.items:
            text += item.serialize()
        text += f'{self.status:03d} {self.header}\r\n'
        return text
