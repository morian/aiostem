from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Final

from ..exceptions import ProtocolError

if TYPE_CHECKING:
    from asyncio import StreamReader
    from collections.abc import AsyncIterator


@dataclass(frozen=True, kw_only=True)
class BaseMessage(ABC):
    """Base class for the whole message and message items."""

    #: The end of line applied while serializing messages.
    END_OF_LINE: Final[str] = '\r\n'

    #: Status code of the whole message.
    status: int
    #: Text that comes along with the status.
    header: str

    @property
    def keyword(self) -> str:
        """
        Extract the first word from the header.

        Note:
            This is not relevant for all kind of messages.

        """
        return self.header.split(' ', maxsplit=1)[0]

    @abstractmethod
    def serialize(self) -> str:
        """Serialize this message to text that could have been sent."""


@dataclass(frozen=True, kw_only=True)
class MessageData(BaseMessage):
    """A sub-message with only a single line."""

    data: str = ''

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


@dataclass(frozen=True, kw_only=True)
class MessageLine(BaseMessage):
    """A sub-message with only a single line."""

    def serialize(self) -> str:
        """Serialize this line sub-message to a string."""
        return f'{self.status:03d}-{self.header}\r\n'


@dataclass(frozen=True, kw_only=True)
class Message(BaseMessage):
    """Utility class used to parse any received message."""

    #: List of sub-messages received within this message.
    items: Sequence[MessageLine | MessageData] = field(default_factory=list)

    @property
    def is_event(self) -> bool:
        """
        Tell whether this message is an event.

        This property is a simple helper to tell whether our status is 650.

        """
        return bool(self.status == 650)

    @property
    def keyword(self) -> str:
        """
        Extract the first word from the header.

        Note:
            An event always provide its keyword in the fist item.

        """
        if self.is_event and len(self.items) > 0:
            return self.items[0].keyword
        return super().keyword

    def serialize(self) -> str:
        """Serialize this message to a string."""
        text = ''
        for item in self.items:
            text += item.serialize()
        text += f'{self.status:03d} {self.header}\r\n'
        return text


async def messages_from_stream(stream: StreamReader) -> AsyncIterator[Message]:
    """
    Parse messages from the underlying stream.

    Args:
        stream: the asyncio stream reader to read messages from.

    Raises:
        ProtocolError: when we receive a malformed message.

    Yields:
        Messages as they are parsed

    """
    items = []  # type: list[MessageLine | MessageData]
    lines = []  # type: list[str]
    data = None  # type: MessageData | None

    while line_bytes := await stream.readline():
        line = line_bytes.decode('ascii')

        if line.endswith('\r\n'):  # pragma: no branch
            line = line[:-2]

        # Continuation of a data sub-message parser.
        if isinstance(data, MessageData):
            if line == '.':
                items.append(
                    MessageData(
                        status=data.status,
                        header=data.header,
                        data='\n'.join(lines),
                    )
                )
                lines.clear()
                data = None
            else:
                if line.startswith('.'):
                    line = line[1:]
                lines.append(line)
            continue

        # We expect a valid header, and require at least 4 characters.
        if len(line) < 4:
            msg = f"Received line is too short: '{line}'"
            raise ProtocolError(msg)

        # The first three characters form a decimal status code.
        try:
            status = int(line[0:3], 10)
        except ValueError:
            msg = f"Unable to parse status code on line '{line}'"
            raise ProtocolError(msg) from None

        separator = line[3]
        content = line[4:]

        match separator:
            case ' ':
                yield Message(status=status, header=content, items=[*items])
                items.clear()

            case '-':
                items.append(MessageLine(status=status, header=content))

            case '+':
                data = MessageData(status=status, header=content)

            case _:
                msg = "Unrecognized separator on line '{line}'"
                raise ProtocolError(msg)
