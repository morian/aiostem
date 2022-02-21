import re
from typing import Optional

from .exception import MessageError, ProtocolError


class MessageLineParser:
    """Helper used to parse arguments on a message line."""

    REGEX_SINGLE_N = re.compile(r'^([^\s]+)')
    REGEX_SINGLE_Q = re.compile(r'^"((?:\\[\\"]|[^"])+)"')
    REGEX_KEYWORD_N = re.compile(r'^([^\s=]+)=([^\s]*)')
    REGEX_KEYWORD_Q = re.compile(r'^([^\s=]+)="((?:\\[\\"]|[^"])*)"')

    def __init__(self, line: str) -> None:
        """Initialize and handle a single line from the control socket."""
        self._raw_line = line
        self._cur_line = line

    def __str__(self) -> str:
        """Just return the raw line."""
        return self._raw_line

    @property
    def at_end(self) -> bool:
        """Whether we are done parsing this line."""
        return bool(not self._cur_line)

    def pop_arg(self, quoted: bool = False) -> str:
        """Parse the next argument as a single argument (returns the content)."""
        pattern = self.REGEX_SINGLE_Q if quoted else self.REGEX_SINGLE_N
        match = pattern.match(self._cur_line)
        if match is None:
            raise MessageError('No matching argument in provided line.')

        self._cur_line = self._cur_line[match.end(0) :].lstrip()
        text = match.group(1)
        if quoted:
            text = re.sub(r'\\([\\"])', r'\1', text)
        return text

    def pop_arg_checked(self, name: str, quoted: bool = False) -> str:
        """Parse the next argument and check that the returned value is `name`.

        Raises an error when the next argument is not what was expected.
        """
        value = self.pop_arg(quoted)
        if value != name:
            raise MessageError("expected argument '{}', got '{}'.".format(name, value))
        return value

    def pop_kwarg(self, quoted: bool = False) -> tuple[str, str]:
        """Parse the next argument as a keyword argument.

        This returns a tuple with keyword and value.
        """
        pattern = self.REGEX_KEYWORD_Q if quoted else self.REGEX_KEYWORD_N
        match = pattern.match(self._cur_line)
        if match is None:
            raise MessageError('No matching keyword argument in provided line.')
        self._cur_line = self._cur_line[match.end(0) :].lstrip()

        keyword = match.group(1)
        value = match.group(2)
        if quoted:
            value = re.sub(r'\\([\\"])', r'\1', value)
        return (keyword, value)

    def pop_kwarg_checked(self, name: str, quoted: bool = False) -> str:
        """Get the next keyword argument and ensures that `keyword` is `name`."""
        keyword, value = self.pop_kwarg(quoted)
        if keyword != name:
            raise MessageError("expected argument '{}', got '{}'.".format(name, keyword))
        return value

    def reset(self) -> None:
        """Reset the parser to its initial state."""
        self._cur_line = self._raw_line


class MessageData:
    """Class for keeping track of data messages."""

    __slots__ = ('header', 'lines')

    def __init__(self, header: str):
        """Create a new message data."""
        self.header = header
        self.lines = []  # type: list[str]


class Message:
    """Store any kind of message received by the controller."""

    def __init__(self) -> None:
        """Initialize a new empty message."""
        self._parsing_data = None  # type: Optional[MessageData]
        self._parsing_done = False

        self._data_items = []  # type: list[MessageData]
        self._event_type = None  # type: Optional[str]
        self._status_code = 0
        self._status_line = ''

    def _event_type_set(self) -> None:
        """Find the event type of the current event."""
        if len(self.items) > 0:
            line = self.items[0].header
        else:
            line = self.status_line

        self._event_type = MessageLineParser(line).pop_arg()

    @property
    def parsed(self) -> bool:
        """Return True when this message is fully parsed.

        This marks the end of a message and the start of another one from the
        controller's point of view (message is then forwarded appropriately).
        """
        return self._parsing_done

    @property
    def event_type(self) -> Optional[str]:
        """Event type (when this message is an event)."""
        return self._event_type

    @property
    def is_event(self) -> bool:
        """Whether this message is an asynchronous event."""
        return bool(self.status_code == 650)

    @property
    def items(self) -> list[MessageData]:
        """Get the ordered list of items in this message."""
        return self._data_items

    @property
    def status_code(self) -> int:
        """Status code of this message."""
        return self._status_code

    @property
    def status_line(self) -> str:
        """Get the raw text content of the end line."""
        return self._status_line

    def add_line(self, line: str) -> None:
        """Add a new line from the controller."""
        if self.parsed:
            raise MessageError('Cannot append an already parsed message.')

        if line.endswith('\r\n'):
            line = line[:-2]

        if isinstance(self._parsing_data, MessageData):
            # This indicates the end of the data part of this message.
            if line == '.':
                self._data_items.append(self._parsing_data)
                self._parsing_data = None
            else:
                # Ignore the leading dot (this is an escape mechanism).
                if line.startswith('.'):
                    line = line[1:]
                self._parsing_data.lines.append(line)
        else:
            if len(line) < 4:
                raise ProtocolError("Received line is too short: '{}'!".format(line))

            code = line[0:3]
            kind = line[3:4]
            data = line[4:]

            if kind == ' ':
                self._status_code = int(code)
                self._status_line = data
                self._parsing_done = True
                if self.is_event:
                    self._event_type_set()
            elif kind == '+':
                self._parsing_data = MessageData(data)
            elif kind == '-':
                self._data_items.append(MessageData(data))
            else:
                raise ProtocolError("Unable to parse line '{}'".format(line))
