from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from .exception import MessageError, ProtocolError

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence


class MessageLineParser:
    """
    Helper parser used to parse a single line containing multiple arguments.

    This class is not intended to be used by the end-user but is rather used internally
    as a helper by replies and events to ease with the parsing.
    """

    #: A single non-quoted positional argument.
    REGEX_SINGLE_N = re.compile(r'^([^\s]+)')

    #: A single quoted positional argument.
    REGEX_SINGLE_Q = re.compile(r'^"((?:\\[\\"]|[^"])+)"')

    #: A line-wide keyword argument.
    REGEX_KEYWORD_L = re.compile(r'^([^\s=]+)=(.*)$')

    #: A non-quoted keyword argument.
    REGEX_KEYWORD_N = re.compile(r'^([^\s=]+)=([^\s]*)')

    #: A quoted keyword argument.
    REGEX_KEYWORD_Q = re.compile(r'^([^\s=]+)="((?:\\[\\"]|[^"])*)"')

    def __init__(self, line: str) -> None:
        """
        Create a new parser for a single message line.

        Args:
            line: the line we want to parse

        """
        self._raw_line = line
        self._cur_line = line

    def __str__(self) -> str:
        """Get the raw line as it was provided."""
        return self._raw_line

    @property
    def at_end(self) -> bool:
        """Whether we are done parsing the line."""
        return bool(not self._cur_line)

    def pop_arg(self, quoted: bool = False) -> str:
        """
        Parse and return the next positional argument.

        Note:
            This method moves the internal cursor past the parsed argument.

        Args:
            quoted: whether we expect the next argument to be between quotes

        Returns:
            The content of the next positional argument.

        """
        pattern = self.REGEX_SINGLE_Q if quoted else self.REGEX_SINGLE_N
        match = pattern.match(self._cur_line)
        if match is None:
            msg = 'No matching argument in provided line.'
            raise MessageError(msg)

        self._cur_line = self._cur_line[match.end(0) :].lstrip()
        text = match.group(1)
        if quoted:
            text = re.sub(r'\\([\\"])', r'\1', text)
        return text

    def pop_arg_checked(self, expected: str, quoted: bool = False) -> str:
        """
        Parse and check the next positional argument.

        Note:
            This method moves the internal cursor past the parsed argument.

        Args:
            expected: the expected value of the next argument
            quoted: whether we expect the next argument to be between quotes

        Raises:
            MessageError: when the argument does not match `expected`.

        Returns:
            The content of the next positional argument.

        """
        value = self.pop_arg(quoted)
        if value != expected:
            msg = f"expected argument '{expected}', got '{value}'."
            raise MessageError(msg)
        return value

    def pop_kwarg(self, quoted: bool = False) -> tuple[str, str]:
        """
        Parse the next argument as a keyword argument.

        Args:
            quoted: whether we expect the value to be between quotes

        Returns:
            A tuple with both the key and the corresponding value.

        """
        pattern = self.REGEX_KEYWORD_Q if quoted else self.REGEX_KEYWORD_N
        match = pattern.match(self._cur_line)
        if match is None:
            msg = 'No matching keyword argument found in the provided line.'
            raise MessageError(msg)
        self._cur_line = self._cur_line[match.end(0) :].lstrip()

        keyword = match.group(1)
        value = match.group(2)
        if quoted:
            value = re.sub(r'\\([\\"])', r'\1', value)
        return (keyword, value)

    def pop_kwarg_line(self) -> tuple[str, str]:
        """
        Parse the next argument as a keyword argument regardless of spaces.

        This means that the whole line is considered as a keyword value.
        This kind of keyword argument cannot be quoted.

        Returns:
            A tuple with both the key and the corresponding value.

        """
        match = self.REGEX_KEYWORD_L.match(self._cur_line)
        if match is None:
            msg = 'No matching keyword argument found in the provided line.'
            raise MessageError(msg)
        self._cur_line = self._cur_line[match.end(0) :].lstrip()
        return (match.group(1), match.group(2))

    def pop_kwarg_checked(self, expected: str, quoted: bool = False) -> str:
        """
        Get the next keyword argument and check the key name.

        Args:
            expected: expected key name
            quoted: whether we expect the value to be between quotes

        Raises:
            MessageError: when the key does not match `expected`.

        Returns:
            A tuple with both the key and the corresponding value.

        """
        keyword, value = self.pop_kwarg(quoted)
        if keyword != expected:
            msg = f"expected key '{expected}', got '{keyword}'."
            raise MessageError(msg)
        return value

    def reset(self) -> None:
        """Reset the parser at the beginning of the line."""
        self._cur_line = self._raw_line


@dataclass(slots=True)
class MessageData:
    """Keep track of the data part of the message."""

    header: str
    lines: list[str] = field(default_factory=list)


class Message:
    """Store and parse any kind of message received on the control socket."""

    def __init__(self, lines: Iterable[str] | str | None = None) -> None:
        """
        Create a new message received from the control socket.

        Args:
            lines: initial line(s) received on the control socket

        """
        self._parsing_data = None  # type: MessageData | None
        self._parsing_done = False

        self._data_items = []  # type: list[MessageData]
        self._event_type = None  # type: str | None
        self._status_code = 0
        self._status_line = ''

        if lines is not None:
            if isinstance(lines, str):
                self.add_line(lines)
            else:
                self.add_lines(lines)

    def _event_type_set(self) -> None:
        """Find and store the event type out of the current event message."""
        line = self.items[0].header if len(self.items) > 0 else self.status_line
        self._event_type = MessageLineParser(line).pop_arg()

    @property
    def event_type(self) -> str | None:
        """Get the event type, is applicable."""
        return self._event_type

    @property
    def is_event(self) -> bool:
        """Tell whether this message is an event."""
        return bool(self.status_code == 650)

    @property
    def items(self) -> Sequence[MessageData]:
        """Get the ordered list of data items in this message."""
        return self._data_items

    @property
    def parsed(self) -> bool:
        """
        Tell whether the current message is fully parsed.

        This marks the end of a message and the start of another one from the
        controller's point of view (message is then forwarded appropriately).
        """
        return self._parsing_done

    @property
    def status_code(self) -> int:
        """Get the status code of this message."""
        return self._status_code

    @property
    def status_line(self) -> str:
        """Get the raw text status of this message."""
        return self._status_line

    def add_lines(self, lines: Iterable[str]) -> None:
        """
        Append multiple lines to this message.

        See Also:
            :meth:`add_line` for more details.

        Args:
            lines: a list of lines to append to this message.

        """
        for line in lines:
            self.add_line(line)

    def add_line(self, line: str) -> None:
        """
        Append a new raw line to this message.

        Raises:
            MessageError: when the current message is already parsed.
            ProtocolError: when the line is invalid

        Args:
            line: a line read by the controller to add to this message

        """
        if self.parsed:
            msg = 'Cannot append to an already parsed message.'
            raise MessageError(msg)

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
                msg = f"Received line is too short: '{line}'!"
                raise ProtocolError(msg)

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
                msg = f"Unable to parse line '{line}'"
                raise ProtocolError(msg)
