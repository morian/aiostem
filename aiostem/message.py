# -*- coding: utf-8 -*-

import re

from typing import List

from aiostem.argument import SingleArgument, KeywordArgument
from aiostem.exception import MessageError, ProtocolError


class MessageLine:
    """ Helper used to parse arguments on a message line.
    """

    REGEX_SINGLE_N  = re.compile(r'^([^\s]+)')
    REGEX_SINGLE_Q  = re.compile(r'^"((?:\\[\\"]|[^"])+)"')
    REGEX_KEYWORD_N = re.compile(r'^([^\s=]+)=([^\s]+)')
    REGEX_KEYWORD_Q = re.compile(r'^([^\s=]+)="((?:\\[\\"]|[^"])+)"')

    def __init__(self, line) -> None:
        self._raw_line = line
        self._cur_line = line

    def __str__(self) -> str:
        """ Just return the raw line.
        """
        return self._raw_line

    @property
    def at_end(self) -> bool:
        """ Whether we are done parsing this line.
        """
        return bool(self._cur_line)

    def pop_arg(self, quoted: bool = False) -> SingleArgument:
        """ Parse the next argument as a single argument.
        """
        pattern = self.REGEX_SINGLE_Q if quoted else self.REGEX_SINGLE_N
        match = pattern.match(self._cur_line)
        if match is None:
            raise MessageError("No matching argument in provided line.")

        self._cur_line = self._cur_line[match.end(0):].lstrip()
        text = match.group(1)
        if quoted:
            text = re.sub(r'\\([\\"])', r'\1', text)
        return SingleArgument(text, quoted)

    def pop_arg_checked(self, name: str, quoted: bool = False) -> KeywordArgument:
        """ Same as pop_arg() but also check that the returned value is `name`.
        """
        arg = self.pop_arg(quoted)
        if arg.value != name:
            raise MessageError("expected argument '{}', got '{}'.".format(name, arg.value))
        return arg

    def pop_kwarg(self, quoted: bool = False) -> KeywordArgument:
        """ Parse the next argument as a keyword argument.
        """
        pattern = self.REGEX_KEYWORD_Q if quoted else self.REGEX_KEYWORD_N
        match = pattern.match(self._cur_line)
        if match is None:
            raise MessageError("No matching keyword argument in provided line.")
        self._cur_line = self._cur_line[match.end(0):].lstrip()

        keyword = match.group(1)
        value = match.group(2)
        if quoted:
            value = re.sub(r'\\([\\"])', r'\1', value)
        return KeywordArgument(keyword, value, quoted)

    def pop_kwarg_checked(self, name: str, quoted: bool = False) -> KeywordArgument:
        """ Same as pop_kwarg() but also check that `keyword` is `name`.
        """
        arg = self.pop_kwarg(quoted)
        if arg.keyword != name:
            raise MessageError("expected argument '{}', got '{}'.".format(name, arg.keyword))
        return arg
# End of class MessageLine.


class Message:
    """ Store any kind of message received by the controller.
    """

    def __init__(self) -> None:
        self._parsed = False
        self._status = 0
        self._dataline = ''
        self._statline = ''
        self._midlines = []  # type: List[str]
        self._datlines = []  # type: List[str]
        self._indata = False

    @property
    def parsed(self) -> bool:
        """ True when this message is fully parsed.

            This marks the end of a message and the start of another one from the
            controller's point of view (message is then forwarded appropriately).
        """
        return self._parsed

    @property
    def data(self) -> str:
        """ Get the text content of the data payload.
        """
        return '\n'.join(self._datlines)

    @property
    def is_event(self) -> bool:
        """ Whether this message is an asynchronous event.
        """
        return bool(self.status == 650)

    @property
    def dataline(self) -> str:
        """ Get the full content of the data line
            This is the one preceding the full data text.
        """
        return self._dataline

    @property
    def midlines(self) -> List[str]:
        """ Get the list of middle lines.
        """
        return self._midlines

    @property
    def endline(self) -> str:
        """ Get the raw text content of the end line.
        """
        return self._statline

    @property
    def status(self) -> int:
        """ Status code of this message.
        """
        return self._status

    def add_line(self, line: str) -> None:
        """ Add a new line from the controller.
        """
        if self.parsed:
            raise MessageError("Cannot append an already parsed message.")

        if line.endswith('\r\n'):
            line = line[:-2]

        if self._indata:
            # This indicates the end of the data part of this message.
            if line == '.':
                self._indata = False
                return

            # Ignore the leading dot (escape mechanism).
            if line.startswith('.'):
                line = line[1:]
            self._datlines.append(line)
        else:
            if len(line) < 4:
                raise ProtocolError("Received line is too short: '{}'!".format(line))

            code = line[0:3]
            kind = line[3]
            data = line[4:]

            if kind == ' ':
                self._parsed = True
                self._status = int(code)
                self._statline = data
            elif kind == '+':
                self._dataline = data
                self._indata = True
            elif kind == '-':
                self._midlines.append(data)
            else:
                raise ProtocolError("Unable to parse line '{}'".format(line))
# End of class Message.
