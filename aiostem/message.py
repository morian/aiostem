# -*- coding: utf-8 -*-

from typing import List
from aiostem.exception import ProtocolError


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

    def add_line(self, line) -> None:
        """ Add a new line from the controller.
        """
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
                raise ProtocolError("Received line is too short!")

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
                raise ProtocolError("Received an invalid line '{}'".format(line))
# End of class Message.
