# -*- coding: utf-8 -*-

from aiostem.message import Message, MessageLine
from aiostem.response.base import Event

from typing import Dict


class BaseStatusEvent(Event):
    """ Parent class for all status events.
    """

    def __init__(self, *args, **kwargs) -> None:
        self._action = ''    # type: str
        self._severity = ''  # type: str
        super().__init__(*args, **kwargs)

    def _message_parse(self, message: Message) -> MessageLine:
        """ Parse this kind of event messages.
        """
        super()._message_parse(message)

        parser = MessageLine(message.endline)
        parser.pop_arg_checked(self.EVENT_NAME)

        self._severity = parser.pop_arg()
        self._action = parser.pop_arg()
        self._arguments = self._keyword_parse(parser)

    @property
    def action(self) -> str:
        """ Action string.
        """
        return self._action

    @property
    def arguments(self) -> Dict[str, str]:
        """ Get the list of keyword arguments (generic).
        """
        return self._arguments

    @property
    def severity(self) -> str:
        """ Message severity ('NOTICE', 'WARN', 'ERR').
        """
        return self._severity
# End of class BaseStatus.


class StatusGeneralEvent(BaseStatusEvent):
    """ General status event.
    """

    EVENT_NAME: str = 'STATUS_GENERAL'
# End of class StatusGeneralEvent.


class StatusClientEvent(BaseStatusEvent):
    """ Client status event.
    """

    EVENT_NAME: str = 'STATUS_CLIENT'
# End of class StatusClientEvent.


class StatusServerEvent(BaseStatusEvent):
    """ Server status event.
    """

    EVENT_NAME: str = 'STATUS_SERVER'
# End of class StatusServerEvent.
