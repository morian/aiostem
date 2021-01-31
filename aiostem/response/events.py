# -*- coding: utf-8 -*-

from aiostem.response.base import Event
from aiostem.response.simple import SimpleReply
from aiostem.message import Message, MessageLine


class SignalEvent(Event):
    """ Parse signal events.
    """

    EVENT_NAME: str = 'SIGNAL'

    def __repr__(self) -> str:
        """ Representation of this Signal event.
        """
        return "<{} '{}'>".format(type(self).__name__, self.signal)

    def _message_parse(self, message: Message) -> None:
        """ Handle the signal event parsing.
        """
        super()._message_parse(message)

        parser = MessageLine(message.endline)
        parser.pop_arg_checked(self.EVENT_NAME)
        self._signal = parser.pop_arg().value

    @property
    def signal(self) -> str:
        """ Name of the signal received in this event.
        """
        return self._signal
# End of class SignalEvent.


class SetEventsReply(SimpleReply):
    """ A reply parser for the SETEVENTS command.
    """
# End of class SetEventsReply.
