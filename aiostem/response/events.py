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
        """ Handle parsing on the signal event.
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


class NetworkLivenessEvent(Event):
    """ Notification of network liveness change.
    """

    EVENT_NAME: str = 'NETWORK_LIVENESS'

    def _message_parse(self, message: Message) -> None:
        """ Parse this event message.
        """
        super()._message_parse(message)

        parser = MessageLine(message.endline)
        parser.pop_arg_checked(self.EVENT_NAME)
        self._network_status = parser.pop_arg().value

    @property
    def network_status(self) -> str:
        """ Returns the network status received with this event.
        """
        return self._network_status

    @property
    def is_connected(self) -> bool:
        """ Whether this event tells that the network is UP.
        """
        return bool(self.network_status == 'UP')
# End of class NetworkLivenessEvent.


class UnknownEvent(Event):
    """ Any kind of event that we could not handle.
    """
# End of class UnknownEvent.


class SetEventsReply(SimpleReply):
    """ A reply parser for the SETEVENTS command.
    """
# End of class SetEventsReply.
