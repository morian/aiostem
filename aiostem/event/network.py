# -*- coding: utf-8 -*-

from aiostem.message import Message, MessageLine
from aiostem.response.base import Event


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
