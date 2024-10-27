from __future__ import annotations

from typing import ClassVar

from ..message import Message, MessageLineParser
from ..reply.base import Event


class DisconnectEvent(Event):
    """
    Disconnect notification from the controller.

    This pseudo-event is generated from the controller when an
    EOF is encountered while reading on the control socket.
    """

    EVENT_NAME: ClassVar[str] = 'DISCONNECT'


class NetworkLivenessEvent(Event):
    """Parser for a notification of change in tor's network liveness."""

    EVENT_NAME: ClassVar[str] = 'NETWORK_LIVENESS'

    def __init__(self, message: Message) -> None:
        """
        Create a network status event parser.

        See Also:
            https://spec.torproject.org/control-spec/replies.html#NETWORK_LIVENESS

        Args:
            message: the event message we just received.

        """
        self._network_status = ''  # type: str
        super().__init__(message)

    def _message_parse(self, message: Message) -> None:
        """
        Parse this event message.

        Args:
            message: the event message we just received.

        """
        super()._message_parse(message)

        parser = MessageLineParser(message.status_line)
        parser.pop_arg_checked(self.EVENT_NAME)
        self._network_status = parser.pop_arg()

    @property
    def network_status(self) -> str:
        """
        Get the network status received with this event.

        Returns:
            A textual representation of the current network status.

        """
        return self._network_status

    @property
    def is_connected(self) -> bool:
        """
        Tell whether this event tells that the network is `UP`.

        Returns:
            A boolean representation of the current network status.

        """
        return bool(self.network_status == 'UP')
