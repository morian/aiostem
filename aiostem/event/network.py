from __future__ import annotations

from typing import Any, ClassVar

from aiostem.message import Message, MessageLineParser
from aiostem.response.base import Event


class DisconnectEvent(Event):
    """Disconnect notification from the controller.

    This pseudo-event is generated from the controller when an
    EOF is encountered while reading on the control socket.
    """

    EVENT_NAME: ClassVar[str] = 'DISCONNECT'


class NetworkLivenessEvent(Event):
    """Notification of network liveness change."""

    EVENT_NAME: ClassVar[str] = 'NETWORK_LIVENESS'

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Initialize a network status event."""
        self._network_status = ''  # type: str
        super().__init__(*args, **kwargs)

    def _message_parse(self, message: Message) -> None:
        """Parse this event message."""
        super()._message_parse(message)

        parser = MessageLineParser(message.status_line)
        parser.pop_arg_checked(self.EVENT_NAME)
        self._network_status = parser.pop_arg()

    @property
    def network_status(self) -> str:
        """Return the network status received with this event."""
        return self._network_status

    @property
    def is_connected(self) -> bool:
        """Tell whether this event tells that the network is UP."""
        return bool(self.network_status == 'UP')
