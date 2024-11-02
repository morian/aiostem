from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar

from stem.descriptor.hidden_service import (
    BaseHiddenServiceDescriptor,
    HiddenServiceDescriptorV2,
    HiddenServiceDescriptorV3,
)

from ..exceptions import MessageError, ProtocolError
from ..message import Message, MessageData, MessageLineParser
from ..reply.base import Event
from ..utils import hs_address_version

if TYPE_CHECKING:
    from collections.abc import Mapping


_DESCRIPTOR_CLASS_MAP: Mapping[int, type[BaseHiddenServiceDescriptor]] = {
    2: HiddenServiceDescriptorV2,
    3: HiddenServiceDescriptorV3,
}


class HsDescEvent(Event):
    """
    Parser for a hidden service descriptor event.

    This is used within Tor to track the different steps of everything related
    to a hidden service descriptor (request, creation, etc...).
    """

    EVENT_NAME: ClassVar[str] = 'HS_DESC'

    def __init__(self, message: Message) -> None:
        """
        Create an event parser from a received hidden service descriptor event message.

        See Also:
            https://spec.torproject.org/control-spec/replies.html#HS_DESC

        Args:
            message: the event message we just received.

        """
        self._action = ''  # type: str
        self._address = ''  # type: str
        self._auth_type = ''  # type: str
        self._directory = ''  # type: str
        self._reason = None  # type: str | None
        self._descriptor_id = None  # type: str | None
        self._index = None  # type: str | None
        self._replica = None  # type: int | None
        super().__init__(message)

    def __repr__(self) -> str:
        """Get the representation of this event."""
        return "<{} address='{}' directory='{}' action='{}'>".format(  # noqa: UP032
            type(self).__name__,
            self.address,
            self.directory,
            self.action,
        )

    def _message_parse(self, message: Message) -> None:
        """
        Parse this event message.

        Args:
            message: the event message we just received.

        """
        super()._message_parse(message)

        parser = MessageLineParser(message.status_line)
        parser.pop_arg_checked(self.EVENT_NAME)

        self._action = parser.pop_arg()
        self._address = parser.pop_arg()
        self._auth_type = parser.pop_arg()
        self._directory = parser.pop_arg()
        keywords = {}

        if not parser.at_end:
            # Maybe this is a keyword, or a descriptor id.
            try:
                key, val = parser.pop_kwarg()
                keywords[key] = val
            except MessageError:
                self._descriptor_id = parser.pop_arg()

        # Parse the remaining keyword arguments.
        while not parser.at_end:
            key, val = parser.pop_kwarg()
            keywords[key] = val

        def reason_set(val: str) -> None:
            self._reason = val

        def replica_set(val: str) -> None:
            self._replica = int(val)

        def index_set(val: str) -> None:
            self._index = val

        keyword_fn = {
            'REASON': reason_set,
            'REPLICA': replica_set,
            'HSDIR_INDEX': index_set,
        }

        for key, val in keywords.items():
            handler = keyword_fn.get(key)
            if handler is not None:
                handler(val)

    @property
    def action(self) -> str:
        """
        Get the type of event we received.

        This value can be one of the following:
        `REQUESTED`, `FAILED`, `UPLOAD`, `RECEIVED`, `UPLOADED`, `IGNORE`, `CREATED`
        """
        return self._action

    @property
    def address(self) -> str:
        """Get the onion domain address or `UNKNOWN`."""
        return self._address

    @property
    def auth_type(self) -> str:
        """Get the type of authentication with the hidden service."""
        return self._auth_type

    @property
    def descriptor_id(self) -> str | None:
        """Get the descriptor ID, if any."""
        return self._descriptor_id

    @property
    def directory(self) -> str:
        """Get the Hidden service directory or `UNKNOWN`."""
        return self._directory

    @property
    def index(self) -> str | None:
        """Get the directory index, if any."""
        return self._index

    @property
    def reason(self) -> str | None:
        """Get the reason why this descriptor failed if applicable."""
        return self._reason

    @property
    def replica(self) -> int | None:
        """Get the replica number of the generated descriptor if available."""
        return self._replica


class HsDescContentEvent(Event):
    """
    Parser for a hidden service descriptor content event.

    These events are triggered when a hidden service descriptor request succeeded.

    """

    EVENT_NAME: ClassVar[str] = 'HS_DESC_CONTENT'

    def __init__(self, message: Message) -> None:
        """
        Create an event parser from a received hidden service descriptor content event message.

        See Also:
            https://spec.torproject.org/control-spec/replies.html#HS_DESC_CONTENT

        Args:
            message: the event message we just received.

        """
        self._address = ''  # type: str
        self._descriptor = None  # type: BaseHiddenServiceDescriptor | None
        self._descriptor_id = ''  # type: str
        self._descriptor_raw = ''  # type: str
        self._directory = ''  # type: str
        super().__init__(message)

    def __repr__(self) -> str:
        """Get the representation of this event."""
        return "<{} address='{}' directory='{}' descid='{}'>".format(  # noqa: UP032
            type(self).__name__,
            self.address,
            self.directory,
            self.descriptor_id,
        )

    def _message_parse(self, message: Message) -> None:
        """
        Parse this event message.

        Args:
            message: the event message we just received.

        """
        super()._message_parse(message)

        if len(message.items) == 0:
            msg = 'Event HS_DESC_CONTENT contains nothing.'
            raise ProtocolError(msg)

        item = message.items[0]
        if not isinstance(item, MessageData):
            msg = 'Event HS_DESC_CONTENT contains no data.'
            raise ProtocolError(msg)

        parser = MessageLineParser(item.header)
        parser.pop_arg_checked(self.EVENT_NAME)

        self._address = parser.pop_arg()
        self._descriptor_id = parser.pop_arg()
        self._descriptor_raw = '\n'.join(item.lines)
        self._directory = parser.pop_arg()

    @property
    def address(self) -> str:
        """Get the hidden service address related to this event."""
        return self._address

    @property
    def descriptor(self) -> BaseHiddenServiceDescriptor:
        """
        Get either a V2 or V3 hidden service descriptor.

        Returns:
            One of the stem HiddenService descriptor class.

        """
        if self._descriptor is None:
            version = hs_address_version(self.address)
            self._descriptor = _DESCRIPTOR_CLASS_MAP[version](self.descriptor_raw)
        return self._descriptor

    @property
    def descriptor_id(self) -> str:
        """Get the descriptor identifier."""
        return self._descriptor_id

    @property
    def descriptor_raw(self) -> str:
        """
        Get the text content of the received descriptor.

        This can be handy if you plan on parsing it by yourself.

        """
        return self._descriptor_raw

    @property
    def directory(self) -> str:
        """Get the hidden service directory name providing this descriptor."""
        return self._directory
