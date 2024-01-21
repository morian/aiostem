from __future__ import annotations

from typing import Any, ClassVar

from stem.descriptor.hidden_service import (
    BaseHiddenServiceDescriptor,
    HiddenServiceDescriptorV2,
    HiddenServiceDescriptorV3,
)

from ..exception import MessageError, ProtocolError
from ..message import Message, MessageData, MessageLineParser
from ..reply.base import Event
from ..util import hs_address_version

_DESCRIPTOR_CLASS_MAP: dict[int, type[BaseHiddenServiceDescriptor]] = {
    2: HiddenServiceDescriptorV2,
    3: HiddenServiceDescriptorV3,
}


class HsDescEvent(Event):
    """We have a new Hidden Service descriptor event."""

    EVENT_NAME: ClassVar[str] = 'HS_DESC'

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Initialize a hidden service descriptor event."""
        self._action = ''  # type: str
        self._address = ''  # type: str
        self._auth_type = ''  # type: str
        self._directory = ''  # type: str
        self._reason = None  # type: str | None
        self._descriptor_id = None  # type: str | None
        self._index = None  # type: str | None
        self._replica = None  # type: int | None
        super().__init__(*args, **kwargs)

    def __repr__(self) -> str:
        """Get the representation of this event."""
        return "<{} address='{}' directory='{}' action='{}'>".format(
            type(self).__name__,
            self.address,
            self.directory,
            self.action,
        )

    def _message_parse(self, message: Message) -> None:
        """Parse the provided message to build our event."""
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
        """Get the type of event we received.

        REQUESTED, FAILED, UPLOAD, RECEIVED, UPLOADED, IGNORE, CREATED
        """
        return self._action

    @property
    def address(self) -> str:
        """Get the onion domain address or UNKNOWN."""
        return self._address

    @property
    def auth_type(self) -> str:
        """Get the type of authentication with the hidden service."""
        return self._auth_type

    @property
    def descriptor_id(self) -> str | None:
        """Get the descriptor ID."""
        return self._descriptor_id

    @property
    def directory(self) -> str:
        """Get the Hidden service directory or 'UNKNOWN'."""
        return self._directory

    @property
    def index(self) -> str | None:
        """Get the directory index, if any."""
        return self._index

    @property
    def reason(self) -> str | None:
        """Get the reason why this descriptor failed."""
        return self._reason

    @property
    def replica(self) -> int | None:
        """Get the replica number of the generated descriptor."""
        return self._replica


class HsDescContentEvent(Event):
    """We have a new Hidden Service descriptor content."""

    EVENT_NAME: ClassVar[str] = 'HS_DESC_CONTENT'

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Initialize a hidden service descriptor content event."""
        self._address = ''  # type: str
        self._descriptor = None  # type: BaseHiddenServiceDescriptor | None
        self._descriptor_id = ''  # type: str
        self._descriptor_raw = ''  # type: str
        self._directory = ''  # type: str
        super().__init__(*args, **kwargs)

    def __repr__(self) -> str:
        """Get the representation of this event."""
        return "<{} address='{}' directory='{}' descid='{}'>".format(
            type(self).__name__,
            self.address,
            self.directory,
            self.descriptor_id,
        )

    def _message_parse(self, message: Message) -> None:
        """Parse the provided message to build our event."""
        super()._message_parse(message)

        if len(message.items) == 0:
            raise ProtocolError('Event HS_DESC_CONTENT contains nothing.')

        item = message.items[0]
        if not isinstance(item, MessageData):
            raise ProtocolError('Event HS_DESC_CONTENT contains no data.')

        parser = MessageLineParser(item.header)
        parser.pop_arg_checked(self.EVENT_NAME)

        self._address = parser.pop_arg()
        self._descriptor_id = parser.pop_arg()
        self._descriptor_raw = '\n'.join(item.lines)
        self._directory = parser.pop_arg()

    @property
    def address(self) -> str:
        """Get the hidden Service address related to this event."""
        return self._address

    @property
    def descriptor(self) -> BaseHiddenServiceDescriptor:
        """Get either a V2 or V3 hidden service descriptor."""
        if self._descriptor is None:
            version = hs_address_version(self.address)
            self._descriptor = _DESCRIPTOR_CLASS_MAP[version](self.descriptor_raw)
        return self._descriptor

    @property
    def descriptor_id(self) -> str:
        """Get the descriptor ID."""
        return self._descriptor_id

    @property
    def descriptor_raw(self) -> str:
        """Get the raw content of the received descriptor."""
        return self._descriptor_raw

    @property
    def directory(self) -> str:
        """Get the hidden service directory name providing this descriptor."""
        return self._directory
