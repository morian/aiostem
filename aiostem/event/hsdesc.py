from typing import Dict, Optional, Type

from stem.descriptor.hidden_service import (
    BaseHiddenServiceDescriptor,
    HiddenServiceDescriptorV2,
    HiddenServiceDescriptorV3,
)

from aiostem.exception import MessageError
from aiostem.message import Message, MessageLine
from aiostem.response.base import Event
from aiostem.util import hs_address_version

_DESCRIPTOR_CLASS_MAP: Dict[int, Type[BaseHiddenServiceDescriptor]] = {
    2: HiddenServiceDescriptorV2,
    3: HiddenServiceDescriptorV3,
}


class HsDescEvent(Event):
    """We have a new Hidden Service descriptor event."""

    EVENT_NAME: str = 'HS_DESC'

    def __init__(self, *args, **kwargs) -> None:
        self._action = ''  # type: str
        self._address = ''  # type: str
        self._auth_type = ''  # type: str
        self._directory = ''  # type: str
        self._reason = None  # type: Optional[str]
        self._descriptor_id = None  # type: Optional[str]
        self._index = None  # type: Optional[str]
        self._replica = None  # type: Optional[int]
        super().__init__(*args, **kwargs)

    def __repr__(self) -> str:
        """Representation of this event."""
        return "<{} address='{}' directory='{}' action='{}'>".format(
            type(self).__name__, self.address, self.directory, self.action
        )

    def _message_parse(self, message: Message) -> None:
        """Parse this event message."""
        super()._message_parse(message)

        parser = MessageLine(message.endline)
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

        def reason_set(val):
            self._reason = val

        def replica_set(val):
            self._replica = int(val)

        def index_set(val):
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
        """Type of event received
        REQUESTED, FAILED, UPLOAD, RECEIVED, UPLOADED,IGNORE, CREATED
        """
        return self._action

    @property
    def address(self) -> str:
        """Onion domain address (or UNKNOWN)"""
        return self._address

    @property
    def auth_type(self) -> str:
        """Type of authentication with the HS."""
        return self._auth_type

    @property
    def descriptor_id(self) -> Optional[str]:
        """Descriptor ID"""
        return self._descriptor_id

    @property
    def directory(self) -> str:
        """Hidden service directory (or 'UNKNOWN')"""
        return self._directory

    @property
    def index(self) -> Optional[str]:
        """Directory index (if any)."""
        return self._index

    @property
    def reason(self) -> Optional[str]:
        """Reason why this descriptor failed."""
        return self._reason

    @property
    def replica(self) -> Optional[int]:
        """Replica number of the generated descriptor."""
        return self._replica


class HsDescContentEvent(Event):
    """We have a new Hidden Service descriptor content."""

    EVENT_NAME: str = 'HS_DESC_CONTENT'

    def __init__(self, *args, **kwargs) -> None:
        self._address = ''  # type: str
        self._descriptor = None  # type: Optional[BaseHiddenServiceDescriptor]
        self._descriptor_id = ''  # type: str
        self._descriptor_raw = ''  # type: str
        self._directory = ''  # type: str
        super().__init__(*args, **kwargs)

    def __repr__(self) -> str:
        """Representation of this event."""
        return "<{} address='{}' directory='{}' descid='{}'>".format(
            type(self).__name__, self.address, self.directory, self.descriptor_id
        )

    def _message_parse(self, message: Message) -> None:
        """Parse this event message."""
        super()._message_parse(message)

        parser = MessageLine(message.dataline)
        parser.pop_arg_checked(self.EVENT_NAME)

        self._address = parser.pop_arg()
        self._descriptor_id = parser.pop_arg()
        self._descriptor_raw = message.data
        self._directory = parser.pop_arg()

    @property
    def address(self) -> str:
        """Hidden Service address related to this event."""
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
        """Descriptor ID"""
        return self._descriptor_id

    @property
    def descriptor_raw(self) -> str:
        """Raw content of the received descriptor."""
        return self._descriptor_raw

    @property
    def directory(self) -> str:
        """Hidden service directory that provided this descriptor."""
        return self._directory
