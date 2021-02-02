# -*- coding: utf-8 -*-

from aiostem.message import Message, MessageLine
from aiostem.response.base import Event
from typing import Optional


class HsDescEvent(Event):
    """ We have a new Hidden Service descriptor event.
    """

    EVENT_NAME: str = 'HS_DESC'

    def __init__(self, *args, **kwargs) -> None:
        self._action = ''            # type: str
        self._address = ''           # type: str
        self._auth_type = ''         # type: str
        self._directory = ''         # type: str
        self._reason = None          # type: Optional[str]
        self._descriptor_id = None   # type: Optional[str]
        self._index = None           # type: Optional[str]
        self._replica = None         # type: Optional[int]
        super().__init__(*args, **kwargs)

    def __repr__(self) -> str:
        """ Representation of this event.
        """
        return "<{} address='{}' directory='{}' action='{}'>" \
               .format(type(self).__name__, self.address, self.directory, self.action)

    def _message_parse(self, message: Message) -> None:
        """ Parse this event message.
        """
        super()._message_parse(message)

        parser = MessageLine(message.endline)
        parser.pop_arg_checked(self.EVENT_NAME)

        self._action = parser.pop_arg()
        self._address = parser.pop_arg()
        self._auth_type = parser.pop_arg()
        self._directory = parser.pop_arg()

        if not parser.at_end:
            self._descriptor_id = parser.pop_arg()

        def reason_set(val):
            self._reason = val

        def replica_set(val):
            self._replica = int(val)

        def index_set(val):
            self._index = val

        keyword_fn = {
            'REASON':      reason_set,
            'REPLICA':     replica_set,
            'HSDIR_INDEX': index_set,
        }

        while not parser.at_end:
            key, val = parser.pop_kwarg()
            handler = keyword_fn.get(key)
            if handler is not None:
                handler(val)

    @property
    def action(self) -> str:
        """ Type of event received
            REQUESTED, FAILED, UPLOAD, RECEIVED, UPLOADED,IGNORE, CREATED
        """
        return self._action

    @property
    def address(self) -> str:
        """ Onion domain address (or UNKNOWN)
        """
        return self._address

    @property
    def auth_type(self) -> str:
        """ Type of authentication with the HS.
        """
        return self._auth_type

    @property
    def directory(self) -> str:
        """ Hidden service directory (or 'UNKNOWN')
        """
        return self._directory

    @property
    def index(self) -> Optional[str]:
        """ Directory index (if any).
        """
        return self._index

    @property
    def reason(self) -> Optional[str]:
        """ Reason why this descriptor failed.
        """
        return self._reason

    @property
    def replica(self) -> Optional[int]:
        """ Replica number of the generated descriptor.
        """
        return self._replica
# End of class HsDescEvent.


class HsDescContentEvent(Event):
    """ We have a new Hidden Service descriptor content.
    """

    EVENT_NAME: str = 'HS_DESC_CONTENT'

    def __init__(self, *args, **kwargs) -> None:
        self._address = ''              # type: str
        self._descriptor_id = ''        # type: str
        self._descriptor_raw = ''       # type: str
        self._directory = ''            # type: str
        super().__init__(*args, **kwargs)

    def __repr__(self) -> str:
        """ Representation of this event.
        """
        return "<{} address='{}' directory='{}' descid='{}'>" \
               .format(type(self).__name__, self.address, self.directory, self.descriptor_id)

    def _message_parse(self, message: Message) -> None:
        """ Parse this event message.
        """
        super()._message_parse(message)

        parser = MessageLine(message.dataline)
        parser.pop_arg_checked(self.EVENT_NAME)

        self._address = parser.pop_arg()
        self._descriptor_id = parser.pop_arg()
        self._descriptor_raw = message.data
        self._directory = parser.pop_arg()

    @property
    def address(self) -> str:
        """ Hidden Service address related to this event.
        """
        return self._address

    @property
    def descriptor_id(self) -> str:
        """ Descriptor ID
        """
        return self._descriptor_id

    @property
    def descriptor_raw(self) -> str:
        """ Raw content of the received descriptor.
        """
        return self._descriptor_raw

    @property
    def directory(self) -> str:
        """ Hidden service directory that provided this descriptor.
        """
        return self._directory
# End of class NetworkLivenessEvent.
