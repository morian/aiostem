# -*- coding: utf-8 -*-

from aiostem.message import Message, MessageLine
from aiostem.response.base import Event
from typing import Optional


class HsDescEvent(Event):
    """ We have a new Hidden Service descriptor event.
    """

    EVENT_NAME: str = 'HS_DESC'

    def __init__(self, *args, **kwargs) -> None:
        self._action = ''               # type: str
        self._address = ''              # type: str
        self._authentication_type = ''  # type: str
        self._hs_dir = ''               # type: str
        self._reason = None             # type: Optional[str]
        self._descriptor_id = None      # type: Optional[str]
        self._hs_dir_index = None       # type: Optional[str]
        self._replica = 0               # type: int
        super().__init__(*args, **kwargs)

    def __repr__(self) -> str:
        """ Representation of this event.
        """
        return "<{} address='{}' action='{}'>" \
               .format(type(self).__name__, self.address, self.action)

    def _message_parse(self, message: Message) -> None:
        """ Parse this event message.
        """
        super()._message_parse(message)

        parser = MessageLine(message.endline)
        parser.pop_arg_checked(self.EVENT_NAME)

        self._action = parser.pop_arg()
        self._address = parser.pop_arg()
        self._authentication_type = parser.pop_arg()
        self._hs_dir = parser.pop_arg()

        # To be continued with optional stuff...

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
    def authentication_type(self) -> str:
        """ Type of authentication with the HS.
        """
        return self._authentication_type

    @property
    def hs_dir(self) -> str:
        """ Hidden service directory (or UNKNOWN)
        """
        return self._hs_dir
# End of class HsDescEvent.


class HsDescContentEvent(Event):
    """ We have a new Hidden Service descriptor content.
    """

    EVENT_NAME: str = 'HS_DESC_CONTENT'

    def __init__(self, *args, **kwargs) -> None:
        self._address = ''              # type: str
        self._descriptor_id = ''        # type: str
        self._descriptor_raw = ''       # type: str
        self._hs_dir = ''               # type: str
        super().__init__(*args, **kwargs)

    def __repr__(self) -> str:
        """ Representation of this event.
        """
        return "<{} address='{}' descid='{}'>" \
               .format(type(self).__name__, self.address, self.descriptor_id)

    def _message_parse(self, message: Message) -> None:
        """ Parse this event message.
        """
        super()._message_parse(message)

        parser = MessageLine(message.dataline)
        parser.pop_arg_checked(self.EVENT_NAME)

        self._address = parser.pop_arg()
        self._descriptor_id = parser.pop_arg()
        self._descriptor_raw = message.data
        self._hs_dir = parser.pop_arg()

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
    def hs_dir(self) -> str:
        """ Hidden service directory that provided this descriptor.
        """
        return self._hs_dir
# End of class NetworkLivenessEvent.
