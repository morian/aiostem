# -*- coding: utf-8 -*-

from aiostem.message import Message, MessageLine
from aiostem.response.base import Event


class HsDescContentEvent(Event):
    """ We have a new Hidden Service descriptor content.
    """

    EVENT_NAME: str = 'HS_DESC_CONTENT'

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

        self._address = parser.pop_arg().value
        self._descriptor_id = parser.pop_arg().value
        self._hs_dir = parser.pop_arg().value
        self._descriptor_raw = message.data

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
