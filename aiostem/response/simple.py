# -*- coding: utf-8 -*-

from aiostem.response.base import Reply
from aiostem.message import Message


class SimpleReply(Reply):
    """ Base class for simple replies (a single line).
    """

    def __init__(self, *args, **kwargs) -> None:
        self._status_text = ''    # type: str
        super().__init__(*args, **kwargs)

    def __repr__(self) -> str:
        """ Representation of this reply.
        """
        return "<{} status='{}' text='{}'>" \
               .format(type(self).__name__, self.status, self.status_text)

    def _message_parse(self, message: Message) -> None:
        """ Parse the whole message.
        """
        super()._message_parse(message)
        self._status_text = message.endline

    @property
    def status_text(self) -> str:
        """ Text version of the `status` code.
        """
        return self._status_text
# End of class SimpleReply.


class QuitReply(SimpleReply):
    """ A reply parser for the QUIT command.
    """
# End of class QuitReply.


class SignalReply(SimpleReply):
    """ A reply parser for the SIGNAL command.
    """
# End of class SignalReply.


class HsFetchReply(SimpleReply):
    """ A reply parser for the HSFETCH command.
    """
# End of class HsFetchReply.


class SetEventsReply(SimpleReply):
    """ A reply parser for the SETEVENTS command.
    """
# End of class SetEventsReply.
