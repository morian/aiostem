# -*- coding: utf-8 -*-

from aiostem.message import Message


class Response:
    """ Base class used by all response messages.
    """

    def __init__(self, message: Message) -> None:
        self._raw_message = message

    @property
    def raw_message(self) -> Message:
        """ Get the raw message received from the control socket.
        """
        return self._raw_message
# End of class Response.


class ResponseEvent(Response):
    """ Base class used by all response events.
    """
    pass
# End of class ResponseEvent.
