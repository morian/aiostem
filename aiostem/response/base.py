# -*- coding: utf-8 -*-

from aiostem.question import Query
from aiostem.message import Message


class BaseResponse:
    """ Base class used by all response messages.
    """

    def __init__(self, message: Message) -> None:
        self._message = message
        self._message_parse(message)

    def _message_parse(self, message: Message) -> None:
        """ Parse the received message and build this response according to the type.
        """
        self._status = message.status

    @property
    def status(self) -> int:
        """ Status code of the received response.
        """
        return self._status

    @property
    def message(self) -> Message:
        """ Get the raw message received from the control socket.
        """
        return self._message
# End of class BaseResponse.


class Reply(BaseResponse):
    """ Anything received in response to a request.
    """

    def __init__(self, query: Query, message: Message) -> None:
        super().__init__(message)
        self._query = query

    @property
    def query(self) -> Query:
        """ This is the original query related to this reply.
        """
        return self._query
# End of class Reply.


class Event(BaseResponse):
    """ Base class for any kind of event received asynchronously.
    """
    pass
# End of class Event.
