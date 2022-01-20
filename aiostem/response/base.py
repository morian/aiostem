from __future__ import annotations

from typing import Dict

from aiostem.exception import MessageError, ResponseError
from aiostem.message import Message, MessageLine
from aiostem.question import Query


class BaseResponse:
    """Base class used by all response messages."""

    def __init__(self, message: Message) -> None:
        """Create a base builder for any kind of response."""
        self._message = message
        self._message_parse(message)

    @staticmethod
    def _keyword_parse(parser: MessageLine) -> Dict[str, str]:
        """Parse keyword arguments from the provided MessageLine.

        This first try to parse as quoted, otherwise as non-quoted.
        """
        keywords = {}

        while not parser.at_end:
            try:
                key, value = parser.pop_kwarg(quoted=True)
                keywords[key] = value
            except MessageError:
                key, value = parser.pop_kwarg(quoted=False)
                keywords[key] = value
        return keywords

    def _message_parse(self, message: Message) -> None:
        """Parse the received message and build this response according to the type."""
        self._status = message.status

    @property
    def status(self) -> int:
        """Get the status code of the received response."""
        return self._status

    @property
    def message(self) -> Message:
        """Get the raw message received from the control socket."""
        return self._message


class Reply(BaseResponse):
    """Anything received in response to a request."""

    def __init__(self, query: Query, message: Message) -> None:
        """Build a response that is a reply to a query we sent."""
        super().__init__(message)
        self._query = query

    @property
    def query(self) -> Query:
        """Get the the original query related to this reply."""
        return self._query

    def _message_parse(self, message: Message) -> None:
        """Parse message but raise for bad status in reply."""
        super()._message_parse(message)
        self.raise_for_status()

    def raise_for_status(self) -> None:
        """Raise a reponse error when the status instructs us to."""
        if self.status >= 400:
            raise ResponseError(self.status, self.message.endline)


class UnknownReply(Reply):
    """A reply with no specific class."""

    pass


class Event(BaseResponse):
    """Base class for any kind of event received asynchronously."""

    EVENT_NAME: str = 'UNKNOWN'


class UnknownEvent(Event):
    """Any kind of event that we could not handle."""

    pass
