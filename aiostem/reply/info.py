from __future__ import annotations

from typing import Any, ClassVar

import aiofiles

from ..message import Message, MessageLineParser
from .simple import SimpleReply


class BaseInfoReply(SimpleReply):
    """Parse replies for GETCONF/GETINFO."""

    WITH_STATUS_LINE: ClassVar[bool] = False

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Build a reply to a GetInfoQuery."""
        self._items = {}  # type: dict[str, str]
        super().__init__(*args, **kwargs)

    def _message_parse(self, message: Message) -> None:
        """Parse the provided message."""
        super()._message_parse(message)

        for item in message.items:
            parser = MessageLineParser(item.header)
            key, value = parser.pop_kwarg_line()
            if len(item.lines):
                value = '\n'.join(item.lines)
            self._items[key] = value

        if self.WITH_STATUS_LINE:
            parser = MessageLineParser(message.status_line)
            key, value = parser.pop_kwarg_line()
            self._items[key] = value

    @property
    def values(self) -> dict[str, str]:
        """Get the list of parsed items."""
        return self._items


class GetConfReply(BaseInfoReply):
    """Parse replies for GETCONF."""

    WITH_STATUS_LINE: ClassVar[bool] = True


class GetInfoReply(BaseInfoReply):
    """Parse replies for GETINFO."""

    WITH_STATUS_LINE: ClassVar[bool] = False


class ProtocolInfoReply(SimpleReply):
    """Parse a protocol info reply."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Build a reply to a ProtocolInfoQuery."""
        self._cookie_file = None  # type: str | None
        self._methods = ()  # type: tuple[str, ...]
        self._proto_version = 0  # type: int
        self._tor_version = ''  # type: str
        super().__init__(*args, **kwargs)

    def __repr__(self) -> str:
        """Reply from a ProtocolInfo Query."""
        return "<{} version='{}' methods='{}'>".format(
            type(self).__name__,
            self.proto_version,
            ','.join(self.methods),
        )

    def _message_resp_parse(self, parser: MessageLineParser) -> None:
        """Parse the PROTOCOLINFO mid-line."""
        self._proto_version = int(parser.pop_arg())

    def _message_auth_parse(self, parser: MessageLineParser) -> None:
        """Parse the AUTH mid-line."""
        methods = parser.pop_kwarg_checked('METHODS')
        self._methods = tuple(methods.split(','))

        if not parser.at_end:
            cookie = parser.pop_kwarg_checked('COOKIEFILE', quoted=True)
            self._cookie_file = cookie

    def _message_vers_parse(self, parser: MessageLineParser) -> None:
        """Parse the VERSION mid-line."""
        version = parser.pop_kwarg_checked('Tor', quoted=True)
        self._tor_version = version

    def _message_parse(self, message: Message) -> None:
        """Parse the provided message."""
        super()._message_parse(message)

        # Control spec says these line can come in any order...
        parser_fn = {
            'PROTOCOLINFO': self._message_resp_parse,
            'AUTH': self._message_auth_parse,
            'VERSION': self._message_vers_parse,
        }

        for item in message.items:
            parser = MessageLineParser(item.header)
            verb = parser.pop_arg()
            func = parser_fn.get(verb)
            if func:  # pragma: no branch
                func(parser)

    @property
    def cookie_file(self) -> str | None:
        """Get the path to the cookie file that can be used to authenticate."""
        return self._cookie_file

    @property
    def methods(self) -> tuple[str, ...]:
        """Get a list of allowed authentication methods."""
        return self._methods

    @property
    def proto_version(self) -> int:
        """Get the protocol version returned by Tor."""
        return self._proto_version

    @property
    def tor_version(self) -> str:
        """Get the version of the Tor daemon we are communicating with."""
        return self._tor_version

    async def cookie_file_read(self) -> bytes | None:
        """Read the content of the cookie file."""
        if self.cookie_file is not None:
            async with aiofiles.open(self.cookie_file, 'rb') as fp:
                return await fp.read()
        return None
