# -*- coding: utf-8 -*-

import aiofiles

from aiostem.response.simple import SimpleReply
from aiostem.message import Message, MessageLine
from typing import Optional, Tuple


class ProtocolInfoReply(SimpleReply):
    """ Parse a protocol info reply.
    """

    def __init__(self, *args, **kwargs) -> None:
        self._cookie_file = None  # type: Optional[str]
        self._methods = ()        # type: Tuple[str, ...]
        self._proto_version = 0   # type: int
        self._tor_version = ''    # type: str
        super().__init__(*args, **kwargs)

    def __repr__(self) -> str:
        """ Reply from a ProtocolInfo Query.
        """
        return "<{} version='{}' methods='{}'>"  \
               .format(type(self).__name__, self.proto_version, ','.join(self.methods))

    def _message_resp_parse(self, parser: MessageLine) -> None:
        """ Parse the PROTOCOLINFO mid-line.
        """
        self._proto_version = parser.pop_arg()

    def _message_auth_parse(self, parser: MessageLine) -> None:
        """ Parse the AUTH mid-line.
        """
        methods = parser.pop_kwarg_checked('METHODS')
        self._methods = tuple(methods.value.split(','))

        if not parser.at_end:
            cookie = parser.pop_kwarg_checked('COOKIEFILE', quoted=True)
            self._cookie_file = cookie.value

    def _message_vers_parse(self, parser: MessageLine) -> None:
        """ Parse the VERSION mid-line.
        """
        version = parser.pop_kwarg_checked('Tor', quoted=True)
        self._tor_version = version.value

    def _message_parse(self, message: Message) -> None:
        """ Parse this whole message!
        """
        super()._message_parse(message)

        # Control spec says these line can come in any order...
        parser_fn = {
            'PROTOCOLINFO': self._message_resp_parse,
            'AUTH':         self._message_auth_parse,
            'VERSION':      self._message_vers_parse,
        }

        for parser in map(MessageLine, message.midlines):
            verb = parser.pop_arg().value
            func = parser_fn.get(verb)
            if func is not None:
                func(parser)

    @property
    def cookie_file(self) -> Optional[str]:
        """ Cookie file that can be used for authentication.
        """
        return self._cookie_file

    @property
    def methods(self) -> Tuple[str, ...]:
        """ List of authentication methods allowed.
        """
        return self._methods

    @property
    def proto_version(self) -> int:
        """ Protocol version returned by Tor.
        """
        return self._proto_version

    @property
    def tor_version(self) -> str:
        """ Version of the Tor daemon we are communicating with.
        """
        return self._tor_version

    async def cookie_file_read(self) -> bytes:
        """ Read the content of the cookie file.
        """
        async with aiofiles.open(self.cookie_file, 'rb') as fp:
            return await fp.read()
# End of class ProtocolInfoReply.
