import hashlib
import hmac
from typing import cast

from aiostem.exception import ProtocolError
from aiostem.message import Message, MessageLineParser
from aiostem.query import AuthChallengeQuery

from .base import Reply
from .simple import SimpleReply


class AuthenticateReply(SimpleReply):
    """Reply to the authentication query."""


class AuthChallengeReply(Reply):
    """Reply to a Authentication challenge query."""

    CLIENT_HASH_CONSTANT: bytes = b'Tor safe cookie authentication controller-to-server hash'
    SERVER_HASH_CONSTANT: bytes = b'Tor safe cookie authentication server-to-controller hash'

    def __init__(self, query: AuthChallengeQuery, message: Message) -> None:
        """Initialize a new authentication challenge response."""
        self._server_hash = b''
        self._server_nonce = b''
        super().__init__(query, message)

    def _message_parse(self, message: Message) -> None:
        """Parse the provided message."""
        super()._message_parse(message)

        parser = MessageLineParser(message.status_line)
        parser.pop_arg_checked('AUTHCHALLENGE')

        server_hash = parser.pop_kwarg_checked('SERVERHASH')
        server_nonce = parser.pop_kwarg_checked('SERVERNONCE')

        self._server_hash = bytes.fromhex(server_hash)
        self._server_nonce = bytes.fromhex(server_nonce)

    @property
    def query(self) -> AuthChallengeQuery:
        """Our query is a AuthChallengeQuery."""
        return cast(AuthChallengeQuery, super().query)

    @property
    def server_hash(self) -> bytes:
        """Get the server hash field from the response."""
        return self._server_hash

    @property
    def server_nonce(self) -> bytes:
        """Get the server nonce field from the response."""
        return self._server_nonce

    def raise_for_server_hash_error(self, cookie: bytes) -> None:
        """Check that the server hash is consistent with what we compute."""
        computed = self.server_token_build(cookie)
        if computed != self.server_hash:
            raise ProtocolError('Tor provided the wrong server nonce.')

    def server_token_build(self, cookie: bytes) -> bytes:
        """Build a token suitable for server hash check from the client."""
        key = self.SERVER_HASH_CONSTANT
        msg = cookie + self.query.nonce + self.server_nonce
        return hmac.new(key, msg, hashlib.sha256).digest()

    def client_token_build(self, cookie: bytes) -> bytes:
        """Build a token suitable for authentication from the client."""
        key = self.CLIENT_HASH_CONSTANT
        msg = cookie + self.query.nonce + self.server_nonce
        return hmac.new(key, msg, hashlib.sha256).digest()
