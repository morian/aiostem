# -*- coding: utf-8 -*-

import hashlib
import hmac

from aiostem.exception import ResponseError
from aiostem.response.base import Reply
from aiostem.response.simple import SimpleReply
from aiostem.message import Message, MessageLine


class AuthenticateReply(SimpleReply):
    """ Reply to the authentication query.
    """
# End of class AuthenticateReply.


class AuthChallengeReply(Reply):
    """ Reply to a Authentication challenge query.
    """

    CLIENT_HASH_CONSTANT = b'Tor safe cookie authentication controller-to-server hash'
    SERVER_HASH_CONSTANT = b'Tor safe cookie authentication server-to-controller hash'

    def __init__(self, *args, **kwargs) -> None:
        self._server_hash = bytes()
        self._server_nonce = bytes()
        super().__init__(*args, **kwargs)

    def _message_parse(self, message: Message) -> None:
        """ Parse this whole message!
        """
        super()._message_parse(message)

        parser = MessageLine(message.endline)
        parser.pop_arg_checked('AUTHCHALLENGE')

        server_hash = parser.pop_kwarg_checked('SERVERHASH')
        server_nonce = parser.pop_kwarg_checked('SERVERNONCE')

        self._server_hash = bytes.fromhex(server_hash.value)
        self._server_nonce = bytes.fromhex(server_nonce.value)

    @property
    def server_hash(self) -> bytes:
        """ Get the server hash field from the response.
        """
        return self._server_hash

    @property
    def server_nonce(self) -> bytes:
        """ Get the server nonce field from the response.
        """
        return self._server_nonce

    def raise_for_server_hash_error(self, cookie: bytes) -> None:
        """ Check that the server hash is consistent with what we compute.
        """
        computed = self.server_token_build(cookie)
        if computed != self.server_hash:
            raise ResponseError("Tor provided the wrong server nonce.")

    def server_token_build(self, cookie: bytes) -> bytes:
        """ Build a token suitable for server hash check from the client.
        """
        key = self.SERVER_HASH_CONSTANT
        msg = cookie + self.query.nonce + self.server_nonce
        return hmac.new(key, msg, hashlib.sha256).digest()

    def client_token_build(self, cookie: bytes) -> bytes:
        """ Build a token suitable for authentication from the client.
        """
        key = self.CLIENT_HASH_CONSTANT
        msg = cookie + self.query.nonce + self.server_nonce
        return hmac.new(key, msg, hashlib.sha256).digest()
# End of class AuthChallengeReply.