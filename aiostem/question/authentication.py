# -*- coding: utf-8 -*-

import secrets

from aiostem.command import Command
from aiostem.question.base import Query
from typing import Optional


class AuthChallengeQuery(Query):
    """ Authentication challenge query.
    """

    COMMAND_NAME: str = 'AUTHCHALLENGE'
    CLIENT_NONCE_SIZE: int = 32

    def __init__(self, nonce: Optional[bytes] = None) -> None:
        if nonce is None:
            nonce = secrets.token_bytes(self.CLIENT_NONCE_SIZE)
        self._nonce = nonce

    @property
    def command(self) -> str:
        """ Convert this query object to a command suitable for `Controller.request()`.
        """
        cmd = Command(self.COMMAND_NAME)
        cmd.add_arg('SAFECOOKIE')
        cmd.add_arg(self.nonce.hex())
        return cmd

    @property
    def nonce(self) -> bytes:
        """ Provided or generated client nonce.
        """
        return self._nonce
# End of class AuthChallengeQuery.


class AuthenticateQuery(Query):
    """ Create an authentication query.
    """

    COMMAND_NAME: str = 'AUTHENTICATE'

    def __init__(self, token: Optional[str] = None) -> None:
        self._token = token

    @property
    def command(self) -> str:
        """ Convert this query object to a command suitable for `Controller.request()`.
        """
        cmd = Command(self.COMMAND_NAME)
        if self.token is not None:
            cmd.add_arg(self.token)
        return cmd

    @property
    def token(self) -> str:
        """ The provided token used for authentication.
        """
        return self._token
# End of class AuthenticateQuery.
