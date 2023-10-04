from __future__ import annotations

import secrets
from typing import ClassVar

from aiostem.command import Command

from .base import Query


class AuthChallengeQuery(Query):
    """Authentication challenge query."""

    COMMAND_NAME: ClassVar[str] = 'AUTHCHALLENGE'
    CLIENT_NONCE_SIZE: ClassVar[int] = 32

    def __init__(self, nonce: bytes | None = None) -> None:
        """Initialize a new authentication challenge query."""
        if nonce is None:
            nonce = secrets.token_bytes(self.CLIENT_NONCE_SIZE)
        self._nonce = nonce  # type: bytes

    @property
    def command(self) -> Command:
        """Convert this query object to a command suitable for `Controller.request()`."""
        cmd = Command(self.COMMAND_NAME)
        cmd.add_arg('SAFECOOKIE')
        cmd.add_arg(self.nonce.hex())
        return cmd

    @property
    def nonce(self) -> bytes:
        """Get the client nonce, either provided or generated."""
        return self._nonce


class AuthenticateQuery(Query):
    """Create an authentication query."""

    COMMAND_NAME: ClassVar[str] = 'AUTHENTICATE'

    def __init__(self, token: str | None = None) -> None:
        """Initialize a new authentication query."""
        self._token = token

    @property
    def command(self) -> Command:
        """Convert this query object to a command suitable for `Controller.request()`."""
        cmd = Command(self.COMMAND_NAME)
        if self.token is not None:
            cmd.add_arg(self.token)
        return cmd

    @property
    def token(self) -> str | None:
        """Get the provided token used for authentication."""
        return self._token
