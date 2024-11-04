from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Annotated, Any, ClassVar

from pydantic import TypeAdapter

from ..exceptions import ReplyStatusError
from .structures import AuthMethod
from .utils import ReplySyntax, ReplySyntaxFlag, StringSequence

if TYPE_CHECKING:
    from typing import Self

    from .message import Message

logger = logging.getLogger(__package__)


@dataclass(kw_only=True, slots=True)
class Reply(ABC):
    """Base interface class for all replies."""

    status: int
    status_text: str | None = None

    @classmethod
    @abstractmethod
    def from_message(cls, message: Message) -> Self:
        """Build a reply structure from a received message."""

    def raise_for_status(self) -> None:
        """Raise a ReplyStatusError when the reply status is an error."""
        if self.status is not None and self.status >= 400:
            text = self.status_text
            if text is None:
                text = f'Got status {self.status} in the command reply.'
            raise ReplyStatusError(text, code=self.status)


@dataclass(kw_only=True, slots=True)
class ReplyProtocolInfo(Reply):
    """A reply for a `PROTOCOLINFO` command."""

    SYNTAXES: ClassVar[Mapping[str, ReplySyntax]] = {
        'AUTH': ReplySyntax(
            args_min=1,
            args_map=(None,),
            kwargs_map={
                'METHODS': 'auth_methods',
                'COOKIEFILE': 'auth_cookie_file',
            },
            flags=ReplySyntaxFlag.KW_ENABLE | ReplySyntaxFlag.KW_QUOTED,
        ),
        'PROTOCOLINFO': ReplySyntax(args_min=2, args_map=(None, 'protocol_version')),
        'VERSION': ReplySyntax(
            args_min=1,
            args_map=[None],
            kwargs_map={'Tor': 'tor_version'},
            flags=ReplySyntaxFlag.KW_ENABLE | ReplySyntaxFlag.KW_QUOTED,
        ),
    }

    #: List of available authentication methods.
    auth_methods: Annotated[set[AuthMethod], StringSequence()] = field(default_factory=set)
    #: Path on the server to the cookie file.
    auth_cookie_file: str | None = None
    #: Version of the Tor control protocol in use.
    protocol_version: int | None = None
    #: Version of Tor.
    tor_version: str | None = None

    @classmethod
    def from_message(cls, message: Message) -> Self:
        """Build a structure from a received message."""
        result: dict[str, Any] = {'status': message.status, 'status_text': message.header}
        for item in message.items:
            keyword = item.keyword
            syntax = cls.SYNTAXES.get(keyword)
            if syntax is not None:
                update = syntax.parse(item)
                for key, val in update.items():
                    if key is not None:  # pragma: no branch
                        result[key] = val
            else:
                logger.info("No syntax handler for keyword '%s'", keyword)

        return TypeAdapter(cls).validate_python(result)


@dataclass(kw_only=True, slots=True)
class ReplyGetConf(Reply):
    """A reply for a `GETCONF` command."""

    SYNTAX: ClassVar[ReplySyntax] = ReplySyntax(
        flags=(
            ReplySyntaxFlag.KW_ENABLE
            | ReplySyntaxFlag.KW_OMIT_VALS
            | ReplySyntaxFlag.KW_USE_DATA
            | ReplySyntaxFlag.KW_EXTRA
        )
    )

    #: List of configuration items.
    items: Mapping[str, str | None] = field(default_factory=dict)

    @classmethod
    def from_message(cls, message: Message) -> Self:
        """Build a structure from a received message."""
        is_success = bool(message.status == 250)
        result = {
            'status': message.status,
            'status_text': None if is_success else message.header,
            'items': {},
        }  # type: dict[str, Any]
        if is_success:
            for item in (*message.items, message):
                update = cls.SYNTAX.parse(item)
                for key, val in update.items():
                    if key is not None and isinstance(val, str | None):  # pragma: no branch
                        result['items'][key] = val
        return TypeAdapter(cls).validate_python(result)
