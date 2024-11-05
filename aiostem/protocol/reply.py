from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Annotated, Any, ClassVar

from pydantic import TypeAdapter

from ..exceptions import ReplyStatusError
from .structures import AuthMethod
from .utils import ReplySyntax, ReplySyntaxFlag, StringSequence

if TYPE_CHECKING:
    from typing import Self

    from .message import BaseMessage, Message

logger = logging.getLogger(__package__)


@dataclass(kw_only=True, slots=True)
class BaseReply(ABC):
    """Base class for all replies and sub-replies."""

    status: int
    status_text: str | None = None

    @property
    def is_error(self) -> bool:
        """Whether our status is an error status (greater than 400)."""
        return bool(self.status >= 400)

    @property
    def is_success(self) -> bool:
        """Whether our status is a success status (=250)."""
        return bool(self.status == 250)

    def raise_for_status(self) -> None:
        """Raise a ReplyStatusError when the reply status is an error."""
        if self.is_error:
            text = self.status_text
            # The following case is theorically possible but never encountered for real.
            if text is None:  # pragma: no cover
                text = f'Got status {self.status} in the command reply.'
            raise ReplyStatusError(text, code=self.status)


@dataclass(kw_only=True, slots=True)
class Reply(BaseReply):
    """Base interface class for all replies."""

    @classmethod
    @abstractmethod
    def from_message(cls, message: Message) -> Self:
        """Build a reply structure from a received message."""


@dataclass(kw_only=True, slots=True)
class _ReplySimple(Reply):
    """Any simple reply with only a status and status_text."""

    @classmethod
    def from_message(cls, message: Message) -> Self:
        """Build a structure from a received message."""
        result = {'status': message.status, 'status_text': message.header}
        return TypeAdapter(cls).validate_python(result)


@dataclass(kw_only=True, slots=True)
class _ReplyGetMap(Reply):
    """A base class for replies such as `GETCONF` and `GETINFO`."""

    #: This needs to be completed by the sub-class.
    KW_SYNTAX: ClassVar[ReplySyntax] = ReplySyntax()

    @classmethod
    def _key_value_extract(
        cls,
        messages: Iterable[BaseMessage],
    ) -> Mapping[str, Sequence[str | None] | str | None]:
        """Extract key/value pairs from `messages`."""
        values = {}  # type: dict[str, list[str | None] | str | None]
        for item in messages:
            update = cls.KW_SYNTAX.parse(item)
            for key, val in update.items():
                if key is not None and isinstance(val, str | None):  # pragma: no branch
                    if key in values:
                        current = values[key]
                        if isinstance(current, list):
                            current.append(val)
                        else:
                            values[key] = [current, val]
                    else:
                        values[key] = val
        return values


@dataclass(kw_only=True, slots=True)
class ReplySetConf(_ReplySimple):
    """A reply for a `SETCONF` command."""


@dataclass(kw_only=True, slots=True)
class ReplyResetConf(_ReplySimple):
    """A reply for a `RESETCONF` command."""


@dataclass(kw_only=True, slots=True)
class ReplyGetConf(_ReplyGetMap):
    """A reply for a `GETCONF` command."""

    KW_SYNTAX: ClassVar[ReplySyntax] = ReplySyntax(
        flags=(
            ReplySyntaxFlag.KW_ENABLE
            | ReplySyntaxFlag.KW_OMIT_VALS
            | ReplySyntaxFlag.KW_EXTRA
            | ReplySyntaxFlag.KW_RAW
        )
    )

    values: Mapping[str, Sequence[str | None] | str | None] = field(default_factory=dict)

    @classmethod
    def from_message(cls, message: Message) -> Self:
        """Build a structure from a received message."""
        has_data = message.is_success and (len(message.items) > 0 or message.header != 'OK')
        status_text = None if has_data else message.header
        result = {
            'status': message.status,
            'status_text': status_text,
        }  # type: dict[str, Any]

        if has_data:
            result['values'] = cls._key_value_extract([*message.items, message])

        return TypeAdapter(cls).validate_python(result)


@dataclass(kw_only=True, slots=True)
class ReplySetEvents(_ReplySimple):
    """A reply for a `SETEVENTS` command."""


@dataclass(kw_only=True, slots=True)
class ReplySaveConf(_ReplySimple):
    """A reply for a `SAVECONF` command."""


@dataclass(kw_only=True, slots=True)
class ReplySignal(_ReplySimple):
    """A reply for a `SIGNAL` command."""


@dataclass(kw_only=True, slots=True)
class ReplyMapAddressItem(BaseReply):
    """A single item from a reply for `MAPADDRESS`."""

    SYNTAX: ClassVar[ReplySyntax] = ReplySyntax(
        flags=ReplySyntaxFlag.KW_ENABLE | ReplySyntaxFlag.KW_EXTRA,
    )

    #: Original address to replace with another one.
    original: str | None = None

    #: Replacement item for the corresponding `original` address.
    replacement: str | None = None

    @classmethod
    def from_message_item(cls, message: BaseMessage) -> Self:
        """Build a sub-reply for a `MAPADDRESS` reply item."""
        result = {'status': message.status}  # type: dict[str, Any]
        if message.is_success:
            values = cls.SYNTAX.parse(message)
            key, val = next(iter(values.items()))
            result.update({'original': key, 'replacement': val})
        else:
            result['status_text'] = message.header
        return TypeAdapter(cls).validate_python(result)


@dataclass(kw_only=True, slots=True)
class ReplyMapAddress(Reply):
    """
    A reply for a `MAPADDRESS` command.

    Note:
        This reply has sub-replies since each mapping request is handled
        independently by the server, which means that each sub-reply has
        its own status and a potential status text.

    """

    #: A list of replies, each can have its own status code.
    items: Sequence[ReplyMapAddressItem] = field(default_factory=list)

    @classmethod
    def from_message(cls, message: Message) -> Self:
        """Build a structure from a received message."""
        status_max = 0
        result: dict[str, Any] = {'items': []}
        for item in (*message.items, message):
            sub = ReplyMapAddressItem.from_message_item(item)
            if sub.status > status_max:
                result.update(
                    {
                        'status': sub.status,
                        'status_text': sub.status_text,
                    }
                )
                status_max = sub.status

            result['items'].append(sub)
        return TypeAdapter(cls).validate_python(result)


@dataclass(kw_only=True, slots=True)
class ReplyGetInfo(_ReplyGetMap):
    """A reply for a `GETINFO` command."""

    KW_SYNTAX: ClassVar[ReplySyntax] = ReplySyntax(
        flags=(
            ReplySyntaxFlag.KW_ENABLE
            | ReplySyntaxFlag.KW_OMIT_VALS
            | ReplySyntaxFlag.KW_USE_DATA
            | ReplySyntaxFlag.KW_EXTRA
            | ReplySyntaxFlag.KW_RAW
        )
    )

    values: Mapping[str, Sequence[str | None] | str | None] = field(default_factory=dict)

    @classmethod
    def from_message(cls, message: Message) -> Self:
        """Build a structure from a received message."""
        result = {
            'status': message.status,
            'status_text': message.header,
        }
        if message.is_success:
            result['values'] = cls._key_value_extract(message.items)
        return TypeAdapter(cls).validate_python(result)


@dataclass(kw_only=True, slots=True)
class ReplyExtendCircuit(_ReplyGetMap):
    """A reply for a `GETINFO` command."""

    SYNTAX: ClassVar[ReplySyntax] = ReplySyntax(args_min=2, args_map=[None, 'circuit'])

    #: Built or extended circuit (None on error).
    circuit: int | None = None

    @classmethod
    def from_message(cls, message: Message) -> Self:
        """Build a structure from a received message."""
        result = {'status': message.status}  # type: dict[str, Any]
        if message.is_success:
            update = cls.SYNTAX.parse(message)
            for key, val in update.items():
                if key is not None:  # pragma: no branch
                    result[key] = val
        else:
            result['status_text'] = message.header

        return TypeAdapter(cls).validate_python(result)


@dataclass(kw_only=True, slots=True)
class ReplyAuthenticate(_ReplySimple):
    """A reply for a `AUTHENTICATE` command."""


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
