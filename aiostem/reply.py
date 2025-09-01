from __future__ import annotations

import asyncio
import logging
from abc import ABC, abstractmethod
from collections.abc import (
    ItemsView,
    Iterable,
    Iterator,
    KeysView,
    Mapping,
    Sequence,
    ValuesView,
)
from dataclasses import dataclass, field
from functools import partial
from typing import Any, ClassVar, TypeAlias, TypeVar

from pydantic import PositiveInt, TypeAdapter

from .exceptions import ReplyStatusError
from .structures import (
    ReplyDataAddOnion,
    ReplyDataAuthChallenge,
    ReplyDataExtendCircuit,
    ReplyDataMapAddressItem,
    ReplyDataOnionClientAuthView,
    ReplyDataProtocolInfo,
)
from .utils import BaseMessage, Message, ReplySyntax, ReplySyntaxFlag, Self

logger = logging.getLogger(__package__)


@dataclass(kw_only=True, slots=True)
class BaseReply(ABC):
    """Base class for all replies and sub-replies."""

    #: Cached adapter used while deserializing the message.
    ADAPTER: ClassVar[TypeAdapter[Self] | None] = None

    #: Reply status received.
    #:
    #: See Also:
    #:     https://spec.torproject.org/control-spec/replies.html#replies
    status: PositiveInt

    #: Text associated with the reply status (if any).
    status_text: str | None = None

    @classmethod
    def adapter(cls) -> TypeAdapter[Self]:
        """Get a cached type adapter to deserialize a reply."""
        if cls.ADAPTER is None:
            cls.ADAPTER = TypeAdapter(cls)
        return cls.ADAPTER

    @property
    def is_error(self) -> bool:
        """Whether our status is an error status (greater or equal to 400)."""
        return bool(self.status >= 400 and self.status != 650)

    @property
    def is_success(self) -> bool:
        """Whether our status is a success status (=250)."""
        return bool(self.status == 250)

    def raise_for_status(self) -> None:
        """
        Raise when the reply status is an error.

        Raises:
            ReplyStatusError: When :meth:`is_error` is :obj:`True`.

        """
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
    def from_message(cls, message: Message) -> Self:
        """
        Build a reply structure from a received message.

        Args:
            message: The received message to build a reply from.

        """
        return cls.adapter().validate_python(cls._message_to_mapping(message))

    @classmethod
    @abstractmethod
    def _message_to_mapping(cls, message: Message) -> Mapping[str, Any]:
        """
        Convert the provided message to a map suitable for our adapter.

        Args:
            message: The received message to build a dictionary from.

        Returns:
            A map of things to validate this structure from.

        """


@dataclass(kw_only=True, slots=True)
class ReplySimple(Reply):
    """Any simple reply with only a :attr:`status` and :attr:`status_text`."""

    @classmethod
    def _message_to_mapping(cls, message: Message) -> Mapping[str, Any]:
        """Build a map from a received message."""
        return {'status': message.status, 'status_text': message.header}


#: Type of values received in ``GETCONF`` or ``GETINFO``.
ReplyMapValueType: TypeAlias = Sequence[str | None] | str | None

#: Type of map we have for :class:`ReplyGetConf` and :class:`ReplyGetInfo`.
ReplyMapType: TypeAlias = Mapping[str, ReplyMapValueType]

#: Placeholder type for the default argument of ``Mapping.get``.
_ReplyMapDefaultType = TypeVar('_ReplyMapDefaultType')


@dataclass(kw_only=True)
class ReplyGetMap(ReplyMapType):
    """
    A base reply class for commands returning maps of values.

    Hint:
        This reply and all subclasses behaves as a :class:`Mapping`.

    These are replies for commands such as:
        - :class:`~.CommandGetConf`
        - :class:`~.CommandGetInfo`

    This class is also used for :class:`.EventConfChanged`.

    """

    #: Syntax to use, needs to be defined by sub-classes.
    SYNTAX: ClassVar[ReplySyntax]

    #: Map of values received on this reply.
    data: ReplyMapType = field(default_factory=dict)

    @classmethod
    def _key_value_extract(cls, messages: Iterable[BaseMessage]) -> ReplyMapType:
        """Extract key/value pairs from ``messages``."""
        values = {}  # type: dict[str, list[str | None] | str | None]
        for item in messages:
            update = cls.SYNTAX.parse(item)
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

    def __contains__(self, key: Any) -> bool:
        """Whether the reply contains the provided key."""
        return self.data.__contains__(key)

    def __getitem__(self, key: str) -> ReplyMapValueType:
        """Get the content of the provided item (if any)."""
        return self.data.__getitem__(key)

    def __iter__(self) -> Iterator[str]:
        """Iterate on our keys."""
        return self.data.__iter__()

    def __len__(self) -> int:
        """Get the number of items we have in our reply."""
        return self.data.__len__()

    def get(
        self,
        key: str,
        /,
        default: _ReplyMapDefaultType | ReplyMapValueType = None,
    ) -> _ReplyMapDefaultType | ReplyMapValueType:
        """Get the value for the provided ``key`` or a default one."""
        return self.data.get(key, default)

    def items(self) -> ItemsView[str, ReplyMapValueType]:
        """Get the pairs of keys and values."""
        return self.data.items()

    def keys(self) -> KeysView[str]:
        """Get the list of all keys."""
        return self.data.keys()

    def values(self) -> ValuesView[ReplyMapValueType]:
        """Get all values."""
        return self.data.values()


@dataclass(kw_only=True, slots=True)
class ReplySetConf(ReplySimple):
    """A reply for a :attr:`~.CommandWord.SETCONF` command."""


@dataclass(kw_only=True, slots=True)
class ReplyResetConf(ReplySimple):
    """A reply for a :attr:`~.CommandWord.RESETCONF` command."""


@dataclass(kw_only=True, slots=True)
class ReplyGetConf(Reply, ReplyGetMap):
    """A reply for a :attr:`~.CommandWord.GETCONF` command."""

    SYNTAX: ClassVar[ReplySyntax] = ReplySyntax(
        flags=(
            ReplySyntaxFlag.KW_ENABLE
            | ReplySyntaxFlag.KW_OMIT_VALS
            | ReplySyntaxFlag.KW_EXTRA
            | ReplySyntaxFlag.KW_RAW
        )
    )

    @classmethod
    def _message_to_mapping(cls, message: Message) -> Mapping[str, Any]:
        """Build a map from a received message."""
        has_data = message.is_success and (len(message.items) > 0 or message.header != 'OK')
        status_text = None if has_data else message.header
        result = {
            'status': message.status,
            'status_text': status_text,
        }  # type: dict[str, Any]

        if has_data:
            result['data'] = cls._key_value_extract([*message.items, message])
        return result


@dataclass(kw_only=True, slots=True)
class ReplySetEvents(ReplySimple):
    """A reply for a :attr:`~.CommandWord.SETEVENTS` command."""


@dataclass(kw_only=True, slots=True)
class ReplyAuthenticate(ReplySimple):
    """A reply for a :attr:`~.CommandWord.AUTHENTICATE` command."""


@dataclass(kw_only=True, slots=True)
class ReplySaveConf(ReplySimple):
    """A reply for a :attr:`~.CommandWord.SAVECONF` command."""


@dataclass(kw_only=True, slots=True)
class ReplySignal(ReplySimple):
    """A reply for a :attr:`~.CommandWord.SIGNAL` command."""


@dataclass(kw_only=True, slots=True)
class ReplyMapAddressItem(BaseReply):
    """Part of a reply for a :attr:`~.CommandWord.MAPADDRESS` command."""

    SYNTAX: ClassVar[ReplySyntax] = ReplySyntax(
        flags=ReplySyntaxFlag.KW_ENABLE | ReplySyntaxFlag.KW_EXTRA,
    )

    #: The reply data associated with this single item.
    data: ReplyDataMapAddressItem | None = None

    @classmethod
    def from_message_item(cls, message: BaseMessage) -> Self:
        """Build a sub-reply for a :attr:`~.CommandWord.MAPADDRESS` reply item."""
        result = {'status': message.status}  # type: dict[str, Any]
        if message.is_success:
            values = cls.SYNTAX.parse(message)
            key, val = next(iter(values.items()))
            result['data'] = {'original': key, 'replacement': val}
        else:
            result['status_text'] = message.header
        return cls.adapter().validate_python(result)


@dataclass(kw_only=True, slots=True)
class ReplyMapAddress(Reply):
    """
    A reply for a :attr:`~.CommandWord.MAPADDRESS` command.

    Note:
        This reply has sub-replies since each mapping request is handled
        independently by the server, which means that each sub-reply has
        its own status and a potential status text.

    """

    #: A list of replies, each can have its own status code.
    items: Sequence[ReplyMapAddressItem] = field(default_factory=list)

    @classmethod
    def _message_to_mapping(cls, message: Message) -> Mapping[str, Any]:
        """Build a map from a received message."""
        status_max = 0
        result = {'items': []}  # type: dict[str, Any]
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
        return result


@dataclass(kw_only=True, slots=True)
class ReplyGetInfo(ReplyGetMap, Reply):
    """A reply for a :attr:`~.CommandWord.GETINFO` command."""

    SYNTAX: ClassVar[ReplySyntax] = ReplySyntax(
        flags=(
            ReplySyntaxFlag.KW_ENABLE
            | ReplySyntaxFlag.KW_OMIT_VALS
            | ReplySyntaxFlag.KW_USE_DATA
            | ReplySyntaxFlag.KW_EXTRA
            | ReplySyntaxFlag.KW_RAW
        )
    )

    @classmethod
    def _message_to_mapping(cls, message: Message) -> Mapping[str, Any]:
        """Build a map from a received message."""
        result = {
            'status': message.status,
            'status_text': message.header,
        }
        if message.is_success:
            result['data'] = cls._key_value_extract(message.items)
        return result


@dataclass(kw_only=True, slots=True)
class ReplyExtendCircuit(Reply):
    """A reply for a :attr:`~.CommandWord.EXTENDCIRCUIT` command."""

    SYNTAX: ClassVar[ReplySyntax] = ReplySyntax(args_min=2, args_map=(None, 'circuit'))

    #: Received data when successful.
    data: ReplyDataExtendCircuit | None = None

    @classmethod
    def _message_to_mapping(cls, message: Message) -> Mapping[str, Any]:
        """Build a map from a received message."""
        result = {'status': message.status}  # type: dict[str, Any]
        if message.is_success:
            data = {}  # type: dict[str, ReplyMapValueType]
            update = cls.SYNTAX.parse(message)
            for key, val in update.items():
                if key is not None:  # pragma: no branch
                    data[key] = val
            result['data'] = data
        else:
            result['status_text'] = message.header
        return result


@dataclass(kw_only=True, slots=True)
class ReplySetCircuitPurpose(ReplySimple):
    """A reply for a :attr:`~.CommandWord.SETCIRCUITPURPOSE` command."""


@dataclass(kw_only=True, slots=True)
class ReplyAttachStream(ReplySimple):
    """A reply for a :attr:`~.CommandWord.ATTACHSTREAM` command."""


@dataclass(kw_only=True, slots=True)
class ReplyPostDescriptor(ReplySimple):
    """A reply for a :attr:`~.CommandWord.POSTDESCRIPTOR` command."""


@dataclass(kw_only=True, slots=True)
class ReplyRedirectStream(ReplySimple):
    """A reply for a :attr:`~.CommandWord.REDIRECTSTREAM` command."""


@dataclass(kw_only=True, slots=True)
class ReplyCloseStream(ReplySimple):
    """A reply for a :attr:`~.CommandWord.CLOSESTREAM` command."""


@dataclass(kw_only=True, slots=True)
class ReplyCloseCircuit(ReplySimple):
    """A reply for a :attr:`~.CommandWord.CLOSECIRCUIT` command."""


@dataclass(kw_only=True, slots=True)
class ReplyQuit(ReplySimple):
    """A reply for a :attr:`~.CommandWord.QUIT` command."""


@dataclass(kw_only=True, slots=True)
class ReplyUseFeature(ReplySimple):
    """A reply for a :attr:`~.CommandWord.USEFEATURE` command."""


@dataclass(kw_only=True, slots=True)
class ReplyResolve(ReplySimple):
    """A reply for a :attr:`~.CommandWord.RESOLVE` command."""


def _read_auth_cookie_file(path: str) -> bytes:
    """
    Read the provided cookie file, synchronously.

    Args:
        path: Path to the cookie file to read from.

    Returns:
        The file contents as bytes.

    """
    with open(path, 'rb') as fp:
        return fp.read()


@dataclass(kw_only=True, slots=True)
class ReplyProtocolInfo(Reply):
    """A reply for a :attr:`~.CommandWord.PROTOCOLINFO` command."""

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
            args_map=(None,),
            kwargs_map={'Tor': 'tor_version'},
            flags=ReplySyntaxFlag.KW_ENABLE | ReplySyntaxFlag.KW_QUOTED,
        ),
    }

    #: Reply data when this command was successful.
    data: ReplyDataProtocolInfo | None = None

    async def read_cookie_file(self) -> bytes:
        """
        Read the content of our the cookie file.

        Raises:
            FileNotFoundError: When there is no cookie file.

        Returns:
            The content of the cookie file.

        """
        if self.data is None or self.data.auth_cookie_file is None:
            msg = 'No cookie file found in this reply.'
            raise FileNotFoundError(msg)

        loop = asyncio.get_running_loop()
        func = partial(_read_auth_cookie_file, self.data.auth_cookie_file)
        return await loop.run_in_executor(None, func)

    @classmethod
    def _message_to_mapping(cls, message: Message) -> Mapping[str, Any]:
        """Build a map from a received message."""
        result = {
            'status': message.status,
            'status_text': message.header,
        }  # type: dict[str, Any]

        if message.is_success:
            data = {}  # type: dict[str, ReplyMapValueType]
            for item in message.items:
                keyword = item.keyword
                syntax = cls.SYNTAXES.get(keyword)
                if syntax is not None:
                    update = syntax.parse(item)
                    for key, val in update.items():
                        if key is not None:  # pragma: no branch
                            data[key] = val
                else:
                    logger.info("No syntax handler for keyword '%s'", keyword)
            result['data'] = data
        return result


@dataclass(kw_only=True, slots=True)
class ReplyLoadConf(ReplySimple):
    """A reply for a :attr:`~.CommandWord.LOADCONF` command."""


@dataclass(kw_only=True, slots=True)
class ReplyTakeOwnership(ReplySimple):
    """A reply for a :attr:`~.CommandWord.TAKEOWNERSHIP` command."""


@dataclass(kw_only=True, slots=True)
class ReplyAuthChallenge(Reply):
    """A reply for a :attr:`~.CommandWord.AUTHCHALLENGE` command."""

    SYNTAX: ClassVar[ReplySyntax] = ReplySyntax(
        args_min=1,
        args_map=(None,),
        kwargs_map={
            'SERVERHASH': 'server_hash',
            'SERVERNONCE': 'server_nonce',
        },
        flags=ReplySyntaxFlag.KW_ENABLE,
    )

    #: Reply content when this command was successful.
    data: ReplyDataAuthChallenge | None = None

    @classmethod
    def _message_to_mapping(cls, message: Message) -> Mapping[str, Any]:
        """Build a map from a received message."""
        result = {'status': message.status}  # type: dict[str, Any]
        if message.is_success:
            data = {}  # type: dict[str, ReplyMapValueType]
            update = cls.SYNTAX.parse(message)
            for key, val in update.items():
                if key is not None and isinstance(val, str):  # pragma: no branch
                    data[key] = val
            result['data'] = data
        else:
            result['status_text'] = message.header
        return result


@dataclass(kw_only=True, slots=True)
class ReplyDropGuards(ReplySimple):
    """A reply for a :attr:`~.CommandWord.DROPGUARDS` command."""


@dataclass(kw_only=True, slots=True)
class ReplyHsFetch(ReplySimple):
    """A reply for a :attr:`~.CommandWord.HSFETCH` command."""


@dataclass(kw_only=True, slots=True)
class ReplyAddOnion(Reply):
    """A reply for a :attr:`~.CommandWord.ADD_ONION` command."""

    SYNTAX: ClassVar[ReplySyntax] = ReplySyntax(
        kwargs_map={
            'ServiceID': 'address',
            'ClientAuth': 'client_auth',
            'ClientAuthV3': 'client_auth_v3',
            'PrivateKey': 'key',
        },
        kwargs_multi={'client_auth', 'client_auth_v3'},
        flags=ReplySyntaxFlag.KW_ENABLE | ReplySyntaxFlag.KW_RAW,
    )

    #: Reply for a successful command.
    data: ReplyDataAddOnion | None = None

    @classmethod
    def _message_to_mapping(cls, message: Message) -> Mapping[str, Any]:
        """Build a map from a received message."""
        result = {
            'status': message.status,
            'status_text': message.header,
        }  # type: dict[str, Any]

        if message.is_success:
            data = {}  # type: dict[str, Any]
            for sub in message.items:
                update = cls.SYNTAX.parse(sub)
                for key, val in update.items():
                    if key is not None:  # pragma: no branch
                        if key in cls.SYNTAX.kwargs_multi and key in data:
                            data[key].extend(val)
                        else:
                            data[key] = val
            result['data'] = data
        else:
            result['status_text'] = message.header
        return result


@dataclass(kw_only=True, slots=True)
class ReplyDelOnion(ReplySimple):
    """A reply for a :attr:`~.CommandWord.DEL_ONION` command."""


@dataclass(kw_only=True, slots=True)
class ReplyHsPost(ReplySimple):
    """A reply for a :attr:`~.CommandWord.HSPOST` command."""


@dataclass(kw_only=True, slots=True)
class ReplyOnionClientAuthAdd(ReplySimple):
    """A reply for a :attr:`~.CommandWord.ONION_CLIENT_AUTH_ADD` command."""


@dataclass(kw_only=True, slots=True)
class ReplyOnionClientAuthRemove(ReplySimple):
    """A reply for a :attr:`~.CommandWord.ONION_CLIENT_AUTH_REMOVE` command."""


@dataclass(kw_only=True, slots=True)
class ReplyOnionClientAuthView(Reply):
    """A reply for a :attr:`~.CommandWord.ONION_CLIENT_AUTH_VIEW` command."""

    SYNTAXES: ClassVar[Mapping[str, ReplySyntax]] = {
        'ONION_CLIENT_AUTH_VIEW': ReplySyntax(args_map=(None, 'address')),
        'CLIENT': ReplySyntax(
            args_min=3,
            args_map=(None, 'address', 'key'),
            kwargs_map={
                'ClientName': 'name',
                'Flags': 'flags',
            },
            flags=ReplySyntaxFlag.KW_ENABLE,
        ),
    }

    #: Data for a successful command.
    data: ReplyDataOnionClientAuthView | None = None

    @classmethod
    def _message_to_mapping(cls, message: Message) -> Mapping[str, Any]:
        """Build a map from a received message."""
        result = {
            'status': message.status,
            'status_text': message.header,
        }  # type: dict[str, Any]

        if message.is_success:
            data = {'clients': []}  # type: dict[str, Any]
            for item in message.items:
                keyword = item.keyword
                syntax = cls.SYNTAXES.get(keyword)
                if syntax is not None:  # pragma: no branch
                    update = syntax.parse(item)
                    if keyword == 'CLIENT':
                        data['clients'].append(update)
                    else:
                        for key, val in update.items():
                            if key is not None:  # pragma: no branch
                                data[key] = val
            result['data'] = data
        return result


@dataclass(kw_only=True, slots=True)
class ReplyDropOwnership(ReplySimple):
    """A reply for a :attr:`~.CommandWord.DROPOWNERSHIP` command."""


@dataclass(kw_only=True, slots=True)
class ReplyDropTimeouts(ReplySimple):
    """A reply for a :attr:`~.CommandWord.DROPTIMEOUTS` command."""
