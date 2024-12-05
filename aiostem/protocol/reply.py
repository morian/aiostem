from __future__ import annotations

import asyncio
import hashlib
import hmac
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
from typing import TYPE_CHECKING, Annotated, Any, ClassVar, Self, TypeAlias, TypeVar

from pydantic import PositiveInt, TypeAdapter

from ..exceptions import ReplyError, ReplyStatusError
from .structures import AuthMethod, OnionClientAuthKey, OnionServiceKeyType
from .syntax import ReplySyntax, ReplySyntaxFlag
from .utils import (
    AnyHost,
    Base32Bytes,
    Base64Bytes,
    HexBytes,
    HiddenServiceAddress,
    StringSequence,
)

if TYPE_CHECKING:
    from .message import BaseMessage, Message

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
        return bool(self.status >= 400)

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
    @abstractmethod
    def from_message(cls, message: Message) -> Self:
        """
        Build a reply structure from a received message.

        Args:
            message: The received message to build a reply from.

        """


@dataclass(kw_only=True, slots=True)
class ReplySimple(Reply):
    """Any simple reply with only a :attr:`status` and :attr:`status_text`."""

    @classmethod
    def from_message(cls, message: Message) -> Self:
        """Build a structure from a received message."""
        result = {'status': message.status, 'status_text': message.header}
        return cls.adapter().validate_python(result)


#: Type of values received in ``GETCONF`` or ``GETINFO``.
ReplyMapValueType: TypeAlias = Sequence[str | None] | str | None

#: Type of map we have for :class:`ReplyGetConf` and :class:`ReplyGetInfo`.
ReplyMapType: TypeAlias = Mapping[str, ReplyMapValueType]

#: Placeholder type for the default argument of ``Mapping.get``.
_ReplyMapDefaultType = TypeVar('_ReplyMapDefaultType')


@dataclass(kw_only=True, slots=True)
class ReplyGetMap(Reply, ReplyMapType):
    """
    A base reply class for commands returning maps of values.

    Hint:
        This reply and all subclasses behaves as a :class:`Mapping`.

    These are replies for commands such as:
        - :class:`~.CommandGetConf`
        - :class:`~.CommandGetInfo`

    """

    #: Syntax to use, needs to be defined by sub-classes.
    SYNTAX: ClassVar[ReplySyntax]

    #: Map of values received on this reply.
    _values: ReplyMapType = field(default_factory=dict)

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
        return self._values.__contains__(key)

    def __getitem__(self, key: str) -> ReplyMapValueType:
        """Get the content of the provided item (if any)."""
        return self._values.__getitem__(key)

    def __iter__(self) -> Iterator[str]:
        """Iterate on our keys."""
        return self._values.__iter__()

    def __len__(self) -> int:
        """Get the number of items we have in our reply."""
        return self._values.__len__()

    def get(
        self,
        key: str,
        /,
        default: _ReplyMapDefaultType | ReplyMapValueType = None,
    ) -> _ReplyMapDefaultType | ReplyMapValueType:
        """Get the value for the provided ``key`` or a default one."""
        return self._values.get(key, default)

    def items(self) -> ItemsView[str, ReplyMapValueType]:
        """Get the pairs of keys and values."""
        return self._values.items()

    def keys(self) -> KeysView[str]:
        """Get the list of all keys."""
        return self._values.keys()

    def values(self) -> ValuesView[ReplyMapValueType]:
        """Get all values."""
        return self._values.values()


@dataclass(kw_only=True, slots=True)
class ReplySetConf(ReplySimple):
    """A reply for a :attr:`~.CommandWord.SETCONF` command."""


@dataclass(kw_only=True, slots=True)
class ReplyResetConf(ReplySimple):
    """A reply for a :attr:`~.CommandWord.RESETCONF` command."""


@dataclass(kw_only=True, slots=True)
class ReplyGetConf(ReplyGetMap):
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
    def from_message(cls, message: Message) -> Self:
        """Build a structure from a received message."""
        has_data = message.is_success and (len(message.items) > 0 or message.header != 'OK')
        status_text = None if has_data else message.header
        result = {
            'status': message.status,
            'status_text': status_text,
        }  # type: dict[str, Any]

        if has_data:
            result['_values'] = cls._key_value_extract([*message.items, message])
        return cls.adapter().validate_python(result)


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

    #: Original address to replace with another one.
    original: AnyHost | None = None

    #: Replacement item for the corresponding :attr:`original` address.
    replacement: AnyHost | None = None

    @classmethod
    def from_message_item(cls, message: BaseMessage) -> Self:
        """Build a sub-reply for a :attr:`~.CommandWord.MAPADDRESS` reply item."""
        result = {'status': message.status}  # type: dict[str, Any]
        if message.is_success:
            values = cls.SYNTAX.parse(message)
            key, val = next(iter(values.items()))
            result.update({'original': key, 'replacement': val})
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
        return cls.adapter().validate_python(result)


@dataclass(kw_only=True, slots=True)
class ReplyGetInfo(ReplyGetMap):
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
    def from_message(cls, message: Message) -> Self:
        """Build a structure from a received message."""
        result = {
            'status': message.status,
            'status_text': message.header,
        }
        if message.is_success:
            result['_values'] = cls._key_value_extract(message.items)
        return cls.adapter().validate_python(result)


@dataclass(kw_only=True, slots=True)
class ReplyExtendCircuit(Reply):
    """A reply for a :attr:`~.CommandWord.EXTENDCIRCUIT` command."""

    SYNTAX: ClassVar[ReplySyntax] = ReplySyntax(args_min=2, args_map=(None, 'circuit'))

    #: Built or extended circuit (:obj:`None` on error).
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

        return cls.adapter().validate_python(result)


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

    #: List of available authentication methods.
    auth_methods: Annotated[set[AuthMethod], StringSequence()] = field(default_factory=set)
    #: Path on the server to the cookie file.
    auth_cookie_file: str | None = None
    #: Version of the Tor control protocol in use.
    protocol_version: int | None = None
    #: Version of Tor.
    tor_version: str | None = None

    async def read_cookie_file(self) -> bytes:
        """
        Read the content of our the cookie file.

        Raises:
            FileNotFoundError: When there is no cookie file.

        Returns:
            The content of the cookie file.

        """
        if self.auth_cookie_file is None:
            msg = 'No cookie file found in this reply.'
            raise FileNotFoundError(msg)

        loop = asyncio.get_running_loop()
        func = partial(_read_auth_cookie_file, self.auth_cookie_file)
        return await loop.run_in_executor(None, func)

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

        return cls.adapter().validate_python(result)


@dataclass(kw_only=True, slots=True)
class ReplyLoadConf(ReplySimple):
    """A reply for a :attr:`~.CommandWord.LOADCONF` command."""


@dataclass(kw_only=True, slots=True)
class ReplyTakeOwnership(ReplySimple):
    """A reply for a :attr:`~.CommandWord.TAKEOWNERSHIP` command."""


@dataclass(kw_only=True, slots=True)
class ReplyAuthChallenge(Reply):
    """A reply for a :attr:`~.CommandWord.AUTHCHALLENGE` command."""

    CLIENT_HASH_CONSTANT: ClassVar[bytes] = (
        b'Tor safe cookie authentication controller-to-server hash'
    )
    SERVER_HASH_CONSTANT: ClassVar[bytes] = (
        b'Tor safe cookie authentication server-to-controller hash'
    )
    SYNTAX: ClassVar[ReplySyntax] = ReplySyntax(
        args_map=(None,),
        kwargs_map={
            'SERVERHASH': 'server_hash',
            'SERVERNONCE': 'server_nonce',
        },
        flags=ReplySyntaxFlag.KW_ENABLE,
    )

    #: Not part of the real response, but very handy to have it here.
    client_nonce: HexBytes | str | None = None
    #: Server hash as computed by the server.
    server_hash: HexBytes | None = None
    #: Server nonce as provided by the server.
    server_nonce: HexBytes | None = None

    @classmethod
    def from_message(cls, message: Message) -> Self:
        """Build a structure from a received message."""
        result = {'status': message.status}  # type: dict[str, Any]
        if message.is_success:
            update = cls.SYNTAX.parse(message)
            for key, val in update.items():
                if key is not None and isinstance(val, str):  # pragma: no branch
                    result[key] = val
        else:
            result['status_text'] = message.header

        return cls.adapter().validate_python(result)

    def build_client_hash(
        self,
        cookie: bytes,
        client_nonce: str | bytes | None = None,
    ) -> bytes:
        """
        Build a token suitable for authentication.

        Args:
            client_nonce: The client nonce used in :class:`.CommandAuthChallenge`.
            cookie: The cookie value read from the cookie file.

        Raises:
            ReplyError: When our client or server nonce is :obj:`None`.

        Returns:
            A value that you can authenticate with.

        """
        client_nonce = client_nonce or self.client_nonce
        if client_nonce is None:
            msg = 'No client_nonce was found or provided.'
            raise ReplyError(msg)

        if self.server_nonce is None:
            msg = 'No server_nonce has been set.'
            raise ReplyError(msg)

        if isinstance(client_nonce, str):
            client_nonce = client_nonce.encode('ascii')
        data = cookie + client_nonce + self.server_nonce
        return hmac.new(self.CLIENT_HASH_CONSTANT, data, hashlib.sha256).digest()

    def build_server_hash(
        self,
        cookie: bytes,
        client_nonce: str | bytes | None = None,
    ) -> bytes:
        """
        Recompute the server hash.

        Args:
            client_nonce: The client nonce used in :class:`.CommandAuthChallenge`.
            cookie: The cookie value read from the cookie file.

        Raises:
            ReplyError: When our client or server nonce is :obj:`None`.

        Returns:
            The same value as in `server_hash` if everything went well.

        """
        client_nonce = client_nonce or self.client_nonce
        if client_nonce is None:
            msg = 'No client_nonce was found or provided.'
            raise ReplyError(msg)

        if self.server_nonce is None:
            msg = 'No server_nonce has been set.'
            raise ReplyError(msg)

        if isinstance(client_nonce, str):
            client_nonce = client_nonce.encode('ascii')
        data = cookie + client_nonce + self.server_nonce
        return hmac.new(self.SERVER_HASH_CONSTANT, data, hashlib.sha256).digest()

    def raise_for_server_hash_error(
        self,
        cookie: bytes,
        client_nonce: str | bytes | None = None,
    ) -> None:
        """
        Check that our server hash is consistent with what we compute.

        Args:
            client_nonce: The client nonce used in :class:`.CommandAuthChallenge`.
            cookie: The cookie value read from the cookie file.

        Raises:
            ReplyError: When our server nonce does not match the one we computed.

        """
        computed = self.build_server_hash(cookie, client_nonce)
        if computed != self.server_hash:
            msg = 'Server hash provided by Tor is invalid.'
            raise ReplyError(msg)


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
            'PrivateKey': 'priv',
        },
        kwargs_multi={'client_auth', 'client_auth_v3'},
        flags=ReplySyntaxFlag.KW_ENABLE | ReplySyntaxFlag.KW_RAW,
    )

    #: Called `ServiceID` in the documentation, this is the onion address.
    address: HiddenServiceAddress | None = None
    #: List of client authentication for a v2 address.
    client_auth: Sequence[str] = field(default_factory=list)
    #: List of client authentication for a v3 address.
    client_auth_v3: Sequence[Base32Bytes] = field(default_factory=list)
    #: Onion service key type.
    key_type: OnionServiceKeyType | None = None
    #: Onion service key bytes.
    key: Base64Bytes | None = None

    @classmethod
    def from_message(cls, message: Message) -> Self:
        """Build a structure from a received message."""
        result = {
            'status': message.status,
            'status_text': message.header,
        }  # type: dict[str, Any]

        if message.is_success:
            keywords = {}  # type: dict[str, Any]
            for sub in message.items:
                update = cls.SYNTAX.parse(sub)
                for key, val in update.items():
                    if key is not None:  # pragma: no branch
                        if key in cls.SYNTAX.kwargs_multi and key in keywords:
                            keywords[key].extend(val)
                        else:
                            keywords[key] = val

            key_spec = keywords.pop('priv', None)
            if key_spec is not None:
                key_type, key_blob = key_spec.split(':', maxsplit=1)
                keywords['key_type'] = key_type
                keywords['key'] = key_blob
            result.update(keywords)
        else:
            result['status_text'] = message.header

        return cls.adapter().validate_python(result)


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

    #: Onion address minus the ``.onion`` suffix.
    address: HiddenServiceAddress | None = None
    #: List of client private keys.
    clients: Sequence[OnionClientAuthKey] = field(default_factory=list)

    @classmethod
    def from_message(cls, message: Message) -> Self:
        """Build a structure from a received message."""
        result = {
            'status': message.status,
            'status_text': message.header,
        }  # type: dict[str, Any]

        if message.is_success:
            clients = []  # type: list[Mapping[str | None, Any]]
            for item in message.items:
                keyword = item.keyword
                syntax = cls.SYNTAXES.get(keyword)
                if syntax is not None:  # pragma: no branch
                    update = syntax.parse(item)
                    if keyword == 'CLIENT':
                        client = dict(update)
                        key_blob = client.pop('key', None)
                        if isinstance(key_blob, str):  # pragma: no branch
                            key_type, key_data = key_blob.split(':', maxsplit=1)
                            client['key_type'] = key_type
                            client['key'] = key_data
                        clients.append(client)
                    else:
                        for key, val in update.items():
                            if key is not None:  # pragma: no branch
                                result[key] = val

            result['clients'] = clients

        return cls.adapter().validate_python(result)


@dataclass(kw_only=True, slots=True)
class ReplyDropOwnership(ReplySimple):
    """A reply for a :attr:`~.CommandWord.DROPOWNERSHIP` command."""


@dataclass(kw_only=True, slots=True)
class ReplyDropTimeouts(ReplySimple):
    """A reply for a :attr:`~.CommandWord.DROPTIMEOUTS` command."""
