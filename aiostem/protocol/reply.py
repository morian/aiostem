from __future__ import annotations

import asyncio
import hashlib
import hmac
import logging
from abc import ABC, abstractmethod
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from functools import partial
from typing import TYPE_CHECKING, Annotated, Any, ClassVar, Self

from pydantic import TypeAdapter

from ..exceptions import ReplyError, ReplyStatusError
from .structures import AuthMethod, OnionClientAuthKey, OnionServiceKeyType
from .syntax import ReplySyntax, ReplySyntaxFlag
from .utils import Base32Bytes, Base64Bytes, HexBytes, StringSequence

if TYPE_CHECKING:
    from .message import BaseMessage, Message

logger = logging.getLogger(__package__)


@dataclass(kw_only=True, slots=True)
class BaseReply(ABC):
    """Base class for all replies and sub-replies."""

    ADAPTER: ClassVar[TypeAdapter[Self] | None] = None

    status: int
    status_text: str | None = None

    @classmethod
    def adapter(cls) -> TypeAdapter[Self]:
        """Get a cached type adapter to deserialize a reply."""
        if cls.ADAPTER is None:
            cls.ADAPTER = TypeAdapter(cls)
        return cls.ADAPTER

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
        return cls.adapter().validate_python(result)


@dataclass(kw_only=True, slots=True)
class _ReplyGetMap(Reply):
    """A base class for replies such as `GETCONF` and `GETINFO`."""

    #: This needs to be completed by the sub-class.
    SYNTAX: ClassVar[ReplySyntax]

    @classmethod
    def _key_value_extract(
        cls,
        messages: Iterable[BaseMessage],
    ) -> Mapping[str, Sequence[str | None] | str | None]:
        """Extract key/value pairs from `messages`."""
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


@dataclass(kw_only=True, slots=True)
class ReplySetConf(_ReplySimple):
    """A reply for a `SETCONF` command."""


@dataclass(kw_only=True, slots=True)
class ReplyResetConf(_ReplySimple):
    """A reply for a `RESETCONF` command."""


@dataclass(kw_only=True, slots=True)
class ReplyGetConf(_ReplyGetMap):
    """A reply for a `GETCONF` command."""

    SYNTAX: ClassVar[ReplySyntax] = ReplySyntax(
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

        return cls.adapter().validate_python(result)


@dataclass(kw_only=True, slots=True)
class ReplySetEvents(_ReplySimple):
    """A reply for a `SETEVENTS` command."""


@dataclass(kw_only=True, slots=True)
class ReplyAuthenticate(_ReplySimple):
    """A reply for a `AUTHENTICATE` command."""


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
        return cls.adapter().validate_python(result)


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
        return cls.adapter().validate_python(result)


@dataclass(kw_only=True, slots=True)
class ReplyGetInfo(_ReplyGetMap):
    """A reply for a `GETINFO` command."""

    SYNTAX: ClassVar[ReplySyntax] = ReplySyntax(
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
        return cls.adapter().validate_python(result)


@dataclass(kw_only=True, slots=True)
class ReplyExtendCircuit(_ReplyGetMap):
    """A reply for a `GETINFO` command."""

    SYNTAX: ClassVar[ReplySyntax] = ReplySyntax(args_min=2, args_map=(None, 'circuit'))

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

        return cls.adapter().validate_python(result)


@dataclass(kw_only=True, slots=True)
class ReplySetCircuitPurpose(_ReplySimple):
    """A reply for a `SETCIRCUITPURPOSE` command."""


@dataclass(kw_only=True, slots=True)
class ReplyAttachStream(_ReplySimple):
    """A reply for a `ATTACHSTREAM` command."""


@dataclass(kw_only=True, slots=True)
class ReplyPostDescriptor(_ReplySimple):
    """A reply for a `POSTDESCRIPTOR` command."""


@dataclass(kw_only=True, slots=True)
class ReplyRedirectStream(_ReplySimple):
    """A reply for a `REDIRECTSTREAM` command."""


@dataclass(kw_only=True, slots=True)
class ReplyCloseStream(_ReplySimple):
    """A reply for a `CLOSESTREAM` command."""


@dataclass(kw_only=True, slots=True)
class ReplyCloseCircuit(_ReplySimple):
    """A reply for a `CLOSECIRCUIT` command."""


@dataclass(kw_only=True, slots=True)
class ReplyQuit(_ReplySimple):
    """A reply for a `QUIT` command."""


@dataclass(kw_only=True, slots=True)
class ReplyUseFeature(_ReplySimple):
    """A reply for a `USEFEATURE` command."""


@dataclass(kw_only=True, slots=True)
class ReplyResolve(_ReplySimple):
    """A reply for a `RESOLVE` command."""


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
            FileNotFoundError: when there is no cookie file.

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
class ReplyLoadConf(_ReplySimple):
    """A reply for a `LOADCONF` command."""


@dataclass(kw_only=True, slots=True)
class ReplyTakeOwnership(_ReplySimple):
    """A reply for a `TAKEOWNERSHIP` command."""


@dataclass(kw_only=True, slots=True)
class ReplyAuthChallenge(Reply):
    """A reply for a `AUTHCHALLENGE` command."""

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

    server_hash: HexBytes | None = None
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
            client_nonce: The client nonce used in :class:`CommandAuthChallenge`.
            cookie: The cookie value read from the cookie file.

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
            client_nonce: The client nonce used in :class:`CommandAuthChallenge`.
            cookie: The cookie value read from the cookie file.

        Raises:
            ReplyError: when our server nonce is :obj:`None`.

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
            client_nonce: The client nonce used in :class:`CommandAuthChallenge`.
            cookie: The cookie value read from the cookie file.

        Raises:
            ReplyError: when our server nonce does not match the one we computed.

        """
        computed = self.build_server_hash(cookie, client_nonce)
        if computed != self.server_hash:
            msg = 'Server hash provided by Tor is invalid.'
            raise ReplyError(msg)


@dataclass(kw_only=True, slots=True)
class ReplyDropGuards(_ReplySimple):
    """A reply for a `DROPGUARDS` command."""


@dataclass(kw_only=True, slots=True)
class ReplyHsFetch(_ReplySimple):
    """A reply for a `HSFETCH` command."""


@dataclass(kw_only=True, slots=True)
class ReplyAddOnion(Reply):
    """A reply for a `ADD_ONION` command."""

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

    #: Called `ServiceID` in the documentation, this is the onion address minus its TLD.
    address: str | None = None
    client_auth: Sequence[str] = field(default_factory=list)
    client_auth_v3: Sequence[Base32Bytes] = field(default_factory=list)
    key_type: OnionServiceKeyType | None = None
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
class ReplyDelOnion(_ReplySimple):
    """A reply for a `DEL_ONION` command."""


@dataclass(kw_only=True, slots=True)
class ReplyHsPost(_ReplySimple):
    """A reply for a `HSPOST` command."""


@dataclass(kw_only=True, slots=True)
class ReplyOnionClientAuthAdd(_ReplySimple):
    """A reply for a `ONION_CLIENT_AUTH_ADD` command."""


@dataclass(kw_only=True, slots=True)
class ReplyOnionClientAuthRemove(_ReplySimple):
    """A reply for a `ONION_CLIENT_AUTH_REMOVE` command."""


@dataclass(kw_only=True, slots=True)
class ReplyOnionClientAuthView(Reply):
    """A reply for a `ONION_CLIENT_AUTH_VIEW` command."""

    SYNTAXES: ClassVar[Mapping[str, ReplySyntax]] = {
        'ONION_CLIENT_AUTH_VIEW': ReplySyntax(args_map=('address',)),
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

    address: str | None = None
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
class ReplyDropOwnership(_ReplySimple):
    """A reply for a `DROPOWNERSHIP` command."""


@dataclass(kw_only=True, slots=True)
class ReplyDropTimeouts(_ReplySimple):
    """A reply for a `DROPTIMEOUTS` command."""
