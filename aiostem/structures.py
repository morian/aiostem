from __future__ import annotations

import base64
import hashlib
import hmac
import logging
import secrets
import struct
from abc import ABC, abstractmethod
from collections.abc import (
    Iterator,
    Mapping,
    Sequence,
    Set as AbstractSet,
)
from contextlib import suppress
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import IntEnum, IntFlag, StrEnum
from functools import cache, cached_property, wraps
from ipaddress import IPv4Address, IPv6Address
from typing import (
    TYPE_CHECKING,
    Annotated,
    Any,
    ClassVar,
    Literal,
    Optional,
    Self,
    TypeAlias,
    Union,
    cast,
)

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives.ciphers.modes import CTR
from pydantic import (
    BeforeValidator,
    Discriminator,
    Field,
    NonNegativeInt,
    PositiveInt,
    Tag,
    TypeAdapter,
    WrapSerializer,
)
from pydantic_core import PydanticCustomError, core_schema

from .exceptions import CryptographyError, ReplySyntaxError
from .types import (
    AnyAddress,
    AnyHost,
    AnyPort,
    Base16Bytes,
    Base32Bytes,
    Base64Bytes,
    DatetimeUTC,
    Ed25519PublicKeyBase64,
    GenericRange,
    RSAPublicKeyBase64,
    TimedeltaMinutesInt,
    TimedeltaSeconds,
    X25519PublicKeyBase32,
    X25519PublicKeyBase64,
)
from .utils import (
    Base64Encoder,
    EncodedBytes,
    TrBeforeSetToNone,
    TrBeforeStringSplit,
    TrCast,
    TrEd25519PrivateKey,
    TrEd25519PublicKey,
    TrRSAPrivateKey,
    TrX25519PrivateKey,
)

if TYPE_CHECKING:
    import builtins

    from pydantic import GetCoreSchemaHandler
    from pydantic_core.core_schema import CoreSchema, SerializerFunctionWrapHandler

logger = logging.getLogger(__package__)


def _parse_block(lines: Iterator[str], kind: str, *, inner: bool = True) -> str:
    """
    Parse a block.

    Args:
        lines: An iterator on a list of data lines.
        kind: Type of block we are expected to parse.

    Keyword Args:
        inner: Return the inner content instead of the full content.

    Returns:
        The full content (newline delimited) or the inner content (concatenated).

    """
    exp_head = f'-----BEGIN {kind}-----'
    exp_tail = f'-----END {kind}-----'
    results = []  # type: list[str]

    line = next(lines)
    if line != exp_head:
        msg = f'Unexpected block start for {kind}: {line}'
        raise ReplySyntaxError(msg)

    results.append(line)
    while True:
        line = next(lines)
        results.append(line)
        if line == exp_tail:
            break

    if inner:
        return ''.join(results[1:-1])
    return '\n'.join(results)


class AuthMethod(StrEnum):
    """Known authentication methods on the control port.."""

    #: No authentication is required.
    NULL = 'NULL'

    #: A simple password authentication (hashed in the configuration file).
    HASHEDPASSWORD = 'HASHEDPASSWORD'

    #: Provide the content of a cookie we read on the file-system.
    COOKIE = 'COOKIE'

    #: Provide a proof that we know the value of the cookie on the file-system.
    SAFECOOKIE = 'SAFECOOKIE'


class CircuitBuildFlags(StrEnum):
    """Known flags when building a new circuit."""

    #: One-hop circuit, used for tunneled directory conns.
    ONEHOP_TUNNEL = 'ONEHOP_TUNNEL'
    #: Internal circuit, not to be used for exiting streams.
    IS_INTERNAL = 'IS_INTERNAL'
    #: This circuit must use only high-capacity nodes.
    NEED_CAPACITY = 'NEED_CAPACITY'
    #: This circuit must use only high-uptime nodes.
    NEED_UPTIME = 'NEED_UPTIME'


class CircuitCloseReason(StrEnum):
    """Known reasons why a circuit can be closed."""

    #: No reason given.
    NONE = 'NONE'
    #: Tor protocol violation.
    PROTOCOL = 'PROTOCOL'
    #: Internal error.
    INTERNAL = 'INTERNAL'
    #: A client sent a TRUNCATE command.
    REQUESTED = 'REQUESTED'
    #: Not currently operating; trying to save bandwidth.
    HIBERNATING = 'HIBERNATING'
    #: Out of memory, sockets, or circuit IDs.
    RESOURCELIMIT = 'RESOURCELIMIT'
    #: Unable to reach relay.
    CONNECTFAILED = 'CONNECTFAILED'
    #: Connected to relay, but its OR identity was not as expected.
    OR_IDENTITY = 'OR_IDENTITY'
    #: The OR connection that was carrying this circuit died.
    CHANNEL_CLOSED = 'CHANNEL_CLOSED'
    #: The circuit has expired for being dirty or old.
    FINISHED = 'FINISHED'
    #: Circuit construction took too long.
    TIMEOUT = 'TIMEOUT'
    #: The circuit was destroyed w/o client TRUNCATE.
    DESTROYED = 'DESTROYED'
    #: Request for unknown hidden service.
    NOSUCHSERVICE = 'NOSUCHSERVICE'
    #: Not enough nodes to make circuit.
    NOPATH = 'NOPATH'
    #: As "TIMEOUT", except that we had left the circuit open for measurement purposes.
    #:
    #: This is to see how long it would take to finish.
    MEASUREMENT_EXPIRED = 'MEASUREMENT_EXPIRED'
    #: Closing a circuit to an introduction point that has become redundant.
    #:
    #: Since some other circuit opened in parallel with it has succeeded.
    IP_NOW_REDUNDANT = 'IP_NOW_REDUNDANT'


class CircuitEvent(StrEnum):
    """List of existing circuit events."""

    #: Circuit cannibalized.
    CANNIBALIZED = 'CANNIBALIZED'
    #: Circuit purpose or HS-related state changed.
    PURPOSE_CHANGED = 'PURPOSE_CHANGED'


@dataclass(kw_only=True, slots=True)
class CircuitHiddenServicePow:
    """
    Hidden service PoW effort attached to a circuit.

    See Also:
        https://spec.torproject.org/hspow-spec/index.html

    """

    #: The type of proof of work system used (currently ``v1``).
    type: str
    #: Proof of work effort associated with this circuit.
    effort: NonNegativeInt


class CircuitHiddenServiceState(StrEnum):
    """State of a hidden service circuit."""

    HSCI_CONNECTING = 'HSCI_CONNECTING'
    HSCI_INTRO_SENT = 'HSCI_INTRO_SENT'
    HSCI_DONE = 'HSCI_DONE'
    HSCR_CONNECTING = 'HSCR_CONNECTING'
    HSCR_ESTABLISHED_IDLE = 'HSCR_ESTABLISHED_IDLE'
    HSCR_ESTABLISHED_WAITING = 'HSCR_ESTABLISHED_WAITING'
    HSCR_JOINED = 'HSCR_JOINED'
    HSSI_CONNECTING = 'HSSI_CONNECTING'
    HSSI_ESTABLISHED = 'HSSI_ESTABLISHED'
    HSSR_CONNECTING = 'HSSR_CONNECTING'
    HSSR_JOINED = 'HSSR_JOINED'


class CircuitPurpose(StrEnum):
    """All possible purposes for circuits."""

    #: Circuit kept open for padding.
    CIRCUIT_PADDING = 'CIRCUIT_PADDING'
    #: Linked conflux circuit.
    CONFLUX_LINKED = 'CONFLUX_LINKED'
    #: Unlinked conflux circuit.
    CONFLUX_UNLINKED = 'CONFLUX_UNLINKED'
    #: Circuit made by controller.
    CONTROLLER = 'CONTROLLER'
    #: General-purpose client.
    GENERAL = 'GENERAL'
    #: Hidden service client, connection to an introduction point.
    HS_CLIENT_INTRO = 'HS_CLIENT_INTRO'
    #: Hidden service client, fetching HS descriptor.
    HS_CLIENT_HSDIR = 'HS_CLIENT_HSDIR'
    #: Hidden service client, connection to a rendezvous point.
    HS_CLIENT_REND = 'HS_CLIENT_REND'
    #: Hidden service, introduction point.
    HS_SERVICE_INTRO = 'HS_SERVICE_INTRO'
    #: Hidden service, uploading HS descriptor.
    HS_SERVICE_HSDIR = 'HS_SERVICE_HSDIR'
    #: Hidden service, connection as a rendezvous point.
    HS_SERVICE_REND = 'HS_SERVICE_REND'
    #: Hidden service, pre-built vanguard circuit.
    HS_VANGUARDS = 'HS_VANGUARDS'
    #: Measuring circuit timeout.
    MEASURE_TIMEOUT = 'MEASURE_TIMEOUT'
    #: Path-bias testing circuit.
    PATH_BIAS_TESTING = 'PATH_BIAS_TESTING'
    #: A controller should never see these, actually.
    SERVER = 'SERVER'
    #: Testing circuit.
    TESTING = 'TESTING'


class CircuitStatus(StrEnum):
    """All possible statuses for a circuit."""

    #: Circuit ID assigned to new circuit.
    LAUNCHED = 'LAUNCHED'
    #: All hops finished, can now accept streams.
    BUILT = 'BUILT'
    #: All hops finished, waiting to see if a circuit with a better guard will be usable.
    GUARD_WAIT = 'GUARD_WAIT'
    #: One more hop has been completed.
    EXTENDED = 'EXTENDED'
    #: Circuit closed (was not built).
    FAILED = 'FAILED'
    #: Circuit closed (was built).
    CLOSED = 'CLOSED'


@dataclass(kw_only=True, slots=True)
class ClockSkewSource:
    """
    Source of a clock skew, properly parsed.

    Note:
        This is to be used with :class:`StatusGeneralClockSkew`.

    """

    #: Name of the source.
    name: Literal['DIRSERV', 'NETWORKSTATUS', 'OR', 'CONSENSUS']

    #: Optional address of the source (:obj:`None` with ``CONSENSUS``).
    address: TcpAddressPort | None = None


class DescriptorPurpose(StrEnum):
    """All possible purposes for a descriptor."""

    CONTROLLER = 'controller'
    GENERAL = 'general'
    BRIDGE = 'bridge'


@dataclass(kw_only=True, slots=True)
class Ed25519CertificateStruct:
    """
    Tor's representation of an ed25519 certificate.

    See Also:
        https://github.com/torproject/torspec/blob/main/cert-spec.txt

    """

    #: Version of the certificate as used by Tor.
    version: PositiveInt

    #: Raw content for this certificate.
    content: Base64Bytes


@dataclass(kw_only=True, slots=True)
class Ed25519Certificate(ABC):
    """
    Tor's representation of an ed25519 certificate.

    See Also:
        https://github.com/torproject/torspec/blob/main/cert-spec.txt

    """

    #: Version of the certificate as used by Tor.
    version: PositiveInt

    @classmethod
    def __get_pydantic_core_schema__(
        cls,
        source: type[Any],
        handler: GetCoreSchemaHandler,
    ) -> CoreSchema:
        """Declare schema and validator for an ed25519 certificate."""
        return core_schema.no_info_before_validator_function(
            function=cls._pydantic_validator,
            schema=handler(source),
        )

    @classmethod
    def _pydantic_validator(cls, value: Any) -> Any:
        """Build a new instance from any value."""
        if isinstance(value, bytes):
            version = value[0]
            match version:
                case 1:
                    value = Ed25519CertificateV1.bytes_to_mapping(value)
                case _:  # pragma: no cover
                    msg = f'Unknown ed25519 certificate version: {version}'
                    raise ReplySyntaxError(msg)
        return value

    @classmethod
    @abstractmethod
    def bytes_to_mapping(cls, value: bytes) -> Mapping[str, Any]:
        """Build a new instance from bytes."""


class Ed25519CertPurpose(IntEnum):
    """All types of ed25519 certificates."""

    #: Link key certificate certified by RSA1024 identity.
    LINK = 1
    #: RSA1024 Identity certificate, self-signed.
    IDENTITY = 2
    #: RSA1024 AUTHENTICATE cell link certificate, signed with RSA1024 key.
    AUTHENTICATE = 3
    #: Ed25519 signing key, signed with identity key.
    ED25519_SIGNING = 4
    #: TLS link certificate signed with ed25519 signing key.
    LINK_CERT = 5
    #: Ed25519 AUTHENTICATE cell key, signed with ed25519 signing key.
    ED25519_AUTHENTICATE = 6
    #: Ed25519 identity, signed with RSA identity.
    ED25519_IDENTITY = 7
    #: Hidden service V3 signing key.
    HS_V3_DESC_SIGNING = 8
    #: Hidden service V3 intro authentication key.
    HS_V3_INTRO_AUTH = 9
    #: ``ntor-onion-key-crosscert`` in a server descriptor.
    NTOR_ONION_KEY = 10
    #: Cross-certification of the encryption key using the descriptor signing key.
    HS_V3_NTOR_ENC = 11


class Ed25519CertExtensionFlags(IntFlag):
    """Available flags on a Ed25519CertExtension."""

    #: The extension affects whether the certificate is valid.
    AFFECTS_VALIDATION = 1


class Ed25519CertExtensionType(IntEnum):
    """Available types of Ed25519CertExtension."""

    #: There is a signing key bundled with this certificate.
    HAS_SIGNING_KEY = 4


@dataclass(kw_only=True, slots=True)
class BaseEd25519CertExtension(ABC):
    """Describe a single ed25519 certificate extension."""

    #: Type of the current extension.
    type: Ed25519CertExtensionType | NonNegativeInt

    #: Set of flags for this extension.
    flags: Ed25519CertExtensionFlags

    @classmethod
    def __get_pydantic_core_schema__(
        cls,
        source: builtins.type[Any],
        handler: GetCoreSchemaHandler,
    ) -> CoreSchema:
        """Declare schema and validator for this extension."""
        return core_schema.no_info_before_validator_function(
            function=cls._pydantic_validator,
            schema=handler(source),
        )

    @classmethod
    @abstractmethod
    def _pydantic_validator(cls, value: Any) -> Any:
        """Update the fields from this extension."""

    @classmethod
    def bytes_to_mapping_list(cls, raw: bytes) -> Sequence[Mapping[str, Any]]:
        """Parse and extract extension structures from ``raw``."""
        results = []  # type: list[dict[str, Any]]
        count = raw[0]
        pos = 1
        for _ in range(count):
            length, kind, flags = struct.unpack_from('!HBB', raw, pos)
            data = raw[pos + 4 : pos + 4 + length]
            results.append({'type': kind, 'flags': flags, 'data': data})
            pos += length + 4
        return results


@dataclass(kw_only=True, slots=True)
class Ed25519CertExtensionSigningKey(BaseEd25519CertExtension):
    """Describe an unknown ed25519 certificate extension."""

    #: Type of extension.
    type: Literal[Ed25519CertExtensionType.HAS_SIGNING_KEY] = (
        Ed25519CertExtensionType.HAS_SIGNING_KEY
    )

    #: Public ed25519 signing key as part of this extension.
    key: Ed25519PublicKeyBase64

    @classmethod
    def _pydantic_validator(cls, value: Any) -> Any:
        """Update the fields from this extension."""
        if isinstance(value, Mapping):
            value = {**value, 'key': value.get('data')}
        return value


@dataclass(kw_only=True, slots=True)
class Ed25519CertExtensionUnkown(BaseEd25519CertExtension):
    """Describe an unknown ed25519 certificate extension."""

    #: Raw data for this mysterious unknown extension.
    data: Base64Bytes

    @classmethod
    def _pydantic_validator(cls, value: Any) -> Any:
        """Update the fields from this extension."""
        return value


def _discriminate_ed25519_cert_extension(v: Any) -> int:
    """Find how to discriminate the provided key."""
    discriminant = 0

    match v:
        case BaseEd25519CertExtension():
            discriminant = v.type
        case Mapping():  # pragma: no branch
            discriminant = v.get('type', 0)

    if discriminant not in set(Ed25519CertExtensionType):
        discriminant = 0
    return discriminant


Ed25519CertExtension: TypeAlias = Annotated[
    Union[  # noqa: UP007
        Annotated[Ed25519CertExtensionSigningKey, Tag(4)],
        Annotated[Ed25519CertExtensionUnkown, Tag(0)],
    ],
    Discriminator(_discriminate_ed25519_cert_extension),
]


@dataclass(kw_only=True)
class Ed25519CertificateV1(Ed25519Certificate):
    """Version 1 of tor's representation of an ed25519 certificate."""

    #: Length of the Ed25519 public key.
    ED25519_KEY_LENGTH: ClassVar[int] = 32
    #: Length of the Ed25519 signature.
    ED25519_SIGNATURE_LENGTH: ClassVar[int] = 64

    #: Version of the certificate as used by Tor.
    version: Literal[1] = 1

    #: Purpose of this ed25519 certificate.
    purpose: Ed25519CertPurpose

    #: Expiration date for this certificate.
    expiration: DatetimeUTC

    #: Ed25519 public key.
    key: Ed25519PublicKeyBase64 | None

    #: List of ed25519 extensions used along with this certificate.
    extensions: Sequence[Ed25519CertExtension]

    #: Ed25519 certificate signature.
    signature: Base64Bytes

    #: Raw content of everything covered by the signature.
    signed_content: Base64Bytes

    @classmethod
    def bytes_to_mapping(cls, data: bytes) -> Mapping[str, Any]:
        """Build a new instance from bytes."""
        extlen = len(data) - 39 - cls.ED25519_SIGNATURE_LENGTH
        fmt = f'!BBIB{cls.ED25519_KEY_LENGTH}s{extlen}s{cls.ED25519_SIGNATURE_LENGTH}s'
        ver, pur, exp, kt, kd, ext, sig = struct.unpack_from(fmt, data)
        signed_content = data[: -cls.ED25519_SIGNATURE_LENGTH]
        return {
            'version': ver,
            'purpose': pur,
            'expiration': 3600 * exp,
            'key': kd if kt == 1 else None,
            'extensions': BaseEd25519CertExtension.bytes_to_mapping_list(ext),
            'signature': sig,
            'signed_content': signed_content,
        }

    @cached_property
    def can_validate(self) -> bool:
        """
        Whether this certificate can be validated.

        This returns :obj:`False` when any extension we do not understand has
        a :attr:`~Ed25519CertExtensionFlags.AFFECTS_VALIDATION` flag.
        """
        for ext in self.extensions:
            if ext.flags & Ed25519CertExtensionFlags.AFFECTS_VALIDATION:
                return False
        return True

    @property
    def expired(self) -> bool:
        """Tell whether this certificate has expired."""
        return bool(datetime.now(UTC) > self.expiration)

    @cached_property
    def signing_key(self) -> Ed25519PublicKey | None:
        """
        Get the signing key used with this certificate.

        This works by looking up for this key in the parsed extensions.
        This key can then be used to check for this certificate's signature.

        Returns:
            The public key used to verify this certificate, if any.

        """
        for ext in self.extensions:
            if isinstance(ext, Ed25519CertExtensionSigningKey):
                return ext.key
        return None

    def raise_for_invalid_signature(self, key: Ed25519PublicKey) -> None:
        """
        Check this certificate's signature.

        Args:
            key: A public key to check this certificate against.

        Raises:
            CryptographyError: When the signature is invalid.

        """
        if not self.can_validate:
            msg = 'Ed25519 certificate has an unknown extension affecting validation.'
            raise CryptographyError(msg)

        try:
            key.verify(self.signature, self.signed_content)
        except InvalidSignature as exc:
            msg = 'Ed25519 certificate has an invalid signature'
            raise CryptographyError(msg) from exc


class Feature(StrEnum):
    """All known features Tor supports."""

    #: Ask for extended information while receiving events.
    EXTENDED_EVENTS = 'EXTENDED_EVENTS'
    #: Replaces ServerID with LongName in events and :attr:`~.CommandWord.GETINFO` results.
    VERBOSE_NAMES = 'VERBOSE_NAMES'


class GuardEventStatus(StrEnum):
    """Possible statuses for a :attr:`~.EventWord.GUARD` event."""

    #: This node was not previously used as a guard.
    #:
    #: Now we have picked it as one.
    NEW = 'NEW'

    #: This node is one we previously picked as a guard.
    #:
    #: We no longer consider it to be a member of our guard list.
    DROPPED = 'DROPPED'

    #: The guard now seems to be reachable.
    UP = 'UP'

    #: The guard now seems to be unreachable.
    DOWN = 'DOWN'

    #: This node is now unusable as a guard.
    #:
    #: Because of flags set in the consensus and/or values in the configuration.
    BAD = 'BAD'

    #: This node is removed from the layer2 guard set.
    #:
    #: This layer2 guard has expired or got removed from the consensus.
    BAD_L2 = 'BAD_L2'

    #: This node is now usable as a guard.
    #:
    #: Because of flags set in the consensus and/or values in the configuration.
    GOOD = 'GOOD'


@dataclass(kw_only=True, slots=True)
class HsDescV3PowParams:
    """
    PoW parameters as parsed from a hidden service v3 descriptor.

    See Also:
        https://onionservices.torproject.org/technology/pow/

    """

    #: The type of PoW system used.
    type: str
    #: A random seed that should be used as the input to the PoW hash function.
    seed: Base64Bytes
    #: An effort value that clients should aim for when contacting the service.
    suggested_effort: NonNegativeInt
    #: A timestamp after which the above seed expires.
    expiration: DatetimeUTC


class HiddenServiceVersion(IntEnum):
    """Any valid onion hidden service version."""

    ONION_V2 = 2
    ONION_V3 = 3


class BaseHiddenServiceAddress(str):
    """Base class for all hidden service addresses."""

    #: Length of the address without the top-level domain.
    ADDRESS_LENGTH: ClassVar[int]

    #: Regular expression pattern used to match the address.
    ADDRESS_PATTERN: ClassVar[str]

    #: Suffix and top-level domain for onion addresses.
    ADDRESS_SUFFIX: ClassVar[str] = '.onion'

    #: Length of the onion suffix.
    ADDRESS_SUFFIX_LENGTH: ClassVar[int] = len(ADDRESS_SUFFIX)

    #: Hidden service version for the current address.
    VERSION: ClassVar[HiddenServiceVersion]

    @classmethod
    def strip_suffix(cls, address: str) -> str:
        """
        Strip the domain suffix from the provided string.

        Args:
            address: a raw string encoding a hidden service address

        Returns:
            The address without its ``.onion`` suffix.

        """
        return address.removesuffix(cls.ADDRESS_SUFFIX)


class HiddenServiceAddressV2(BaseHiddenServiceAddress):
    """Represent a V2 hidden service."""

    ADDRESS_LENGTH: ClassVar[int] = 16
    ADDRESS_PATTERN: ClassVar[str] = '^[a-z2-7]{16}([.]onion)?$'
    VERSION: ClassVar[HiddenServiceVersion] = HiddenServiceVersion.ONION_V2

    @classmethod
    def __get_pydantic_core_schema__(
        cls,
        source: type[Any],
        handler: GetCoreSchemaHandler,
    ) -> CoreSchema:
        """Declare schema and validator for a v2 hidden service address."""
        return core_schema.union_schema(
            choices=[
                core_schema.is_instance_schema(cls),
                core_schema.no_info_after_validator_function(
                    function=cls.from_string,
                    schema=core_schema.str_schema(
                        pattern=cls.ADDRESS_PATTERN,
                        min_length=cls.ADDRESS_LENGTH,
                        max_length=cls.ADDRESS_LENGTH + cls.ADDRESS_SUFFIX_LENGTH,
                        ref='onion_v2',
                        strict=True,
                    ),
                ),
            ]
        )

    @classmethod
    def from_string(cls, domain: str) -> Self:
        """
        Build from a user string.

        Args:
            domain: A valid ``.onion`` domain, with or without its TLD.

        Returns:
            A valid V2 domain without its ``.onion`` suffix.

        """
        return cls(cls.strip_suffix(domain))


class HiddenServiceAddressV3(BaseHiddenServiceAddress):
    """Represent a V3 hidden service."""

    ADDRESS_CHECKSUM: ClassVar[bytes] = b'.onion checksum'
    ADDRESS_LENGTH: ClassVar[int] = 56
    ADDRESS_PATTERN: ClassVar[str] = '^[a-z2-7]{56}([.]onion)?$'
    VERSION: ClassVar[HiddenServiceVersion] = HiddenServiceVersion.ONION_V3

    @classmethod
    def __get_pydantic_core_schema__(
        cls,
        source: type[Any],
        handler: GetCoreSchemaHandler,
    ) -> CoreSchema:
        """Declare schema and validator for a v3 hidden service address."""
        return core_schema.union_schema(
            choices=[
                core_schema.is_instance_schema(cls),
                core_schema.no_info_after_validator_function(
                    function=cls.from_string,
                    schema=core_schema.str_schema(
                        pattern=cls.ADDRESS_PATTERN,
                        min_length=cls.ADDRESS_LENGTH,
                        max_length=cls.ADDRESS_LENGTH + cls.ADDRESS_SUFFIX_LENGTH,
                        ref='onion_v3',
                        strict=True,
                    ),
                ),
            ]
        )

    @classmethod
    def from_string(cls, domain: str) -> Self:
        """
        Build from a user string.

        Args:
            domain: A valid ``.onion`` domain, with or without its TLD.

        Raises:
            PydanticCustomError: On invalid onion V3 domain.

        Returns:
            A valid V3 domain without its ``.onion`` suffix.

        """
        address = cls.strip_suffix(domain)
        data = base64.b32decode(address, casefold=True)
        pkey = data[00:32]
        csum = data[32:34]
        version = data[34]
        if version == cls.VERSION:
            blob = cls.ADDRESS_CHECKSUM + pkey + bytes([cls.VERSION])
            digest = hashlib.sha3_256(blob).digest()
            if digest.startswith(csum):
                return cls(address)

        raise PydanticCustomError(
            'invalid_onion_v3',
            f'Invalid v3 hidden service address: "{address}"',
            {'address': address},
        )

    @cached_property
    def public_key(self) -> Ed25519PublicKey:
        """
        Get the ed25519 public key for this domain.

        Returns:
            The ed25519 public key associated with this v3 onion domain.

        """
        data = base64.b32decode(self, casefold=True)
        return Ed25519PublicKey.from_public_bytes(data[00:32])


class HsDescAction(StrEnum):
    """Possible actions in a :attr:`~.EventWord.HS_DESC` event."""

    CREATED = 'CREATED'
    FAILED = 'FAILED'
    IGNORE = 'IGNORE'
    RECEIVED = 'RECEIVED'
    REQUESTED = 'REQUESTED'
    UPLOAD = 'UPLOAD'
    UPLOADED = 'UPLOADED'


@dataclass(kw_only=True, slots=True)
class HsDescAuthCookie:
    """An authentication cookie used for onion v2."""

    #: Length of the random key generated here.
    REND_DESC_COOKIE_LEN: ClassVar[int] = 16
    #: Length of the base64 value without the useless padding.
    REND_DESC_COOKIE_LEN_BASE64: ClassVar[int] = 22
    #: Length of the base64 value with the useless padding.
    REND_DESC_COOKIE_LEN_EXT_BASE64: ClassVar[int] = 24

    #: Allowed values describing the type of authentication cookie we have.
    auth_type: Literal[HsDescAuthTypeInt.BASIC_AUTH, HsDescAuthTypeInt.STEALTH_AUTH]

    #: Raw cookie value as 16 random bytes.
    cookie: bytes

    def __str__(self) -> str:
        """Get the string representation of this authentication cookie."""
        raw = list(self.cookie)
        raw.append((int(self.auth_type) - 1) << 4)
        return base64.b64encode(bytes(raw)).decode('ascii')

    @classmethod
    def __get_pydantic_core_schema__(
        cls,
        source: type[Any],
        handler: GetCoreSchemaHandler,
    ) -> CoreSchema:
        """Declare schema and validator for an onion v2 authentication cookie."""
        return core_schema.union_schema(
            choices=[
                # Case were we already have a nice structure.
                handler(source),
                # Case where we are building from a base64-encoded string.
                core_schema.chain_schema(
                    steps=[
                        core_schema.str_schema(strict=True),
                        core_schema.no_info_before_validator_function(
                            function=cls.from_string,
                            schema=handler(source),
                        ),
                    ],
                ),
                # Case where we are building from raw bytes.
                core_schema.chain_schema(
                    steps=[
                        core_schema.bytes_schema(strict=True),
                        core_schema.no_info_before_validator_function(
                            function=cls.from_bytes,
                            schema=handler(source),
                        ),
                    ],
                ),
            ],
            serialization=core_schema.to_string_ser_schema(when_used='always'),
        )

    @classmethod
    def from_string(cls, value: str) -> Self:
        """Get the bytes from a standard string."""
        # Add the padding to make ``b64decode`` happy.
        if len(value) == cls.REND_DESC_COOKIE_LEN_BASE64:
            value += 'A='
        return cls.from_bytes(base64.b64decode(value))

    @classmethod
    def from_bytes(cls, value: bytes) -> Self:
        """Build a new instance from raw bytes."""
        auth_byte = value[cls.REND_DESC_COOKIE_LEN] >> 4
        auth_type = (
            HsDescAuthTypeInt.BASIC_AUTH if auth_byte == 0 else HsDescAuthTypeInt.STEALTH_AUTH
        )  # type: Literal[HsDescAuthTypeInt.BASIC_AUTH, HsDescAuthTypeInt.STEALTH_AUTH]
        return cls(auth_type=auth_type, cookie=value[: cls.REND_DESC_COOKIE_LEN])

    @classmethod
    def generate(
        cls,
        auth_type: Literal[HsDescAuthTypeInt.BASIC_AUTH, HsDescAuthTypeInt.STEALTH_AUTH],
    ) -> Self:
        """Generate a new authentication cookie."""
        return cls(auth_type=auth_type, cookie=secrets.token_bytes(cls.REND_DESC_COOKIE_LEN))


class HsDescAuthTypeInt(IntEnum):
    """Integer values for :class:`HsDescAuthTypeStr`."""

    NO_AUTH = 0
    BASIC_AUTH = 1
    STEALTH_AUTH = 2


class HsDescAuthTypeStr(StrEnum):
    """Possible values for AuthType in a :attr:`~.EventWord.HS_DESC` event."""

    BASIC_AUTH = 'BASIC_AUTH'
    NO_AUTH = 'NO_AUTH'
    STEALTH_AUTH = 'STEALTH_AUTH'
    UNKNOWN = 'UNKNOWN'


@dataclass(kw_only=True, slots=True)
class HsDescClientAuth:
    """Client authentication for onion v2."""

    #: Client name for this authentication.
    name: str

    #: The authentication cookie, generated by Tor when :obj:`None`.
    cookie: HsDescAuthCookie | None = None


#: Annotated structure for hidden service v2 client authentication.
HsDescClientAuthV2: TypeAlias = Annotated[
    HsDescClientAuth,
    TrBeforeStringSplit(
        dict_keys=('name', 'cookie'),
        maxsplit=1,
        separator=':',
    ),
]
#: Annotated structure for hidden service v3 client authentication.
HsDescClientAuthV3: TypeAlias = X25519PublicKeyBase32


class HsDescFailReason(StrEnum):
    """Possible values for ``REASON`` in a :attr:`~.EventWord.HS_DESC` event."""

    #: Descriptor was retrieved, but found to be unparsable.
    BAD_DESC = 'BAD_DESC'
    #: HS descriptor with given identifier was not found.
    NOT_FOUND = 'NOT_FOUND'
    #: No suitable HSDir were found for the query.
    QUERY_NO_HSDIR = 'QUERY_NO_HSDIR'
    #: Query for this service is rate-limited.
    QUERY_RATE_LIMITED = 'QUERY_RATE_LIMITED'
    #: Query was rejected by HS directory.
    QUERY_REJECTED = 'QUERY_REJECTED'
    #: Nature of failure is unknown.
    UNEXPECTED = 'UNEXPECTED'
    #: Descriptor was rejected by HS directory.
    UPLOAD_REJECTED = 'UPLOAD_REJECTED'


@dataclass(kw_only=True)
class HsDescBase:
    """Hidden service descriptor base class."""

    #: Cached adapter used while deserializing the message.
    ADAPTER: ClassVar[TypeAdapter[Self] | None] = None

    @classmethod
    def adapter(cls) -> TypeAdapter[Self]:
        """Get a cached type adapter to deserialize this object."""
        if cls.ADAPTER is None:  # pragma: no branch
            cls.ADAPTER = TypeAdapter(cls)
        return cls.ADAPTER


@dataclass(kw_only=True, slots=True)
class HsIntroPointV2(HsDescBase):
    """A single introduction point for a v2 descriptor."""

    #: The identifier of this introduction point.
    introduction_point: Base32Bytes

    #: The IP address of this introduction point.
    ip: IPv4Address

    #: The TCP port on which the introduction point is listening for incoming requests.
    onion_port: AnyPort

    #: The public key that can be used to encrypt messages to this introduction point.
    onion_key: RSAPublicKeyBase64

    #: The public key that can be used to encrypt messages to the hidden service.
    service_key: RSAPublicKeyBase64

    @classmethod
    def text_to_mapping_list(cls, body: str) -> Sequence[Mapping[str, Any]]:
        """
        Parse ``body`` to a list of raw introduction points mappings.

        Args:
            body: The raw content of the descriptors.

        Returns:
            A list of mappings for introduction points.

        """
        current = {}  # type: dict[str, Any]
        intros = []  # type: list[dict[str, Any]]

        lines = iter(body.splitlines())
        with suppress(StopIteration):
            while True:
                line = next(lines)
                if not len(line):
                    continue

                key, *args = line.split(' ', maxsplit=1)
                match key:
                    case 'introduction-point':
                        if current:
                            intros.append(current)
                        current = {'introduction_point': args[0]}

                    case 'ip-address':
                        current['ip'] = args[0]

                    case 'onion-port':
                        current['onion_port'] = args[0]

                    case 'onion-key':
                        current['onion_key'] = _parse_block(lines, 'RSA PUBLIC KEY')

                    case 'service-key':
                        current['service_key'] = _parse_block(lines, 'RSA PUBLIC KEY')

                    case _:  # pragma: no cover
                        content = args[0] if len(args) else '__NONE__'
                        logger.warning('Unhandled HsIntroPointV2 key %s: %s', key, content)

        if current:  # pragma: no branch
            intros.append(current)
        return intros


@dataclass(kw_only=True)
class HsDescV2(HsDescBase):
    """Hidden service descriptor for v2 onions."""

    #: Adapter used to list introduction points.
    INTROS_ADAPTER: ClassVar[TypeAdapter[Sequence[HsIntroPointV2]]] = TypeAdapter(
        Sequence[HsIntroPointV2]
    )

    #: Periodically changing identifier of 160 bits.
    descriptor_id: Base32Bytes

    #: The version number of this descriptor's format.
    version: PositiveInt

    #: Permanent public RSA key linked to this onion service.
    permanent_key: RSAPublicKeyBase64

    #: Secret id so we can verify that the signed descriptor belongs to "descriptor-id".
    secret_id_part: Base32Bytes

    #: A timestamp when this descriptor has been created.
    published: DatetimeUTC

    #: A comma-separated list of recognized and permitted version numbers.
    #:
    #: For use in INTRODUCE cells.
    protocol_versions: Annotated[AbstractSet[int], TrBeforeStringSplit(separator=',')]

    #: Content of the introduction points.
    introduction_points_bytes: Base64Bytes

    #: Computed digest of this descriptor (everything except the signature).
    #:
    #: This field is computed and not part of the original descriptor.
    #: It is used to check the signature against the ``permanent_key``.
    computed_digest: Base64Bytes

    #: A signature of all fields with the service's private key.
    signature: Base64Bytes

    def introduction_points(
        self,
        auth_cookie: HsDescAuthCookie | None = None,
    ) -> Sequence[HsIntroPointV2]:
        """
        Parse introduction points for this descriptor.

        Note that decryption is not implemented and will probably never be since onion v2
        has been deprecated for a long time now. Instead it raises :exc:`NotImplementedError`.

        Args:
            auth_cookie: Optional authentication cookie used to decrypt introduction points.

        Raises:
            NotImplementedError: When ``auth_cookie`` is not :obj:`None`.

        Returns:
            A list of introduction points used in this descriptor.

        """
        # This will not be implemented since OnionV2 has been deprecated for a long time.
        if auth_cookie is not None:
            msg = 'Authentication cookie for V2 descriptor is not yet implemented.'
            raise NotImplementedError(msg)

        body = self.introduction_points_bytes.decode('ascii')
        intros = HsIntroPointV2.text_to_mapping_list(body)
        return self.INTROS_ADAPTER.validate_python(intros)

    @classmethod
    def text_to_mapping(cls, body: str) -> Mapping[str, Any]:
        """
        Parse ``body`` to a raw descriptor to mapping.

        Args:
            body: The content of the descriptor.

        Returns:
            A map suitable for parsing from pydantic.

        """
        digest: bytes | None
        lines_raw = body.splitlines()
        try:
            pos = lines_raw.index('signature')
            buffer = '\n'.join(lines_raw[: pos + 1]) + '\n'
            digest = hashlib.sha1(buffer.encode('ascii')).digest()  # noqa: S324
        except ValueError:  # pragma: no cover
            digest = None

        results = {'computed_digest': digest}  # type: dict[str, Any]
        lines = iter(lines_raw)
        with suppress(StopIteration):
            while True:
                line = next(lines)
                # Ignore any empty line not part of an item.
                if not len(line):  # pragma: no cover
                    continue

                key, *args = line.split(' ', maxsplit=1)
                match key:
                    case 'rendezvous-service-descriptor':
                        results['descriptor_id'] = args[0]

                    case 'version':
                        results['version'] = args[0]

                    case 'permanent-key':
                        block = _parse_block(lines, 'RSA PUBLIC KEY')
                        results['permanent_key'] = block

                    case 'secret-id-part':
                        results['secret_id_part'] = args[0]

                    case 'publication-time':
                        results['published'] = args[0]

                    case 'protocol-versions':
                        results['protocol_versions'] = args[0]

                    case 'introduction-points':
                        block = _parse_block(lines, 'MESSAGE')
                        results['introduction_points_bytes'] = block

                    case 'signature':
                        block = _parse_block(lines, 'SIGNATURE')
                        results['signature'] = block

                    case _:  # pragma: no cover
                        content = args[0] if len(args) else '__NONE__'
                        logger.warning('Unhandled HsDescV2 key %s: %s', key, content)

        return results

    @classmethod
    def from_text(cls, body: str) -> Self:
        """
        Build a HsDescV2 object from a text descriptor.

        Args:
            body: The content of the descriptor.

        Returns:
            A parsed descriptor.

        """
        return cls.adapter().validate_python(cls.text_to_mapping(body))

    def raise_for_invalid_signature(self) -> None:
        """
        Check the provided signature.

        This does not use cryptography's signature mechanism since Tor seems to have a
        specific signature method, not implemented by cryptography.

        An issue was opened by stem on this matter:
           - https://github.com/pyca/cryptography/issues/3713

        Raises:
            CryptographyError: When the certificate is improperly signed.

        Returns:
            Whether the signature is correct for the current descriptor.

        """
        key_nums = self.permanent_key.public_numbers()
        blocklen = len(self.signature)
        signature_int = int.from_bytes(self.signature, byteorder='big')
        decrypted_int = pow(signature_int, key_nums.e, key_nums.n)

        # Format for ``decrypted``:
        # 1 byte:  0x00
        # 1 byte:  0x01 (block identifier, always 1)
        # N bytes: 0xff (padding)
        # 1 byte:  0x00 (separator)
        # M bytes: message
        decrypted = decrypted_int.to_bytes(blocklen, byteorder='big')
        if not decrypted.startswith(b'\x00\x01'):
            msg = 'Decrypted certificate signature has an invalid format.'
            raise CryptographyError(msg)

        # This part is not covered since that would mean building and signing
        # a new hidden service v2, which has been deprecated for a while now.
        message = decrypted[2:].lstrip(b'\xff')
        if not message.startswith(b'\x00'):
            msg = 'Decrypted certificate signature has an invalid format.'
            raise CryptographyError(msg)

        if self.computed_digest != message[1:]:
            msg = 'Invalid certificate signature.'
            raise CryptographyError(msg)


@dataclass(kw_only=True, slots=True)
class HsDescV3AuthClient:
    """
    Entry for a single authenticated client on HsDescV3.

    Note:
        When client authentication is not enabled, these values are populated
        with random values.

    """

    #: Unique client identifier (8 bytes).
    client_id: Base64Bytes

    #: Initialization vector (16 bytes).
    iv: Base64Bytes

    #: Descriptor cookie cipher-text (16 bytes).
    encrypted_cookie: Base64Bytes

    def decrypt_cookie(self, key: bytes) -> bytes:
        """
        Decrypt the encrypted cookie with the provided key.

        Args:
            key: The AES key needed to decrypt this cookie.

        Returns:
            A decrypted version of the authentication cookie.

        """
        decryptor = Cipher(AES(key), CTR(self.iv)).decryptor()
        return decryptor.update(self.encrypted_cookie) + decryptor.finalize()


HsDescV3AuthClientType: TypeAlias = Annotated[
    HsDescV3AuthClient,
    TrBeforeStringSplit(
        dict_keys=('client_id', 'iv', 'encrypted_cookie'),
        separator=' ',
    ),
]


@dataclass(kw_only=True)
class HsDescV3Layer(ABC, HsDescBase):
    """Base class for both layers in a hidden service v3 descriptor."""

    #: Constant used while creating the decryption key material.
    CONSTANT: ClassVar[bytes]

    #: Salt length at the beginning of the encrypted blob.
    ENC_SALT_LEN: ClassVar[int] = 16
    #: Message authentication code length at the end of the encrypted blob.
    ENC_MAC_LEN: ClassVar[int] = 32

    #: Length of the AES key in the computed secret material.
    SEC_KEY_LEN: ClassVar[int] = 32
    #: Length of the IV in the computed secret material.
    SEC_IV_LEN: ClassVar[int] = 16
    #: Length of the MAC from the computed secret material.
    SEC_MAC_LEN: ClassVar[int] = 32
    #: Total length of the secret material.
    SEC_TOTAL_LEN: ClassVar[int] = SEC_KEY_LEN + SEC_IV_LEN + SEC_MAC_LEN

    @classmethod
    def decrypt_layer(
        cls,
        desc: HsDescV3,
        address: HiddenServiceAddressV3,
        blob: bytes,
        cookie: bytes = b'',
    ) -> Self:
        """
        Decrypt the provided cipher using the provided material.

        Args:
            desc: Hidden service v3 descriptor this layer is attached to.
            address: Hidden service v3 address the descriptor is related to.
            blob: Raw bytes of the cipher we want to decrypt.
            cookie: Additional bytes to add in the mix of secret_data.

        Raises:
            ReplySyntaxError: When the descriptor does not have a signing key.
            CryptographyError: When the provided parameters do not fit.

        Returns:
            An instance of this layer.

        """
        hs_subcred = desc.get_subcred(address)

        # This cast is valid here since ``get_subcred`` did not raise.
        blinded_key = cast('Ed25519PublicKey', desc.signing_cert.signing_key)

        # Extract parts of the blob in to salt/cipher/mac.
        salt = blob[: cls.ENC_SALT_LEN]
        cipher = blob[cls.ENC_SALT_LEN : -cls.ENC_MAC_LEN]
        expected_mac = blob[-cls.ENC_MAC_LEN :]

        # Build the secret key.
        revision_bytes = struct.pack('>Q', desc.revision)
        secret_data = blinded_key.public_bytes_raw() + cookie
        content = secret_data + hs_subcred + revision_bytes + salt + cls.CONSTANT
        keys = hashlib.shake_256(content).digest(cls.SEC_TOTAL_LEN)

        # Check the MAC against what was provided to ensure everything is in control.
        fmt = f'>Q{cls.SEC_MAC_LEN}sQ{cls.ENC_SALT_LEN}s'
        sec_mac = keys[cls.SEC_KEY_LEN + cls.SEC_IV_LEN :]
        mac_prefix = struct.pack(fmt, cls.SEC_MAC_LEN, sec_mac, cls.ENC_SALT_LEN, salt)
        computed_mac = hashlib.sha3_256(mac_prefix + cipher).digest()
        if computed_mac != expected_mac:
            msg = 'Invalid MAC, something is corrupted!'
            raise CryptographyError(msg)

        # Perform the real layer decryption and enjoy the brand new layer!
        aes_key = keys[: cls.SEC_KEY_LEN]
        aes_iv = keys[cls.SEC_KEY_LEN : cls.SEC_KEY_LEN + cls.SEC_IV_LEN]
        decryptor = Cipher(AES(aes_key), CTR(aes_iv)).decryptor()
        decrypted = decryptor.update(cipher) + decryptor.finalize()
        return cls.from_text(decrypted.rstrip(b'\x00').decode('ascii'))

    @classmethod
    @abstractmethod
    def text_to_mapping(cls, body: str) -> Mapping[str, Any]:
        """Parse the body of a raw layer to a mapping."""

    @classmethod
    def from_text(cls, body: str) -> Self:
        """
        Build a layer object from decrypted text content.

        Args:
            body: The layer content as raw text.

        Returns:
            A parsed layer.

        """
        return cls.adapter().validate_python(cls.text_to_mapping(body))


@dataclass(kw_only=True)
class HsDescV3Layer1(HsDescV3Layer):
    """First layer decrypted from a hidden service v3 (outer layer)."""

    #: Length of the AES key used to decrypt the authentication cookie.
    AUTH_KEY_KEN: ClassVar[int] = 32
    #: Length of the client identifier.
    CLIENT_ID_LEN: ClassVar[int] = 8
    #: Total length of the keys used to decrypt the authentication cookie.
    AUTH_KEYS_TOTAL_LEN: ClassVar[int] = CLIENT_ID_LEN + AUTH_KEY_KEN

    #: Constant used while creating the decryption key material.
    CONSTANT: ClassVar[bytes] = b'hsdir-superencrypted-data'

    #: Key type for client authentication.
    auth_key_type: OnionClientAuthKeyType

    #: Ephemeral x25519 public key generated by the hidden service.
    auth_ephemeral_key: X25519PublicKeyBase64

    #: List of authentication clients.
    auth_clients: Sequence[HsDescV3AuthClientType]

    #: Encrypted content of the layer.
    #:
    #: This contains the second layer (or inner layer).
    encrypted: Base64Bytes

    @classmethod
    def from_descriptor(cls, desc: HsDescV3, address: HiddenServiceAddressV3) -> Self:
        """
        Build the layer from a hidden service v3 descriptor.

        Args:
            desc: Hidden service descriptor
            address: Hidden service v3 address

        Returns:
            An instance of this layer.

        """
        return cls.decrypt_layer(desc, address, desc.superencrypted)

    @classmethod
    def text_to_mapping(cls, body: str) -> Mapping[str, Any]:
        """
        Parse the body of a raw layer1 to a mapping.

        Args:
            body: The decrypted content of the layer.

        Returns:
            A map suitable for parsing from pydantic.

        """
        results = {}  # type: dict[str, Any]
        lines = iter(body.splitlines())
        with suppress(StopIteration):
            while True:
                line = next(lines)
                # Ignore any empty line not part of an item.
                if not len(line):  # pragma: no cover
                    continue

                key, *args = line.split(' ', maxsplit=1)
                match key:
                    case 'desc-auth-type':
                        results['auth_key_type'] = args[0]

                    case 'desc-auth-ephemeral-key':
                        results['auth_ephemeral_key'] = args[0]

                    case 'auth-client':
                        clients = results.setdefault('auth_clients', [])
                        clients.append(args[0])

                    case 'encrypted':
                        block = _parse_block(lines, 'MESSAGE')
                        results['encrypted'] = block

                    case _:  # pragma: no cover
                        content = args[0] if len(args) else '__NONE__'
                        logger.warning('Unhandled HsDescV3 layer1 key %s: %s', key, content)

        return results

    def decrypt_auth_cookie(
        self,
        desc: HsDescV3,
        address: HiddenServiceAddressV3,
        client_key: X25519PrivateKey,
    ) -> bytes:
        """
        Find and decrypt the authentication cookie so we can then decrypt the second layer.

        Args:
            desc: Hidden service v3 descriptor.
            address: Hidden service v3 address.
            client_key: Client's secret authorization key.

        Raises:
            CryptographyError: When no authentication client matches the provided key.

        Returns:
            The decrypted authentication cookie.

        """
        hs_subcred = desc.get_subcred(address)
        secret_seed = client_key.exchange(self.auth_ephemeral_key)
        keys = hashlib.shake_256(hs_subcred + secret_seed).digest(self.AUTH_KEYS_TOTAL_LEN)
        client_id = keys[: self.CLIENT_ID_LEN]
        aes_key = keys[self.CLIENT_ID_LEN :]

        auth_client = None  # type: HsDescV3AuthClient | None
        for client in self.auth_clients:
            if client.client_id == client_id:
                auth_client = client
                break

        if auth_client is None:
            msg = 'No client matching the secret key was found in the descriptor.'
            raise CryptographyError(msg)

        return auth_client.decrypt_cookie(aes_key)


class VersionRange(GenericRange[NonNegativeInt]):
    """A range of versions numbers."""


@dataclass(kw_only=True, slots=True)
class HsDescV3FlowControl:
    """Flow and congestion control for a hidden service."""

    #: Range of supported flow control versions.
    version_range: Annotated[
        VersionRange,
        TrBeforeStringSplit(
            dict_keys=('min', 'max'),
            separator='-',
        ),
    ]

    #: Comes from the service's current ``cc_sendme_inc`` consensus parameter.
    sendme_inc: PositiveInt


class TrLinkSpecifierList:
    """Specific transformer for link specifiers."""

    def __get_pydantic_core_schema__(
        self,
        source: type[Any],
        handler: GetCoreSchemaHandler,
    ) -> CoreSchema:
        """Parse link specifiers to a simple dict structure."""
        return core_schema.no_info_before_validator_function(
            function=self._pydantic_validator,
            schema=handler(source),
        )

    def _pydantic_validator(self, value: Any) -> Any:
        """Parse link specifiers as binary data."""
        if isinstance(value, bytes):
            return self.from_bytes(value)
        return value

    def from_bytes(self, raw: bytes) -> Sequence[Mapping[str, Any]]:
        """Parse the binary data to a list of link specifier mappings."""
        results = []  # type: list[dict[str, Any]]
        count = raw[0]
        pos = 1
        for _ in range(count):
            type_, len_ = raw[pos : pos + 2]
            results.append({'type': type_, 'data': raw[pos + 2 : pos + 2 + len_]})
            pos += 2 + len_
        return results


class LinkSpecifierType(IntEnum):
    """List of types of link specifiers."""

    #: Relay identified by its IPv4 address/port.
    IPV4 = 0
    #: Relay identified by its IPv6 address/port.
    IPV6 = 1
    #: Relay identified by its SHA1 fingerprint.
    FINGERPRINT = 2
    #: Relay identified by its ed25519 fingerprint.
    ED25519 = 3


@dataclass(kw_only=True, frozen=True)
class LinkSpecifierStruct:
    """Intermediate structure used to discriminate link identifiers."""

    #: Type of link identifier.
    type: LinkSpecifierType
    #: Raw identifier packed as bytes.
    data: Base64Bytes


def _discriminate_link_specifier(v: Any) -> LinkSpecifierType | None:
    """Find how to discriminate the relay identifier."""
    discriminant = None
    match v:
        case LinkSpecifierStruct():
            discriminant = v.type
    return discriminant


def _link_specifier_from_struct(link: LinkSpecifierStruct) -> Any:
    """Extract the data part of our struct, if applicable."""
    match link.type:
        case LinkSpecifierType.IPV4:
            host, port = struct.unpack('!LH', link.data)
            return {'host': host, 'port': port}
        case LinkSpecifierType.IPV6:
            host, port = struct.unpack('!16sH', link.data)
            return {'host': host, 'port': port}
        case LinkSpecifierType.FINGERPRINT:
            return {'fingerprint': link.data}
        case LinkSpecifierType.ED25519:
            return link.data
        case _:  # pragma: no cover
            msg = f'Unhandled link specifier type {link.type}'
            raise RuntimeError(msg)
    return link


#: Validator used to extract the appropriate structure from a link specifier.
ExtractLinkSpecifier = BeforeValidator(_link_specifier_from_struct)


@dataclass(kw_only=True, slots=True)
class HsIntroPointV3(HsDescBase):
    """A single introduction point for a v3 descriptor."""

    #: Location and identities of introduction point nodes.
    #:
    #: These are automatically parsed from bytes as provided by the second layer.
    link_specifiers: Annotated[
        Sequence[
            # This would look better as a TypeAlias but would require to move types
            # such as TcpAddressPort and LongServerName before this declaration.
            Annotated[
                Union[  # noqa: UP007
                    Annotated[
                        TcpAddressPort,
                        ExtractLinkSpecifier,
                        Tag(LinkSpecifierType.IPV4),
                    ],
                    Annotated[
                        TcpAddressPort,
                        ExtractLinkSpecifier,
                        Tag(LinkSpecifierType.IPV6),
                    ],
                    Annotated[
                        LongServerName,
                        ExtractLinkSpecifier,
                        Tag(LinkSpecifierType.FINGERPRINT),
                    ],
                    Annotated[
                        Ed25519PublicKey,
                        TrEd25519PublicKey(),
                        ExtractLinkSpecifier,
                        Tag(LinkSpecifierType.ED25519),
                    ],
                ],
                Discriminator(_discriminate_link_specifier),
                TrCast(LinkSpecifierStruct, mode='before'),
            ],
        ],
        TrLinkSpecifierList(),
        EncodedBytes(encoder=Base64Encoder),
    ]

    #: Key of the introduction point Tor node used for the ``ntor`` handshake.
    ntor_onion_key: X25519PublicKeyBase64

    #: Contains the introduction authentication key.
    auth_key_cert: Annotated[Ed25519CertificateV1, EncodedBytes(encoder=Base64Encoder)]

    #: Public key used to encrypt the introduction request to service.
    enc_key: X25519PublicKeyBase64

    #: Cross-certification of the encryption key using the descriptor signing key.
    enc_key_cert: Annotated[Ed25519CertificateV1, EncodedBytes(encoder=Base64Encoder)]

    @classmethod
    def text_to_mapping_list(cls, body: str) -> Sequence[Mapping[str, Any]]:
        """
        Parse body to a list of raw introduction points mappings.

        Args:
            body: The raw content of the descriptors.

        Returns:
            A list of mappings for introduction points.

        """
        current = {}  # type: dict[str, Any]
        intros = []  # type: list[dict[str, Any]]

        lines = iter(body.splitlines())
        with suppress(StopIteration):
            while True:
                line = next(lines)
                if not len(line):  # pragma: no branch
                    continue  # pragma: no cover

                key, *args = line.split(' ', maxsplit=1)
                match key:
                    case 'introduction-point':
                        if current:
                            intros.append(current)
                        current = {'link_specifiers': args[0]}

                    case 'onion-key':
                        key_type, key_data = args[0].split(' ', maxsplit=1)
                        if key_type == 'ntor':
                            current['ntor_onion_key'] = key_data
                        else:  # pragma: no cover
                            logger.warning("Unknown onion key type '%s'", key_type)

                    case 'auth-key':
                        block = _parse_block(lines, 'ED25519 CERT')
                        current['auth_key_cert'] = block

                    case 'enc-key':
                        key_type, key_data = args[0].split(' ', maxsplit=1)
                        if key_type == 'ntor':
                            current['enc_key'] = key_data
                        else:  # pragma: no cover
                            logger.warning("Unknown env key type '%s'", key_type)

                    case 'enc-key-cert':
                        block = _parse_block(lines, 'ED25519 CERT')
                        current['enc_key_cert'] = block

                    case _:  # pragma: no cover
                        content = args[0] if len(args) else '__NONE__'
                        logger.warning('Unhandled HsIntroPointV3 key %s: %s', key, content)

        if current:  # pragma: no branch
            intros.append(current)
        return intros


@dataclass(kw_only=True)
class HsDescV3Layer2(HsDescV3Layer):
    """Second layer decrypted from a hidden service v3 (inner layer)."""

    #: Constant used while creating the decryption key material.
    CONSTANT: ClassVar[bytes] = b'hsdir-encrypted-data'

    #: Flow control protocol version and congestion value (proposal 324).
    flow_control: (
        Annotated[
            HsDescV3FlowControl,
            TrBeforeStringSplit(
                dict_keys=('version_range', 'sendme_inc'),
                separator=' ',
            ),
        ]
        | None
    ) = None

    #: Proof of work parameters used when contacting the service.
    pow_params: (
        Annotated[
            HsDescV3PowParams,
            TrBeforeStringSplit(
                dict_keys=('type', 'seed', 'suggested_effort', 'expiration'),
                separator=' ',
            ),
        ]
        | None
    ) = None

    #: ``CREATE2`` cell format numbers that the server recognizes.
    formats: Annotated[set[PositiveInt], TrBeforeStringSplit(separator=' ')]

    #: List of introduction-layer authentication types.
    #:
    #: A client that does not support at least one of these authentication
    #: types will not be able to contact the host.
    introduction_auth: Annotated[set[str], TrBeforeStringSplit(separator=' ')] | None = None

    #: List of introduction points used to connect to this hidden service.
    introduction_points: Sequence[HsIntroPointV3] = field(default_factory=list)

    #: Whether this service is a single onion service (see proposal 260).
    single_service: bool = False

    @classmethod
    def from_descriptor(
        cls,
        desc: HsDescV3,
        address: HiddenServiceAddressV3,
        client: X25519PrivateKey | None = None,
    ) -> Self:
        """
        Build the layer from a hidden service v3 descriptor.

        Args:
            desc: Hidden service descriptor.
            address: Hidden service v3 address.
            client: An optional client authorization key.

        Returns:
            An instance of this layer.

        """
        auth_cookie = b''

        # This is supposed to be already cached.
        layer1 = desc.decrypt_layer1(address)
        if client is not None:
            auth_cookie = layer1.decrypt_auth_cookie(desc, address, client)
        return cls.decrypt_layer(desc, address, layer1.encrypted, auth_cookie)

    @classmethod
    def text_to_mapping(cls, body: str) -> Mapping[str, Any]:
        """
        Parse the body of a raw layer2 to a mapping.

        Args:
            body: The decrypted content of the layer.

        Returns:
            A map suitable for parsing from pydantic.

        """
        results = {}  # type: dict[str, Any]
        lines = iter(body.splitlines())
        with suppress(StopIteration):
            while True:
                line = next(lines)
                # Ignore any empty line not part of an item.
                if not len(line):  # pragma: no cover
                    continue

                key, *args = line.split(' ', maxsplit=1)
                match key:
                    case 'create2-formats':
                        results['formats'] = args[0]

                    case 'intro-auth-required':
                        results['introduction_auth'] = args[0]

                    case 'single-onion-service':
                        results['single_service'] = True

                    case 'flow-control':
                        results['flow_control'] = args[0]

                    case 'pow-params':
                        results['pow_params'] = args[0]

                    case 'introduction-point':
                        # We reached the introduction point part!
                        intro_lines = [line]
                        with suppress(StopIteration):
                            while True:
                                intro_lines.append(next(lines))

                        intros = HsIntroPointV3.text_to_mapping_list('\n'.join(intro_lines))
                        results['introduction_points'] = intros

                    case _:  # pragma: no cover
                        content = args[0] if len(args) else '__NONE__'
                        logger.warning('Unhandled HsDescV3 layer2 key %s: %s', key, content)

        return results


@dataclass(kw_only=True)
class HsDescV3(HsDescBase):
    """Hidden service descriptor for v3 onions."""

    #: Prefix used while checking the signature of this descriptor.
    SIGNATURE_PREFIX: ClassVar[bytes] = b'Tor onion service descriptor sig v3'

    #: The version number of this descriptor's format.
    hs_descriptor: PositiveInt

    #: The revision number of the descriptor.
    revision: NonNegativeInt

    #: The lifetime of a descriptor in minutes.
    lifetime: TimedeltaMinutesInt

    #: Ed25519 certificate used to validate this descriptor.
    signing_cert: Annotated[Ed25519CertificateV1, EncodedBytes(encoder=Base64Encoder)]

    #: Encrypted content of the descriptor.
    #:
    #: This contains the first layer (or outer layer). This can simply
    #: be decrypted with the name of the hidden service this descriptor
    #: is created for.
    superencrypted: Base64Bytes

    #: A signature of all fields with the service's private key.
    signature: Base64Bytes

    #: Raw content of everything covered by the signature.
    signed_content: Base64Bytes

    def __post_init__(self) -> None:
        """
        Wrap some methods with their cached alternative.

        These cache wrappers are set during post-init because they need to be bound
        to this instance to avoid memory leaks.

        See Also:
            https://rednafi.com/python/lru_cache_on_methods/

        """
        for name in ('decrypt_layer1', 'decrypt_layer2', 'get_subcred'):
            func = getattr(self, name)
            wrapper = wraps(func)(cache(func))
            setattr(self, name, wrapper)

    @classmethod
    def text_to_mapping(cls, body: str) -> Mapping[str, Any]:
        """
        Parse the ``body`` of a raw descriptor to a mapping.

        Args:
            body: The content of the descriptor.

        Returns:
            A map suitable for parsing from pydantic.

        """
        lines_raw = body.splitlines()

        pos = None  # type: int | None
        # Lookup at the line that has a signature prefix.
        for i in range(len(lines_raw) - 1, -1, -1):
            if lines_raw[i].startswith('signature '):
                pos = i

        if pos is None:
            msg = 'No signature found on the HsV3 descriptor.'
            raise ReplySyntaxError(msg)

        signed_str = '\n'.join(lines_raw[:pos]) + '\n'
        signed_content = signed_str.encode('ascii')

        results = {'signed_content': signed_content}  # type: dict[str, Any]
        lines = iter(lines_raw)
        with suppress(StopIteration):
            while True:
                line = next(lines)
                # Ignore any empty line not part of an item.
                if not len(line):  # pragma: no cover
                    continue

                key, *args = line.split(' ', maxsplit=1)
                match key:
                    case 'hs-descriptor':
                        results['hs_descriptor'] = args[0]

                    case 'revision-counter':
                        results['revision'] = args[0]

                    case 'descriptor-lifetime':
                        results['lifetime'] = args[0]

                    case 'descriptor-signing-key-cert':
                        block = _parse_block(lines, 'ED25519 CERT')
                        results['signing_cert'] = block

                    case 'superencrypted':
                        block = _parse_block(lines, 'MESSAGE')
                        results['superencrypted'] = block

                    case 'signature':
                        results['signature'] = args[0]

                    case _:  # pragma: no cover
                        content = args[0] if len(args) else '__NONE__'
                        logger.warning('Unhandled HsDescV3 key %s: %s', key, content)

        return results

    @classmethod
    def from_text(cls, body: str) -> Self:
        """
        Build a HsDescV3 object from a text descriptor.

        Args:
            body: The content of the descriptor.

        Returns:
            A parsed descriptor.

        """
        return cls.adapter().validate_python(cls.text_to_mapping(body))

    def decrypt_layer1(self, address: HiddenServiceAddressV3) -> HsDescV3Layer1:
        """
        Decrypt the descriptor's first layer using the onion address.

        Args:
            address: The hidden service v3 address.

        Raises:
            ReplySyntaxError: When no signing key was provided with this descriptor.
            CryptographyError: When an invalid onion domain was provided.

        Returns:
            A layer1 object, containing additional data.

        """
        return HsDescV3Layer1.from_descriptor(self, address)

    def decrypt_layer2(
        self,
        address: HiddenServiceAddressV3,
        client: X25519PrivateKey | None = None,
    ) -> HsDescV3Layer2:
        """
        Decrypt the descriptor's second layer using the onion address.

        Args:
            address: The hidden service v3 address.
            client: An optional client authentication key.

        Raises:
            ReplySyntaxError: When no signing key was provided with this descriptor.
            CryptographyError: When an invalid onion domain or client key was provided.

        Returns:
            A layer2 object, containing additional data.

        """
        return HsDescV3Layer2.from_descriptor(self, address, client)

    def get_subcred(self, address: HiddenServiceAddressV3) -> bytes:
        """
        Get the computed sub-credential bytes used decrypt layers.

        Args:
            address: Hidden service v3 address.

        Raises:
            ReplySyntaxError: When the descriptor does not have a signing key.

        Returns:
            Computed digest used as sub-credential.

        """
        blinded_key = self.signing_cert.signing_key
        if blinded_key is None:
            msg = 'No signing key found in the descriptor.'
            raise ReplySyntaxError(msg)

        # N_hs_cred = H("credential" | public-identity-key).
        content = b'credential' + address.public_key.public_bytes_raw()
        hs_cred = hashlib.sha3_256(content).digest()

        # N_hs_subcred = H("subcredential" | N_hs_cred | blinded-public-key).
        content = b'subcredential' + hs_cred + blinded_key.public_bytes_raw()
        return hashlib.sha3_256(content).digest()

    def raise_for_invalid_signature(self) -> None:
        """
        Check that this descriptor is properly signed.

        This is checked against :attr:`signing_cert`.
        """
        signing_key = self.signing_cert.key
        if signing_key is not None:
            signed_content = self.SIGNATURE_PREFIX + self.signed_content
            try:
                signing_key.verify(self.signature, signed_content)
            except InvalidSignature as exc:
                msg = 'Descriptor has an invalid signature'
                raise CryptographyError(msg) from exc


class LivenessStatus(StrEnum):
    """Possible values for :attr:`.EventNetworkLiveness.status`."""

    #: Network or service is down.
    DOWN = 'DOWN'
    #: Network or service is up and running.
    UP = 'UP'

    def __bool__(self) -> bool:
        """
        Whether the network is up as a boolean.

        Returns:
            :obj:`True` when this value is ``UP``.

        """
        return bool(self.value == self.UP)


class LogSeverity(StrEnum):
    """Possible severities for all kind of log events."""

    DEBUG = 'DEBUG'
    INFO = 'INFO'
    NOTICE = 'NOTICE'
    WARNING = 'WARN'
    ERROR = 'ERROR'

    @classmethod
    def __get_pydantic_core_schema__(
        cls,
        source: type[Any],
        handler: GetCoreSchemaHandler,
    ) -> CoreSchema:
        """Build a core schema to validate this value."""
        return core_schema.union_schema(
            choices=[
                # In case we are already a LogSeverity.
                handler(source),
                # Otherwise execute the chain of validators.
                core_schema.chain_schema(
                    steps=[
                        # First we require the input to be a string in upper case.
                        core_schema.str_schema(to_upper=True),
                        # Then we setup our own validator.
                        core_schema.no_info_before_validator_function(
                            function=cls._pydantic_validator,
                            schema=handler(source),
                        ),
                    ]
                ),
            ]
        )

    @classmethod
    def _pydantic_validator(cls, value: str) -> Self:
        """Normalize the input value to a log severity."""
        if value == 'ERR':
            value = 'ERROR'
        return cls(value)


@dataclass(frozen=True, slots=True)
class LongServerName:
    """A Tor Server name and its optional nickname."""

    #: Server fingerprint as a 20 bytes value.
    fingerprint: Base16Bytes

    #: Server nickname (optional).
    nickname: str | None = None

    def __str__(self) -> str:
        """Get the string representation of this server."""
        value = f'${self.fingerprint.hex().upper()}'
        if self.nickname is not None:
            value += f'~{self.nickname}'
        return value

    @classmethod
    def __get_pydantic_core_schema__(
        cls,
        source: type[Any],
        handler: GetCoreSchemaHandler,
    ) -> CoreSchema:
        """Declare schema and validator for a long server name."""
        # There is an issue while serializing CommandExtendCircuit where this class
        # is badly serialized, not taking our serialization method into account.
        # Using a before validator fixes this issue, for an unknown reason.
        return core_schema.no_info_before_validator_function(
            function=cls._pydantic_validator,
            schema=handler(source),
            serialization=core_schema.to_string_ser_schema(when_used='always'),
        )

    @classmethod
    def _pydantic_validator(cls, value: Any) -> Any:
        """Validate any value."""
        if isinstance(value, str):
            return cls.from_string(value)
        return value

    @classmethod
    def from_string(cls, server: str) -> Self:
        """
        Build a new instance from a single string.

        See Also:
            https://spec.torproject.org/control-spec/message-format.html#tokens

        Returns:
            An instance of this class properly parsed from the provided string.

        """
        if not server.startswith('$'):
            msg = 'LongServerName does not start with a $'
            raise ValueError(msg)

        server = server[1:]
        if '~' in server:
            fingerprint, nickname = server.split('~', maxsplit=1)
        else:
            fingerprint, nickname = server, None

        return cls(fingerprint=bytes.fromhex(fingerprint), nickname=nickname)


class OnionClientAuthFlags(StrEnum):
    """List of flags attached to a running onion service."""

    #: This client's credentials should be stored on the file system.
    PERMANENT = 'Permanent'


class OnionClientAuthKeyType(StrEnum):
    """All types of keys for onion client authentication."""

    X25519 = 'x25519'


@dataclass(frozen=True, slots=True)
class OnionClientAuthKeyStruct:
    """Intermediate structure used to parse a key for an authorized client."""

    #: Type of key we are about to parse.
    auth_type: OnionClientAuthKeyType

    #: Data bytes for the provided key.
    data: Base64Bytes


class OrConnCloseReason(StrEnum):
    """All possible reasons why an OR connection is closed."""

    #: The OR connection has shut down cleanly.
    DONE = 'DONE'
    #: We got an ECONNREFUSED while connecting to the target OR.
    CONNECTREFUSED = 'CONNECTREFUSED'
    #: We connected to the OR, but found that its identity was not what we expected.
    IDENTITY = 'IDENTITY'
    #: We got an ECONNRESET or similar IO error from the connection with the OR.
    CONNECTRESET = 'CONNECTRESET'
    #: We got an ETIMEOUT or similar IO error from the connection with the OR.
    TIMEOUT = 'TIMEOUT'
    #: We got an ENETUNREACH, EHOSTUNREACH, or similar error while connecting to the OR.
    NOROUTE = 'NOROUTE'
    #: We got some other IO error on our connection to the OR.
    IOERROR = 'IOERROR'
    #: We don't have enough OS resources (file descriptors, etc.) to connect to the OR.
    RESOURCELIMIT = 'RESOURCELIMIT'
    #:  Problem in TLS protocol.
    TLS_ERROR = 'TLS_ERROR'
    #: The OR connection closed for some other reason.
    MISC = 'MISC'
    #: No pluggable transport was available.
    PT_MISSING = 'PT_MISSING'


class OrConnStatus(StrEnum):
    """All possible statuses used in :attr:`~.EventWord.ORCONN`."""

    #: We have received a new incoming OR connection, and are starting the server handshake.
    NEW = 'NEW'
    #: We have launched a new outgoing OR connection, and are starting the client handshake.
    LAUNCHED = 'LAUNCHED'
    #: The OR connection has been connected and the handshake is done.
    CONNECTED = 'CONNECTED'
    #: Our attempt to open the OR connection failed.
    FAILED = 'FAILED'
    #: The OR connection closed in an unremarkable way.
    CLOSED = 'CLOSED'


def _discriminate_client_auth_private_key(v: Any) -> str | None:
    """Find how to discriminate the provided key."""
    match v:
        case OnionClientAuthKeyStruct():
            return v.auth_type.value

        case X25519PrivateKey():
            return OnionClientAuthKeyType.X25519.value

    return None


def _onion_client_auth_key_to_struct(
    key: X25519PrivateKey,
    serializer: SerializerFunctionWrapHandler,
) -> OnionClientAuthKeyStruct:
    """Build a OnionClientAuthKeyStruct from a raw key."""
    match key:
        case X25519PrivateKey():
            return OnionClientAuthKeyStruct(
                auth_type=OnionClientAuthKeyType.X25519,
                data=serializer(key),
            )

        case _:
            msg = 'Unhandled onion client authentication key type.'
            raise TypeError(msg)


def _onion_client_auth_key_from_struct(value: Any) -> Any:
    """Extract the data part of our struct, if applicable."""
    if isinstance(value, OnionClientAuthKeyStruct):
        return value.data
    return value


#: Validator used to extract the raw key material after discrimination.
ExtractOnionClientAuthKeyFromStruct = BeforeValidator(_onion_client_auth_key_from_struct)

#: Build a :class:`OnionClientAuthKeyStruct` structure from a real key.
SerializeOnionClientAuthKeyToStruct = WrapSerializer(
    func=_onion_client_auth_key_to_struct,
    return_type=OnionClientAuthKeyStruct,
)

#: Parse and serialize any onion client authentication key with format ``x25519:[base64]``.
OnionClientAuthKey: TypeAlias = Annotated[
    Union[  # noqa: UP007
        Annotated[
            X25519PrivateKey,
            TrX25519PrivateKey(),
            ExtractOnionClientAuthKeyFromStruct,
            SerializeOnionClientAuthKeyToStruct,
            Tag('x25519'),
        ],
        # Needed as we don't handle another type in this union (yet).
        Annotated[OnionClientAuthKeyStruct, Tag('fallback')],
    ],
    Discriminator(_discriminate_client_auth_private_key),
    TrCast(OnionClientAuthKeyStruct, mode='before'),
    TrBeforeStringSplit(
        dict_keys=('auth_type', 'data'),
        maxsplit=1,
        separator=':',
    ),
]


@dataclass(kw_only=True, slots=True)
class OnionClientAuth:
    """A client key attached to a single onion domain."""

    #: Hidden service address without the ``.onion`` suffix.
    address: HiddenServiceAddress

    #: Client's private ``x25519`` key.
    key: OnionClientAuthKey

    #: Client name (optional).
    name: str | None = None

    #: Flags associated with this client.
    flags: Annotated[AbstractSet[OnionClientAuthFlags], TrBeforeStringSplit()] = field(
        default_factory=set
    )


class OnionServiceFlags(StrEnum):
    """Available flag options for command :attr:`~.CommandWord.ADD_ONION`."""

    #: The server should not include the newly generated private key as part of the response.
    DISCARD_PK = 'DiscardPK'
    #: Do not associate the newly created Onion Service to the current control connection.
    DETACH = 'Detach'
    #: Client authorization is required using the "basic" method (v2 only).
    BASIC_AUTH = 'BasicAuth'
    #: Version 3 client authorization is required (v3 only).
    V3AUTH = 'V3Auth'
    #: Add a non-anonymous Single Onion Service.
    NON_ANONYMOUS = 'NonAnonymous'
    #: Close the circuit is the maximum streams allowed is reached.
    MAX_STREAMS_CLOSE_CIRCUIT = 'MaxStreamsCloseCircuit'


class OnionServiceKeyType(StrEnum):
    """All types of keys for onion services."""

    #: The server should use the 1024 bit RSA key provided in as KeyBlob (v2).
    RSA1024 = 'RSA1024'
    #: The server should use the ed25519 v3 key provided in as KeyBlob (v3).
    ED25519_V3 = 'ED25519-V3'


@dataclass(frozen=True, slots=True)
class OnionServiceNewKeyStruct:
    """Structure used to parse any new KEY."""

    #: Type of key we want to generate.
    key_type: OnionServiceKeyType | Literal['BEST']

    #: Common prefix for all new keys.
    prefix: Literal['NEW'] = 'NEW'


OnionServiceNewKey: TypeAlias = Annotated[
    OnionServiceNewKeyStruct,
    TrBeforeStringSplit(
        dict_keys=('prefix', 'key_type'),
        maxsplit=1,
        separator=':',
    ),
]


@dataclass(frozen=True, slots=True)
class OnionServiceKeyStruct:
    """Intermediate structure used to parse a key for an onion service."""

    #: Type of key we are about to use.
    key_type: OnionServiceKeyType

    #: Data bytes for the provided key.
    data: Base64Bytes


def _discriminate_service_private_key(v: Any) -> str | None:
    """
    Find how to discriminate the provided key.

    Note:
        Ed25519PrivateKey does not handle the expanded key provided by Tor.
        This is why a :class:`OnionServiceKeyStruct` is provided here instead.

    """
    # This is used while serializing.
    match v:
        case OnionServiceKeyStruct():
            key = v.key_type.value
            if key == 'ED25519-V3':
                key = 'fallback'
            return key

        case RSAPrivateKey():
            return OnionServiceKeyType.RSA1024.value

        case Ed25519PrivateKey():
            return OnionServiceKeyType.ED25519_V3.value

    return None


def _onion_service_key_to_struct(
    key: Ed25519PrivateKey | RSAPrivateKey,
    serializer: SerializerFunctionWrapHandler,
) -> OnionServiceKeyStruct:
    """Build a OnionClientAuthKeyStruct from a raw key."""
    match key:
        case Ed25519PrivateKey():
            return OnionServiceKeyStruct(
                key_type=OnionServiceKeyType.ED25519_V3,
                data=serializer(key),
            )

        case RSAPrivateKey():
            return OnionServiceKeyStruct(
                key_type=OnionServiceKeyType.RSA1024,
                data=serializer(key),
            )

        case _:
            msg = 'Unhandled onion service key type.'
            raise TypeError(msg)


def _onion_service_key_from_struct(value: Any) -> Any:
    """Extract the data part of our struct, if applicable."""
    if isinstance(value, OnionServiceKeyStruct):
        return value.data
    return value


#: Validator used to extract the raw key material after discrimination.
ExtractServiceKeyFromStruct = BeforeValidator(_onion_service_key_from_struct)

#: Build a OnionClientAuthKeyStruct structure from a real key.
SerializeOnionServiceKeyFromStruct = WrapSerializer(
    func=_onion_service_key_to_struct,
    return_type=OnionServiceKeyStruct,
)

#: Parse and serialize any onion service key with format ``RSA1024:[base64]``.
OnionServiceKey: TypeAlias = Annotated[
    Union[  # noqa: UP007
        Annotated[
            RSAPrivateKey,
            TrRSAPrivateKey(),
            ExtractServiceKeyFromStruct,
            SerializeOnionServiceKeyFromStruct,
            Tag('RSA1024'),
        ],
        Annotated[
            Ed25519PrivateKey,
            TrEd25519PrivateKey(expanded=True),
            ExtractServiceKeyFromStruct,
            SerializeOnionServiceKeyFromStruct,
            Tag('ED25519-V3'),
        ],
        Annotated[OnionServiceKeyStruct, Tag('fallback')],
    ],
    Discriminator(_discriminate_service_private_key),
    TrCast(OnionServiceKeyStruct, mode='before'),
    TrBeforeStringSplit(
        dict_keys=('key_type', 'data'),
        maxsplit=1,
        separator=':',
    ),
]


class PortRange(GenericRange[AnyPort]):
    """A range of ports."""


@dataclass(kw_only=True, slots=True)
class PortPolicy:
    """A port policy for outgoing streams out of a router."""

    #: Type of policy (``accept`` or ``reject``).
    policy: Literal['accept', 'reject']
    #: List of ports or port ranges.
    ports: Annotated[
        Sequence[
            Union[  # noqa: UP007
                AnyPort,
                Annotated[
                    PortRange,
                    TrBeforeStringSplit(
                        dict_keys=('min', 'max'),
                        maxsplit=1,
                        separator='-',
                    ),
                ],
            ],
        ],
        TrBeforeStringSplit(separator=','),
    ]


class Signal(StrEnum):
    """All possible signals that can be sent to Tor."""

    #: Reload configuration items.
    RELOAD = 'RELOAD'
    #: Controlled shutdown, if server is an OP, exit immediately.
    SHUTDOWN = 'SHUTDOWN'
    #: Dump stats, log information about open connections and circuits.
    DUMP = 'DUMP'
    #: Debug, switch all open logs to log level debug.
    DEBUG = 'DEBUG'
    #: Immediate shutdown, clean up and exit now.
    HALT = 'HALT'
    #: Forget the client-side cached IP addresses for all host names.
    CLEARDNSCACHE = 'CLEARDNSCACHE'
    #: Switch to clean circuits, so new requests don't share any circuits with old ones.
    NEWNYM = 'NEWNYM'
    #: Make Tor dump an unscheduled Heartbeat message to log.
    HEARTBEAT = 'HEARTBEAT'
    #: Tell Tor to become "dormant".
    DORMANT = 'DORMANT'
    #: Tell Tor to stop being "dormant".
    ACTIVE = 'ACTIVE'


class StatusActionClient(StrEnum):
    """
    Possible actions for a :attr:`~.EventWord.STATUS_CLIENT` event.

    See Also:
        :class:`.EventStatusClient`

    """

    #: Tor has made some progress at establishing a connection to the Tor network.
    #:
    #: See Also:
    #:    :class:`StatusClientBootstrap`
    BOOTSTRAP = 'BOOTSTRAP'
    #: Tor is able to establish circuits for client use.
    CIRCUIT_ESTABLISHED = 'CIRCUIT_ESTABLISHED'
    #: We are no longer confident that we can build circuits.
    #:
    #: See Also:
    #:    :class:`StatusClientCircuitNotEstablished`
    CIRCUIT_NOT_ESTABLISHED = 'CIRCUIT_NOT_ESTABLISHED'
    #: Tor has received and validated a new consensus networkstatus.
    CONSENSUS_ARRIVED = 'CONSENSUS_ARRIVED'
    #: A stream was initiated to a port that's commonly used for vuln-plaintext protocols.
    #:
    #: See Also:
    #:    :class:`StatusClientDangerousPort`
    DANGEROUS_PORT = 'DANGEROUS_PORT'
    #: A connection was made to Tor's SOCKS port without support for hostnames.
    #:
    #: See Also:
    #:    :class:`StatusClientDangerousSocks`
    DANGEROUS_SOCKS = 'DANGEROUS_SOCKS'
    #: Tor now knows enough network-status documents and enough server descriptors.
    ENOUGH_DIR_INFO = 'ENOUGH_DIR_INFO'
    #: We fell below the desired threshold directory information.
    NOT_ENOUGH_DIR_INFO = 'NOT_ENOUGH_DIR_INFO'
    #: Some application gave us a funny-looking hostname.
    #:
    #: See Also:
    #:    :class:`StatusClientSocksBadHostname`
    SOCKS_BAD_HOSTNAME = 'SOCKS_BAD_HOSTNAME'
    #: A connection was made to Tor's SOCKS port and did not speak the SOCKS protocol.
    #:
    #: See Also:
    #:    :class:`StatusClientSocksUnknownProtocol`
    SOCKS_UNKNOWN_PROTOCOL = 'SOCKS_UNKNOWN_PROTOCOL'


class StatusActionServer(StrEnum):
    """
    Possible actions for a :attr:`~.EventWord.STATUS_SERVER` event.

    See Also:
        :class:`.EventStatusServer`

    Note:
       ``SERVER_DESCRIPTOR_STATUS`` was never implemented.

    """

    #: Our best idea for our externally visible IP has changed to 'IP'.
    #:
    #: See Also:
    #:    :class:`StatusServerExternalAddress`
    EXTERNAL_ADDRESS = 'EXTERNAL_ADDRESS'
    #: We're going to start testing the reachability of our external OR port or directory port.
    #:
    #: See Also:
    #:    :class:`StatusServerCheckingReachability`
    CHECKING_REACHABILITY = 'CHECKING_REACHABILITY'
    #: We successfully verified the reachability of our external OR port or directory port.
    #:
    #: See Also:
    #:    :class:`StatusServerReachabilitySucceeded`
    REACHABILITY_SUCCEEDED = 'REACHABILITY_SUCCEEDED'
    #: We successfully uploaded our server descriptor to one of the directory authorities.
    GOOD_SERVER_DESCRIPTOR = 'GOOD_SERVER_DESCRIPTOR'
    #: One of our name servers has changed status.
    #:
    #: See Also:
    #:    :class:`StatusServerNameserverStatus`
    NAMESERVER_STATUS = 'NAMESERVER_STATUS'
    #: All of our nameservers have gone down.
    NAMESERVER_ALL_DOWN = 'NAMESERVER_ALL_DOWN'
    #: Our DNS provider is providing an address when it should be saying ``NOTFOUND``.
    DNS_HIJACKED = 'DNS_HIJACKED'
    #: Our DNS provider is giving a hijacked address instead of well-known websites.
    DNS_USELESS = 'DNS_USELESS'
    #: A directory authority rejected our descriptor.
    #:
    #: See Also:
    #:    :class:`StatusServerBadServerDescriptor`
    BAD_SERVER_DESCRIPTOR = 'BAD_SERVER_DESCRIPTOR'
    #: A single directory authority accepted our descriptor.
    #:
    #: See Also:
    #:    :class:`StatusServerAcceptedServerDescriptor`
    ACCEPTED_SERVER_DESCRIPTOR = 'ACCEPTED_SERVER_DESCRIPTOR'
    #: We failed to connect to our external OR port or directory port successfully.
    #:
    #: See Also:
    #:    :class:`StatusServerReachabilityFailed`
    REACHABILITY_FAILED = 'REACHABILITY_FAILED'
    #: Our bandwidth based accounting status has changed.
    #:
    #: See Also:
    #:    :class:`StatusServerHibernationStatus`
    HIBERNATION_STATUS = 'HIBERNATION_STATUS'


class StatusActionGeneral(StrEnum):
    """
    Possible actions for a :attr:`~.EventWord.STATUS_GENERAL` event.

    Note:
       ``BAD_LIBEVENT`` has been removed since ``Tor 0.2.7.1``.

    See Also:
        :class:`.EventStatusGeneral`

    """

    #: Tor has encountered a situation that its developers never expected.
    #:
    #: See Also:
    #:    :class:`StatusGeneralBug`
    BUG = 'BUG'
    #: Tor believes that none of the known directory servers are reachable.
    DIR_ALL_UNREACHABLE = 'DIR_ALL_UNREACHABLE'
    #: Tor spent enough time without CPU cycles that it has closed all its circuits.
    #:
    #: See Also:
    #:    :class:`StatusGeneralClockJumped`
    CLOCK_JUMPED = 'CLOCK_JUMPED'
    #: A lock skew has been detected by Tor.
    #:
    #: See Also:
    #:    :class:`StatusGeneralClockSkew`
    CLOCK_SKEW = 'CLOCK_SKEW'
    #: Tor has found that directory servers don't recommend its version of the Tor software.
    #:
    #: See Also:
    #:    :class:`StatusGeneralDangerousVersion`
    DANGEROUS_VERSION = 'DANGEROUS_VERSION'
    #: Tor has reached its ulimit -n on file descriptors or sockets.
    #:
    #: See Also:
    #:    :class:`StatusGeneralTooManyConnections`
    TOO_MANY_CONNECTIONS = 'TOO_MANY_CONNECTIONS'


@dataclass(kw_only=True, slots=True)
class StatusClientBootstrap:
    """Arguments for action :attr:`StatusActionClient.BOOTSTRAP`."""

    #: A number between 0 and 100 for how far through the bootstrapping process we are.
    progress: NonNegativeInt
    #: Describe the *next* task that Tor will tackle.
    summary: str
    #: A string that controllers can use to recognize bootstrap phases.
    tag: str
    #: Tells how many bootstrap problems there have been so far at this phase.
    count: NonNegativeInt | None = None
    #: The identity digest of the node we're trying to connect to.
    host: Base16Bytes | None = None
    #: An address and port combination, where 'address' is an ipv4 or ipv6 address.
    hostaddr: TcpAddressPort | None = None
    #: Lists one of the reasons allowed in the :attr:`~.EventWord.ORCONN` event.
    reason: str | None = None
    #: Either "ignore" or "warn" as a recommendation.
    recommendation: Literal['ignore', 'warn'] | None = None
    #: Any hints Tor has to offer about why it's having troubles bootstrapping.
    warning: str | None = None


@dataclass(kw_only=True, slots=True)
class StatusClientCircuitNotEstablished:
    """Arguments for action :attr:`StatusActionClient.CIRCUIT_ESTABLISHED`."""

    #: Which other status event type caused our lack of confidence.
    reason: Literal['CLOCK_JUMPED', 'DIR_ALL_UNREACHABLE', 'EXTERNAL_ADDRESS']


@dataclass(kw_only=True, slots=True)
class StatusClientDangerousPort:
    """Arguments for action :attr:`StatusActionClient.DANGEROUS_PORT`."""

    #: When "reject", we refused the connection; whereas if it's "warn", we allowed it.
    reason: Literal['REJECT', 'WARN']
    #: A stream was initiated and this port is commonly used for vulnerable protocols.
    port: AnyPort


@dataclass(kw_only=True, slots=True)
class StatusClientDangerousSocks:
    """Arguments for action :attr:`StatusActionClient.DANGEROUS_SOCKS`."""

    #: The protocol implied in this dangerous connection.
    protocol: Literal['SOCKS4', 'SOCKS5']

    #: The address and port implied in this connection.
    address: TcpAddressPort


@dataclass(kw_only=True, slots=True)
class StatusClientSocksUnknownProtocol:
    """
    Arguments for action :attr:`StatusActionClient.SOCKS_UNKNOWN_PROTOCOL`.

    This class is currently unused as the quotes are buggy.
    Additionally the escaping is performed as ``CSTRING``, which we do not handle.

    """

    #: First few characters that were sent to Tor on the SOCKS port.
    data: str


@dataclass(kw_only=True, slots=True)
class StatusClientSocksBadHostname:
    """Arguments for action :attr:`StatusActionClient.SOCKS_BAD_HOSTNAME`."""

    #: The host name that triggered this event.
    hostname: str


@dataclass(kw_only=True, slots=True)
class StatusGeneralClockJumped:
    """Arguments for action :attr:`StatusActionGeneral.CLOCK_JUMPED`."""

    #: Duration Tor thinks it was unconscious for (or went back in time).
    time: TimedeltaSeconds


class StatusGeneralDangerousVersionReason(StrEnum):
    """All reasons why we can get a dangerous version notice."""

    NEW = 'NEW'
    OBSOLETE = 'OBSOLETE'
    RECOMMENDED = 'RECOMMENDED'


@dataclass(kw_only=True, slots=True)
class StatusGeneralDangerousVersion:
    """Arguments for action :attr:`StatusActionGeneral.DANGEROUS_VERSION`."""

    #: Current running version.
    current: str
    #: Tell why is this a dangerous version.
    reason: StatusGeneralDangerousVersionReason
    #: List of recommended versions to use instead.
    recommended: Annotated[AbstractSet[str], TrBeforeStringSplit()]


@dataclass(kw_only=True, slots=True)
class StatusGeneralTooManyConnections:
    """Arguments for action :attr:`StatusActionGeneral.TOO_MANY_CONNECTIONS`."""

    #: Number of currently opened file descriptors.
    current: NonNegativeInt


@dataclass(kw_only=True, slots=True)
class StatusGeneralBug:
    """Arguments for action :attr:`StatusActionGeneral.BUG`."""

    #: Tell why we got a general status report for a bug.
    reason: str


@dataclass(kw_only=True, slots=True)
class StatusGeneralClockSkew:
    """Arguments for action :attr:`StatusActionGeneral.CLOCK_SKEW`."""

    #: Estimate of how far we are from the time declared in the source.
    skew: TimedeltaSeconds

    #: Source of the clock skew event.
    source: Annotated[
        ClockSkewSource,
        TrBeforeStringSplit(
            dict_keys=('name', 'address'),
            maxsplit=1,
            separator=':',
        ),
    ]


class ExternalAddressResolveMethod(StrEnum):
    """How the external method was resolved."""

    NONE = 'NONE'
    CONFIGURED = 'CONFIGURED'
    CONFIGURED_ORPORT = 'CONFIGURED_ORPORT'
    GETHOSTNAME = 'GETHOSTNAME'
    INTERFACE = 'INTERFACE'
    RESOLVED = 'RESOLVED'


class RemapSource(StrEnum):
    """All known remapping sources."""

    #: Tor client decided to remap the address because of a cached answer.
    CACHE = 'CACHE'
    #: The remote node we queried gave us the new address as a response.
    EXIT = 'EXIT'


@dataclass(kw_only=True, slots=True)
class ReplyDataMapAddressItem:
    """
    A single reply data associated for a successful :attr:`~.CommandWord.MAPADDRESS` command.

    See Also:
        - :class:`.ReplyMapAddressItem`
        - :class:`.ReplyMapAddress`

    """

    #: Original address to replace with another one.
    original: Optional[AnyHost] = None  # noqa: UP007

    #: Replacement item for the corresponding :attr:`original` address.
    replacement: Optional[AnyHost] = None  # noqa: UP007


@dataclass(kw_only=True, slots=True)
class ReplyDataExtendCircuit:
    """
    Reply data linked to a successful :attr:`~.CommandWord.EXTENDCIRCUIT` command.

    See Also:
        - :class:`.ReplyExtendCircuit`

    """

    #: Build or extended circuit.
    circuit: int


@dataclass(kw_only=True, slots=True)
class ReplyDataProtocolInfo:
    """
    Reply data linked to a successful :attr:`~.CommandWord.PROTOCOLINFO` command.

    See Also:
        - :class:`.ReplyProtocolInfo`

    """

    #: List of available authentication methods.
    auth_methods: Annotated[AbstractSet[AuthMethod], TrBeforeStringSplit()] = field(
        default_factory=set
    )

    #: Path on the server to the cookie file.
    auth_cookie_file: str | None = None

    #: Version of the Tor control protocol in use.
    protocol_version: int

    #: Version of Tor.
    tor_version: str


@dataclass(kw_only=True, slots=True)
class ReplyDataAuthChallenge:
    """
    Reply data linked to a successful :attr:`~.CommandWord.AUTHCHALLENGE` command.

    See Also:
        - :class:`.ReplyAuthChallenge`

    """

    CLIENT_HASH_CONSTANT: ClassVar[bytes] = (
        b'Tor safe cookie authentication controller-to-server hash'
    )
    SERVER_HASH_CONSTANT: ClassVar[bytes] = (
        b'Tor safe cookie authentication server-to-controller hash'
    )

    #: Not part of the response, but it is very nice to have it here.
    #:
    #: This eases the handling of cryptography routines used to check hashes.
    client_nonce: Base16Bytes | str | None = None

    #: Server hash as computed by the server.
    server_hash: Base16Bytes

    #: Server nonce as provided by the server.
    server_nonce: Base16Bytes

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
            CryptographyError: When our client nonce is :obj:`None`.

        Returns:
            A value that you can authenticate with.

        """
        client_nonce = client_nonce or self.client_nonce
        if client_nonce is None:
            msg = 'No client_nonce was found or provided.'
            raise CryptographyError(msg)

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
            CryptographyError: When our client nonce is :obj:`None`.

        Returns:
            The same value as in `server_hash` if everything went well.

        """
        client_nonce = client_nonce or self.client_nonce
        if client_nonce is None:
            msg = 'No client_nonce was found or provided.'
            raise CryptographyError(msg)

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
            CryptographyError: When our server nonce does not match the one we computed.

        """
        computed = self.build_server_hash(cookie, client_nonce)
        if computed != self.server_hash:
            msg = 'Server hash provided by Tor is invalid.'
            raise CryptographyError(msg)


@dataclass(kw_only=True, slots=True)
class ReplyDataAddOnion:
    """
    Reply data linked to a successful :attr:`~.CommandWord.ADD_ONION` command.

    See Also:
        - :class:`.ReplyAddOnion`

    """

    #: Called `ServiceID` in the documentation, this is the onion address.
    address: HiddenServiceAddressV3

    #: List of client authentication for a v2 address.
    client_auth: Sequence[HsDescClientAuthV2] = field(default_factory=list)

    #: List of client authentication for a v3 address.
    client_auth_v3: Sequence[HsDescClientAuthV3] = field(default_factory=list)

    #: Onion service key.
    key: OnionServiceKey | None = None


@dataclass(kw_only=True, slots=True)
class ReplyDataOnionClientAuthView:
    """
    Reply data linked to a successful :attr:`~.CommandWord.ONION_CLIENT_AUTH_VIEW` command.

    See Also:
        - :class:`.ReplyOnionClientAuthView`

    """

    #: Onion address minus the ``.onion`` suffix.
    address: HiddenServiceAddressV3 | None = None

    #: List of authorized clients and their private key.
    clients: Sequence[OnionClientAuth] = field(default_factory=list)


class RouterFlags(StrEnum):
    """All possible flags for an onion router."""

    #: Is a directory authority.
    AUTHORITY = 'Authority'
    #: Is believed to be useless as an exit node
    BAD_EXIT = 'BadExit'
    #: Supports commonly used exit ports.
    EXIT = 'Exit'
    #: Is suitable for high-bandwidth circuits.
    FAST = 'Fast'
    #: Is suitable for use as an entry guard.
    GUARD = 'Guard'
    #: Is considered a v2 hidden service directory.
    HSDIR = 'HSDir'
    #: Is considered unsuitable for usage other than as a middle relay.
    MIDDLE_ONLY = 'MiddleOnly'
    #: Any Ed25519 key in the descriptor does not reflect authority consensus.
    NO_ED_CONSENSUS = 'NoEdConsensus'
    #: Is suitable for long-lived circuits.
    STABLE = 'Stable'
    #: Should upload a new descriptor because the old one is too old.
    STALE_DESC = 'StaleDesc'
    #: Is currently usable over all its published ORPorts.
    RUNNING = 'Running'
    #: Has been 'validated'.
    VALID = 'Valid'
    #: Implements the v2 directory protocol or higher.
    V2DIR = 'V2Dir'


@dataclass(kw_only=True, slots=True)
class RouterStatus:
    """Router status V3 item."""

    #: Router status flags describing router properties.
    flags: AbstractSet[
        Annotated[
            RouterFlags | str,
            Field(union_mode='left_to_right'),
        ],
    ]

    #: Server nickname.
    nickname: str

    #: Unique router fingerprint.
    identity: Base64Bytes

    #: Hash of its most recent descriptor as signed.
    digest: Base64Bytes

    #: Current IPv4 address.
    ip: IPv4Address

    #: Current onion routing port.
    or_port: int

    #: Optional directory port.
    dir_port: Annotated[Union[int | None], TrBeforeSetToNone({'0', 0})] = None  # noqa: UP007

    #: Other known onion routing addresses
    addresses: Sequence[TcpAddressPort] | None = None

    #: Port policy for outgoing streams.
    port_policy: PortPolicy | None = None

    #: An estimate of the bandwidth of this relay (in KB/s).
    bandwidth: int | None = None

    #: Measured bandwidth currently produced by measuring stream capacities.
    bw_measured: int | None = None

    #: Bandwidth value is not based on a threshold of 3 or more measurements.
    bw_unmeasured: bool | None = None


@dataclass(kw_only=True, slots=True)
class StatusServerExternalAddress:
    """Arguments for action :attr:`StatusActionServer.EXTERNAL_ADDRESS`."""

    #: Our external IP address.
    address: AnyAddress
    #: When set, we got our new IP by resolving this host name.
    hostname: str | None = None
    #: How we found out our external IP address.
    method: ExternalAddressResolveMethod


@dataclass(kw_only=True, slots=True)
class StatusServerCheckingReachability:
    """Arguments for action :attr:`StatusActionServer.CHECKING_REACHABILITY`."""

    #: Checking reachability to this onion routing address that is our own.
    or_address: TcpAddressPort | None = None


@dataclass(kw_only=True, slots=True)
class StatusServerReachabilitySucceeded:
    """Arguments for action :attr:`StatusActionServer.REACHABILITY_SUCCEEDED`."""

    #: Reachability succeeded to our onion routing address.
    or_address: TcpAddressPort | None = None


@dataclass(kw_only=True, slots=True)
class StatusServerNameserverStatus:
    """Arguments for action :attr:`StatusActionServer.NAMESERVER_STATUS`."""

    #: This is our name server.
    ns: str
    #: This is its status.
    status: LivenessStatus
    #: Error message when :attr:`status` is ``DOWN``.
    err: str | None = None


@dataclass(kw_only=True, slots=True)
class StatusServerBadServerDescriptor:
    """Arguments for action :attr:`StatusActionServer.BAD_SERVER_DESCRIPTOR`."""

    #: Directory that rejected our descriptor as an address and port.
    dir_auth: TcpAddressPort
    #: Include malformed descriptors, incorrect keys, highly skewed clocks, and so on.
    reason: str


@dataclass(kw_only=True, slots=True)
class StatusServerAcceptedServerDescriptor:
    """Arguments for action :attr:`StatusActionServer.ACCEPTED_SERVER_DESCRIPTOR`."""

    #: Directory that accepted our server descriptor as an address and port.
    dir_auth: TcpAddressPort


@dataclass(kw_only=True, slots=True)
class StatusServerReachabilityFailed:
    """Arguments for action :attr:`StatusActionServer.REACHABILITY_FAILED`."""

    #: Reachability failed to our onion routing address.
    or_address: TcpAddressPort | None = None


@dataclass(kw_only=True, slots=True)
class StatusServerHibernationStatus:
    """Arguments for action :attr:`StatusActionServer.HIBERNATION_STATUS`."""

    status: Literal['AWAKE', 'SOFT', 'HARD']


class StreamClientProtocol(StrEnum):
    """All known client protocols for a stream."""

    #: Connecting using SocksV4.
    SOCKS4 = 'SOCKS4'
    #: Connecting using SocksV5.
    SOCKS5 = 'SOCKS5'
    #: Transparent connections redirected by pf or netfilter.
    TRANS = 'TRANS'
    #: Transparent connections redirected by natd.
    NATD = 'NATD'
    #: DNS requests.
    DNS = 'DNS'
    #: HTTP CONNECT tunnel connections.
    HTTPCONNECT = 'HTTPCONNECT'
    #: Metrics query connections.
    METRICS = 'METRICS'
    #: Unknown client protocol type.
    UNKNOWN = 'UNKNOWN'


class StreamCloseReason(StrEnum):
    """
    All reasons provided to close a stream (as a string).

    See Also:
        https://spec.torproject.org/tor-spec/closing-streams.html#closing-streams

    """

    #: Catch-all for unlisted reasons.
    MISC = 'MISC'
    #: Couldn't look up hostname.
    RESOLVEFAILED = 'RESOLVEFAILED'
    #: Remote host refused connection.
    CONNECTREFUSED = 'CONNECTREFUSED'
    #: Relay refuses to connect to host or port.
    EXITPOLICY = 'EXITPOLICY'
    #: Circuit is being destroyed.
    DESTROY = 'DESTROY'
    #: Anonymized TCP connection was closed.
    DONE = 'DONE'
    #: Anonymized TCP connection was closed while connecting.
    TIMEOUT = 'TIMEOUT'
    #: Routing error while attempting to contact destination.
    NOROUTE = 'NOROUTE'
    #: Relay is temporarily hibernating.
    HIBERNATING = 'HIBERNATING'
    #: Internal error at the relay.
    INTERNAL = 'INTERNAL'
    #: Relay has no resources to fulfill request.
    RESOURCELIMIT = 'RESOURCELIMIT'
    #: Connection was unexpectedly reset.
    CONNRESET = 'CONNRESET'
    #: Sent when closing connection because of Tor protocol violations.
    TORPROTOCOL = 'TORPROTOCOL'
    #: Client sent ``RELAY_BEGIN_DIR`` to a non-directory relay.
    NOTDIRECTORY = 'NOTDIRECTORY'

    #: The client tried to connect to a private address like 127.0.0.1 or 10.0.0.1 over Tor.
    PRIVATE_ADDR = 'PRIVATE_ADDR'
    #: We received a RELAY_END message from the other side of this stream.
    END = 'END'


class StreamCloseReasonInt(IntEnum):
    """
    All reasons provided to close a stream.

    See Also:
        https://spec.torproject.org/tor-spec/closing-streams.html#closing-streams

    """

    #: Catch-all for unlisted reasons.
    MISC = 1
    #: Couldn't look up hostname.
    RESOLVEFAILED = 2
    #: Remote host refused connection.
    CONNECTREFUSED = 3
    #: Relay refuses to connect to host or port.
    EXITPOLICY = 4
    #: Circuit is being destroyed.
    DESTROY = 5
    #: Anonymized TCP connection was closed.
    DONE = 6
    #: Anonymized TCP connection was closed while connecting.
    TIMEOUT = 7
    #: Routing error while attempting to contact destination.
    NOROUTE = 8
    #: Relay is temporarily hibernating.
    HIBERNATING = 9
    #: Internal error at the relay.
    INTERNAL = 10
    #: Relay has no resources to fulfill request.
    RESOURCELIMIT = 11
    #: Connection was unexpectedly reset.
    CONNRESET = 12
    #: Sent when closing connection because of Tor protocol violations.
    TORPROTOCOL = 13
    #: Client sent ``RELAY_BEGIN_DIR`` to a non-directory relay.
    NOTDIRECTORY = 14


class StreamPurpose(StrEnum):
    """All known purposes for a stream."""

    #: This stream is generated internally to Tor for fetching directory information.
    DIR_FETCH = 'DIR_FETCH'
    #: An internal stream for uploading information to a directory authority.
    DIR_UPLOAD = 'DIR_UPLOAD'
    #: A stream we're using to test our own directory port to make sure it's reachable.
    DIRPORT_TEST = 'DIRPORT_TEST'
    #: A user-initiated DNS request.
    DNS_REQUEST = 'DNS_REQUEST'
    #: This stream is handling user traffic.
    #:
    #: I can also be internal to Tor, but it doesn't match one of the other purposes.
    USER = 'USER'


class StreamStatus(StrEnum):
    """All possible statuses for a stream."""

    #: New request to connect.
    NEW = 'NEW'
    #: New request to resolve an address.
    NEWRESOLVE = 'NEWRESOLVE'
    #: Address re-mapped to another.
    REMAP = 'REMAP'
    #: Sent a connect message along a circuit.
    SENTCONNECT = 'SENTCONNECT'
    #: Sent a resolve message along a circuit.
    SENTRESOLVE = 'SENTRESOLVE'
    #: Received a reply; stream established.
    SUCCEEDED = 'SUCCEEDED'
    #: Stream failed and not be retried.
    FAILED = 'FAILED'
    #: Stream closed.
    CLOSED = 'CLOSED'
    #: Detached from circuit; can still be retried.
    DETACHED = 'DETACHED'
    #: Waiting for controller to use :attr:`~.CommandWord.ATTACHSTREAM`.
    CONTROLLER_WAIT = 'CONTROLLER_WAIT'
    #: XOFF has been sent for this stream.
    XOFF_SENT = 'XOFF_SENT'
    #: XOFF has been received for this stream.
    XOFF_RECV = 'XOFF_RECV'
    #: XON has been sent for this stream.
    XON_SENT = 'XON_SENT'
    #: XON has been received for this stream.
    XON_RECV = 'XON_RECV'


@dataclass(frozen=True, slots=True)
class StreamTarget:
    """Describe the target of a stream."""

    #: Target server for the stream.
    host: AnyAddress | str
    #: Exit node (if any).
    node: LongServerName | None
    #: Target port.
    port: AnyPort

    def __str__(self) -> str:
        """Get the string representation of this connection."""
        host = str(self.host)
        if isinstance(self.host, IPv6Address):
            host = f'[{host}]'

        suffix = ''
        if isinstance(self.node, LongServerName):
            fphex = self.node.fingerprint.hex().upper()
            suffix = f'.${fphex}.exit'

        return f'{host}{suffix}:{self.port:d}'

    @classmethod
    def __get_pydantic_core_schema__(
        cls,
        source: type[Any],
        handler: GetCoreSchemaHandler,
    ) -> CoreSchema:
        """Declare schema and validator for a stream target."""
        return core_schema.no_info_before_validator_function(
            function=cls._pydantic_validator,
            schema=handler(source),
            serialization=core_schema.to_string_ser_schema(when_used='always'),
        )

    @classmethod
    def _pydantic_validator(cls, value: Any) -> Any:
        """
        Build a new instance from a single string.

        Note:
            This parsing results from ``write_stream_target_to_buf`` in Tor.

        Returns:
            An instance of this class properly parsed from the provided string value.

        """
        if isinstance(value, str):
            host: AnyAddress | LongServerName | str
            node = None  # type: LongServerName | None

            if '.exit:' in value:
                # This is an exit node, extract the fingerprint form the IP address.
                if value.startswith('['):
                    ipv6, suffix = value[1:].split('].$', maxsplit=1)
                    fphex, port = suffix.split(':', maxsplit=1)
                    fphex = fphex.removesuffix('.exit')
                    node = LongServerName(fingerprint=bytes.fromhex(fphex))
                    host = IPv6Address(ipv6)
                else:
                    str_host, port = value.split(':', maxsplit=1)
                    ipv4, fphex = str_host.removesuffix('.exit').split('.$', maxsplit=1)
                    node = LongServerName(fingerprint=bytes.fromhex(fphex))
                    host = IPv4Address(ipv4)
            else:
                if value.startswith('['):
                    str_host, port = value.removeprefix('[').split(']:', maxsplit=1)
                    host = IPv6Address(str_host)
                else:
                    str_host, port = value.split(':', maxsplit=1)
                    try:
                        host = IPv4Address(str_host)
                    except ValueError:
                        # In the end it turns out it was just a domain name.
                        host = str_host

            value = cls(host=host, node=node, port=int(port))

        return value


@dataclass(frozen=True, slots=True)
class TcpAddressPort:
    """Describe a TCP target with a host and a port."""

    #: Target host for the TCP connection.
    host: AnyAddress
    #: Target port for the TCP connection.
    port: AnyPort

    def __str__(self) -> str:
        """Get the string representation of this connection."""
        if isinstance(self.host, IPv6Address):
            return f'[{self.host:s}]:{self.port:d}'
        return f'{self.host:s}:{self.port:d}'

    @classmethod
    def __get_pydantic_core_schema__(
        cls,
        source: type[Any],
        handler: GetCoreSchemaHandler,
    ) -> CoreSchema:
        """Declare schema and validator for a TCP connection."""
        # There is an issue here due to our complex handling or EventStatusClient.
        # Our schema is not taken into account when used in a discriminated union...
        # The only way we found to have this work is to use a before validation here.
        return core_schema.no_info_before_validator_function(
            function=cls._pydantic_validator,
            schema=handler(source),
            serialization=core_schema.to_string_ser_schema(when_used='always'),
        )

    @classmethod
    def _pydantic_validator(cls, value: Any) -> Any:
        """
        Build a new instance from a single string.

        Returns:
            An instance of this class properly parsed from the provided string value.

        """
        if isinstance(value, str):
            host: AnyAddress

            if value.startswith('['):
                str_host, port = value.removeprefix('[').split(']:', maxsplit=1)
                host = IPv6Address(str_host)
            else:
                str_host, port = value.split(':', maxsplit=1)
                host = IPv4Address(str_host)

            value = cls(host=host, port=int(port))

        return value


@dataclass(kw_only=True, slots=True)
class VirtualPortTarget:
    """Target for an onion virtual port."""

    #: Virtual port to listen to on a hidden service.
    port: AnyPort
    #: Local target for this virtual port.
    target: TcpAddressPort


def _discriminate_hidden_service_version(value: str) -> HiddenServiceVersion | None:
    """Discriminate a hidden service version based on the string length."""
    match value:
        case HiddenServiceAddressV2() | HiddenServiceAddressV3():
            return value.VERSION
        case str():
            if len(value) < HiddenServiceAddressV3.ADDRESS_LENGTH:
                return HiddenServiceVersion.ONION_V2
            return HiddenServiceVersion.ONION_V3
    return None


#: Any kind of onion service address.
HiddenServiceAddress: TypeAlias = Annotated[
    Union[  # noqa: UP007
        Annotated[HiddenServiceAddressV2, Tag(HiddenServiceVersion.ONION_V2)],
        Annotated[HiddenServiceAddressV3, Tag(HiddenServiceVersion.ONION_V3)],
    ],
    Discriminator(_discriminate_hidden_service_version),
]

#: A virtual port parser and serializer from/to a :class:`VirtualPortTarget`.
VirtualPort: TypeAlias = Annotated[
    VirtualPortTarget,
    TrBeforeStringSplit(
        dict_keys=('port', 'target'),
        maxsplit=1,
        separator=',',
    ),
]
