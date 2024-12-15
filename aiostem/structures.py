from __future__ import annotations

import base64
import hashlib
import secrets
from collections.abc import Set as AbstractSet
from dataclasses import dataclass, field
from enum import IntEnum, StrEnum
from functools import cached_property
from ipaddress import IPv4Address, IPv6Address
from typing import TYPE_CHECKING, Annotated, Any, ClassVar, Literal, Self, TypeAlias, Union

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import NonNegativeInt
from pydantic_core import PydanticCustomError, core_schema

from .types import AnyAddress, AnyPort, Base16Bytes, TimedeltaSeconds, X25519PrivateKeyBase64
from .utils import TrBeforeStringSplit

if TYPE_CHECKING:
    from pydantic import GetCoreSchemaHandler
    from pydantic_core.core_schema import CoreSchema, ValidatorFunctionWrapHandler


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


class CircuitPurpose(StrEnum):
    """All possible purposes for circuits."""

    CONTROLLER = 'controller'
    GENERAL = 'general'
    BRIDGE = 'bridge'


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


class CloseStreamReason(IntEnum):
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


class Feature(StrEnum):
    """All known features Tor supports."""

    #: Ask for extended information while receiving events.
    EXTENDED_EVENTS = 'EXTENDED_EVENTS'
    #: Replaces ServerID with LongName in events and :attr:`~.CommandWord.GETINFO` results.
    VERBOSE_NAMES = 'VERBOSE_NAMES'


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
        return core_schema.no_info_wrap_validator_function(
            cls._pydantic_wrap_validator,
            core_schema.str_schema(
                pattern=cls.ADDRESS_PATTERN,
                min_length=cls.ADDRESS_LENGTH,
                max_length=cls.ADDRESS_LENGTH + cls.ADDRESS_SUFFIX_LENGTH,
                ref='onion_v2',
                strict=True,
            ),
        )

    @classmethod
    def _pydantic_wrap_validator(
        cls,
        value: Any,
        validator: ValidatorFunctionWrapHandler,
    ) -> Self:
        """Validate any input value provided by the user."""
        if isinstance(value, cls):
            return value
        return cls.from_string(validator(value))

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
        return core_schema.no_info_wrap_validator_function(
            cls._pydantic_wrap_validator,
            core_schema.str_schema(
                pattern=cls.ADDRESS_PATTERN,
                min_length=cls.ADDRESS_LENGTH,
                max_length=cls.ADDRESS_LENGTH + cls.ADDRESS_SUFFIX_LENGTH,
                ref='onion_v3',
                strict=True,
            ),
        )

    @classmethod
    def _pydantic_wrap_validator(
        cls,
        value: Any,
        validator: ValidatorFunctionWrapHandler,
    ) -> Self:
        """Validate any input value provided by the user."""
        if isinstance(value, cls):
            return value
        return cls.from_string(validator(value))

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
            'Invalid v3 hidden service address: "{address}"',
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
    #: Length of the base64 value without the usefless padding.
    REND_DESC_COOKIE_LEN_BASE64: ClassVar[int] = 22
    #: Length of the base64 value with the usefless padding.
    REND_DESC_COOKIE_LEN_EXT_BASE64: ClassVar[int] = 24

    #: Allowed values describing the type of auth cookie we have.
    auth_type: Literal[HsDescAuthTypeInt.BASIC_AUTH, HsDescAuthTypeInt.STEALTH_AUTH]

    #: Raw cookie value as 16 random bytes.
    cookie: bytes

    def __str__(self) -> str:
        """Get the string representation of this auth cookie."""
        raw = list(self.cookie)
        raw.append((int(self.auth_type) - 1) << 4)
        # print(self.auth_type, raw)
        return base64.b64encode(bytes(raw)).decode('ascii')

    @classmethod
    def __get_pydantic_core_schema__(
        cls,
        source: type[Any],
        handler: GetCoreSchemaHandler,
    ) -> CoreSchema:
        """Declare schema and validator for a TCP connection."""
        return core_schema.no_info_before_validator_function(
            function=cls.from_value,
            schema=handler(source),
            serialization=core_schema.to_string_ser_schema(when_used='always'),
        )

    @classmethod
    def generate(
        cls,
        auth_type: Literal[HsDescAuthTypeInt.BASIC_AUTH, HsDescAuthTypeInt.STEALTH_AUTH],
    ) -> Self:
        """Generate a new auth cookie."""
        return cls(auth_type=auth_type, cookie=secrets.token_bytes(cls.REND_DESC_COOKIE_LEN))

    @classmethod
    def from_value(cls, value: Any) -> Any:
        """Build a new auth cookie from any value."""
        if isinstance(value, str):
            # Add the padding to make b64decode happy.
            if len(value) == cls.REND_DESC_COOKIE_LEN_BASE64:
                value += 'A='
            value = base64.b64decode(value)

        if isinstance(value, bytes):
            auth_byte = value[cls.REND_DESC_COOKIE_LEN] >> 4
            auth_type = (
                HsDescAuthTypeInt.BASIC_AUTH
                if auth_byte == 0
                else HsDescAuthTypeInt.STEALTH_AUTH
            )  # type: Literal[HsDescAuthTypeInt.BASIC_AUTH, HsDescAuthTypeInt.STEALTH_AUTH]
            value = cls(auth_type=auth_type, cookie=value[: cls.REND_DESC_COOKIE_LEN])

        return value


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
        return core_schema.no_info_after_validator_function(
            function=cls.from_string,
            schema=core_schema.str_schema(),
            serialization=core_schema.to_string_ser_schema(when_used='always'),
        )

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

    #: This client's credentials should be stored in the filesystem.
    PERMANENT = 'Permanent'


class OnionClientAuthKeyType(StrEnum):
    """All types of keys for onion client authentication."""

    X25519 = 'x25519'


@dataclass(kw_only=True, slots=True)
class OnionClientAuthKey:
    """A client key attached to a single onion domain."""

    #: Hidden service address without the ``.onion`` suffix.
    address: HiddenServiceAddress

    #: Client's private key type (currently only :attr:`~OnionClientAuthKeyType.X25519`).
    key_type: OnionClientAuthKeyType = OnionClientAuthKeyType.X25519

    #: Client's private ``x25519`` key (32 bytes).
    key: X25519PrivateKeyBase64

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
    #: Forget the client-side cached IPs for all host names.
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
    #: One of our nameservers has changed status.
    #:
    #: See Also:
    #:    :class:`StatusServerNameserverStatus`
    NAMESERVER_STATUS = 'NAMESERVER_STATUS'
    #: All of our nameservers have gone down.
    NAMESERVER_ALL_DOWN = 'NAMESERVER_ALL_DOWN'
    #: Our DNS provider is providing an address when it should be saying "NOTFOUND".
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

    #: A stream was initiated and this port is commonly used for vulnerable protocols.
    port: AnyPort
    #: When "reject", we refused the connection; whereas if it's "warn", we allowed it.
    reason: Literal['REJECT', 'WARN']


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
    recommended: Annotated[set[str], TrBeforeStringSplit()]


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
        return core_schema.no_info_after_validator_function(
            function=cls.from_string,
            schema=core_schema.str_schema(),
            serialization=core_schema.to_string_ser_schema(when_used='always'),
        )

    @classmethod
    def from_string(cls, string: str) -> Self:
        """
        Build a new instance from a single string.

        Returns:
            An instance of this class properly parsed from the provided string.

        """
        if string.startswith('['):
            str_host, port = string.removeprefix('[').split(']:', maxsplit=1)
            host = IPv6Address(str_host)  # type: AnyAddress
        else:
            str_host, port = string.split(':', maxsplit=1)
            host = IPv4Address(str_host)

        return cls(host=host, port=int(port))


@dataclass(kw_only=True, slots=True)
class VirtualPortTarget:
    """Target for an onion virtual port."""

    #: Virtual port to listen to on a hidden service.
    port: AnyPort
    #: Local target for this virtual port.
    target: TcpAddressPort


#: Any kind of onion service address.
HiddenServiceAddress: TypeAlias = Union[HiddenServiceAddressV2 | HiddenServiceAddressV3]  # noqa: UP007

#: A virtual port parser and serializer from/to a :class:`VirtualPortTarget`.
VirtualPort: TypeAlias = Annotated[
    VirtualPortTarget,
    TrBeforeStringSplit(
        dict_keys=('port', 'target'),
        maxsplit=1,
        separator=',',
    ),
]