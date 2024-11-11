from __future__ import annotations

from collections.abc import Set as AbstractSet
from dataclasses import dataclass, field
from enum import IntEnum, StrEnum
from typing import Annotated, Literal

from .utils import Base64Bytes, StringSequence, TimedeltaSeconds


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
    #: Client sent `RELAY_BEGIN_DIR` to a non-directory relay.
    NOTDIRECTORY = 14


class Feature(StrEnum):
    """All known features."""

    #: Same as passing 'EXTENDED' to SETEVENTS.
    EXTENDED_EVENTS = 'EXTENDED_EVENTS'
    #: Replaces ServerID with LongName in events and GETINFO results.
    VERBOSE_NAMES = 'VERBOSE_NAMES'


class HsDescAction(StrEnum):
    """Possible actions in a `HD_DESC` event."""

    CREATED = 'CREATED'
    FAILED = 'FAILED'
    IGNORE = 'IGNORE'
    RECEIVED = 'RECEIVED'
    REQUESTED = 'REQUESTED'
    UPLOAD = 'UPLOAD'
    UPLOADED = 'UPLOADED'


class HsDescAuthType(StrEnum):
    """Possible values for AuthType in `HS_DESC` event."""

    BASIC_AUTH = 'BASIC_AUTH'
    NO_AUTH = 'NO_AUTH'
    STEALTH_AUTH = 'STEALTH_AUTH'
    UNKNOWN = 'UNKNOWN'


class HsDescFailReason(StrEnum):
    """Possible values for `REASON` in a `HS_DESC` event."""

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
    """Possible values for `Status` in a `NETWORK_LIVENESS` event."""

    DOWN = 'DOWN'
    UP = 'UP'

    def __bool__(self) -> bool:
        """
        Whether the network is up as a boolean.

        Returns:
            :obj:`True` when this value is `UP`.

        """
        return bool(self.value == self.UP)


class LogSeverity(StrEnum):
    """Possible severities for all kind of log events."""

    DEBUG = 'DEBUG'
    INFO = 'INFO'
    NOTICE = 'NOTICE'
    WARNING = 'WARN'
    ERROR = 'ERROR'


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

    #: Hidden service address.
    address: str

    #: Client's private x25519 key.
    key_type: OnionClientAuthKeyType = OnionClientAuthKeyType.X25519
    key: Base64Bytes

    #: Client name (optional)
    name: str | None = None

    #: Flags associated with this client.
    flags: Annotated[AbstractSet[OnionClientAuthFlags], StringSequence()] = field(
        default_factory=set
    )


class OnionServiceFlags(StrEnum):
    """Available flag options for command `ADD_ONION`."""

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
    """All possible signals."""

    #: Reload: reload config items.
    RELOAD = 'RELOAD'
    #: Controlled shutdown: if server is an OP, exit immediately.
    SHUTDOWN = 'SHUTDOWN'
    #: Dump stats: log information about open connections and circuits.
    DUMP = 'DUMP'
    #: Debug: switch all open logs to loglevel debug.
    DEBUG = 'DEBUG'
    #: Immediate shutdown: clean up and exit now.
    HALT = 'HALT'
    #: Forget the client-side cached IPs for all hostnames.
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
    """Possible actions for a client status event."""

    #: Tor has made some progress at establishing a connection to the Tor network.
    BOOTSTRAP = 'BOOTSTRAP'
    #: Tor is able to establish circuits for client use.
    CIRCUIT_ESTABLISHED = 'CIRCUIT_ESTABLISHED'
    #: We are no longer confident that we can build circuits.
    CIRCUIT_NOT_ESTABLISHED = 'CIRCUIT_NOT_ESTABLISHED'
    #: Tor has received and validated a new consensus networkstatus.
    CONSENSUS_ARRIVED = 'CONSENSUS_ARRIVED'
    #: A stream was initiated to a port that's commonly used for vuln-plaintext protocols.
    DANGEROUS_PORT = 'DANGEROUS_PORT'
    #: A connection was made to Tor's SOCKS port without support for hostnames.
    DANGEROUS_SOCKS = 'DANGEROUS_SOCKS'
    #: Tor now knows enough network-status documents and enough server descriptors.
    ENOUGH_DIR_INFO = 'ENOUGH_DIR_INFO'
    #: We fell below the desired threshold directory information.
    NOT_ENOUGH_DIR_INFO = 'NOT_ENOUGH_DIR_INFO'
    #: Some application gave us a funny-looking hostname.
    SOCKS_BAD_HOSTNAME = 'SOCKS_BAD_HOSTNAME'
    #: A connection was made to Tor's SOCKS port and did not speak the SOCKS protocol.
    SOCKS_UNKNOWN_PROTOCOL = 'SOCKS_UNKNOWN_PROTOCOL'


class StatusActionServer(StrEnum):
    """
    Possible actions for a server status event.

    Note:
       `SERVER_DESCRIPTOR_STATUS` was never implemented.

    """

    #: Our best idea for our externally visible IP has changed to 'IP'.
    EXTERNAL_ADDRESS = 'EXTERNAL_ADDRESS'
    #: We're going to start testing the reachability of our external OR port or directory port.
    CHECKING_REACHABILITY = 'CHECKING_REACHABILITY'
    #: We successfully verified the reachability of our external OR port or directory port.
    REACHABILITY_SUCCEEDED = 'REACHABILITY_SUCCEEDED'
    #: We successfully uploaded our server descriptor to one of the directory authorities.
    GOOD_SERVER_DESCRIPTOR = 'GOOD_SERVER_DESCRIPTOR'
    #: One of our nameservers has changed status.
    NAMESERVER_STATUS = 'NAMESERVER_STATUS'
    #: All of our nameservers have gone down.
    NAMESERVER_ALL_DOWN = 'NAMESERVER_ALL_DOWN'
    #: Our DNS provider is providing an address when it should be saying "NOTFOUND".
    DNS_HIJACKED = 'DNS_HIJACKED'
    #: Our DNS provider is giving a hijacked address instead of well-known websites.
    DNS_USELESS = 'DNS_USELESS'
    #: A directory authority rejected our descriptor.
    BAD_SERVER_DESCRIPTOR = 'BAD_SERVER_DESCRIPTOR'
    #: A single directory authority accepted our descriptor.
    ACCEPTED_SERVER_DESCRIPTOR = 'ACCEPTED_SERVER_DESCRIPTOR'
    #: We failed to connect to our external OR port or directory port successfully.
    REACHABILITY_FAILED = 'REACHABILITY_FAILED'
    #: Our bandwidth based accounting status has changed.
    HIBERNATION_STATUS = 'HIBERNATION_STATUS'


class StatusActionGeneral(StrEnum):
    """
    Possible actions for a general status event.

    Note:
       `BAD_LIBEVENT` has been removed since Tor 0.2.7.1.

    """

    #: Tor has encountered a situation that its developers never expected.
    BUG = 'BUG'
    #: Tor believes that none of the known directory servers are reachable.
    DIR_ALL_UNREACHABLE = 'DIR_ALL_UNREACHABLE'
    #: Tor spent enough time without CPU cycles that it has closed all its circuits.
    CLOCK_JUMPED = 'CLOCK_JUMPED'
    #: A lock skew has been detected by Tor.
    CLOCK_SKEW = 'CLOCK_SKEW'
    #: Tor has found that directory servers don't recommend its version of the Tor software.
    DANGEROUS_VERSION = 'DANGEROUS_VERSION'
    #: Tor has reached its ulimit -n on file descriptors or sockets.
    TOO_MANY_CONNECTIONS = 'TOO_MANY_CONNECTIONS'


@dataclass(kw_only=True, slots=True)
class StatusClientBootstrap:
    """Arguments for a `STATUS_CLIENT` event with action `BOOTSTRAP`."""

    progress: int
    summary: str
    tag: str
    count: int | None = None
    host: str | None = None
    hostaddr: str | None = None
    reason: str | None = None
    recommendation: str | None = None
    warning: str | None = None


@dataclass(kw_only=True, slots=True)
class StatusClientCircuitNotEstablished:
    """Arguments for a `STATUS_CLIENT` event with action `CIRCUIT_NOT_ESTABLISHED`."""

    reason: Literal['CLOCK_JUMPED', 'DIR_ALL_UNREACHABLE', 'EXTERNAL_ADDRESS']


@dataclass(kw_only=True, slots=True)
class StatusClientDangerousPort:
    """Arguments for a `STATUS_CLIENT` event with action `DANGEROUS_PORT`."""

    port: int
    reason: Literal['REJECT', 'WARN']


@dataclass(kw_only=True, slots=True)
class StatusClientDangerousSocks:
    """Arguments for a `STATUS_CLIENT` event with action `DANGEROUS_SOCKS`."""

    address: str
    protocol: Literal['SOCKS4', 'SOCKS5']


@dataclass(kw_only=True, slots=True)
class StatusClientSocksUnknownProtocol:
    """
    Arguments for a `STATUS_CLIENT` event with action `SOCKS_UNKNOWN_PROTOCOL`.

    This class is currently unused as the quotes are buggy.
    Additionally the escaping is performed as CSTRING, which we do not handle.

    """

    #: First few characters that were sent to Tor on the SOCKS port.
    data: str


@dataclass(kw_only=True, slots=True)
class StatusClientSocksBadHostname:
    """Arguments for a `STATUS_CLIENT` event with action `SOCKS_BAD_HOSTNAME`."""

    hostname: str


@dataclass(kw_only=True, slots=True)
class StatusGeneralClockJumped:
    """Arguments for a `STATUS_GENERAL` event with action `CLOCK_JUMPED`."""

    time: TimedeltaSeconds


class StatusGeneralDangerousVersionReason(StrEnum):
    """All reasons why we can get a dangerous version notice."""

    NEW = 'NEW'
    OBSOLETE = 'OBSOLETE'
    RECOMMENDED = 'RECOMMENDED'


@dataclass(kw_only=True, slots=True)
class StatusGeneralDangerousVersion:
    """Arguments for a `STATUS_GENERAL` event with action `DANGEROUS_VERSION`."""

    current: str
    reason: StatusGeneralDangerousVersionReason
    recommended: Annotated[set[str], StringSequence()]


@dataclass(kw_only=True, slots=True)
class StatusGeneralTooManyConnections:
    """Arguments for a `STATUS_GENERAL` event with action `TOO_MANY_CONNECTIONS`."""

    #: Number of currently opened file descriptors.
    current: int


@dataclass(kw_only=True, slots=True)
class StatusGeneralBug:
    """Arguments for a `STATUS_GENERAL` event with action `BUG`."""

    reason: str


@dataclass(kw_only=True, slots=True)
class StatusGeneralClockSkew:
    """Arguments for a `STATUS_GENERAL` event with action `CLOCK_SKEW`."""

    #: Estimate of how far we are from the time declared in the source.
    skew: TimedeltaSeconds
    #: "DIRSERV:" IP ":" Port
    #: "NETWORKSTATUS:" IP ":" Port
    #: "OR:" IP ":" Port
    #: "CONSENSUS"
    source: str


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
    """Arguments for a `STATUS_SERVER` event with action `EXTERNAL_ADDRESS`."""

    #: Our external IP address.
    address: str
    hostname: str | None = None
    method: ExternalAddressResolveMethod


@dataclass(kw_only=True, slots=True)
class StatusServerCheckingReachability:
    """Arguments for a `STATUS_SERVER` event with action `CHECKING_REACHABILITY`."""

    dir_address: str | None = None
    or_address: str


@dataclass(kw_only=True, slots=True)
class StatusServerReachabilitySucceeded:
    """Arguments for a `STATUS_SERVER` event with action `REACHABILITY_SUCCEEDED`."""

    dir_address: str | None = None
    or_address: str


@dataclass(kw_only=True, slots=True)
class StatusServerNameserverStatus:
    """Arguments for a `STATUS_SERVER` event with action `NAMESERVER_STATUS`."""

    ns: str
    status: LivenessStatus
    err: str | None = None


@dataclass(kw_only=True, slots=True)
class StatusServerBadServerDescriptor:
    """Arguments for a `STATUS_SERVER` event with action `BAD_SERVER_DESCRIPTOR`."""

    dir_auth: str
    reason: str


@dataclass(kw_only=True, slots=True)
class StatusServerAcceptedServerDescriptor:
    """Arguments for a `STATUS_SERVER` event with action `ACCEPTED_SERVER_DESCRIPTOR`."""

    dir_auth: str


@dataclass(kw_only=True, slots=True)
class StatusServerReachabilityFailed:
    """Arguments for a `STATUS_SERVER` event with action `REACHABILITY_FAILED`."""

    dir_address: str | None = None
    or_address: str


@dataclass(kw_only=True, slots=True)
class StatusServerHibernationStatus:
    """Arguments for a `STATUS_SERVER` event with action `HIBERNATION_STATUS`."""

    status: Literal['AWAKE', 'SOFT', 'HARD']
