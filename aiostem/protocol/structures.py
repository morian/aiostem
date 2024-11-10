from __future__ import annotations

from collections.abc import Set as AbstractSet
from dataclasses import dataclass, field
from enum import IntEnum, StrEnum
from typing import Annotated

from .utils import Base64Bytes, StringSequence


class AuthMethod(StrEnum):
    """Known authentication methods."""

    NULL = 'NULL'
    HASHEDPASSWORD = 'HASHEDPASSWORD'
    COOKIE = 'COOKIE'
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


class NetworkLivenessStatus(StrEnum):
    """Possible values for `Status` in a `NETWORK_LIVENESS` event."""

    DOWN = 'DOWN'
    UP = 'UP'

    def __bool__(self) -> bool:
        """Whether the network is up as a boolean."""
        return bool(self.value == self.UP)


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
