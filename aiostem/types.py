from __future__ import annotations

from datetime import datetime, timedelta
from ipaddress import IPv4Address, IPv6Address
from typing import Annotated, Generic, TypeAlias, TypeVar, Union

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from pydantic import BaseModel, Field

from .utils import (
    Base16Encoder,
    Base32Encoder,
    Base64Encoder,
    EncodedBytes,
    TrAfterAsTimezone,
    TrBeforeTimedelta,
    TrBoolYesNo,
    TrEd25519PublicKey,
    TrRSAPublicKey,
    TrX25519PrivateKey,
    TrX25519PublicKey,
)

#: Any boundary of a range structure (int, float, etc...).
RangeVal = TypeVar('RangeVal')


# Generic models do not work well with dataclasses even on recent pydantic :(.
class GenericRange(BaseModel, Generic[RangeVal]):
    """Any kind of numeric range."""

    #: Minimum value in the range (inclusive).
    min: RangeVal
    #: Maximum value in the range (inclusive).
    max: RangeVal


#: Any IP address, either IPv4 or IPv6.
AnyAddress: TypeAlias = Union[IPv4Address | IPv6Address]  # noqa: UP007

#: Any host, either by IP address or hostname.
AnyHost: TypeAlias = Annotated[
    IPv4Address | IPv6Address | str,
    Field(union_mode='left_to_right'),
]
#: Any TCP or UDP port.
AnyPort: TypeAlias = Annotated[int, Field(gt=0, lt=65536)]

#: Bytes that are hex encoded.
Base16Bytes: TypeAlias = Annotated[bytes, EncodedBytes(encoder=Base16Encoder)]

#: Bytes that are base32 encoded.
Base32Bytes: TypeAlias = Annotated[bytes, EncodedBytes(encoder=Base32Encoder)]

#: Bytes that are base64 encoded.
Base64Bytes: TypeAlias = Annotated[bytes, EncodedBytes(encoder=Base64Encoder)]

#: A boolean value serialized as a yes/no string.
BoolYesNo: TypeAlias = Annotated[bool, TrBoolYesNo()]

#: Base64 encoded bytes parsed as an ed25519 public key.
Ed25519PublicKeyBase64 = Annotated[
    Ed25519PublicKey,
    TrEd25519PublicKey(),
    EncodedBytes(encoder=Base64Encoder),
]

#: A datetime that always puts or convert to UTC.
DatetimeUTC: TypeAlias = Annotated[datetime, TrAfterAsTimezone()]

#: Base64 encoded bytes parsed as a public RSA key.
RSAPublicKeyBase64: TypeAlias = Annotated[
    RSAPublicKey,
    TrRSAPublicKey(),
    EncodedBytes(encoder=Base64Encoder),
]

#: A :class:`~datetime.timedelta` parsed from an integer value in milliseconds.
TimedeltaMilliseconds: TypeAlias = Annotated[
    timedelta,
    TrBeforeTimedelta(unit='milliseconds'),
]
#: A :class:`~datetime.timedelta` parsed from an integer value in minutes.
TimedeltaMinutesInt: TypeAlias = Annotated[
    timedelta,
    TrBeforeTimedelta(unit='minutes', is_float=False),
]
#: A :class:`~datetime.timedelta` parsed from an integer value in seconds.
TimedeltaSeconds: TypeAlias = Annotated[
    timedelta,
    TrBeforeTimedelta(unit='seconds'),
]

#: Base32 encoded bytes parsed as a public x25519 key.
X25519PublicKeyBase32: TypeAlias = Annotated[
    X25519PublicKey,
    TrX25519PublicKey(),
    EncodedBytes(encoder=Base32Encoder),
]

#: Base64 encoded bytes parsed as a public x25519 key.
X25519PublicKeyBase64: TypeAlias = Annotated[
    X25519PublicKey,
    TrX25519PublicKey(),
    EncodedBytes(encoder=Base64Encoder),
]

#: Base64 encoded bytes parsed as a private x25519 key.
X25519PrivateKeyBase64: TypeAlias = Annotated[
    X25519PrivateKey,
    TrX25519PrivateKey(),
    EncodedBytes(encoder=Base64Encoder),
]
