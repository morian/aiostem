from __future__ import annotations

from datetime import datetime, timedelta
from ipaddress import IPv4Address, IPv6Address
from typing import Annotated, TypeAlias, Union

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from pydantic import Field

from .utils import (
    Base16Encoder,
    Base32Encoder,
    Base64Encoder,
    EncodedBytes,
    TrAfterAsTimezone,
    TrBeforeTimedelta,
    TrBoolYesNo,
    TrX25519PrivateKey,
    TrX25519PublicKey,
)

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

#: A datetime that always puts or convert to UTC.
DatetimeUTC: TypeAlias = Annotated[datetime, TrAfterAsTimezone()]

#: A :class:`~datetime.timedelta` parsed from an integer value in milliseconds.
TimedeltaMilliseconds: TypeAlias = Annotated[
    timedelta,
    TrBeforeTimedelta(milliseconds=True),
]

#: A :class:`~datetime.timedelta` parsed from an integer value in seconds.
TimedeltaSeconds: TypeAlias = Annotated[
    timedelta,
    TrBeforeTimedelta(milliseconds=False),
]

#: Base32 encoded bytes parsed as a public x25519 key.
X25519PublicKeyBase32: TypeAlias = Annotated[
    X25519PublicKey,
    EncodedBytes(encoder=Base32Encoder),
    TrX25519PublicKey(),
]

#: Base64 encoded bytes parsed as a private x25519 key.
X25519PrivateKeyBase64: TypeAlias = Annotated[
    X25519PrivateKey,
    EncodedBytes(encoder=Base64Encoder),
    TrX25519PrivateKey(),
]
