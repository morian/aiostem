from __future__ import annotations

import base64
import hashlib
import typing
from collections.abc import (
    Collection,
    MutableSequence,
    Sequence,
    Set as AbstractSet,
)
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta, tzinfo
from enum import IntEnum
from functools import cached_property, partial
from ipaddress import IPv4Address, IPv6Address
from typing import (
    TYPE_CHECKING,
    Annotated,
    Any,
    ClassVar,
    Generic,
    Literal,
    Protocol,
    Self,
    TypeAlias,
    TypeVar,
    Union,
)

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
from pydantic import ConfigDict, Field, TypeAdapter
from pydantic_core import PydanticCustomError, core_schema
from pydantic_core.core_schema import CoreSchema, WhenUsed

from ..exceptions import CommandError

if TYPE_CHECKING:
    from pydantic import GetCoreSchemaHandler, GetJsonSchemaHandler
    from pydantic.json_schema import JsonSchemaValue
    from pydantic_core.core_schema import (
        SerializationInfo,
        SerializerFunctionWrapHandler,
        ValidatorFunctionWrapHandler,
    )

    from .argument import ArgumentKeyword, ArgumentString
    from .command import CommandWord


#: Any IP address, either IPv4 or IPv6.
AnyAddress: TypeAlias = Union[IPv4Address | IPv6Address]  # noqa: UP007

#: Any host, either by IP address or hostname.
AnyHost: TypeAlias = Annotated[
    IPv4Address | IPv6Address | str,
    Field(union_mode='left_to_right'),
]
#: Any TCP or UDP port.
AnyPort: TypeAlias = Annotated[int, Field(gt=0, lt=65536)]


@dataclass(frozen=True, slots=True)
class AsTimezone:
    """Post-validator that enforces a timezone."""

    #: Timezone to map this date to.
    timezone: tzinfo = UTC

    def __get_pydantic_core_schema__(
        self,
        source: type[Any],
        handler: GetCoreSchemaHandler,
    ) -> CoreSchema:
        """Declare a validator to add or change the timezone."""
        if not issubclass(source, datetime):
            msg = f"source type is not a datetime, got '{source.__name__}'"
            raise TypeError(msg)

        return core_schema.no_info_after_validator_function(
            function=self.from_value,
            schema=handler(source),
        )

    def from_value(self, value: datetime) -> datetime:
        """
        Apply the timezone of change the offset.

        Args:
            value: The original datetime to change.

        Returns:
            A new datetime with the proper timezone applied.

        """
        if value.tzinfo is None:
            return value.replace(tzinfo=self.timezone)
        return value.astimezone(self.timezone)


class CommandSerializer:
    """Helper class used to serialize an existing command."""

    #: End of line to use while serializing a command.
    END_OF_LINE: ClassVar[str] = '\r\n'

    def __init__(self, name: CommandWord) -> None:
        """
        Create a new command serializer.

        This is used internally by :meth:`.Command.serialize`.

        Args:
            name: The command name.

        """
        self._body = None  # type: str | None
        self._command = name
        self._arguments = []  # type: MutableSequence[ArgumentKeyword | ArgumentString]

    def serialize(self) -> str:
        """
        Serialize the arguments to a string.

        Returns:
            Text that can be pushed to the server.

        """
        # Build the header line.
        args = [self._command.value]
        for argument in self._arguments:
            args.append(str(argument))

        header = ' '.join(args)
        # Check for command injection in case some user-controlled values went through.
        if any(c in header for c in '\r\v\n'):
            msg = 'Command injection was detected and prevented'
            raise CommandError(msg)
        lines = [header]

        # Include the potential body, if applicable.
        if self._body is None:
            prefix = ''
        else:
            for line in self._body.splitlines():
                if line.startswith('.'):
                    line = '.' + line
                lines.append(line)
            lines.append('.')
            prefix = '+'
        return prefix + self.END_OF_LINE.join(lines) + self.END_OF_LINE

    @property
    def command(self) -> CommandWord:
        """Get the command name for the underlying command."""
        return self._command

    @property
    def arguments(self) -> MutableSequence[ArgumentKeyword | ArgumentString]:
        """Get the list of command arguments."""
        return self._arguments

    @property
    def body(self) -> str | None:
        """Get the command body, if any."""
        return self._body

    @body.setter
    def body(self, body: str) -> None:
        """
        Set the command body.

        Args:
            body: The new body content for the command.

        """
        self._body = body


#: Generic type used for our encoders.
T = TypeVar('T', bound=bytes | int)


class EncoderProtocol(Protocol, Generic[T]):
    """Protocol for encoding from and decoding data to another type."""

    @classmethod
    def decode(cls, data: str) -> T:
        """
        Decode the data using the encoder.

        Args:
            data: A string that can be decoded to type ``T``.

        Returns:
            The newly decoded type.

        """

    @classmethod
    def encode(cls, value: T) -> str:
        """
        Encode the provided value using the encoder.

        Args:
            value: A generic value of type ``T``.

        Returns:
            The exact value encoded to a string.

        """

    @classmethod
    def get_json_format(cls) -> str:
        """
        Get the JSON format for the encoded data.

        Returns:
            A short descriptive name for the format.

        """


class Base32Encoder(EncoderProtocol[bytes]):
    """Encoder for base32 bytes."""

    #: Whether we are case insensitive when decoding.
    casefold: ClassVar[bool] = True
    #: Whether to remove the padding characters when serializing.
    trim_padding: ClassVar[bool] = True

    @classmethod
    def decode(cls, data: str) -> bytes:
        """
        Decode the provided base32 bytes to original bytes data.

        Args:
            data: A base32-encoded string to decode.

        Raises:
            PydanticCustomError: On decoding error.

        Returns:
            The corresponding decoded bytes.

        """
        try:
            if cls.trim_padding:
                data = data.rstrip('=')
                padlen = -len(data) % 8
                data = data + padlen * '='
            return base64.b32decode(data, cls.casefold)
        except ValueError as e:
            raise PydanticCustomError(
                'base32_decode',
                "Base32 decoding error: '{error}'",
                {'error': str(e)},
            ) from e

    @classmethod
    def encode(cls, value: bytes) -> str:
        """
        Encode a value to a base32 encoded string.

        Args:
            value: A byte value to encode to base32.

        Returns:
            The corresponding encoded string value.

        """
        if isinstance(value, bytes):
            encoded = base64.b32encode(value)
            if cls.trim_padding:
                encoded = encoded.rstrip(b'=')
            return encoded.decode()
        return value

    @classmethod
    def get_json_format(cls) -> Literal['base32']:
        """Get the JSON format for the encoded data."""
        return 'base32'


class Base64Encoder(EncoderProtocol[bytes]):
    """Encoder for base64 bytes."""

    #: Whether to remove the padding characters when serializing.
    trim_padding: ClassVar[bool] = True

    @classmethod
    def decode(cls, data: str) -> bytes:
        """
        Decode the provided base64 bytes to original bytes data.

        Args:
            data: A base64-encoded string to decode.

        Raises:
            PydanticCustomError: On decoding error.

        Returns:
            The corresponding decoded bytes.

        """
        try:
            encoded = data.encode()
            if cls.trim_padding:
                encoded = encoded.rstrip(b'=')
                padlen = -len(encoded) % 4
                encoded = encoded + padlen * b'='
            return base64.standard_b64decode(encoded)
        except ValueError as e:
            raise PydanticCustomError(
                'base64_decode',
                "Base64 decoding error: '{error}'",
                {'error': str(e)},
            ) from e

    @classmethod
    def encode(cls, value: bytes) -> str:
        """
        Encode a value to a base64 encoded string.

        Args:
            value: A byte value to encode to base64.

        Returns:
            The corresponding encoded string value.

        """
        if isinstance(value, bytes):
            encoded = base64.standard_b64encode(value)
            if cls.trim_padding:
                encoded = encoded.rstrip(b'=')
            return encoded.decode()
        return value

    @classmethod
    def get_json_format(cls) -> Literal['base64']:
        """Get the JSON format for the encoded data."""
        return 'base64'


class HexEncoder(EncoderProtocol[bytes]):
    """Specific encoder for hex encoded strings."""

    @classmethod
    def decode(cls, data: str) -> bytes:
        """
        Decode the provided hex string to original bytes data.

        Args:
            data: A hex-encoded string to decode.

        Raises:
            PydanticCustomError: On decoding error.

        Returns:
            The corresponding decoded bytes.

        """
        try:
            return bytes.fromhex(data.zfill((len(data) + 1) & ~1))
        except ValueError as e:
            raise PydanticCustomError(
                'base16_decode',
                "Base16 decoding error: '{error}'",
                {'error': str(e)},
            ) from e

    @classmethod
    def encode(cls, value: bytes) -> str:
        """
        Encode a value to a hex encoded string.

        Args:
            value: A byte value to encode to a hexadecimal string.

        Returns:
            The corresponding encoded string value.

        """
        if isinstance(value, bytes):
            return value.hex()
        return value

    @classmethod
    def get_json_format(cls) -> Literal['base16']:
        """Get the JSON format for the encoded data."""
        return 'base16'


@dataclass(slots=True)
class EncodedBase(Generic[T]):
    """Generic encoded value to/from a string using the :class:`EncoderProtocol`."""

    CORE_SCHEMA: ClassVar[CoreSchema]

    #: The encoder protocol to use.
    encoder: type[EncoderProtocol[T]]
    #: When to use the encoder.
    when_used: WhenUsed = 'always'

    def __get_pydantic_core_schema__(
        self,
        source: type[Any],
        handler: GetCoreSchemaHandler,
    ) -> CoreSchema:
        """Tell the core schema and how to validate the whole thing."""
        return core_schema.no_info_wrap_validator_function(
            function=self._pydantic_validator,
            schema=self.CORE_SCHEMA,
            serialization=core_schema.plain_serializer_function_ser_schema(
                function=self.to_string,
                when_used=self.when_used,
            ),
        )

    def __get_pydantic_json_schema__(
        self,
        core_schema: CoreSchema,
        handler: GetJsonSchemaHandler,
    ) -> JsonSchemaValue:
        """
        Update JSON schema to also tell about this field.

        See Also:
            https://json-schema.org/draft/2020-12/json-schema-validation#name-contentencoding

        """
        field_schema = handler(core_schema)
        field_schema.update(type='string', contentEncoding=self.encoder.get_json_format())
        return field_schema

    def _pydantic_validator(
        self,
        data: Any,
        validator: ValidatorFunctionWrapHandler,
    ) -> T:
        """Decode the data using the specified encoder."""
        if isinstance(data, str):
            return validator(self.from_string(data))
        return validator(data)

    def from_string(self, string: str) -> T:
        """Decode a string to the underlying type."""
        return self.encoder.decode(string)

    def to_string(self, value: T) -> str:
        """Encode the value using the specified encoder."""
        return self.encoder.encode(value)


@dataclass(slots=True)
class EncodedBytes(EncodedBase[bytes]):
    """Bytes that can be encoded and decoded from a string using an external encoder."""

    #: Our core schema is for :class:`bytes`.
    CORE_SCHEMA = core_schema.bytes_schema()

    def __hash__(self) -> int:
        """
        Provide the hash from the encoder.

        Returns:
            An unique hash for our byte encoder.

        """
        return hash(self.encoder)


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
    def public_key(self) -> X25519PublicKey:
        """
        Get the x25519 public key for this domain.

        Returns:
            The x25519 public key associated with this v3 onion domain.

        """
        data = base64.b32decode(self, casefold=True)
        return X25519PublicKey.from_public_bytes(data[00:32])


#: Any kind of onion service address.
HiddenServiceAddress: TypeAlias = Union[HiddenServiceAddressV2 | HiddenServiceAddressV3]  # noqa: UP007


@dataclass(frozen=True, slots=True)
class LongServerName:
    """A Tor Server name and its optional nickname."""

    #: Server fingerprint as a 20 bytes value.
    fingerprint: HexBytes

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


class LogSeverityTransformer:
    """Pre-validator for strings to build a valid :class:`.LogSeverity`."""

    def __get_pydantic_core_schema__(
        self,
        source: type[str],
        handler: GetCoreSchemaHandler,
    ) -> CoreSchema:
        """Set a custom validator used to transform the input string."""
        return core_schema.no_info_before_validator_function(
            self.from_value,
            handler(source),
        )

    def from_value(self, value: Any) -> Any:
        """Parse the input value, split it when it is a string."""
        if isinstance(value, str):  # pragma: no branch
            value = value.upper()
            if value == 'ERR':
                value = 'ERROR'
        return value


@dataclass(frozen=True, slots=True)
class StringSplit:
    """Deserialize sequences from/to strings."""

    #: Base pydantic configuration to apply when serializing.
    model_config: ClassVar[ConfigDict | None] = None

    #: Maximum number of string split.
    maxsplit: int = -1

    #: How to split this string sequence.
    separator: str = ','

    #: Optional list of keys when converted to a dictionary.
    dict_keys: Sequence[str] | None = None

    #: When serialization is supposed to be used.
    when_used: WhenUsed = 'always'

    def __get_pydantic_core_schema__(
        self,
        source: type[Any],
        handler: GetCoreSchemaHandler,
    ) -> CoreSchema:
        """Tell the core schema and how to validate the whole thing."""
        if self.dict_keys is None:
            # Check that we have a valid collection of something like a str, int, float, bool.
            origin = typing.get_origin(source)
            if not isinstance(origin, type) or not issubclass(origin, Collection):
                msg = f"source type is not a collection, got '{source.__name__}'"
                raise TypeError(msg)

        return core_schema.no_info_before_validator_function(
            function=self.from_value,
            schema=handler(source),
            serialization=core_schema.plain_serializer_function_ser_schema(
                function=partial(self.serialize, TypeAdapter(source)),
                info_arg=True,
                return_schema=core_schema.str_schema(),
                when_used=self.when_used,
            ),
        )

    def __get_pydantic_json_schema__(
        self,
        core_schema: CoreSchema,
        handler: GetJsonSchemaHandler,
    ) -> JsonSchemaValue:
        """Update JSON schema to tell about plain text and separator."""
        field_schema = handler(core_schema)
        field_schema.update(
            type='string',
            maxSplit=self.maxsplit,
            separator=self.separator,
        )
        return field_schema

    def from_value(self, value: Any) -> Any:
        """Parse the input value, split it when it is a string."""
        if isinstance(value, bytes | bytearray):
            value = value.decode()
        if isinstance(value, str):
            items = value.split(self.separator, maxsplit=self.maxsplit)
            if self.dict_keys is not None:
                return dict(zip(self.dict_keys, items, strict=False))
            return items
        return value

    def serialize(
        self,
        adapter: TypeAdapter[Any],
        item: Any,
        info: SerializationInfo,
    ) -> str:
        """Tells how we serialize this collection for JSON."""
        mode = 'json' if info.mode_is_json() else 'python'  # type: Literal['json', 'python']
        dump = adapter.dump_python(
            item,
            exclude_defaults=info.exclude_defaults,
            exclude_none=info.exclude_none,
            exclude_unset=info.exclude_unset,
            mode=mode,
        )

        values = []  # type: MutableSequence[Any]
        if self.dict_keys is not None:
            for key in self.dict_keys:
                values.append(dump[key])
        else:
            values.extend(dump)

        return self.separator.join(map(str, values))


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


@dataclass(frozen=True, slots=True)
class SetToNone:
    """Pre-validator that sets a value to :obj:`None`."""

    #: List of values mapped to None.
    values: AbstractSet[Any] = field(default_factory=set)

    def __get_pydantic_core_schema__(
        self,
        source: type[Any],
        handler: GetCoreSchemaHandler,
    ) -> CoreSchema:
        """Declare schema and validator to replace values to None."""
        return core_schema.no_info_before_validator_function(
            self.from_value,
            handler(source),
        )

    def from_value(self, value: Any) -> Any:
        """
        Set the return value to :obj:`None` when applicable.

        Args:
            value: The value to check against :attr:`values`.

        Returns:
            The same value of :obj:`None` when matching any value in :attr:`values`.

        """
        if value in self.values:
            return None
        return value


@dataclass(frozen=True, slots=True)
class TimedeltaTransformer:
    """Pre-validator that gets a timedelta from an int or float."""

    #: Whether the input value is expected to be in milliseconds.
    milliseconds: bool = False

    def __get_pydantic_core_schema__(
        self,
        source: type[Any],
        handler: GetCoreSchemaHandler,
    ) -> CoreSchema:
        """Set a custom validator used to transform seconds in a timedelta."""
        if not issubclass(source, timedelta):
            msg = f"source type is not a timedelta, got '{source.__name__}'"
            raise TypeError(msg)

        return core_schema.no_info_before_validator_function(
            self.from_value,
            handler(source),
        )

    def from_value(self, value: Any) -> Any:
        """Parse the input value as an integer or float timedelta."""
        if isinstance(value, int | str):
            value = float(value)
        if isinstance(value, float):
            if self.milliseconds:
                value = value / 1000.0
            value = timedelta(seconds=value)
        return value


@dataclass(frozen=True, slots=True)
class X25519PublicKeyTransformer:
    """Transform bytes into a X25519 public key."""

    def __get_pydantic_core_schema__(
        self,
        source: type[X25519PublicKey],
        handler: GetCoreSchemaHandler,
    ) -> CoreSchema:
        """Declare schema and validator for a X25519 public key."""
        if not issubclass(source, X25519PublicKey):
            msg = f"source type is not a x25519 public key, got '{source.__name__}'"
            raise TypeError(msg)

        return core_schema.no_info_wrap_validator_function(
            function=self._pydantic_validator,
            schema=handler(source),
            serialization=core_schema.wrap_serializer_function_ser_schema(
                function=self._pydantic_serializer,
                schema=handler(source),
            ),
        )

    def _pydantic_serializer(
        self,
        key: X25519PublicKey,
        serialize: SerializerFunctionWrapHandler,
    ) -> Any:
        """Serialize the current key to bytes and beyond."""
        return serialize(self.to_bytes(key))

    def _pydantic_validator(
        self,
        data: Any,
        validator: ValidatorFunctionWrapHandler,
    ) -> X25519PublicKey:
        """Decode the underlying X25519 public key."""
        if isinstance(data, str | bytes):
            data = self.from_bytes(validator(data))
        return data

    def from_bytes(self, data: bytes) -> X25519PublicKey:
        """
        Build a X25519 public key out of the provided bytes.

        Returns:
            An instance of a X25519 public key.

        """
        return X25519PublicKey.from_public_bytes(data)

    def to_bytes(self, key: X25519PublicKey) -> bytes:
        """
        Serialize the provided public key to bytes.

        Returns:
            32 bytes corresponding to the public key.

        """
        return key.public_bytes_raw()


#: Bytes that are base32 encoded.
Base32Bytes: TypeAlias = Annotated[bytes, EncodedBytes(encoder=Base32Encoder)]
#: Bytes that are base64 encoded.
Base64Bytes: TypeAlias = Annotated[bytes, EncodedBytes(encoder=Base64Encoder)]
#: Bytes that are base64 encoded.
HexBytes: TypeAlias = Annotated[bytes, EncodedBytes(encoder=HexEncoder)]

#: A :class:`timedelta` parsed from an integer value in seconds.
TimedeltaSeconds: TypeAlias = Annotated[
    timedelta,
    TimedeltaTransformer(milliseconds=False),
]
#: A :class:`timedelta` parsed from an integer value in milliseconds.
TimedeltaMilliseconds: TypeAlias = Annotated[
    timedelta,
    TimedeltaTransformer(milliseconds=True),
]
#: Base32 encoded bytes parsed as a public x25519 key.
X25519PublicKeyBase32: TypeAlias = Annotated[
    X25519PublicKey,
    EncodedBytes(encoder=Base32Encoder),
    X25519PublicKeyTransformer(),
]
