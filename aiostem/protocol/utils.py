from __future__ import annotations

import base64
import typing
from collections.abc import Collection, MutableSequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Annotated, Any, ClassVar, Generic, Literal, Protocol, TypeVar

from pydantic_core import PydanticCustomError, core_schema
from pydantic_core.core_schema import CoreSchema, WhenUsed

from ..exceptions import CommandError

if TYPE_CHECKING:
    from pydantic import GetCoreSchemaHandler, GetJsonSchemaHandler
    from pydantic.json_schema import JsonSchemaValue
    from pydantic_core.core_schema import ValidationInfo, ValidatorFunctionWrapHandler

    from .argument import Argument
    from .command import CommandWord


class CommandSerializer:
    """Helper class used to serialize an existing command."""

    END_OF_LINE: ClassVar[str] = '\r\n'

    def __init__(self, name: CommandWord) -> None:
        """
        Create a new command serializer.

        Args:
            name: the command name.

        """
        self._command = name
        self._arguments = []  # type: MutableSequence[Argument]
        self._body = None  # type: str | None

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
    def arguments(self) -> MutableSequence[Argument]:
        """Get the list of command arguments."""
        return self._arguments

    @property
    def body(self) -> str | None:
        """Get the command body, is any."""
        return self._body

    @body.setter
    def body(self, body: str) -> None:
        """
        Set the command body.

        Args:
            body: the new body content for the command

        """
        self._body = body


T = TypeVar('T', bound=bytes | int)


class EncoderProtocol(Protocol, Generic[T]):
    """Protocol for encoding from and decoding data to another type."""

    @classmethod
    def decode(cls, data: str) -> T:
        """
        Decode the data using the encoder.

        Args:
            data: a string that can be decoded to type `T`.

        Returns:
            The newly decoded type.

        """

    @classmethod
    def encode(cls, value: T) -> str:
        """
        Encode the provided value using the encoder.

        Args:
            value: a generic value of type `T`

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

    casefold: ClassVar[bool] = True
    trim_padding: ClassVar[bool] = True

    @classmethod
    def decode(cls, data: str) -> bytes:
        """Decode the provided base32 bytes to original bytes data."""
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
        """Encode the data to a base32 encoded string."""
        encoded = base64.b32encode(value)
        if cls.trim_padding:
            encoded = encoded.rstrip(b'=')
        return encoded.decode()

    @classmethod
    def get_json_format(cls) -> Literal['base32']:
        """Get the JSON format for the encoded data."""
        return 'base32'


class Base64Encoder(EncoderProtocol[bytes]):
    """Encoder for base64 bytes."""

    trim_padding: ClassVar[bool] = True

    @classmethod
    def decode(cls, data: str) -> bytes:
        """Decode the provided base64 bytes to original bytes data."""
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
        """Encode the data to a base64 encoded string."""
        encoded = base64.standard_b64encode(value)
        if cls.trim_padding:
            encoded = encoded.rstrip(b'=')
        return encoded.decode()

    @classmethod
    def get_json_format(cls) -> Literal['base64']:
        """Get the JSON format for the encoded data."""
        return 'base64'


class HexEncoder(EncoderProtocol[bytes]):
    """Specific encoder for hex encoded strings."""

    @classmethod
    def decode(cls, data: str) -> bytes:
        """Decode the provided hex string to original bytes data."""
        try:
            return bytes.fromhex(data.zfill((len(data) + 1) & ~1))
        except ValueError as e:
            raise PydanticCustomError(
                'hex_decode',
                "Hex decoding error: '{error}'",
                {'error': str(e)},
            ) from e

    @classmethod
    def encode(cls, value: bytes) -> str:
        """Encode the data to a hex encoded string."""
        return value.hex()

    @classmethod
    def get_json_format(cls) -> Literal['hex']:
        """Get the JSON format for the encoded data."""
        return 'hex'


@dataclass(slots=True)
class EncodedBase(Generic[T]):
    """Generic encoded value to/from a string using the :class:`EncoderProtocol`."""

    CORE_SCHEMA: ClassVar[CoreSchema]

    encoder: type[EncoderProtocol[T]]
    when_used: WhenUsed = 'always'

    def __get_pydantic_core_schema__(
        self,
        source: type[Any],
        handler: GetCoreSchemaHandler,
    ) -> CoreSchema:
        """Tell the core schema and how to validate the whole thing."""
        return core_schema.with_info_wrap_validator_function(
            function=self.decode,
            schema=self.CORE_SCHEMA,
            serialization=core_schema.plain_serializer_function_ser_schema(
                function=self.encode,
                when_used=self.when_used,
            ),
        )

    def __get_pydantic_json_schema__(
        self,
        core_schema: CoreSchema,
        handler: GetJsonSchemaHandler,
    ) -> JsonSchemaValue:
        """Update JSON schema to also tell about this field."""
        field_schema = handler(core_schema)
        field_schema.update(type='string', format=self.encoder.get_json_format())
        return field_schema

    def decode(
        self,
        data: Any,
        validator: ValidatorFunctionWrapHandler,
        info: ValidationInfo,
    ) -> T:
        """Decode the data using the specified encoder."""
        if isinstance(data, str):
            return validator(self.encoder.decode(data))
        return validator(data)

    def encode(self, value: T) -> str:
        """Encode the value using the specified encoder."""
        return self.encoder.encode(value)


@dataclass(slots=True)
class EncodedBytes(EncodedBase[bytes]):
    """Bytes that can be encoded and decoded from a string using a specified encoder."""

    CORE_SCHEMA = core_schema.bytes_schema()

    def __hash__(self) -> int:
        """
        Provide the hash from the encoder.

        Returns:
            An unique hash for our byte encoder.

        """
        return hash(self.encoder)


@dataclass(frozen=True, slots=True)
class StringSequence:
    """Serialized and deserialize sequences from/to strings."""

    separator: str = ','

    def __get_pydantic_core_schema__(
        self,
        source: type[Collection[Any]],
        handler: GetCoreSchemaHandler,
    ) -> CoreSchema:
        """Tell the core schema and how to validate the whole thing."""
        # Check that we have a valid collection of something like a str, int, float, bool.
        origin = typing.get_origin(source)
        if not isinstance(origin, type) or not issubclass(origin, Collection):
            msg = f"source type is not a collection, got '{source.__name__}'"
            raise TypeError(msg)

        return core_schema.no_info_before_validator_function(
            function=self.parse_value,
            schema=handler(source),
        )

    def __get_pydantic_json_schema__(
        self,
        core_schema: CoreSchema,
        handler: GetJsonSchemaHandler,
    ) -> JsonSchemaValue:
        """Update JSON schema to tell about plain text and separator."""
        field_schema = handler(core_schema)
        field_schema.update(type='string', separator=self.separator)
        return field_schema

    def parse_value(self, value: Any) -> Any:
        """Parse the input value, split it when it is a string."""
        if isinstance(value, bytes | bytearray):
            value = value.decode()
        if isinstance(value, str):
            return value.split(self.separator)
        return value


HexBytes = Annotated[bytes, EncodedBytes(encoder=HexEncoder)]
Base32Bytes = Annotated[bytes, EncodedBytes(encoder=Base32Encoder)]
Base64Bytes = Annotated[bytes, EncodedBytes(encoder=Base64Encoder)]
