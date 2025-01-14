from __future__ import annotations

import base64
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, ClassVar, Generic, Literal, Protocol, TypeVar

from pydantic_core import PydanticCustomError, core_schema
from pydantic_core.core_schema import CoreSchema, WhenUsed

if TYPE_CHECKING:
    from pydantic import GetCoreSchemaHandler, GetJsonSchemaHandler
    from pydantic.json_schema import JsonSchemaValue


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


class Base16Encoder(EncoderProtocol[bytes]):
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
        return core_schema.union_schema(
            choices=[
                # We can already be made of bytes and skip all processing from here.
                self.CORE_SCHEMA,
                # Otherwise we have to be a string and follow the decoding path.
                core_schema.chain_schema(
                    steps=[
                        core_schema.str_schema(strict=True),
                        core_schema.no_info_before_validator_function(
                            function=self.from_string,
                            schema=self.CORE_SCHEMA,
                        ),
                    ],
                ),
            ],
            # We are bytes and will be returned as a string.
            serialization=core_schema.plain_serializer_function_ser_schema(
                function=self.to_string,
                when_used=self.when_used,
            ),
        )

    def __get_pydantic_json_schema__(
        self,
        schema: CoreSchema,
        handler: GetJsonSchemaHandler,
    ) -> JsonSchemaValue:
        """
        Update JSON schema to also tell about this field.

        See Also:
            https://json-schema.org/draft/2020-12/json-schema-validation#name-contentencoding

        """
        content_encoding = self.encoder.get_json_format()
        field_schema = handler(core_schema.bytes_schema())
        field_schema.update(contentEncoding=content_encoding, type='string')
        return field_schema

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
    CORE_SCHEMA = core_schema.bytes_schema(strict=True)

    def __hash__(self) -> int:
        """
        Provide the hash from the encoder.

        Returns:
            An unique hash for our byte encoder.

        """
        return hash(self.encoder)
