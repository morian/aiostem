from __future__ import annotations

import typing
from collections.abc import (
    Collection,
    MutableSequence,
    Sequence,
    Set as AbstractSet,
)
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta, tzinfo
from functools import partial
from typing import (
    TYPE_CHECKING,
    Any,
    ClassVar,
    Literal,  # noqa: F401
)

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from pydantic import ConfigDict, TypeAdapter
from pydantic_core import core_schema
from pydantic_core.core_schema import CoreSchema, WhenUsed

if TYPE_CHECKING:
    from pydantic import GetCoreSchemaHandler, GetJsonSchemaHandler
    from pydantic.json_schema import JsonSchemaValue
    from pydantic_core.core_schema import (
        SerializationInfo,
        SerializerFunctionWrapHandler,
        ValidatorFunctionWrapHandler,
    )


@dataclass(frozen=True, slots=True)
class TrAfterAsTimezone:
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


class TrBeforeLogSeverity:
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
class TrBeforeSetToNone:
    """Pre-validator that sets a value to :obj:`None`."""

    #: List of values mapped to None.
    values: AbstractSet[Any] = field(default_factory=frozenset)

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
class TrBeforeStringSplit:
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

        values: MutableSequence[Any] = []
        if self.dict_keys is not None:
            for key in self.dict_keys:
                values.append(dump[key])
        else:
            values.extend(dump)

        return self.separator.join(map(str, values))


@dataclass(frozen=True, slots=True)
class TrBeforeTimedelta:
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
class TrWrapX25519PrivateKey:
    """Transform bytes into a X25519 private key."""

    def __get_pydantic_core_schema__(
        self,
        source: type[X25519PrivateKey],
        handler: GetCoreSchemaHandler,
    ) -> CoreSchema:
        """Declare schema and validator for a X25519 private key."""
        if not issubclass(source, X25519PrivateKey):
            msg = f"source type is not a x25519 private key, got '{source.__name__}'"
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
        key: X25519PrivateKey,
        serialize: SerializerFunctionWrapHandler,
    ) -> Any:
        """Serialize the current key to bytes and beyond."""
        return serialize(self.to_bytes(key))

    def _pydantic_validator(
        self,
        data: Any,
        validator: ValidatorFunctionWrapHandler,
    ) -> X25519PrivateKey:
        """Decode the underlying X25519 private key."""
        if isinstance(data, str | bytes):
            data = self.from_bytes(validator(data))
        return data

    def from_bytes(self, data: bytes) -> X25519PrivateKey:
        """
        Build a X25519 private key out of the provided bytes.

        Returns:
            An instance of a X25519 private key.

        """
        return X25519PrivateKey.from_private_bytes(data)

    def to_bytes(self, key: X25519PrivateKey) -> bytes:
        """
        Serialize the provided private key to bytes.

        Returns:
            32 bytes corresponding to the private key.

        """
        return key.private_bytes_raw()


@dataclass(frozen=True, slots=True)
class TrWrapX25519PublicKey:
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
