from __future__ import annotations

import typing
from collections.abc import (
    Collection,
    Mapping,
    MutableSequence,  # noqa: F401
    Sequence,
    Set as AbstractSet,
)
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta, tzinfo
from typing import TYPE_CHECKING, Any, ClassVar

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from pydantic import ConfigDict, PydanticSchemaGenerationError
from pydantic_core import core_schema
from pydantic_core.core_schema import CoreSchema, WhenUsed

if TYPE_CHECKING:
    from pydantic import GetCoreSchemaHandler
    from pydantic_core.core_schema import SerializerFunctionWrapHandler


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

        return core_schema.chain_schema(
            steps=[
                core_schema.datetime_schema(),
                core_schema.no_info_after_validator_function(
                    function=self.from_value,
                    schema=core_schema.datetime_schema(),
                ),
            ],
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


@dataclass(frozen=True, slots=True)
class TrCast:
    """Pre-validator that converts to the target type."""

    #: Type we want to cast this to!
    target: type[Any]

    def __get_pydantic_core_schema__(
        self,
        source: type[Any],
        handler: GetCoreSchemaHandler,
    ) -> CoreSchema:
        """Declare schema and validator to cast to the provided type."""
        source_schema = handler(source)
        target_schema = handler.generate_schema(self.target)
        return core_schema.chain_schema(
            steps=[
                target_schema,
                source_schema,
            ],
        )


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
            function=self.from_value,
            schema=handler(source),
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
            # Check that we have a valid collection of something else.
            origin = typing.get_origin(source) or source
            if not isinstance(origin, type) or not issubclass(origin, Collection):
                msg = f"source type is not a collection, got '{source.__name__}'"
                raise TypeError(msg)

        return core_schema.union_schema(
            choices=[
                handler(source),
                core_schema.chain_schema(
                    steps=[
                        core_schema.str_schema(),
                        core_schema.no_info_before_validator_function(
                            function=self._pydantic_validator,
                            schema=handler(source),
                        ),
                    ],
                ),
            ],
            serialization=core_schema.wrap_serializer_function_ser_schema(
                function=self._pydantic_serializer,
                schema=handler(source),
                return_schema=core_schema.str_schema(),
                when_used=self.when_used,
            ),
        )

    def _pydantic_validator(self, value: str) -> Sequence[str] | Mapping[str, str]:
        """Parse the input string and convert it to a list or a dictionary."""
        items = value.split(self.separator, maxsplit=self.maxsplit)
        if self.dict_keys is not None:
            return dict(zip(self.dict_keys, items, strict=False))
        return items

    def _pydantic_serializer(
        self,
        value: Any,
        serializer: SerializerFunctionWrapHandler,
    ) -> str:
        """Tells how we serialize this collection for JSON."""
        values = []  # type: MutableSequence[str]
        parts = serializer(value)

        if isinstance(parts, Mapping) and isinstance(self.dict_keys, Sequence):
            for key in self.dict_keys:
                values.append(parts[key])
        else:
            values.extend(parts)
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

        return core_schema.union_schema(
            choices=[
                handler(source),
                core_schema.chain_schema(
                    steps=[
                        core_schema.float_schema(),
                        core_schema.no_info_before_validator_function(
                            self.from_float,
                            handler(source),
                        ),
                    ],
                ),
            ],
            serialization=core_schema.plain_serializer_function_ser_schema(
                function=self.to_float,
                return_schema=core_schema.float_schema(),
            ),
        )

    def from_float(self, value: float) -> timedelta:
        """Parse the input value as an integer or float timedelta."""
        if self.milliseconds:
            value = value / 1000.0
        return timedelta(seconds=value)

    def to_float(self, delta: timedelta) -> float:
        """Convert the timedelta value to a float."""
        value = delta.total_seconds()
        if self.milliseconds:
            value = 1000.0 * value
        return value


@dataclass(frozen=True, slots=True)
class TrX25519PrivateKey:
    """Transform bytes into a X25519 private key."""

    def __get_pydantic_core_schema__(
        self,
        source: type[Any],
        handler: GetCoreSchemaHandler,
    ) -> CoreSchema:
        """Declare schema and validator for a X25519 private key."""
        if not issubclass(source, X25519PrivateKey):
            msg = f"source type is not a x25519 private key, got '{source.__name__}'"
            raise TypeError(msg)

        try:
            source_schema = handler(source)
        except PydanticSchemaGenerationError:
            source_schema = core_schema.bytes_schema(strict=True)

        return core_schema.union_schema(
            choices=[
                core_schema.is_instance_schema(X25519PrivateKey),
                core_schema.chain_schema(
                    steps=[
                        source_schema,
                        core_schema.no_info_after_validator_function(
                            function=self.from_bytes,
                            schema=core_schema.bytes_schema(strict=True),
                        ),
                    ],
                ),
            ],
            serialization=core_schema.plain_serializer_function_ser_schema(
                function=self.to_bytes,
                return_schema=source_schema,
            ),
        )

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
class TrX25519PublicKey:
    """Transform bytes into a X25519 public key."""

    def __get_pydantic_core_schema__(
        self,
        source: type[Any],
        handler: GetCoreSchemaHandler,
    ) -> CoreSchema:
        """Declare schema and validator for a X25519 public key."""
        if not issubclass(source, X25519PublicKey):
            msg = f"source type is not a x25519 public key, got '{source.__name__}'"
            raise TypeError(msg)

        try:
            source_schema = handler(source)
        except PydanticSchemaGenerationError:
            source_schema = core_schema.bytes_schema(strict=True)

        return core_schema.union_schema(
            choices=[
                core_schema.is_instance_schema(X25519PublicKey),
                core_schema.chain_schema(
                    steps=[
                        source_schema,
                        core_schema.no_info_after_validator_function(
                            function=self.from_bytes,
                            schema=core_schema.bytes_schema(strict=True),
                        ),
                    ],
                ),
            ],
            serialization=core_schema.plain_serializer_function_ser_schema(
                function=self.to_bytes,
                return_schema=source_schema,
            ),
        )

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
