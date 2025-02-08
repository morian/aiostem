from __future__ import annotations

import hashlib
import typing
from abc import ABC, abstractmethod
from collections.abc import (
    Collection,
    Mapping,
    MutableSequence,  # noqa: F401
    Sequence,
    Set as AbstractSet,
)
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta, tzinfo
from typing import TYPE_CHECKING, Any, ClassVar, Generic, Literal, TypeVar

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    load_der_private_key,
    load_der_public_key,
)
from pydantic import ConfigDict
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

    #: Whether to apply this transformation before or after the main handler.
    mode: Literal['before', 'after'] = 'before'

    def __get_pydantic_core_schema__(
        self,
        source: type[Any],
        handler: GetCoreSchemaHandler,
    ) -> CoreSchema:
        """Declare schema and validator to cast to the provided type."""
        schema: CoreSchema
        source_schema = handler(source)
        target_schema = handler.generate_schema(self.target)

        match self.mode:
            case 'before':
                schema = core_schema.no_info_before_validator_function(
                    function=self._pydantic_validator,
                    schema=core_schema.union_schema(
                        choices=[
                            core_schema.chain_schema(
                                steps=[
                                    target_schema,
                                    source_schema,
                                ],
                            ),
                            source_schema,
                        ]
                    ),
                )

            case 'after':  # pragma: no branch
                schema = core_schema.no_info_after_validator_function(
                    function=self._pydantic_validator,
                    schema=core_schema.union_schema(
                        choices=[
                            core_schema.chain_schema(
                                steps=[
                                    source_schema,
                                    target_schema,
                                ],
                            ),
                            source_schema,
                        ]
                    ),
                )

        return schema

    def _pydantic_validator(self, value: Any) -> Any:
        """Do not validate, simply pass the value."""
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

    #: Unit used to serialize and deserialize.
    unit: Literal['milliseconds', 'seconds', 'minutes'] = 'seconds'

    #: Whether to serialize / deserialize to a float number.
    is_float: bool = True

    def __get_pydantic_core_schema__(
        self,
        source: type[Any],
        handler: GetCoreSchemaHandler,
    ) -> CoreSchema:
        """Set a custom validator used to transform seconds in a timedelta."""
        if not issubclass(source, timedelta):
            msg = f"source type is not a timedelta, got '{source.__name__}'"
            raise TypeError(msg)

        if self.is_float:
            source_schema = core_schema.float_schema()  # type: CoreSchema
        else:
            source_schema = core_schema.int_schema()

        return core_schema.union_schema(
            choices=[
                handler(source),
                core_schema.chain_schema(
                    steps=[
                        source_schema,
                        core_schema.no_info_before_validator_function(
                            self.from_number,
                            handler(source),
                        ),
                    ],
                ),
            ],
            serialization=core_schema.plain_serializer_function_ser_schema(
                function=self.to_number,
                return_schema=source_schema,
            ),
        )

    def from_number(self, value: float) -> timedelta:
        """
        Parse the input value as an integer or float timedelta.

        Args:
            value: The input value we want to create a timedelta from.

        Returns:
            A simple timedelta built from the provided value.

        """
        match self.unit:
            case 'milliseconds':
                value = value / 1000.0
            case 'minutes':
                value = value * 60.0
        return timedelta(seconds=value)

    def to_number(self, delta: timedelta) -> float | int:
        """
        Convert the timedelta value to a float or int.

        Args:
            delta: The timedelta value we want to serialize.

        Returns:
            A float or integer value.

        """
        value = delta.total_seconds()

        match self.unit:
            case 'milliseconds':
                value = 1000 * value
            case 'minutes':
                value = value / 60.0

        if not self.is_float:
            return int(value)
        return value


KeyType = TypeVar('KeyType')


class TrGenericKey(ABC, Generic[KeyType]):
    """Transform bytes in a key."""

    def __get_pydantic_core_schema__(
        self,
        source: type[Any],
        handler: GetCoreSchemaHandler,
    ) -> CoreSchema:
        """Declare schema and validator for any kind of keys."""
        key_type = self._get_type()

        if not issubclass(source, key_type):
            msg = f"source type is not a {key_type.__name__}, got '{source.__name__}'"
            raise TypeError(msg)

        source_schema = core_schema.bytes_schema(strict=True)
        return core_schema.union_schema(
            choices=[
                core_schema.is_instance_schema(key_type),
                core_schema.no_info_after_validator_function(
                    function=self.from_bytes,
                    schema=source_schema,
                ),
            ],
            serialization=core_schema.plain_serializer_function_ser_schema(
                function=self.to_bytes,
                return_schema=source_schema,
            ),
        )

    @abstractmethod
    def _get_type(self) -> type[KeyType]:
        """Get the key type used by this generic class."""

    @abstractmethod
    def from_bytes(self, data: bytes) -> KeyType:
        """Build a key from the provided bytes."""

    @abstractmethod
    def to_bytes(self, key: KeyType) -> bytes:
        """Serialize a key to its corresponding bytes."""


@dataclass(frozen=True, slots=True)
class TrEd25519PrivateKey(TrGenericKey[Ed25519PrivateKey]):
    """
    Transform bytes into an ed25519 private key.

    Note:
        Tor's implementation of Ed25519 is donna-ed25519 and uses the expanded
        form as the private key (64 bytes). Unfortunately ``cryptography`` does
        not provide such interface, which means that we are left with this
        implementation.

    """

    #: Whether to generate the expanded form while serializing.
    #:
    #: Note:
    #:     This makes parsing impossible...
    expanded: bool = False

    def _get_type(self) -> type[Ed25519PrivateKey]:
        """Get the key type used by this generic class."""
        return Ed25519PrivateKey

    def from_bytes(self, data: bytes) -> Ed25519PrivateKey:
        """
        Build an ed25519 private key out of the provided bytes.

        Args:
            data: a 32 bytes seed representing a secret key.

        Returns:
            An instance of an ed25519 private key.

        """
        return Ed25519PrivateKey.from_private_bytes(data)

    def to_bytes(self, key: Ed25519PrivateKey) -> bytes:
        """
        Serialize the provided private key to bytes.

        See Also:
            - :meth:`to_expanded_bytes`
            - :meth:`to_seed_bytes`

        Returns:
            32 or 64 bytes corresponding to the private key.

        """
        if self.expanded:
            return self.to_expanded_bytes(key)
        return self.to_seed_bytes(key)

    def to_expanded_bytes(self, key: Ed25519PrivateKey) -> bytes:
        """
        Serialize to the expanded form.

        Returns:
            64 bytes corresponding to the expanded private key.

        """
        seed = self.to_seed_bytes(key)
        extsk = list(hashlib.sha512(seed).digest())
        extsk[0] &= 248
        extsk[31] &= 127
        extsk[31] |= 64
        return bytes(extsk)

    def to_seed_bytes(self, key: Ed25519PrivateKey) -> bytes:
        """
        Serialize the seed bytes, which is the default behavior.

        Returns:
            32 bytes corresponding to the private key.

        """
        return key.private_bytes_raw()


@dataclass(frozen=True, slots=True)
class TrEd25519PublicKey(TrGenericKey[Ed25519PublicKey]):
    """Transform bytes into a ed25519 public key."""

    def _get_type(self) -> type[Ed25519PublicKey]:
        """Get the key type used by this generic class."""
        return Ed25519PublicKey

    def from_bytes(self, data: bytes) -> Ed25519PublicKey:
        """
        Build an ed25519 public key out of the provided bytes.

        Returns:
            An instance of an ed25519 public key.

        """
        return Ed25519PublicKey.from_public_bytes(data)

    def to_bytes(self, key: Ed25519PublicKey) -> bytes:
        """
        Serialize the provided public key to bytes.

        Returns:
            32 bytes corresponding to the public key.

        """
        return key.public_bytes_raw()


@dataclass(frozen=True, slots=True)
class TrRSAPrivateKey(TrGenericKey[RSAPrivateKey]):
    """Transform bytes into a RSA private key."""

    #: Encoding format for the public RSA key.
    encoding: Encoding = Encoding.DER

    #: Key format used while serializing.
    format: PrivateFormat = PrivateFormat.TraditionalOpenSSL

    def _get_type(self) -> type[RSAPrivateKey]:
        """Get the key type used by this generic class."""
        return RSAPrivateKey

    def from_bytes(self, data: bytes) -> RSAPrivateKey:
        """
        Build a RSA private key out of the provided bytes.

        Returns:
            An instance of a RSA private key.

        """
        key = load_der_private_key(data, password=None)
        if not isinstance(key, RSAPrivateKey):
            msg = 'Loaded key is not a valid RSA private key.'
            raise TypeError(msg)
        return key

    def to_bytes(self, key: RSAPrivateKey) -> bytes:
        """Serialize the provided private key to bytes."""
        return key.private_bytes(self.encoding, self.format, NoEncryption())


@dataclass(frozen=True, slots=True)
class TrRSAPublicKey(TrGenericKey[RSAPublicKey]):
    """Transform bytes into a RSA public key."""

    #: Encoding format for the public RSA key.
    encoding: Encoding = Encoding.DER

    #: Key format used while serializing.
    format: PublicFormat = PublicFormat.PKCS1

    def _get_type(self) -> type[RSAPublicKey]:
        """Get the key type used by this generic class."""
        return RSAPublicKey

    def from_bytes(self, data: bytes) -> RSAPublicKey:
        """
        Build a RSA public key out of the provided bytes.

        Returns:
            An instance of a RSA public key.

        """
        key = load_der_public_key(data)
        if not isinstance(key, RSAPublicKey):
            msg = f'Loaded key is not a valid RSA public key: got {type(key)}.'
            raise TypeError(msg)
        return key

    def to_bytes(self, key: RSAPublicKey) -> bytes:
        """Serialize the provided public key to bytes."""
        return key.public_bytes(self.encoding, self.format)


@dataclass(frozen=True, slots=True)
class TrX25519PrivateKey(TrGenericKey[X25519PrivateKey]):
    """Transform bytes into a X25519 private key."""

    def _get_type(self) -> type[X25519PrivateKey]:
        """Get the key type used by this generic class."""
        return X25519PrivateKey

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
class TrX25519PublicKey(TrGenericKey[X25519PublicKey]):
    """Transform bytes into a X25519 public key."""

    def _get_type(self) -> type[X25519PublicKey]:
        """Get the key type used by this generic class."""
        return X25519PublicKey

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


@dataclass(frozen=True, slots=True)
class TrBoolYesNo:
    """Transform yes/no to and from a boolean."""

    #: What we use when this value is :obj:`True`.
    true: str = 'yes'
    #: What we use when this value is :obj:`False`.
    false: str = 'no'

    def __get_pydantic_core_schema__(
        self,
        source: type[Any],
        handler: GetCoreSchemaHandler,
    ) -> CoreSchema:
        """Serialize and deserialize from/to a string."""
        return core_schema.union_schema(
            choices=[
                core_schema.bool_schema(),
            ],
            serialization=core_schema.plain_serializer_function_ser_schema(
                function=self.to_string,
                return_schema=core_schema.str_schema(strict=True),
            ),
        )

    def to_string(self, value: bool) -> str:
        """Serialize this value to a string."""
        return self.true if value else self.false
