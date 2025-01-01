from __future__ import annotations

import re
from abc import ABC, abstractmethod
from enum import IntEnum, StrEnum
from ipaddress import IPv4Address, IPv6Address
from typing import TYPE_CHECKING, Any, TypeAlias, Union, overload

if TYPE_CHECKING:
    from collections.abc import Set as AbstractSet


from ..exceptions import CommandError

#: List of characters in a string that need an escape.
_AUTO_CHARS: AbstractSet[str] = frozenset({' ', '"', '\\'})

#: All types allowed as a key in a keyword argument.
KeyTypes: TypeAlias = Union[str, None]  # noqa: UP007

#: All types allowed as a value, either for a keyword or a simple string.
ValueTypes: TypeAlias = Union[  # noqa: UP007
    IPv4Address,
    IPv6Address,
    IntEnum,
    StrEnum,
    int,
    str,
]


@overload
def _serialize_value(value: None, *, allow_none: bool) -> None: ...


@overload
def _serialize_value(value: ValueTypes, *, allow_none: bool) -> str: ...


def _serialize_value(value: Any, *, allow_none: bool = False) -> str | None:
    """Serialize a single value to a string."""
    result: str | None

    match value:
        case IntEnum() | StrEnum():
            result = str(value.value)
        case None:
            if allow_none is False:
                msg = 'Value cannot be None.'
                raise CommandError(msg)
            result = None
        case IPv4Address() | IPv6Address() | int() | str():
            result = str(value)
        case _:
            msg = f'Type {type(value).__name__} cannot be serialized to a string.'
            raise CommandError(msg)

    return result


class QuoteStyle(IntEnum):
    """Set the type of quote to use."""

    #: No quote are added around the value, no checks are being performed.
    NEVER = 0

    #: No quote are added around the value, check input to ensure that.
    NEVER_ENSURE = 1

    #: Value is always enclosed with quotes.
    ALWAYS = 2

    #: Automatically determine the quoting style.
    AUTO = 3

    @staticmethod
    def should_have_quotes(text: str) -> bool:
        """
        Tell whether the provided `text` should have quotes.

        Args:
            text: Input text to check for quotes.

        Returns:
            Whether the input text should be enclosed with quotes.

        """
        return any(c in text for c in _AUTO_CHARS)

    def escape(self, text: str) -> str:
        """
        Escape the provided text, if needed.

        Args:
            text: string value to quote according to the current style

        Returns:
            The input value quoted according to the current style.

        """
        do_quote = False

        match self.value:
            case QuoteStyle.ALWAYS.value:
                do_quote = True
            case QuoteStyle.AUTO.value:
                do_quote = self.should_have_quotes(text)
            case QuoteStyle.NEVER_ENSURE.value:
                if self.should_have_quotes(text):
                    msg = 'Argument is only safe with quotes'
                    raise CommandError(msg)

        if do_quote:
            text = '"' + re.sub(r'([\\"])', r'\\\1', text) + '"'
        return text


class BaseArgument(ABC):
    """Base class for any command argument."""

    @abstractmethod
    def __str__(self) -> str:
        """Serialize the argument to string."""


class ArgumentKeyword(BaseArgument):
    """Describe a keyword argument."""

    def __init__(
        self,
        key: KeyTypes,
        value: ValueTypes | None,
        *,
        quotes: QuoteStyle = QuoteStyle.AUTO,
    ) -> None:
        """
        Create a new keyword argument.

        Important:
            Both ``key`` and ``value`` cannot be :obj:`None` at the same time.

        Note:
            When value is :obj:`None`, quotes is enforced to :data:`QuoteStyle.NEVER`.

        Args:
            key: Key part of the keyword, if any.
            value: Value part of the keyword, if any.

        Raises:
            CommandError: when ``key`` and ``value`` are both :obj:`None`.

        Keyword Args:
            quotes: Tell how to quote the value part when serialized.

        """
        # When value is None, we are treated as a flag and never need to have quotes.
        if value is None:
            quotes = QuoteStyle.NEVER
            if key is None:
                msg = 'Both key and value cannot be None.'
                raise CommandError(msg)

        self._key = _serialize_value(key, allow_none=True)
        self._value = _serialize_value(value, allow_none=True)
        self._quotes = quotes

    def __str__(self) -> str:
        """Serialize the argument to a string."""
        if self._value is None:
            # This check was already performed during __init__.
            return self._key  # type: ignore[return-value]

        value = self._quotes.escape(self._value)
        if self._key is None:
            return value

        return f'{self._key}={value}'

    @property
    def key(self) -> str | None:
        """Get the key part of the keyword argument."""
        return self._key

    @property
    def value(self) -> str | None:
        """Get the value of the keyword argument as a string."""
        return self._value

    @property
    def quotes(self) -> QuoteStyle:
        """Get the applied quoting style."""
        return self._quotes


class ArgumentString(BaseArgument):
    """Describe a string argument."""

    def __init__(self, value: ValueTypes, *, safe: bool = False) -> None:
        """
        Create a new string argument.

        Args:
            value: Raw string value.

        Keyword Args:
            safe: Whether the caller ensures that the value contains no space.

        Note:
            This value cannot contain spaces.

        """
        value_str = _serialize_value(value, allow_none=False)
        if not safe and ' ' in value_str:
            msg = f"Invalid space in argument '{value_str}'"
            raise CommandError(msg)

        self._value = value_str

    def __str__(self) -> str:
        """Serialize the argument to a string."""
        return self._value

    @property
    def value(self) -> str:
        """Get the value of the string argument."""
        return self._value
