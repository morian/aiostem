from __future__ import annotations

import re
from abc import ABC, abstractmethod
from enum import IntEnum, StrEnum
from typing import TYPE_CHECKING, Any, TypeAlias, overload

if TYPE_CHECKING:
    from collections.abc import Set as AbstractSet

from ..exceptions import CommandError

#: List of characters in a string that need an escape.
_AUTO_CHARS: AbstractSet[str] = frozenset({' ', '"', '\\'})


@overload
def _serialize_value(value: None, *, allow_none: bool) -> None: ...


@overload
def _serialize_value(value: IntEnum | StrEnum | int | str, *, allow_none: bool) -> str: ...


def _serialize_value(value: Any, *, allow_none: bool = False) -> str | None:
    """Serialize a single value to a string."""
    result: str | None

    match value:
        case IntEnum() | StrEnum():
            result = str(value.value)
        case int() | str():
            result = str(value)
        case None:
            if allow_none is False:
                msg = 'Value cannot be None.'
                raise CommandError(msg)
            result = None
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

    #: Value is always encloded with quotes.
    ALWAYS = 2

    #: Automatically determine the quoting style.
    AUTO = 3

    @staticmethod
    def should_have_quotes(text: str) -> bool:
        """
        Tell whether the provided `text` should have quotes.

        Args:
            text: input text to check for quotes.

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
        key: str,
        value: IntEnum | StrEnum | str | int | None,
        *,
        quotes: QuoteStyle = QuoteStyle.AUTO,
    ) -> None:
        """
        Create a new keyword argument.

        Args:
            key: key part of the keyword
            value: value part of the keyword, if any

        Keyword Args:
            quotes: tell how to quote the value part when serialized

        """
        self._key = key
        self._value = _serialize_value(value, allow_none=True)
        self._quotes = quotes

    def __str__(self) -> str:
        """Serialize the argument to string."""
        if self._value is None:
            return self._key

        value = self._quotes.escape(self._value)
        return f'{self._key}={value}'

    @property
    def key(self) -> str:
        """Get the key part of the keyword argument."""
        return self._key

    @property
    def value(self) -> str | None:
        """Get the value of the keyword argument as a string."""
        return self._value

    @property
    def quotes(self) -> QuoteStyle:
        """Get the applied quote style."""
        return self._quotes


class ArgumentString(BaseArgument):
    """Describe a string argument."""

    def __init__(
        self,
        value: IntEnum | StrEnum | str | int,
        *,
        quotes: QuoteStyle = QuoteStyle.AUTO,
    ) -> None:
        """
        Create a new string argument.

        Args:
            value: raw string value

        Keyword Args:
            quotes: tell how to quote the argument when serialized

        """
        self._value = _serialize_value(value, allow_none=False)
        self._quotes = quotes

    def __str__(self) -> str:
        """Serialize the argument to string."""
        return self._quotes.escape(self._value)

    @property
    def value(self) -> str:
        """Get the value of the string argument."""
        return self._value

    @property
    def quotes(self) -> QuoteStyle:
        """Get the applied quote style."""
        return self._quotes


Argument: TypeAlias = ArgumentKeyword | ArgumentString
