from __future__ import annotations

import re
from abc import ABC, abstractmethod
from enum import Enum
from typing import TypeAlias


class QuoteStyle(Enum):
    """Set the type of quote to use."""

    #: No quote are added around the value.
    NEVER = 0

    #: Value is always encloded with quotes.
    ALWAYS = 1

    #: Automatically determine the quoting style.
    AUTO = 2

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
                do_quote = bool(('\\' in text) or ('"' in text))

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
        value: str | None,
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
        self._value = value
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
        """Get the value of the keyword argument."""
        return self._value

    @property
    def quotes(self) -> QuoteStyle:
        """Get the applied quote style."""
        return self._quotes


class ArgumentString(BaseArgument):
    """Describe a string argument."""

    def __init__(self, value: str, *, quotes: QuoteStyle = QuoteStyle.AUTO) -> None:
        """
        Create a new string argument.

        Args:
            value: raw string value

        Keyword Args:
            quotes: tell how to quote the argument when serialized

        """
        self._value = value
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
