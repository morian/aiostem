from __future__ import annotations

import re
from abc import abstractmethod


class BaseArgument:
    """Base class all kinds of command and response arguments."""

    @abstractmethod
    def __str__(self) -> str:
        """Get the string representation of the argument."""
        msg = '__str__() must be implemented by BaseArgument subclass'
        raise NotImplementedError(msg)

    @staticmethod
    def _quote(value: str) -> str:
        """
        Add quotes around the provided value and escape its content.

        Args:
            value: the raw value that needs to be quoted

        Returns:
            Return the quoted value, including the quotes.

        """
        quoted = re.sub(r'([\\"])', r'\\\1', value)
        return f'"{quoted}"'


class SingleArgument(BaseArgument):
    """Store a positional argument."""

    def __init__(self, value: str, quoted: bool = False) -> None:
        """
        Create a new positional argument.

        Args:
            value: the argument value
            quoted: whether the value is expected to be quoted

        """
        self._value = value
        self._quoted = quoted

    @property
    def value(self) -> str:
        """Get the value of the argument."""
        return self._value

    @property
    def quoted(self) -> bool:
        """Tell whether this argument is enclosed by quotes."""
        return self._quoted

    def __str__(self) -> str:
        """Get the value as it would appear on the socket."""
        if self.quoted:
            return self._quote(self.value)
        return self.value


class KeywordArgument(BaseArgument):
    """Store a keyword argument."""

    def __init__(self, keyword: str, value: str, quoted: bool = False) -> None:
        """
        Create a new keyword argument.

        Args:
            keyword: key part of the argument
            value: value of the argument
            quoted: whether the value is expected to be quoted

        """
        self._keyword = keyword
        self._value = value
        self._quoted = quoted

    @property
    def keyword(self) -> str:
        """Get the keyword for this argument."""
        return self._keyword

    @property
    def value(self) -> str:
        """Get the value of the argument."""
        return self._value

    @property
    def quoted(self) -> bool:
        """Tell whether the value is enclosed by quotes."""
        return self._quoted

    def __str__(self) -> str:
        """Get the value as it would appear on the socket."""
        if self.quoted:
            quoted = self._quote(self.value)
            return f'{self.keyword}={quoted}'
        return f'{self.keyword}={self.value}'
