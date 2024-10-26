from __future__ import annotations

import re
from abc import abstractmethod


class BaseArgument:
    """Base class for any kind of command argument."""

    @abstractmethod
    def __str__(self) -> str:
        """Need to be implemented by subclasses."""
        msg = '__str__() must be implemented by BaseArgument subclass'
        raise NotImplementedError(msg)

    @staticmethod
    def _quote(value: str) -> str:
        """Quote `value` so it can be used by Tor's controller."""
        return re.sub(r'([\\"])', r'\\\1', value)


class SingleArgument(BaseArgument):
    """Represents a single argument."""

    def __init__(self, value: str, quoted: bool = False) -> None:
        """Initialize a single argument (may be quoted)."""
        self._value = value
        self._quoted = quoted

    @property
    def value(self) -> str:
        """Get the raw string value for this argument."""
        return self._value

    @property
    def quoted(self) -> bool:
        """Tell whether this argument is quoted."""
        return self._quoted

    def __str__(self) -> str:
        """Get the value as sent on the socket."""
        if self.quoted:
            quoted = self._quote(self.value)
            return f'"{quoted}"'
        return self.value


class KeywordArgument(BaseArgument):
    """Represents a keyword argument."""

    def __init__(self, keyword: str, value: str, quoted: bool = False) -> None:
        """Build a new keyword argument (can be quoted)."""
        self._keyword = keyword
        self._value = value
        self._quoted = quoted

    @property
    def keyword(self) -> str:
        """Name of the `keyword` provided in constructor."""
        return self._keyword

    @property
    def value(self) -> str:
        """Value provided in the constructor."""
        return self._value

    @property
    def quoted(self) -> bool:
        """Tell whether this argument is quoted."""
        return self._quoted

    def __str__(self) -> str:
        """Get the value as sent on the socket."""
        if self.quoted:
            quoted = self._quote(self.value)
            return f'{self.keyword}="{quoted}"'
        return f'{self.keyword}={self.value}'
