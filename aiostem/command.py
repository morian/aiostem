from __future__ import annotations

from typing import TYPE_CHECKING

from .argument import BaseArgument, KeywordArgument, SingleArgument

if TYPE_CHECKING:
    from collections.abc import Sequence


class Command:
    """Base command class that can be sent through the Controller."""

    def __init__(self, name: str) -> None:
        """
        Create a new command to send through the controller.

        This is raw material and should probably not be used by the end-user.
        Please see :class:`.query.Query` and all its subclasses for more details.

        See Also:
            https://spec.torproject.org/control-spec/commands.html

        Args:
            name: main verb of the command

        """
        self._name = name
        self._args = []  # type: list[BaseArgument]
        self._data = []  # type: list[str]

    def __str__(self) -> str:
        """Build and get the full command text to send though the controller."""
        has_data = bool(len(self._data))
        prefix = '+' if has_data else ''

        items = [prefix + self.name]
        items.extend(map(str, self._args))

        lines = [' '.join(items)]
        if has_data:
            for line in self._data:
                if line.startswith('.'):
                    line = '.' + line
                lines.append(line)
            lines.append('.')
        lines.append('')
        return '\r\n'.join(lines)

    @property
    def arguments(self) -> Sequence[BaseArgument]:
        """Get the list of arguments from this command."""
        return self._args

    @property
    def data(self) -> str:
        """Get the full text content sent in this command."""
        return '\n'.join(self._data)

    @property
    def name(self) -> str:
        """Get the name of this command."""
        return self._name

    def add_data(self, text: str) -> None:
        """
        Append the provided text payload in this command.

        Args:
            text: text data to append to this command

        """
        # Split and clean the lines in this text.
        lines = [line.rstrip('\r') for line in text.split('\n')]
        self._data.extend(lines)

    def add_arg(self, value: str, quoted: bool = False) -> None:
        """
        Add a single positional argument.

        Args:
            value: positional argument value
            quoted: whether the positional argument is enclosed with quotes

        """
        self.add_rawarg(SingleArgument(value, quoted))

    def add_kwarg(self, key: str, value: str, quoted: bool = False) -> None:
        """
        Add a single keyword argument.

        Args:
            key: keyword argument name
            value: keyword argument value
            quoted: whether the positional argument is enclosed with quotes

        """
        self.add_rawarg(KeywordArgument(key, value, quoted))

    def add_rawarg(self, arg: BaseArgument) -> None:
        """
        Add any kind of argument to this command.

        Args:
            arg: the argument to append to this command

        """
        self._args.append(arg)
