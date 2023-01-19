from typing import List

from .argument import BaseArgument, KeywordArgument, SingleArgument


class Command:
    """Generic command that can be sent through a Controller."""

    def __init__(self, name: str) -> None:
        """Create a new command to send to the controller."""
        self._name = name
        self._args = []  # type: List[BaseArgument]
        self._data = []  # type: List[str]

    def __str__(self) -> str:
        """Build the full command to send to the controller."""
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
    def arguments(self) -> List[BaseArgument]:
        """List of arguments in this command."""
        return self._args

    @property
    def data(self) -> str:
        """Get the full text content sent along with this command."""
        return '\n'.join(self._data)

    @property
    def name(self) -> str:
        """Name of the performed command."""
        return self._name

    def add_data(self, text: str) -> None:
        """Append the provided text payload in this command."""
        # Split and clean the lines in this text.
        lines = map(lambda line: line.rstrip('\r'), text.split('\n'))
        self._data.extend(lines)

    def add_arg(self, value: str, quoted: bool = False) -> None:
        """Add a single argument (can be quoted)."""
        self.add_rawarg(SingleArgument(value, quoted))

    def add_kwarg(self, key: str, value: str, quoted: bool = False) -> None:
        """Add a single keyword argument (can be quoted)."""
        self.add_rawarg(KeywordArgument(key, value, quoted))

    def add_rawarg(self, arg: BaseArgument) -> None:
        """Add any kind of argument to the list of arguments."""
        self._args.append(arg)
