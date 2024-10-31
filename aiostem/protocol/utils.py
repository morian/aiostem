from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar

if TYPE_CHECKING:
    from collections.abc import MutableSequence

    from .argument import Argument
    from .command import Command


class CommandSerializer:
    """Helper class used to serialize an existing command."""

    END_OF_LINE: ClassVar[str] = '\r\n'

    def __init__(self, name: Command) -> None:
        """
        Create a new command serializer.

        Args:
            name: the command name.

        """
        self._command = name
        self._arguments = []  # type: MutableSequence[Argument]
        self._body = None  # type: str | None

    def serialize(self) -> str:
        """
        Serialize the arguments to a string.

        Returns:
            Text that can be pushed to the server.

        """
        # Build the header line.
        args = [self._command.value]
        for argument in self._arguments:
            args.append(str(argument))
        lines = [' '.join(args)]

        # Include the potential body, if applicable.
        if self._body is None:
            prefix = ''
        else:
            for line in self._body.split('\n'):
                line = line.rstrip('\r')
                if line.startswith('.'):
                    line = '.' + line
                lines.append(line)
            lines.append('.')
            prefix = '+'
        return prefix + self.END_OF_LINE.join(lines) + self.END_OF_LINE

    @property
    def command(self) -> Command:
        """Get the command name for the underlying command."""
        return self._command

    @property
    def arguments(self) -> MutableSequence[Argument]:
        """Get the list of command arguments."""
        return self._arguments

    @property
    def body(self) -> str | None:
        """Get the command body, is any."""
        return self._body

    @body.setter
    def body(self, body: str) -> None:
        """
        Set the command body.

        Args:
            body: the new body content for the command

        """
        self._body = body
