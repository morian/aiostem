from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar

if TYPE_CHECKING:
    from ..command import Command


class Query:
    """Base class for everything that can be converted to a Command."""

    COMMAND_NAME: ClassVar[str] = 'UNKNOWN'

    @property
    def command(self) -> Command:
        """Convert this query object to a command suitable for `Controller.request()`."""
        raise NotImplementedError('command must be implemented by Query subclass.')
