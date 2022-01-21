from __future__ import annotations

from typing import ClassVar

from aiostem.command import Command
from aiostem.question.base import Query


class SimpleQuery(Query):
    """Base class for single command queries."""

    def __repr__(self) -> str:
        """Query representation."""
        return '<{}>'.format(type(self).__name__)

    @property
    def command(self) -> Command:
        """Build this very simple query."""
        return Command(self.COMMAND_NAME)


class QuitQuery(SimpleQuery):
    """Create a query for the quit command."""

    COMMAND_NAME: ClassVar[str] = 'QUIT'
