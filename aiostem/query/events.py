from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar

from ..command import Command
from .base import Query

if TYPE_CHECKING:
    from collections.abc import Iterable


class SetEventsQuery(Query):
    """Create a query that sets the list of events to subscribe to."""

    COMMAND_NAME: ClassVar[str] = 'SETEVENTS'

    def __init__(self, events: Iterable[str]) -> None:
        """Build a query that setst the list of events to subscribe to."""
        self._events = list(events)

    @property
    def events(self) -> list[str]:
        """Get the list of events this query contains."""
        return self._events

    @property
    def command(self) -> Command:
        """Build the command that sets the list of events we would like to receive."""
        cmd = Command(self.COMMAND_NAME)
        for event in self.events:
            cmd.add_arg(event)
        return cmd
