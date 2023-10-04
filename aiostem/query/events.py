from __future__ import annotations

from collections.abc import Iterable
from typing import ClassVar

from aiostem.command import Command

from .base import Query


class SetEventsQuery(Query):
    """Create a query that sets the list of events to subscribe to."""

    COMMAND_NAME: ClassVar[str] = 'SETEVENTS'

    def __init__(self, events: Iterable[str], extended: bool = False) -> None:
        """Build a query that setst the list of events to subscribe to."""
        self._events = list(events)
        self._extended = extended

    @property
    def events(self) -> list[str]:
        """Get the list of events this query contains."""
        return self._events

    @property
    def extended(self) -> bool:
        """Tell whether we want to get extended information on subscribed events."""
        return self._extended

    @property
    def command(self) -> Command:
        """Build the command that sets the list of events we would like to receive."""
        cmd = Command(self.COMMAND_NAME)
        for event in self.events:
            cmd.add_arg(event)
        if self.extended:
            cmd.add_arg('EXTENDED')
        return cmd
