# -*- coding: utf-8 -*-

from aiostem.command import Command
from aiostem.question.base import Query
from typing import Iterable, List


class SetEventsQuery(Query):
    """ Create a query that sets the list of events to subscribe to.
    """

    COMMAND_NAME: str = 'SETEVENTS'

    def __init__(self, events: Iterable[str], extended: bool = False) -> None:
        self._events = list(events)
        self._extended = extended

    @property
    def events(self) -> List[str]:
        """ List of events we want to subscribe to.
        """
        return self._events

    @property
    def extended(self) -> bool:
        """ Whether we want to get extended information on subscribed events.
        """
        return self._extended

    @property
    def command(self) -> Command:
        """ Build the command that sets the list of events we would like to receive.
        """
        cmd = Command(self.COMMAND_NAME)
        for event in self.events:
            cmd.add_arg(event)
        if self.extended:
            cmd.add_arg('EXTENDED')
        return cmd
# End of class SetEventsQuery.
