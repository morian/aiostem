from __future__ import annotations

from typing import ClassVar

from ..command import Command
from .base import Query


class SignalQuery(Query):
    """
    Build a Signal query to send to Tor.

    RELOAD         reload configuration
    SHUTDOWN       shutdown the remote Tor daemon
    DUMP           dump statistics, open connections and circuits
    DEBUG          switch all open logs to loglevel debug
    HALT           immediate shutdown, do not wait for connections
    CLEARDNSCACHE  forget the client-side cached IPs
    NEWNYM         new circuits for everyone, clear many caches
    HEARTBEAT      dump an unscheduled heartbeat to the logs
    DORMANT        tell Tor to become "dormant"
    ACTIVE         wake Tor from its "dormant" state

    Also supports UNIX signals such as HUP, USR1, USR2, TERM.
    """

    COMMAND_NAME: ClassVar[str] = 'SIGNAL'

    def __init__(self, signal: str) -> None:
        """Create a new SIGNAL query."""
        self._signal = signal

    @property
    def command(self) -> Command:
        """Convert this query object to a command suitable for `Controller.request()`."""
        cmd = Command(self.COMMAND_NAME)
        cmd.add_arg(self.signal)
        return cmd

    @property
    def signal(self) -> str:
        """Get the name of the signal we want to send."""
        return self._signal
