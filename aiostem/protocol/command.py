from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import MutableMapping, MutableSequence, MutableSet
from dataclasses import dataclass, field
from enum import StrEnum
from typing import ClassVar

from .argument import ArgumentKeyword, ArgumentString, QuoteStyle
from .event import Event
from .utils import CommandSerializer


class Command(StrEnum):
    """All handled command words."""

    SETCONF = 'SETCONF'
    RESETCONF = 'RESETCONF'
    GETCONF = 'GETCONF'
    SETEVENTS = 'SETEVENTS'
    AUTHENTICATE = 'AUTHENTICATE'
    SAVECONF = 'SAVECONF'
    GETINFO = 'GETINFO'
    HSFETCH = 'HSFETCH'


class BaseCommand(ABC):
    """Base interface class for all commands."""

    command: ClassVar[Command]

    @abstractmethod
    def _serialize(self) -> CommandSerializer:
        """
        Create a new serializer for this command.

        Returns:
            A basic command serializer for this command.

        """
        return CommandSerializer(self.command)

    def serialize(self) -> str:
        """
        Serialize the command to text.

        Returns:
            Text that can be sent through the wire.

        """
        ser = self._serialize()
        return ser.serialize()


@dataclass(kw_only=True)
class CommandSetConf(BaseCommand):
    """Command implementation for 'SETCONF'."""

    command: ClassVar[Command] = Command.SETCONF
    values: MutableMapping[str, str | None] = field(default_factory=dict)

    def _serialize(self) -> CommandSerializer:
        """Append 'SETCONF' specific arguments."""
        ser = super()._serialize()
        for key, value in self.values.items():
            arg = ArgumentKeyword(key, value)
            ser.arguments.append(arg)
        return ser


@dataclass(kw_only=True)
class CommandResetConf(BaseCommand):
    """Command implementation for 'RESETCONF'."""

    command: ClassVar[Command] = Command.RESETCONF
    values: MutableMapping[str, str | None] = field(default_factory=dict)

    def _serialize(self) -> CommandSerializer:
        """Append 'RESETCONF' specific arguments."""
        ser = super()._serialize()
        for key, value in self.values.items():
            arg = ArgumentKeyword(key, value)
            ser.arguments.append(arg)
        return ser


@dataclass(kw_only=True)
class CommandGetConf(BaseCommand):
    """Command implementation for 'GETCONF'."""

    command: ClassVar[Command] = Command.GETCONF
    keywords: MutableSequence[str] = field(default_factory=list)

    def _serialize(self) -> CommandSerializer:
        """Append 'GETCONF' specific arguments."""
        ser = super()._serialize()
        for keyword in self.keywords:
            arg = ArgumentString(keyword)
            ser.arguments.append(arg)
        return ser


@dataclass(kw_only=True)
class CommandSetEvents(BaseCommand):
    """Command implementation for 'SETEVENTS'."""

    command: ClassVar[Command] = Command.RESETCONF
    events: MutableSet[Event] = field(default_factory=set)
    extended: bool = False

    def _serialize(self) -> CommandSerializer:
        """Append 'SETEVENTS' specific arguments."""
        ser = super()._serialize()
        if self.extended:
            arg = ArgumentString('EXTENDED', quotes=QuoteStyle.NEVER)
            ser.arguments.append(arg)
        for evt in self.events:
            arg = ArgumentString(evt.value, quotes=QuoteStyle.NEVER)
            ser.arguments.append(arg)
        return ser


@dataclass(kw_only=True)
class CommandAuthenticate(BaseCommand):
    """Command implementation for 'AUTHENTICATE'."""

    command: ClassVar[Command] = Command.AUTHENTICATE
    token: bytes | str | None

    def _serialize(self) -> CommandSerializer:
        """Append 'AUTHENTICATE' specific arguments."""
        ser = super()._serialize()
        match self.token:
            case bytes():
                arg = ArgumentString(self.token.hex(), quotes=QuoteStyle.NEVER)
                ser.arguments.append(arg)
            case str():
                arg = ArgumentString(self.token, quotes=QuoteStyle.ALWAYS)
                ser.arguments.append(arg)
        return ser


@dataclass(kw_only=True)
class CommandSaveConf(BaseCommand):
    """Command implementation for 'SAVECONF'."""

    command: ClassVar[Command] = Command.SAVECONF
    force: bool = False

    def _serialize(self) -> CommandSerializer:
        """Append 'SAVECONF' specific arguments."""
        ser = super()._serialize()
        if self.force:
            arg = ArgumentString('FORCE', quotes=QuoteStyle.NEVER)
            ser.arguments.append(arg)
        return ser
