from __future__ import annotations

import asyncio
import os
from typing import TYPE_CHECKING

import pytest_asyncio

from aiostem import Controller
from aiostem.exceptions import ReplyStatusError

if TYPE_CHECKING:
    from collections.abc import (
        Mapping,
        Sequence,
        Set as AbstractSet,
    )

    from aiostem.controller import EventCallbackType
    from aiostem.protocol import (
        Command,
        EventWord,
        Message,
        ReplyAuthChallenge,
        ReplyProtocolInfo,
        ReplySetEvents,
        ReplySignal,
    )


class CustomController(Controller):
    """A controller finely tuned for tests."""

    def __init__(self, connector) -> None:
        super().__init__(connector)
        self.auth_cookie_data = None
        self.auth_cookie_file = None
        self.error_on_set_events = False
        self.enabled_auth_methods = set()
        self.traces = set()
        self.event_signal_active = asyncio.Event()
        self.trace_commands = []
        self.trace_replies = []
        self.trace_signals = []

    @property
    def event_handlers(self) -> Mapping[str, Sequence[EventCallbackType]]:
        """Direct acccess to the event handlers."""
        return self._evt_callbacks

    async def protocol_info(self, version: int | None = None) -> ReplyProtocolInfo:
        """Filter out some auth_methods when asked to."""
        reply = await super().protocol_info(version)
        if self.enabled_auth_methods:
            reply.auth_methods = self.enabled_auth_methods
        if self.auth_cookie_file is not None:
            reply.auth_cookie_file = self.auth_cookie_file
        return reply

    async def auth_challenge(self, nonce: bytes | str | None = None) -> ReplyAuthChallenge:
        """Fix the auth challenge a little bit when needed."""
        reply = await super().auth_challenge(nonce)
        if self.auth_cookie_data is not None:
            reply.server_hash = reply.build_server_hash(self.auth_cookie_data)
        return reply

    async def push_event_message(self, message: Message) -> None:
        """Push a spurious event for test purposes."""
        await self._on_event_received(message)

    async def request(self, command: Command) -> Message:
        if 'command' in self.traces:
            self.trace_commands.append(command)

        message = await super().request(command)

        if 'replies' in self.traces:
            self.trace_replies.append(message)

        return message

    async def set_events(
        self,
        events: AbstractSet[EventWord],
        *,
        extended: bool = False,
    ) -> ReplySetEvents:
        if self.error_on_set_events:
            msg = 'Triggered by PyTest.'
            raise ReplyStatusError(msg, code=500)
        return await super().set_events(events, extended=extended)

    async def signal(self, signal: str) -> ReplySignal:
        result = await super().signal(signal)

        if 'signal' in self.traces:
            self.trace_signals.append(signal)

        match signal:
            case 'ACTIVE':
                self.event_signal_active.set()

        return result


@pytest_asyncio.fixture()
async def controller_raw():
    host = os.environ.get('AIOSTEM_HOST', '127.0.0.1')
    port = int(os.environ.get('AIOSTEM_PORT', 9051))
    return CustomController.from_port(host, port)


@pytest_asyncio.fixture()
async def controller_unauth(controller_raw):
    async with controller_raw:
        yield controller_raw


@pytest_asyncio.fixture()
async def controller(controller_unauth):
    password = os.environ.get('AIOSTEM_PASS', 'onionfarm')
    await controller_unauth.authenticate(password)
    return controller_unauth
