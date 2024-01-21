import asyncio
import os
from dataclasses import dataclass

import pytest_asyncio

from aiostem import Controller
from aiostem.event import HsDescContentEvent, HsDescEvent
from aiostem.message import Message
from aiostem.query import HsFetchQuery
from aiostem.reply import HsFetchReply


@dataclass
class TorControllerResult:
    descriptors: list[HsDescEvent]
    contents: HsDescContentEvent


def parse_messages(lines: list[str]) -> list[Message]:
    messages = []  # type: list[Message]

    message = Message()
    for line in lines:
        message.add_line(line.rstrip('\n'))
        if message.parsed:
            messages.append(message)
            message = Message()

    return messages


CONTROLLER_HS_RESULTS = {}  # type: dict[str, TorControllerResult]
for name in os.listdir('tests/samples'):
    descriptors = []  # type: list[HsDescEvent]
    contents = []  # type: list[HsDescEvent]

    filepath = os.path.join('tests/samples', name, 'descriptor.txt')
    if os.path.exists(filepath):
        with open(filepath) as fp:
            for message in parse_messages(fp.readlines()):
                descriptors.append(HsDescEvent(message))

    filepath = os.path.join('tests/samples', name, 'content.txt')
    if os.path.exists(filepath):
        with open(filepath) as fp:
            for message in parse_messages(fp.readlines()):
                contents.append(HsDescContentEvent(message))

    CONTROLLER_HS_RESULTS[name] = TorControllerResult(descriptors, contents)


class CustomController(Controller):
    def __init__(self, connector) -> None:
        super().__init__(connector)
        self.ignore_condition = asyncio.Condition()
        self.ignore_enabled = False
        self.ignore_requests = False
        self.raise_enabled = False

    async def fake_hs_events(self, address: str) -> None:
        result = CONTROLLER_HS_RESULTS[address]
        for descriptor in result.descriptors:
            await self._handle_event(descriptor.message)
        for content in result.contents:
            await self._handle_event(content.message)

    async def hs_fetch(self, address: str, servers: list[str] | None = None) -> HsFetchReply:
        result = CONTROLLER_HS_RESULTS.get(address)
        if result is None:
            return await super().hs_fetch(address, servers)

        if self.raise_enabled is True:
            self.raise_enabled = False
            raise Exception('pytest exception!')

        if self.ignore_enabled is True:
            # Only push 'REQUESTED' messages here when asked to.
            if not self.ignore_requests:
                for descriptor in result.descriptors:
                    if descriptor.action == 'REQUESTED':
                        await self._handle_event(descriptor.message)

            async with self.ignore_condition:
                self.ignore_enabled = False
                self.ignore_condition.notify_all()
        else:
            await self.fake_hs_events(address)

        return HsFetchReply(HsFetchQuery(address, servers), Message(['250 OK']))

    async def push_spurious_event(self, message: Message) -> None:
        await self._handle_event(message)


@pytest_asyncio.fixture()
async def raw_controller():
    host = os.environ.get('AIOSTEM_HOST', '127.0.0.1')
    port = int(os.environ.get('AIOSTEM_PORT', 9051))

    async with CustomController.from_port(host, port) as controller:
        yield controller


@pytest_asyncio.fixture()
async def controller(raw_controller):
    password = os.environ.get('AIOSTEM_PASS', 'onionfarm')
    await raw_controller.authenticate(password)
    return raw_controller
