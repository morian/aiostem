from __future__ import annotations

import logging

import pytest

from aiostem.exceptions import ReplyStatusError
from aiostem.protocol import (
    AuthMethod,
    Message,
    ReplyGetConf,
    ReplyProtocolInfo,
    messages_from_stream,
)

from .test_message import create_stream

# All test coroutines will be treated as marked for asyncio.
pytestmark = pytest.mark.asyncio


async def create_message(lines: list[str]) -> Message:
    """Build a single message of the provided lines."""
    stream = create_stream(lines)
    async for msg in messages_from_stream(stream):
        return msg
    msg = 'Unable to find a message in the provided lines.'
    raise RuntimeError(msg)


class TestReplies:
    """Check that replies are well parsed."""

    async def test_get_conf(self):
        lines = [
            '250-ControlPort=0.0.0.0:9051',
            '250-Log=notice stdout',
            '250-EntryNode=',
            '250 HashedControlPassword',
        ]
        message = await create_message(lines)
        reply = ReplyGetConf.from_message(message)
        assert len(reply.values) == 4
        assert reply.values['ControlPort'] == '0.0.0.0:9051'
        assert reply.values['Log'] == 'notice stdout'
        assert reply.values['EntryNode'] == ''
        assert reply.values['HashedControlPassword'] is None

    async def test_get_conf_empty(self):
        message = await create_message(['250 OK'])
        reply = ReplyGetConf.from_message(message)
        assert len(reply.values) == 0
        assert reply.status_text == 'OK'

    async def test_get_conf_error(self):
        lines = ['552 Unrecognized configuration key "A"']
        message = await create_message(lines)
        reply = ReplyGetConf.from_message(message)
        with pytest.raises(ReplyStatusError, match='Unrecognized configuration key "A"'):
            reply.raise_for_status()

    async def test_protocol_info(self):
        lines = [
            '250-PROTOCOLINFO 1',
            (
                '250-AUTH METHODS=COOKIE,SAFECOOKIE,HASHEDPASSWORD '
                'COOKIEFILE="/run/tor/control.authcookie"'
            ),
            '250-VERSION Tor="0.4.8.12"',
            '250 OK',
        ]
        message = await create_message(lines)
        reply = ReplyProtocolInfo.from_message(message)
        # Is not supposed to raise anything.
        reply.raise_for_status()
        assert reply.protocol_version == 1
        assert reply.tor_version == '0.4.8.12'
        assert AuthMethod.COOKIE in reply.auth_methods

    async def test_protocol_info_error(self):
        message = await create_message(['513 No such version "aa"'])
        reply = ReplyProtocolInfo.from_message(message)
        assert reply.status == 513
        with pytest.raises(ReplyStatusError, match='No such version "aa"'):
            reply.raise_for_status()

    async def test_protocol_info_unknown_line(self, caplog):
        lines = [
            '250-PROTOCOLINFO 1',
            '250-TEST For="science"',
            '250-VERSION Tor="0.4.8.12"',
            '250 OK',
        ]
        message = await create_message(lines)
        with caplog.at_level(logging.INFO, logger='aiostem.protocol'):
            ReplyProtocolInfo.from_message(message)
        assert "No syntax handler for keyword 'TEST'" in caplog.text
