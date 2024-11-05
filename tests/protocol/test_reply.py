from __future__ import annotations

import logging

import pytest

from aiostem.exceptions import ReplyStatusError
from aiostem.protocol import (
    AuthMethod,
    Message,
    ReplyAuthenticate,
    ReplyExtendCircuit,
    ReplyGetConf,
    ReplyGetInfo,
    ReplyMapAddress,
    ReplyProtocolInfo,
    messages_from_stream,
)

from .test_message import create_stream

# All test coroutines will be treated as marked for asyncio.
pytestmark = pytest.mark.asyncio


async def create_message(lines: list[str]) -> Message:
    """
    Get a single message from the provided lines.

    Args:
        lines: a list of lines to build a stream from.

    Raises:
        RuntimeError: when no message was found.

    Returns:
        The first message extracted from the lines.

    """
    stream = create_stream(lines)
    async for msg in messages_from_stream(stream):
        return msg
    msg = 'Unable to find a message in the provided lines.'
    raise RuntimeError(msg)


class TestReplies:
    """Check that replies are properly parsed."""

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
        assert reply.is_success is True

    async def test_get_conf_error(self):
        lines = ['552 Unrecognized configuration key "A"']
        message = await create_message(lines)
        reply = ReplyGetConf.from_message(message)
        with pytest.raises(ReplyStatusError, match='Unrecognized configuration key "A"'):
            reply.raise_for_status()

    async def test_get_conf_multi(self):
        lines = [
            '250-ControlPort=0.0.0.0:9051',
            '250-ControlPort=0.0.0.0:9052',
            '250 ControlPort=0.0.0.0:9053',
        ]
        message = await create_message(lines)
        reply = ReplyGetConf.from_message(message)
        assert isinstance(reply.values['ControlPort'], list)
        assert len(reply.values['ControlPort']) == 3

    async def test_map_address(self):
        lines = [
            '250-127.218.108.43=bogus1.google.com',
            '250 one.one.one.one=1.1.1.1',
        ]
        message = await create_message(lines)
        reply = ReplyMapAddress.from_message(message)
        assert reply.status == 250
        assert reply.status_text is None
        assert len(reply.items) == 2
        assert reply.items[0].original == '127.218.108.43'
        assert reply.items[0].replacement == 'bogus1.google.com'
        assert reply.items[1].original == 'one.one.one.one'
        assert reply.items[1].replacement == '1.1.1.1'

    async def test_map_address_error(self):
        lines = [
            "512-syntax error: invalid address '@@@'",
            '250 one.one.one.one=1.1.1.1',
        ]
        message = await create_message(lines)
        reply = ReplyMapAddress.from_message(message)
        assert reply.status == 512
        assert reply.status_text == "syntax error: invalid address '@@@'"
        assert len(reply.items) == 2
        assert reply.items[0].status == 512
        assert reply.items[0].original is None
        assert reply.items[0].replacement is None
        assert reply.items[1].status == 250
        assert reply.items[1].original == 'one.one.one.one'
        assert reply.items[1].replacement == '1.1.1.1'

    async def test_get_info(self):
        lines = [
            '250-version=0.4.8.12',
            '250+orconn-status=',
            '$4D0F2ADB9CD55C3EBD14823D54B6541B99A51C19~Unnamed CONNECTED',
            '$DCD645A9C7183A893AC4EF0369AAB5ED1ADBD2AF~fifo4ka CONNECTED',
            '$DAC825BBF05D678ABDEA1C3086E8D99CF0BBF112~malene CONNECTED',
            '$CB44E8ED1FAB648275C39756EB1758060C43BCA4~NOTaGlowieRelay CONNECTED',
            '.',
            '250 OK',
        ]
        message = await create_message(lines)
        reply = ReplyGetInfo.from_message(message)
        assert len(reply.values) == 2
        assert set(reply.values) == {'version', 'orconn-status'}

    async def test_get_info_error(self):
        lines = ['552 Not running in server mode']
        message = await create_message(lines)
        reply = ReplyGetInfo.from_message(message)
        assert reply.is_error is True
        assert reply.is_success is False
        assert len(reply.values) == 0

    async def test_extend_circuit(self):
        lines = ['250 EXTENDED 56832']
        message = await create_message(lines)
        reply = ReplyExtendCircuit.from_message(message)
        assert reply.circuit == 56832

    async def test_extend_circuit_error(self):
        lines = ['552 Unknown circuit "12"']
        message = await create_message(lines)
        reply = ReplyExtendCircuit.from_message(message)
        assert reply.status == 552
        assert reply.status_text == 'Unknown circuit "12"'
        assert reply.circuit is None

    async def test_authenticate(self):
        lines = ['250 OK']
        message = await create_message(lines)
        reply = ReplyAuthenticate.from_message(message)
        assert reply.status == 250
        assert reply.status_text == 'OK'

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
