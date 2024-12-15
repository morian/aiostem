from __future__ import annotations

from asyncio import StreamReader

import pytest

from aiostem.exceptions import ProtocolError
from aiostem.utils import MessageData, MessageLine, messages_from_stream

# All test coroutines will be treated as marked for asyncio.
pytestmark = pytest.mark.asyncio


def serialize(lines: list[str]) -> str:
    """
    Serialize lines to build a message suitable for the stream.

    Args:
        lines: a list of lines to serialize.

    Returns:
        A serialized text message.

    """
    return '\r\n'.join(lines) + '\r\n'


def create_stream(lines: list[str]) -> StreamReader:
    """
    Create a new stream reader that was fed with initial lines.

    Args:
        lines: a list of initial lines.

    Returns:
        A stream reader already fed with the provided lines.

    """
    data = serialize(lines)
    stream = StreamReader()
    stream.feed_data(data.encode('ascii'))
    stream.feed_eof()
    return stream


class TestMessage:
    async def test_simple_message(self):
        """Check that we can parse a single simple message."""
        stream = create_stream(['650 DEBUG'])
        messages = [msg async for msg in messages_from_stream(stream)]
        assert len(messages) == 1

        message = messages[0]
        assert message.status == 650
        assert message.header == 'DEBUG'
        assert message.is_event is True
        assert message.is_success is False
        assert message.is_error is False

    async def test_simple_serialized(self):
        """Check that our simple message can be serialized back."""
        lines = ['650 DEBUG']
        stream = create_stream(['650 DEBUG'])
        messages = [msg async for msg in messages_from_stream(stream)]
        text = serialize(lines)
        assert messages[0].serialize() == text

    async def test_multiple_simple_messages(self):
        stream = create_stream(['650 DEBUG', '250 OK', '250 LOG'])
        messages = [msg async for msg in messages_from_stream(stream)]
        assert len(messages) == 3

        assert messages[0].status == 650
        assert messages[0].header == 'DEBUG'
        assert messages[1].status == 250
        assert messages[1].header == 'OK'
        assert messages[2].status == 250
        assert messages[2].header == 'LOG'

    async def test_with_sub_messages(self):
        lines = [
            '650-key=value',
            '650+multi=',
            '..DOT-VALUE',
            'SECOND-LINE',
            '.',
            '650 DEBUG',
        ]
        stream = create_stream(lines)
        messages = [msg async for msg in messages_from_stream(stream)]
        assert len(messages) == 1

        message = messages[0]
        assert message.status == 650
        assert message.header == 'DEBUG'
        assert len(message.items) == 2
        assert isinstance(message.items[0], MessageLine)
        assert isinstance(message.items[1], MessageData)

        serialized = serialize(lines)
        assert serialized == message.serialize()

    @pytest.mark.parametrize(
        ('line', 'error'),
        [
            ('65', 'Received line is too short'),
            ('65X ', 'Unable to parse status code'),
            ('650_', 'Unrecognized separator'),
        ],
    )
    async def test_protocol_errors(self, line, error):
        stream = create_stream([line])
        iterator = messages_from_stream(stream)
        with pytest.raises(ProtocolError, match=error):
            await iterator.__anext__()

    async def test_basic_keyword(self):
        stream = create_stream(
            [
                '250-PROTOCOLINFO 1',
                '250-AUTH METHODS=HASHEDPASSWORD',
                '250-VERSION Tor="0.4.8.12"',
                '250 OK',
            ]
        )
        messages = [msg async for msg in messages_from_stream(stream)]
        assert len(messages) == 1
        message = messages[0]
        assert message.keyword == 'OK'
        assert message.items[0].keyword == 'PROTOCOLINFO'
        assert message.items[1].keyword == 'AUTH'
        assert message.items[2].keyword == 'VERSION'

    async def test_event_keyword_single(self):
        """Check that a keyword on an event works well."""
        stream = create_stream(['650 CIRC KEY=VALUE'])
        messages = [msg async for msg in messages_from_stream(stream)]
        assert len(messages) == 1
        assert messages[0].keyword == 'CIRC'

    async def test_event_keyword_multi(self):
        """Check that a keyword on a multi-message event in on the first item."""
        stream = create_stream(['650-CIRC KEY=VALUE', '650 OK'])
        messages = [msg async for msg in messages_from_stream(stream)]
        assert len(messages) == 1
        assert messages[0].keyword == 'CIRC'
