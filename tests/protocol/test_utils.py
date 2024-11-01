from __future__ import annotations

import pytest

from aiostem.exceptions import CommandError
from aiostem.protocol import ArgumentString, Command, QuoteStyle
from aiostem.protocol.utils import CommandSerializer


class TestCommandSerializer:
    """Check that the command serializer works."""

    def test_default_properties(self):
        ser = CommandSerializer(Command.SETCONF)
        assert ser.command == Command.SETCONF
        assert len(ser.arguments) == 0
        assert ser.body is None

    def test_serialize_argument(self):
        ser = CommandSerializer(Command.SETCONF)
        arg = ArgumentString('hello', quotes=QuoteStyle.ALWAYS)
        ser.arguments.append(arg)
        assert len(ser.arguments) == 1
        assert ser.serialize() == 'SETCONF "hello"\r\n'

    def test_serialize_simple_body(self):
        ser = CommandSerializer(Command.SETCONF)
        ser.body = 'Hello world'
        assert ser.serialize() == '+SETCONF\r\nHello world\r\n.\r\n'

    def test_serialize_multiline_body(self):
        ser = CommandSerializer(Command.SETCONF)
        ser.body = 'Hello world\n.dot'
        assert ser.serialize() == '+SETCONF\r\nHello world\r\n..dot\r\n.\r\n'

    def test_line_injection(self):
        ser = CommandSerializer(Command.SETCONF)
        ser.arguments.append(ArgumentString('\r\nQUIT'))
        with pytest.raises(CommandError, match='Command injection was detected'):
            ser.serialize()
