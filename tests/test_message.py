import pytest

from aiostem.exception import ProtocolError
from aiostem.message import Message, MessageError


class TestMessage:
    def test_message_already_parsed(self):
        message = Message('250 OK')
        with pytest.raises(MessageError, match='Cannot append an already parsed message.'):
            message.add_line('250 OK')

    def test_line_too_short(self):
        with pytest.raises(ProtocolError, match='Received line is too short:'):
            Message('25')

    def test_line_invalid(self):
        with pytest.raises(ProtocolError, match='Unable to parse line'):
            Message('/INVALID')

    def test_line_with_leading_dot(self):
        message = Message(['650+KIND_OF_EVENT', '.LOL', '.', '650 OK'])
        assert message.parsed is True
        assert message.status_code == 650
