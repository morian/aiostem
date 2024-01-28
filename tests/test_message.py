import pytest

from aiostem.exception import ProtocolError
from aiostem.message import Message, MessageError, MessageLineParser


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


class TestMessageLineParser:
    def test_pop_kwarg_checked_error(self):
        parser = MessageLineParser('KEY_A=VALUE')
        with pytest.raises(MessageError, match='expected argument'):
            parser.pop_kwarg_checked('KEY_B')

    def test_pop_kwarg_line_error(self):
        parser = MessageLineParser('SIMPLE_ARGUMENT')
        with pytest.raises(MessageError, match='No matching keyword argument'):
            parser.pop_kwarg_line()

    def test_pop_arg_checked_error(self):
        parser = MessageLineParser('VALUE_A')
        with pytest.raises(MessageError, match='expected argument '):
            parser.pop_arg_checked('VALUE_B')

    def test_pop_arg_error(self):
        parser = MessageLineParser('')
        with pytest.raises(MessageError, match='No matching argument in provided line.'):
            parser.pop_arg()

    def test_pop_arg_quoted(self):
        parser = MessageLineParser('"a quoted argument"')
        value = parser.pop_arg(quoted=True)
        assert value == 'a quoted argument'

    def test_reset(self):
        line = 'ARG_0 ARG_1'
        parser = MessageLineParser(line)
        assert str(parser) == line

        value0 = parser.pop_arg()
        assert value0 == 'ARG_0'

        parser.reset()
        value1 = parser.pop_arg()
        assert value0 == value1
