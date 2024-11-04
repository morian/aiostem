from __future__ import annotations

import logging
from typing import Annotated, Any

import pytest
from pydantic import TypeAdapter

from aiostem.exceptions import CommandError, ReplySyntaxError
from aiostem.protocol import (
    ArgumentKeyword,
    ArgumentString,
    AuthMethod,
    CommandWord,
    Message,
    MessageData,
    QuoteStyle,
)
from aiostem.protocol.utils import (
    CommandSerializer,
    ReplySyntax,
    ReplySyntaxFlag,
    StringSequence,
)


class TestCommandSerializer:
    """Check that the command serializer works."""

    def test_default_properties(self):
        ser = CommandSerializer(CommandWord.SETCONF)
        assert ser.command == CommandWord.SETCONF
        assert len(ser.arguments) == 0
        assert ser.body is None

    def test_serialize_argument(self):
        ser = CommandSerializer(CommandWord.SETCONF)
        arg = ArgumentKeyword(None, 'hello', quotes=QuoteStyle.ALWAYS)
        ser.arguments.append(arg)
        assert len(ser.arguments) == 1
        assert ser.serialize() == 'SETCONF "hello"\r\n'

    def test_serialize_simple_body(self):
        ser = CommandSerializer(CommandWord.SETCONF)
        ser.body = 'Hello world'
        assert ser.serialize() == '+SETCONF\r\nHello world\r\n.\r\n'

    def test_serialize_multiline_body(self):
        ser = CommandSerializer(CommandWord.SETCONF)
        ser.body = 'Hello world\n.dot'
        assert ser.serialize() == '+SETCONF\r\nHello world\r\n..dot\r\n.\r\n'

    def test_line_injection(self):
        ser = CommandSerializer(CommandWord.SETCONF)
        ser.arguments.append(ArgumentString('\r\nQUIT'))
        with pytest.raises(CommandError, match='Command injection was detected'):
            ser.serialize()


class TestReplySyntax:
    """Checks on our reply parser."""

    def test_positional(self):
        syntax = ReplySyntax(args_min=2, args_map=['severity', 'message'])
        message = Message(status=650, header='NOTICE HelloWorld')
        result = syntax.parse(message)
        assert len(result) == 2
        assert result['severity'] == 'NOTICE'
        assert result['message'] == 'HelloWorld'

    def test_positional_with_omission(self):
        syntax = ReplySyntax(args_min=2, args_map=[None, 'message'])
        message = Message(status=650, header='NOTICE HelloWorld')
        result = syntax.parse(message)
        assert len(result) == 1
        assert result['message'] == 'HelloWorld'

    def test_positional_with_remain(self):
        text = 'No user activity in a long time: becoming dormant'
        syntax = ReplySyntax(
            args_min=2,
            args_map=['severity', 'message'],
            flags=ReplySyntaxFlag.POS_REMAIN,
        )
        message = Message(status=650, header=f'NOTICE {text}')
        result = syntax.parse(message)
        assert result['message'] == text

    def test_keyword(self):
        syntax = ReplySyntax(
            args_map=['positional'],
            kwargs_map={'ControlPort': 'control_port'},
            flags=ReplySyntaxFlag.KW_ENABLE,
        )
        message = Message(status=650, header='TEST ControlPort=0.0.0.0:9051')
        result = syntax.parse(message)
        assert result['control_port'] == '0.0.0.0:9051'
        assert result['positional'] == 'TEST'

    def test_keyword_quoted(self):
        syntax = ReplySyntax(
            kwargs_map={'KEY': 'key'},
            flags=ReplySyntaxFlag.KW_ENABLE | ReplySyntaxFlag.KW_QUOTED,
        )
        message = Message(status=250, header='KEY="He said \\"Hello world\\"."')
        result = syntax.parse(message)
        assert result['key'] == 'He said "Hello world".'

    def test_keyword_omit_keys(self):
        syntax = ReplySyntax(
            kwargs_map={None: 'flags'},
            kwargs_multi={'flags'},
            flags=(
                ReplySyntaxFlag.KW_ENABLE
                | ReplySyntaxFlag.KW_QUOTED
                | ReplySyntaxFlag.KW_OMIT_KEYS
            ),
        )
        # Some flags are quoted here, because why not!
        message = Message(status=250, header='EXTENDED_EVENTS "VERBOSE_NAMES"')
        result = syntax.parse(message)
        flags = result['flags']
        assert len(flags) == 2
        assert flags == ['EXTENDED_EVENTS', 'VERBOSE_NAMES']

    def test_keyword_omit_value(self):
        syntax = ReplySyntax(
            kwargs_map={
                'EXTENDED_EVENTS': 'EXTENDED_EVENTS',
                'VERBOSE_NAMES': 'VERBOSE_NAMES',
            },
            flags=ReplySyntaxFlag.KW_ENABLE | ReplySyntaxFlag.KW_OMIT_VALS,
        )
        message = Message(status=250, header='EXTENDED_EVENTS VERBOSE_NAMES')
        result = syntax.parse(message)
        assert set(result.keys()) == set(syntax.kwargs_map.keys())

    def test_keyword_allow_all(self):
        syntax = ReplySyntax(
            flags=ReplySyntaxFlag.KW_ENABLE | ReplySyntaxFlag.KW_EXTRA,
        )
        message = Message(status=250, header='Server=127.0.0.1 Port=9051')
        result = syntax.parse(message)
        assert len(result) == 2
        assert result['Server'] == '127.0.0.1'
        assert result['Port'] == '9051'

    def test_keyword_ignored(self, caplog):
        syntax = ReplySyntax(
            kwargs_map={'Server': 'Server'},
            flags=ReplySyntaxFlag.KW_ENABLE,
        )
        message = Message(status=250, header='Server=127.0.0.1 Port=9051')
        with caplog.at_level(logging.INFO, logger='aiostem.protocol'):
            result = syntax.parse(message)
        assert len(result) == 1
        assert 'Found an unhandled keyword: Port=9051' in caplog.text

    def test_keyword_value_empty_value(self):
        syntax = ReplySyntax(
            kwargs_map={'KEY': 'key'},
            flags=ReplySyntaxFlag.KW_ENABLE,
        )
        message = Message(status=250, header='KEY=')
        result = syntax.parse(message)
        assert result['key'] == ''

    def test_keyword_value_in_data(self):
        syntax = ReplySyntax(
            kwargs_map={'KEY': 'key'},
            flags=ReplySyntaxFlag.KW_ENABLE | ReplySyntaxFlag.KW_USE_DATA,
        )
        message = MessageData(status=250, header='KEY=', data='Our value is "here"!')
        result = syntax.parse(message)
        assert result['key'] == message.data

    def test_bad_parse_too_few_arguments(self):
        syntax = ReplySyntax(args_min=2, args_map=['severity', 'message'])
        message = Message(status=650, header='NOTICE')
        with pytest.raises(ReplySyntaxError, match='Received too few arguments'):
            syntax.parse(message)

    def test_bad_parse_remaining_data(self):
        syntax = ReplySyntax(args_min=2, args_map=['severity', 'message'])
        message = Message(status=650, header='NOTICE Hello world')
        with pytest.raises(ReplySyntaxError, match='Unexpectedly found remaining data:'):
            syntax.parse(message)

    def test_bad_parse_keyword_quote_syntax(self):
        syntax = ReplySyntax(
            kwargs_map={'KEY': 'key'},
            flags=ReplySyntaxFlag.KW_ENABLE | ReplySyntaxFlag.KW_QUOTED,
        )
        message = Message(status=250, header='KEY="Hello word')
        with pytest.raises(ReplySyntaxError, match='No double-quote found before the end'):
            syntax.parse(message)

    def test_bad_parse_keyword_unexpected_quote(self):
        syntax = ReplySyntax(
            kwargs_map={'KEY': 'key'},
            flags=ReplySyntaxFlag.KW_ENABLE,
        )
        message = Message(status=250, header='KEY="Hello word"')
        with pytest.raises(ReplySyntaxError, match='Got an unexpected quoted value.'):
            syntax.parse(message)

    def test_bad_parse_no_omit_vals(self):
        syntax = ReplySyntax(
            kwargs_map={
                'EXTENDED_EVENTS': 'EXTENDED_EVENTS',
                'VERBOSE_NAMES': 'VERBOSE_NAMES',
            },
            flags=ReplySyntaxFlag.KW_ENABLE,
        )
        message = Message(status=250, header='EXTENDED_EVENTS VERBOSE_NAMES')
        with pytest.raises(ReplySyntaxError, match='Got a single string without either'):
            syntax.parse(message)

    def test_bad_syntax_min_max(self):
        with pytest.raises(RuntimeError, match='Minimum argument count is greater'):
            ReplySyntax(args_min=2, args_map=['version'])

    def test_bad_syntax_remain_vs_kw(self):
        with pytest.raises(RuntimeError, match='Positional remain and keywords are mutually'):
            ReplySyntax(flags=ReplySyntaxFlag.POS_REMAIN | ReplySyntaxFlag.KW_ENABLE)

    def test_bad_syntax_keys_vs_vals(self):
        with pytest.raises(RuntimeError, match='OMIT_KEYS and OMIT_VALS are mutually'):
            ReplySyntax(flags=ReplySyntaxFlag.KW_OMIT_KEYS | ReplySyntaxFlag.KW_OMIT_VALS)

    def test_bad_syntax_kw_disabled_but_with_kvmap(self):
        with pytest.raises(RuntimeError, match='Keywords are disabled but we found items'):
            ReplySyntax(kwargs_map={'SERVER', 'server'})


class TestStringSequence:
    @pytest.mark.parametrize(
        'entry',
        [
            [1, 2, 3, 4],
            '1,2,3,4',
            b'1,2,3,4',
        ],
    )
    def test_with_simple_types(self, entry: Any):
        adapter = TypeAdapter(Annotated[list[int], StringSequence()])
        res = adapter.validate_python(entry)
        assert res == [1, 2, 3, 4]

        assert adapter.dump_python(res) == [1, 2, 3, 4]

    @pytest.mark.parametrize(
        ('entry', 'output'),
        [
            ('COOKIE', {AuthMethod.COOKIE}),
            ('NULL,SAFECOOKIE', {AuthMethod.NULL, AuthMethod.SAFECOOKIE}),
        ],
    )
    def test_with_strenum(self, entry: str, output: set[AuthMethod]):
        adapter = TypeAdapter(Annotated[set[AuthMethod], StringSequence()])
        for item in (entry, output):
            assert adapter.validate_python(item) == output

    def test_json_schema(self):
        adapter = TypeAdapter(Annotated[tuple[str, int], StringSequence()])
        schema = adapter.json_schema()
        assert schema == {
            'maxItems': 2,
            'minItems': 2,
            'prefixItems': [
                {'type': 'string'},
                {'type': 'integer'},
            ],
            'separator': ',',
            'type': 'string',
        }

    @pytest.mark.parametrize(
        'type_',
        [
            Annotated[int, StringSequence()],
            Annotated[bytes, StringSequence()],
        ],
    )
    def test_usage_error(self, type_):
        with pytest.raises(TypeError, match='source type is not a collection'):
            TypeAdapter(type_)
