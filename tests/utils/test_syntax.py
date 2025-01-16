from __future__ import annotations

import logging

import pytest

from aiostem.exceptions import ReplySyntaxError
from aiostem.utils import Message, MessageData
from aiostem.utils.syntax import ReplySyntax, ReplySyntaxFlag


class TestReplySyntax:
    """Checks on our reply parser."""

    def test_positional(self):
        syntax = ReplySyntax(args_min=2, args_map=['severity', 'message'])
        message = Message(status=650, header='NOTICE HelloWorld')
        result = syntax.parse(message)
        assert len(result) == 2
        assert result['severity'] == 'NOTICE'
        assert result['message'] == 'HelloWorld'

    def test_positional_as_string(self):
        syntax = ReplySyntax(args_min=2, args_map=['severity', 'message'])
        result = syntax.parse_string('NOTICE HelloWorld')
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
            args_min=1,
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
        with caplog.at_level(logging.INFO, logger='aiostem.utils'):
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

    def test_keyword_value_is_raw(self):
        syntax = ReplySyntax(
            kwargs_map={'KEY': 'key'},
            flags=ReplySyntaxFlag.KW_ENABLE | ReplySyntaxFlag.KW_RAW,
        )
        message = MessageData(status=250, header='KEY=A long weird string')
        result = syntax.parse(message)
        assert result['key'] == 'A long weird string'

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
        with pytest.raises(ReplySyntaxError, match='Got an unexpected quoted value'):
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
            ReplySyntax(
                args_min=2,
                args_map=['version'],
            )

    def test_bad_syntax_opt_arg_with_kwarg(self):
        msg = 'Cannot have optional argument along with keyword arguments'
        with pytest.raises(RuntimeError, match=msg):
            ReplySyntax(
                args_min=0,
                args_map=['version'],
                flags=ReplySyntaxFlag.KW_ENABLE,
            )

    def test_bad_syntax_remain_vs_kw(self):
        msg = 'Positional remain and keywords are mutually exclusive'
        with pytest.raises(RuntimeError, match=msg):
            ReplySyntax(flags=ReplySyntaxFlag.POS_REMAIN | ReplySyntaxFlag.KW_ENABLE)

    def test_bad_syntax_keys_vs_vals(self):
        msg = 'KW_OMIT_KEYS and KW_OMIT_VALS are mutually exclusive'
        with pytest.raises(RuntimeError, match=msg):
            ReplySyntax(flags=ReplySyntaxFlag.KW_OMIT_KEYS | ReplySyntaxFlag.KW_OMIT_VALS)

    def test_bad_syntax_raw_vs_quoted(self):
        with pytest.raises(RuntimeError, match='KW_RAW and KW_QUOTED are mutually exclusive'):
            ReplySyntax(flags=ReplySyntaxFlag.KW_RAW | ReplySyntaxFlag.KW_QUOTED)

    def test_bad_syntax_kw_disabled_but_with_kvmap(self):
        with pytest.raises(RuntimeError, match='Keywords are disabled but we found items'):
            ReplySyntax(kwargs_map={'SERVER', 'server'})
