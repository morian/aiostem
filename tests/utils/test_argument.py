from __future__ import annotations

import pytest

from aiostem.command import CommandWord
from aiostem.exceptions import CommandError
from aiostem.utils import ArgumentKeyword, ArgumentString, QuoteStyle


class TestArgument:
    """Check all kind of arguments."""

    @pytest.mark.parametrize(
        ('value', 'string'),
        [
            ('TEST', 'TEST'),
            (123456, '123456'),
            (QuoteStyle.NEVER, '0'),
            (CommandWord.SETCONF, 'SETCONF'),
        ],
    )
    def test_string(self, value, string):
        arg = ArgumentString(value)
        assert arg.value == string
        assert str(arg) == string

    def test_string_error_on_space(self):
        with pytest.raises(CommandError, match='Invalid space in argument'):
            ArgumentString('Hello world')

    def test_string_error_on_invalid_type(self):
        with pytest.raises(CommandError, match='Type object cannot be serialized'):
            ArgumentString(object())

    def test_string_error_on_none(self):
        with pytest.raises(CommandError, match='Value cannot be None'):
            ArgumentString(None)

    @pytest.mark.parametrize(
        ('quotes', 'original', 'escaped'),
        [
            (QuoteStyle.ALWAYS, 'AIOSTEM', '"AIOSTEM"'),
            (QuoteStyle.NEVER, 'AIOSTEM', 'AIOSTEM'),
            (QuoteStyle.AUTO, 'AIOSTEM', 'AIOSTEM'),
            (QuoteStyle.AUTO, 'AIO"STEM', '"AIO\\"STEM"'),
            (QuoteStyle.AUTO, 'AIO\\STEM', '"AIO\\\\STEM"'),
        ],
    )
    def test_keyword(self, quotes, original, escaped):
        """Check keyword argument methods and properties."""
        arg = ArgumentKeyword('key', original, quotes=quotes)
        assert arg.key == 'key'
        assert arg.value == original
        assert arg.quotes == quotes
        assert str(arg) == f'key={escaped}'

    def test_keyword_with_none_key(self):
        """Check that a key of None only returns the value."""
        arg = ArgumentKeyword(None, 'value')
        assert arg.key is None
        assert str(arg) == 'value'

    def test_keyword_with_none_value(self):
        """
        Check that a value of None only returns the key.

        This is allowed in special occasions such as `SETCONF` or `RESETCONF`.
        """
        arg = ArgumentKeyword('key', None)
        assert arg.value is None
        assert str(arg) == 'key'

    def test_keyword_with_none_value_ignored_quotes(self):
        """Check that a none value means that quotes are enforced to NEVER."""
        arg = ArgumentKeyword('key', None, quotes=QuoteStyle.ALWAYS)
        assert arg.quotes == QuoteStyle.NEVER

    @pytest.mark.parametrize(
        'original',
        [
            'C:\\windows\\system',
            'This string contains spaces',
            'qu"ote',
        ],
    )
    def test_keyword_quote_error(self, original: str):
        arg = ArgumentKeyword('key', original, quotes=QuoteStyle.NEVER_ENSURE)
        with pytest.raises(CommandError, match='Argument is only safe with quotes'):
            str(arg)

    def test_keyword_key_and_value_none(self):
        with pytest.raises(CommandError, match='Both key and value cannot be None'):
            ArgumentKeyword(None, None)
