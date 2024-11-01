from __future__ import annotations

import pytest

from aiostem.exceptions import CommandError
from aiostem.protocol import ArgumentKeyword, ArgumentString, QuoteStyle


class TestArgument:
    """Check all kind of arguments."""

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
    def test_string(self, quotes, original, escaped):
        """Check string argument methods and properties."""
        arg = ArgumentString(original, quotes=quotes)
        assert arg.value == original
        assert arg.quotes == quotes
        assert str(arg) == f'{escaped}'

    @pytest.mark.parametrize(
        'original',
        [
            'C:\\windows\\system',
            'This string contains spaces',
            'qu"ote',
        ],
    )
    def test_string_error(self, original: str):
        arg = ArgumentString(original, quotes=QuoteStyle.NEVER_ENSURE)
        with pytest.raises(CommandError, match='Argument is only safe with quotes'):
            str(arg)
