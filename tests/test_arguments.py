import pytest

from aiostem.argument import SingleArgument, KeywordArgument


def test_single_argument():
    arg = SingleArgument('dummy')
    assert str(arg) == 'dummy'

def test_single_quoted_argument():
    arg = SingleArgument('dummy', quoted=True)
    assert str(arg) == '"dummy"'

def test_keyword_argument():
    arg = KeywordArgument('key', 'dummy')
    assert str(arg) == 'key=dummy'

def test_keyword_quoted_argument():
    arg = KeywordArgument('key', 'dummy', quoted=True)
    assert str(arg) == 'key="dummy"'

    arg = KeywordArgument('key', 'du"mmy', quoted=True)
    assert str(arg) == 'key="du\\"mmy"'
