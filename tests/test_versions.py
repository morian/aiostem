import pytest

import aiostem
import aiostem.extra


def test_version_attribute_is_present():
    assert hasattr(aiostem, '__version__')


def test_version_attribute_is_a_string():
    assert isinstance(aiostem.__version__, str)
    assert aiostem.version == aiostem.__version__
