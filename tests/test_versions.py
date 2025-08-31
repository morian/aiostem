from __future__ import annotations

import aiostem
from aiostem.version import Version


class TestPackageVersion:
    def test_version_attribute_is_present(self):
        assert hasattr(aiostem, '__version__')

    def test_version_attribute_is_a_string(self):
        assert isinstance(aiostem.__version__, str)
        assert aiostem.version == aiostem.__version__


class TestVersion:
    def test_version_gt(self):
        assert Version('2.2.2') > Version('1.1.1')

    def test_version_lt(self):
        assert Version('1.1.1') < Version('2.2.2')

    def test_version_ge(self):
        assert Version('2.2.2') >= Version('1.1.1')
        assert Version('2.2.2') >= Version('2.2.2')

    def test_version_le(self):
        assert Version('1.1.1') <= Version('2.2.2')
        assert Version('2.2.2') <= Version('2.2.2')
