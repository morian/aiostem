from __future__ import annotations

import aiostem


class TestVersion:
    def test_version_attribute_is_present(self):
        assert hasattr(aiostem, '__version__')

    def test_version_attribute_is_a_string(self):
        assert isinstance(aiostem.__version__, str)
        assert aiostem.version == aiostem.__version__
