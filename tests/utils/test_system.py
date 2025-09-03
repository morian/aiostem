from aiostem.utils.system import call, is_avalible

import pytest 

pytestmark = pytest.mark.asyncio


async def test_call():
    out = await call('echo hello-world')
    assert out == ["hello-world"]

