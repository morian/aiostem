import os
import pytest

from aiostem import Controller


@pytest.fixture
async def raw_controller():
    host = os.environ.get('AIOSTEM_HOST', '127.0.0.1')
    port = os.environ.get('AIOSTEM_PORT', 9051)

    async with Controller.from_port(host, port) as controller:
        yield controller


async def test_base_controller(raw_controller):
    assert raw_controller.authenticated == False
    assert raw_controller.connected == True


@pytest.fixture
async def controller(raw_controller):
    password = os.environ.get('AIOSTEM_PASS', 'onionfarm')
    await raw_controller.authenticate(password)
    yield raw_controller


async def test_authenticated_controller(controller):
    assert controller.connected
    assert controller.authenticated


async def test_proto_getinfo(controller):
    info = await controller.get_info('version')
    assert 'version' in info.values


async def test_getconf(controller):
    info = await controller.get_conf('DormantClientTimeout')
    assert info.values == {'DormantClientTimeout': '86400'}
