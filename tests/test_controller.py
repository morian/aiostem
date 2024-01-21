import asyncio
from functools import partial

import pytest

from aiostem.event import NetworkLivenessEvent, SignalEvent, StatusClientEvent
from aiostem.exception import ResponseError
from aiostem.message import Message

# All test coroutines will be treated as marked.
pytestmark = pytest.mark.asyncio


class TestController:
    async def test_base_controller(self, raw_controller):
        assert raw_controller.authenticated is False
        assert raw_controller.connected is True

    async def test_authenticated_controller(self, controller):
        assert controller.connected
        assert controller.authenticated

    async def test_cmd_getinfo(self, controller):
        info = await controller.get_info('version')
        assert 'version' in info.values

    async def test_cmd_getinfo_exception(self, controller):
        with pytest.raises(ResponseError, match='Unrecognized key') as exc:
            await controller.get_info('THIS_IS_AN_INVALID_VALUE')
        assert isinstance(exc.value, ResponseError)
        assert exc.value.status >= 400

    async def test_cmd_getconf(self, controller):
        info = await controller.get_conf('DormantClientTimeout')
        assert info.values == {'DormantClientTimeout': '86400'}

    async def test_cmd_setconf(self, controller):
        conf = {'MaxClientCircuitsPending': '64'}

        result = await controller.set_conf(conf)
        assert result.status == 250

        info = await controller.get_conf('MaxClientCircuitsPending')
        assert info.values == conf

    async def test_cmd_protocol_info(self, controller):
        res1 = await controller.protocol_info()
        assert res1.cookie_file is not None
        assert res1.proto_version == 1
        assert isinstance(res1.tor_version, str)

        with pytest.raises(Exception, match='No such file or directory'):
            await res1.cookie_file_read()

    @pytest.mark.timeout(2)
    async def test_cmd_quit(self, controller):
        test_event = asyncio.Event()

        def test_callback(event, ignored):
            event.set()

        callback = partial(test_callback, test_event)

        await controller.event_subscribe('DISCONNECT', callback)
        reply = await controller.quit()
        assert reply.status == 250

        message = reply.message
        assert message.parsed is True
        assert message.status_code == 250

        await test_event.wait()
        assert test_event.is_set()

        await controller.event_unsubscribe('DISCONNECT', callback)

    @pytest.mark.timeout(2)
    async def test_event_network(self, controller):
        loop = asyncio.get_running_loop()
        future = loop.create_future()

        def on_network_event(fut, event):
            fut.set_result(event)

        callback = partial(on_network_event, future)
        await controller.event_subscribe('NETWORK_LIVENESS', callback)

        message = Message(['650 NETWORK_LIVENESS UP'])
        await controller.push_spurious_event(message)

        evt = await asyncio.ensure_future(future)
        assert isinstance(evt, NetworkLivenessEvent)
        assert evt.network_status == 'UP'
        assert evt.is_connected is True

    @pytest.mark.timeout(2)
    async def test_event_status_client(self, controller):
        loop = asyncio.get_running_loop()
        future = loop.create_future()

        def on_status_event(fut, event):
            fut.set_result(event)

        callback = partial(on_status_event, future)
        await controller.event_subscribe('STATUS_CLIENT', callback)

        message = Message(['650 STATUS_CLIENT NOTICE BOOTSTRAP PROGRESS=100'])
        await controller.push_spurious_event(message)

        evt = await asyncio.ensure_future(future)
        assert isinstance(evt, StatusClientEvent)
        assert evt.action == 'BOOTSTRAP'
        assert evt.severity == 'NOTICE'
        assert evt.arguments['PROGRESS'] == '100'

    @pytest.mark.timeout(2)
    async def test_event_signal(self, controller):
        loop = asyncio.get_running_loop()
        future = loop.create_future()

        def on_signal_event(fut, event):
            fut.set_result(event)

        callback = partial(on_signal_event, future)
        await controller.event_subscribe('SIGNAL', callback)

        res = await controller.signal('RELOAD')
        assert res.status_text == 'OK'

        evt = await asyncio.ensure_future(future)
        assert isinstance(evt, SignalEvent)
        assert evt.signal == 'RELOAD'
