from __future__ import annotations

import asyncio
from functools import partial

import pytest

from aiostem import Controller
from aiostem.event import (
    NetworkLivenessEvent,
    SignalEvent,
    StatusClientEvent,
    UnknownEvent,
    event_parser,
)
from aiostem.exceptions import CommandError, ControllerError, ProtocolError, ReplyStatusError
from aiostem.message import Message

# All test coroutines will be treated as marked for asyncio.
pytestmark = pytest.mark.asyncio


class TestController:
    async def test_base_controller(self, raw_controller):
        assert raw_controller.authenticated is False
        assert raw_controller.connected is True
        assert raw_controller.entered is True

    async def test_unauth_protoinfo(self, raw_controller):
        res1 = await raw_controller.protocol_info()
        res2 = await raw_controller.protocol_info()
        assert res1 == res2

    async def test_already_entered(self, raw_controller):
        with pytest.raises(RuntimeError, match='Controller is already entered'):
            await raw_controller.__aenter__()

    async def test_not_entered_from_path(self):
        controller = Controller.from_path('/run/tor/not_a_valid_socket.sock')
        with pytest.raises(FileNotFoundError, match='No such file'):
            await controller.__aenter__()
        assert controller.connected is False

    async def test_authenticate_no_password(self, raw_controller):
        with pytest.raises(FileNotFoundError, match='No such file'):
            await raw_controller.authenticate()

    @pytest.mark.timeout(2)
    async def test_cmd_auth_challenge(self, raw_controller):
        res = await raw_controller.auth_challenge(b'NOT A TOKEN')
        with pytest.raises(ProtocolError, match='Tor provided the wrong server nonce.'):
            res.raise_for_server_hash_error(b'THIS IS A COOKIE')

        token = res.client_token_build(b'THIS IS A COOKIE')
        assert isinstance(token, bytes), token
        assert len(token) == 32

    @pytest.mark.timeout(2)
    async def test_cmd_auth_challenge_no_nonce(self, raw_controller):
        res = await raw_controller.auth_challenge()
        assert len(res.query.nonce) == 32
        assert len(res.server_nonce) == 32

    async def test_not_entered_from_port(self):
        controller = Controller.from_port('qweqwe', 9051)
        assert controller.connected is False

        with pytest.raises(ControllerError, match='Controller is not connected'):
            await controller.protocol_info()

    async def test_authenticated_controller(self, controller):
        assert controller.connected
        assert controller.authenticated

    async def test_cmd_getinfo(self, controller):
        info = await controller.get_info('version')
        assert 'version' in info.values

    async def test_cmd_getinfo_exception(self, controller):
        with pytest.raises(ReplyStatusError, match='Unrecognized key') as exc:
            await controller.get_info('THIS_IS_AN_INVALID_VALUE')
        assert exc.value.code >= 400

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

    async def test_cmd_hsfetch_v2_error(self, controller):
        with pytest.raises(ReplyStatusError, match='Invalid argument'):
            await controller.hs_fetch('tor66sezptuu2nta')

    async def test_cmd_drop_guard(self, controller):
        res = await controller.drop_guards()
        assert res.status_text == 'OK'

    @pytest.mark.timeout(2)
    async def test_cmd_quit(self, controller):
        test_event = asyncio.Event()

        def test_callback(event, ignored):
            event.set()

        callback = partial(test_callback, test_event)

        await controller.add_event_handler('DISCONNECT', callback)
        reply = await controller.quit()
        assert reply.status == 250

        message = reply.message
        assert message.parsed is True
        assert message.status_code == 250

        await test_event.wait()
        assert test_event.is_set()

        await controller.del_event_handler('DISCONNECT', callback)

    async def test_cmd_subscribe_bad_event(self, controller):
        with pytest.raises(CommandError, match="Unknown event 'INVALID_EVENT'"):
            await controller.add_event_handler('INVALID_EVENT', lambda x: None)

    @pytest.mark.timeout(2)
    async def test_event_network(self, controller):
        loop = asyncio.get_running_loop()
        future = loop.create_future()

        def on_network_event(fut, event):
            fut.set_result(event)

        callback = partial(on_network_event, future)
        await controller.add_event_handler('NETWORK_LIVENESS', callback)

        message = Message('650 NETWORK_LIVENESS UP')
        await controller.push_spurious_event(message)

        evt = await asyncio.ensure_future(future)
        assert isinstance(evt, NetworkLivenessEvent)
        assert evt.network_status == 'UP'
        assert evt.is_connected is True

    async def test_unknown_event(self):
        evt = event_parser(Message('650 SPECIAL_EVENT'))
        assert isinstance(evt, UnknownEvent)

    @pytest.mark.timeout(2)
    async def test_event_status_client(self, controller):
        loop = asyncio.get_running_loop()
        future = loop.create_future()

        def on_status_event(fut, event):
            fut.set_result(event)

        callback = partial(on_status_event, future)
        await controller.add_event_handler('STATUS_CLIENT', callback)

        message = Message('650 STATUS_CLIENT NOTICE BOOTSTRAP PROGRESS=100')
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
        await controller.add_event_handler('SIGNAL', callback)

        res = await controller.signal('RELOAD')
        assert res.status_text == 'OK'

        evt = await asyncio.ensure_future(future)
        assert isinstance(evt, SignalEvent)
        assert evt.signal == 'RELOAD'
