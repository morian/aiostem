from __future__ import annotations

import asyncio
import logging
import secrets
from functools import partial
from ipaddress import IPv4Address

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from pydantic import ValidationError

from aiostem import Controller
from aiostem.command import CommandHsFetch
from aiostem.event import (
    EventNetworkLiveness,
    EventSignal,
    EventStatusClient,
    EventUnknown,
    event_from_message,
)
from aiostem.exceptions import (
    CommandError,
    ControllerError,
    CryptographyError,
    ReplyStatusError,
)
from aiostem.structures import (
    CircuitPurpose,
    LongServerName,
    OnionServiceKeyStruct,
    StreamCloseReasonInt,
)
from aiostem.utils import Message

# All test coroutines will be treated as marked for asyncio.
pytestmark = pytest.mark.asyncio


@pytest.fixture
def tmp_cookie_data():
    return secrets.token_bytes(32)


@pytest.fixture
def tmp_cookie_path(tmp_path, tmp_cookie_data):
    cookie_path = tmp_path / 'cookiefile'
    with open(cookie_path, 'wb') as fp:
        fp.write(tmp_cookie_data)
    return cookie_path


class TestController:
    """Various tests around the main controller."""

    async def test_initialized(self, controller_raw):
        assert controller_raw.authenticated is False
        assert controller_raw.connected is False
        assert controller_raw.entered is False

    async def test_exit_not_entered(self, controller_raw):
        assert controller_raw.entered is False
        await controller_raw.__aexit__(None, None, None)
        assert controller_raw.entered is False

    async def test_entered(self, controller_unauth):
        assert controller_unauth.authenticated is False
        assert controller_unauth.connected is True
        assert controller_unauth.entered is True

    async def test_already_entered(self, controller_unauth):
        with pytest.raises(RuntimeError, match='Controller is already entered'):
            await controller_unauth.__aenter__()

    async def test_controller_reuse(self, controller_raw):
        for _ in range(3):
            assert controller_raw.entered is False
            async with controller_raw:
                assert controller_raw.entered is True

    async def test_not_entered_from_path(self):
        controller = Controller.from_path('/run/tor/not_a_valid_socket.sock')
        with pytest.raises(FileNotFoundError, match='No such file'):
            await controller.__aenter__()
        assert controller.connected is False

    async def test_not_entered_from_port(self):
        controller = Controller.from_port('qweqwe', 9051)
        assert controller.connected is False

        with pytest.raises(ControllerError, match='Controller is not connected'):
            await controller.protocol_info()

    async def test_unauth_protoinfo(self, controller_unauth):
        res1 = await controller_unauth.protocol_info()
        res2 = await controller_unauth.protocol_info()
        assert res1 == res2

    async def test_authenticate_with_null(self, controller_unauth):
        controller_unauth.enabled_auth_methods = {'NULL'}
        reply = await controller_unauth.authenticate()
        assert reply.is_error is True

    async def test_authenticate_with_safecookie(
        self,
        controller_unauth,
        tmp_cookie_data,
        tmp_cookie_path,
    ) -> None:
        controller_unauth.enabled_auth_methods = {'SAFECOOKIE'}
        controller_unauth.auth_cookie_data = tmp_cookie_data
        controller_unauth.auth_cookie_file = tmp_cookie_path
        reply = await controller_unauth.authenticate()
        assert reply.is_error is True

    async def test_authenticate_with_cookie(
        self,
        controller_unauth,
        tmp_cookie_data,
        tmp_cookie_path,
    ):
        controller_unauth.enabled_auth_methods = {'COOKIE'}
        controller_unauth.auth_cookie_data = tmp_cookie_data
        controller_unauth.auth_cookie_file = tmp_cookie_path
        reply = await controller_unauth.authenticate()
        assert reply.is_error is True

    async def test_authenticate_with_unknown_auth(self, controller_unauth):
        controller_unauth.enabled_auth_methods = {'UNKNOWN'}
        with pytest.raises(ControllerError, match='No compatible authentication method found'):
            await controller_unauth.authenticate()

    async def test_authenticate_no_password(self, controller_unauth):
        with pytest.raises(FileNotFoundError, match='No such file'):
            await controller_unauth.authenticate()

    @pytest.mark.timeout(2)
    async def test_cmd_auth_challenge(self, controller_unauth):
        res = await controller_unauth.auth_challenge(b'NOT A TOKEN')
        res.raise_for_status()

        with pytest.raises(CryptographyError, match='Server hash provided by Tor is invalid'):
            res.data.raise_for_server_hash_error(b'THIS IS A COOKIE')

        token = res.data.build_client_hash(b'THIS IS A COOKIE')
        assert isinstance(token, bytes), token
        # This is the expected length of the client hash.
        assert len(token) == 32

    @pytest.mark.timeout(2)
    async def test_cmd_auth_challenge_error(self, controller_unauth):
        res = await controller_unauth.auth_challenge(b'')
        with pytest.raises(ReplyStatusError, match='Wrong number of arguments'):
            res.raise_for_status()

    @pytest.mark.timeout(2)
    async def test_cmd_auth_challenge_no_nonce(self, controller_unauth):
        # This means that the nonce is generated locally by `auth_challenge`.
        res = await controller_unauth.auth_challenge()
        res.raise_for_status()
        assert len(res.data.client_nonce) == 32
        assert len(res.data.server_nonce) == 32

    async def test_authenticated_controller(self, controller):
        assert controller.connected
        assert controller.authenticated

    async def test_cmd_attach_stream(self, controller):
        reply = await controller.attach_stream(0, 0)
        assert reply.is_error is True
        assert reply.status == 552
        assert 'Unknown stream' in reply.status_text

    async def test_cmd_close_circuit(self, controller):
        reply = await controller.close_circuit(0)
        assert reply.is_error is True
        assert reply.status == 552
        assert 'Unknown circuit' in reply.status_text

    async def test_cmd_extend_circuit(self, controller):
        reply = await controller.extend_circuit(
            0,
            [
                '$9695DFC35FFEB861329B9F1AB04C46397020CE31~Test1',
                LongServerName(
                    fingerprint=b'\xc3\x07\xda\xa2\r(a\x19\tGS\r~XiD\x9d\x0bis',
                ),
            ],
        )
        assert reply.is_error is True
        assert reply.status == 552
        assert 'No such router' in reply.status_text

    async def test_cmd_post_descriptor(self, controller):
        reply = await controller.post_descriptor('XXX')
        assert reply.is_error is True
        assert reply.status == 554
        assert "Couldn't parse router descriptor" in reply.status_text

    async def test_cmd_set_circuit_purpose(self, controller):
        reply = await controller.set_circuit_purpose(0, CircuitPurpose.GENERAL)
        assert reply.is_error is True
        assert reply.status == 552
        assert 'Unknown circuit' in reply.status_text

    async def test_cmd_close_stream(self, controller):
        reply = await controller.close_stream(0, StreamCloseReasonInt.MISC)
        assert reply.is_error is True
        assert reply.status == 552
        assert 'Unknown stream' in reply.status_text

    async def test_cmd_redirect_stream(self, controller):
        reply = await controller.redirect_stream(0, IPv4Address('127.0.0.1'))
        assert reply.is_error is True
        assert reply.status == 552
        assert 'Unknown stream' in reply.status_text

    async def test_cmd_get_info(self, controller):
        info = await controller.get_info('version')
        assert 'version' in info

    async def test_cmd_get_info_error(self, controller):
        res = await controller.get_info('THIS_IS_AN_INVALID_VALUE')
        with pytest.raises(ReplyStatusError, match='Unrecognized key') as exc:
            res.raise_for_status()
        assert exc.value.code >= 400

    async def test_cmd_get_conf(self, controller):
        info = await controller.get_conf('DormantClientTimeout')
        assert info.get('DormantClientTimeout') == '86400'

    async def test_cmd_load_conf(self, controller):
        info = await controller.get_info('config-text')
        info.raise_for_status()

        resp = await controller.load_conf(info['config-text'])
        resp.raise_for_status()

    async def test_map_address(self, controller):
        reply = await controller.map_address(
            {
                'one.one.one.one': '1.1.1.1',
                'dns.google': '8.8.8.8',
            }
        )
        reply.raise_for_status()
        for item in reply.items:
            item.raise_for_status()
        assert len(reply.items) == 2

        info = await controller.get_info('address-mappings/control')
        info.raise_for_status()

        entries = info['address-mappings/control'].splitlines()
        assert isinstance(entries, list)
        assert len(entries) == 2

    async def test_cmd_onion_client_auth_add(self, controller):
        address = 'aiostem26gcjyybsi3tyek6txlivvlc5tczytz52h4srsttknvd5s3qd'
        reply = await controller.onion_client_auth_add(
            address=address,
            key=X25519PrivateKey.generate(),
        )
        assert reply.is_success is True

    async def test_cmd_onion_client_auth_remove(self, controller):
        address = 'aiostpy74pbvneqehctjqan6242vcxeppxmjkschdpqe7tgn7wve65qd'
        added = await controller.onion_client_auth_add(
            address=address,
            key=X25519PrivateKey.generate(),
        )
        assert added.is_success is True

        removed = await controller.onion_client_auth_remove(address)
        assert removed.is_success is True

    async def test_cmd_onion_client_auth_view(self, controller):
        address = 'aiostpy74pbvneqehctjqan6242vcxeppxmjkschdpqe7tgn7wve65qd'
        added = await controller.onion_client_auth_view(address)
        assert added.is_success is True

    async def test_cmd_reset_conf(self, controller):
        conf = {'MaxClientCircuitsPending': '64'}
        result = await controller.reset_conf(conf)
        assert result.status == 250

        info = await controller.get_conf('MaxClientCircuitsPending')
        assert dict(info.items()) == conf

    async def test_cmd_resolve(self, controller):
        result = await controller.resolve(['one.one.one.one'])
        assert result.status == 250

    async def test_cmd_save_conf(self, controller):
        result = await controller.save_conf()
        with pytest.raises(ReplyStatusError, match='Unable to write configuration to disk'):
            assert result.raise_for_status()

    async def test_cmd_set_conf(self, controller):
        conf = {'MaxClientCircuitsPending': '64'}
        result = await controller.set_conf(conf)
        assert result.status == 250

        info = await controller.get_conf('MaxClientCircuitsPending')
        assert dict(info.items()) == conf

    async def test_cmd_protocol_info(self, controller):
        res1 = await controller.protocol_info()
        res1.raise_for_status()

        assert res1.data.auth_cookie_file is not None
        assert res1.data.protocol_version == 1
        assert isinstance(res1.data.tor_version, str)

    async def test_cmd_protocol_info_read_cookie_file_error(self, controller):
        res1 = await controller.protocol_info()
        with pytest.raises(FileNotFoundError, match='No such file or directory'):
            await res1.read_cookie_file()

    async def test_cmd_hs_fetch_v2_error(self, controller):
        reply = await controller.hs_fetch('tor66sezptuu2nta')
        with pytest.raises(ReplyStatusError, match='Invalid argument'):
            reply.raise_for_status()

    async def test_cmd_hs_fetch_with_servers(self, controller):
        # Enable tracing for all sent commands.
        controller.traces.add('command')

        # This is an invalid argument here, no side effect.
        await controller.hs_fetch(
            'tor66sezptuu2nta',
            servers=(
                '$9695DFC35FFEB861329B9F1AB04C46397020CE31~Test1',
                LongServerName(
                    fingerprint=b'\xc3\x07\xda\xa2\r(a\x19\tGS\r~XiD\x9d\x0bis',
                    nickname=None,
                ),
            ),
        )

        # Check that our trace has our command with our servers.
        assert len(controller.trace_commands) == 1
        command = controller.trace_commands[0]
        assert isinstance(command, CommandHsFetch)
        assert len(command.servers) == 2

    async def test_cmd_hs_post(self, controller):
        address = 'oftestt7ffa4tt7et5wab7xhnzeooavy2xdmn6dtfa4pot7dk4xhviid'
        reply = await controller.hs_post('XXX', address=address)
        assert reply.is_error
        assert reply.status == 554
        assert 'Invalid descriptor' in reply.status_text

    async def test_cmd_drop_guard(self, controller):
        res = await controller.drop_guards()
        assert res.status_text == 'OK'

    async def test_cmd_drop_ownership(self, controller):
        res = await controller.drop_ownership()
        assert res.status_text == 'OK'

    async def test_cmd_drop_timeouts(self, controller):
        res = await controller.drop_timeouts()
        assert res.status_text == 'OK'

    async def test_cmd_take_ownership(self, controller):
        res = await controller.take_ownership()
        assert res.status_text == 'OK'

    @pytest.mark.timeout(2)
    async def test_cmd_quit(self, controller):
        """Also checks that both sync and async callbacks are triggered."""
        evt_sync = asyncio.Event()
        evt_async = asyncio.Event()

        def callback_sync(event, _):
            event.set()

        async def callback_async(event, _):
            event.set()

        cb_sync = partial(callback_sync, evt_sync)
        cb_async = partial(callback_async, evt_async)

        await controller.add_event_handler('DISCONNECT', cb_sync)
        await controller.add_event_handler('DISCONNECT', cb_async)

        reply = await controller.quit()
        reply.raise_for_status()

        await asyncio.wait(
            (
                asyncio.create_task(evt_sync.wait()),
                asyncio.create_task(evt_async.wait()),
            ),
            return_when=asyncio.ALL_COMPLETED,
        )
        assert evt_sync.is_set()
        assert evt_async.is_set()

        await controller.del_event_handler('DISCONNECT', cb_async)
        await controller.del_event_handler('DISCONNECT', cb_sync)

    @pytest.mark.timeout(2)
    async def test_add_onion_existing_key(self, controller):
        reply = await controller.add_onion(
            key=Ed25519PrivateKey.generate(),
            ports=['80,127.0.0.1:80'],
        )
        reply.raise_for_status()
        assert reply.data.key is None

    @pytest.mark.timeout(2)
    async def test_add_onion_generate_best_locally(self, controller):
        reply = await controller.add_onion(key='NEW:BEST', ports=['80,127.0.0.1:80'])
        reply.raise_for_status()
        assert isinstance(reply.data.key, Ed25519PrivateKey)

    @pytest.mark.timeout(2)
    async def test_add_onion_generate_rsa1024_locally(self, controller):
        """Note: this is not supported anymore for a few years now."""
        reply = await controller.add_onion(key='NEW:RSA1024', ports=['80,127.0.0.1:80'])
        with pytest.raises(ReplyStatusError, match='Invalid key type'):
            reply.raise_for_status()

    @pytest.mark.timeout(2)
    async def test_add_onion_generate_on_tor(self, controller):
        reply = await controller.add_onion(
            key='NEW:BEST',
            ports=['80,127.0.0.1:80'],
            client_auth_v3=[
                X25519PublicKey.from_public_bytes(secrets.token_bytes(32)),
                X25519PublicKey.from_public_bytes(secrets.token_bytes(32)),
            ],
            generate_locally=False,
        )
        reply.raise_for_status()
        assert isinstance(reply.data.key, OnionServiceKeyStruct)

    @pytest.mark.timeout(2)
    async def test_add_and_del_onion(self, controller):
        added = await controller.add_onion(key='NEW:BEST', ports=['80,127.0.0.1:80'])
        added.raise_for_status()

        deleted = await controller.del_onion(added.data.address)
        deleted.raise_for_status()
        assert deleted.status_text == 'OK'


class TestControllerEvents:
    """Event related tests for the controller."""

    async def test_cmd_add_event_handler_error(self, controller):
        controller.error_on_set_events = True
        with pytest.raises(ReplyStatusError, match='Triggered by PyTest'):
            await controller.add_event_handler('STATUS_CLIENT', lambda: None)
        assert len(controller.event_handlers) == 0

    async def test_cmd_del_event_handler_error(self, controller):
        def callback(_):
            pass

        await controller.add_event_handler('STATUS_CLIENT', callback)
        assert len(controller.event_handlers) == 1

        controller.error_on_set_events = True

        with pytest.raises(ReplyStatusError, match='Triggered by PyTest'):
            await controller.del_event_handler('STATUS_CLIENT', callback)
        assert len(controller.event_handlers) == 1

    async def test_cmd_subscribe_bad_event(self, controller):
        with pytest.raises(CommandError, match="Unknown event 'INVALID_EVENT'"):
            await controller.add_event_handler('INVALID_EVENT', lambda: None)

    async def test_signal_bad_signal(self, controller):
        with pytest.raises(ValidationError, match='Input should be '):
            await controller.signal('INVALID_SIGNAL')

    async def test_bad_event_received(self, controller, caplog):
        message = Message(status=250, header='HELLO WORLD')
        with caplog.at_level(logging.ERROR, logger='aiostem'):
            await controller.push_event_message(message)
        assert 'Unable to handle a received event.' in caplog.text

    @pytest.mark.timeout(2)
    async def test_event_handler_with_error(self, controller, caplog):
        """Check that we log and survive with a broken handler."""

        def cb_sync(event, _):
            event.set()
            msg = 'Unexpected type XXX in YYY.'
            raise TypeError(msg)

        evt_sync = asyncio.Event()
        callback = partial(cb_sync, evt_sync)
        await controller.add_event_handler('DISCONNECT', callback)

        with caplog.at_level(logging.ERROR, logger='aiostem'):
            reply = await controller.quit()
            reply.raise_for_status()
            await evt_sync.wait()

        assert evt_sync.is_set()
        assert "Error while handling callback for 'DISCONNECT'" in caplog.text

    async def test_del_non_existant_event_handler(self, controller):
        assert len(controller.event_handlers) == 0
        await controller.del_event_handler('DISCONNECT', lambda: None)
        assert len(controller.event_handlers) == 0

    @pytest.mark.timeout(2)
    async def test_event_network(self, controller):
        loop = asyncio.get_running_loop()
        future = loop.create_future()

        def on_network_event(fut, event):
            fut.set_result(event)

        callback = partial(on_network_event, future)
        await controller.add_event_handler('NETWORK_LIVENESS', callback)

        message = Message(status=650, header='NETWORK_LIVENESS UP')
        await controller.push_event_message(message)

        evt = await asyncio.ensure_future(future)
        assert isinstance(evt, EventNetworkLiveness)
        assert evt.status == 'UP'

    async def test_unknown_event(self):
        evt = event_from_message(Message(status=650, header='SPECIAL_EVENT'))
        assert isinstance(evt, EventUnknown)

    @pytest.mark.timeout(2)
    async def test_event_status_client(self, controller):
        loop = asyncio.get_running_loop()
        future = loop.create_future()

        def on_status_event(fut, event):
            fut.set_result(event)

        callback = partial(on_status_event, future)
        await controller.add_event_handler('STATUS_CLIENT', callback)

        message = Message(
            header='STATUS_CLIENT NOTICE BOOTSTRAP TAG=done SUMMARY="Done" PROGRESS=100',
            status=650,
        )
        await controller.push_event_message(message)

        evt = await asyncio.ensure_future(future)
        assert isinstance(evt, EventStatusClient)
        assert evt.action == 'BOOTSTRAP'
        assert evt.severity == 'NOTICE'
        assert evt.arguments.progress == 100

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
        assert isinstance(evt, EventSignal)
        assert evt.signal == 'RELOAD'
