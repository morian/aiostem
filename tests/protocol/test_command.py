from __future__ import annotations

import secrets

import pytest

from aiostem.exceptions import CommandError
from aiostem.protocol import (
    CircuitPurpose,
    CloseStreamReason,
    CommandAttachStream,
    CommandAuthChallenge,
    CommandAuthenticate,
    CommandCloseCircuit,
    CommandCloseStream,
    CommandDropGuards,
    CommandExtendCircuit,
    CommandGetConf,
    CommandGetInfo,
    CommandHsFetch,
    CommandLoadConf,
    CommandMapAddress,
    CommandPostDescriptor,
    CommandProtocolInfo,
    CommandQuit,
    CommandRedirectStream,
    CommandResetConf,
    CommandResolve,
    CommandSaveConf,
    CommandSetCircuitPurpose,
    CommandSetConf,
    CommandSetEvents,
    CommandSignal,
    CommandTakeOwnership,
    CommandUseFeature,
    Event,
    Signal,
)


class TestCommands:
    """Test all commands."""

    def test_set_conf_with_value(self):
        cmd = CommandSetConf(values={'ControlPort': 9872})
        assert cmd.serialize() == 'SETCONF ControlPort=9872\r\n'

    def test_set_conf_with_null(self):
        cmd = CommandSetConf(values={'ControlPort': None})
        assert cmd.serialize() == 'SETCONF ControlPort\r\n'

    def test_set_conf_error(self):
        with pytest.raises(CommandError, match='No value provided'):
            CommandSetConf().serialize()

    def test_reset_conf_with_value(self):
        cmd = CommandResetConf(values={'ControlPort': 9872})
        assert cmd.serialize() == 'RESETCONF ControlPort=9872\r\n'

    def test_reset_conf_with_null(self):
        cmd = CommandResetConf(values={'ControlPort': None})
        assert cmd.serialize() == 'RESETCONF ControlPort\r\n'

    def test_reset_conf_error(self):
        with pytest.raises(CommandError, match='No value provided'):
            CommandResetConf().serialize()

    def test_get_conf(self):
        cmd = CommandGetConf(keywords=['ControlPort', 'PIDFile'])
        assert cmd.serialize() == 'GETCONF ControlPort PIDFile\r\n'

    def test_set_events_extended(self):
        cmd = CommandSetEvents(extended=True)
        assert cmd.serialize() == 'SETEVENTS EXTENDED\r\n'

    def test_set_events_circ(self):
        cmd = CommandSetEvents(events={Event.CIRC})
        assert cmd.serialize() == 'SETEVENTS CIRC\r\n'

    def test_authenticate_with_password(self):
        cmd = CommandAuthenticate(token='A real stuff')  # noqa: S106
        assert cmd.serialize() == 'AUTHENTICATE "A real stuff"\r\n'

    def test_authenticate_with_token(self):
        token = b'A real stuff'
        cmd = CommandAuthenticate(token=token)
        assert cmd.serialize() == f'AUTHENTICATE {token.hex()}\r\n'

    def test_authenticate_with_null(self):
        cmd = CommandAuthenticate(token=None)
        assert cmd.serialize() == 'AUTHENTICATE\r\n'

    def test_save_conf_standard(self):
        cmd = CommandSaveConf()
        assert cmd.serialize() == 'SAVECONF\r\n'

    def test_save_conf_forced(self):
        cmd = CommandSaveConf(force=True)
        assert cmd.serialize() == 'SAVECONF FORCE\r\n'

    def test_signal(self):
        cmd = CommandSignal(signal=Signal.NEWNYM)
        assert cmd.serialize() == 'SIGNAL NEWNYM\r\n'

    def test_map_address(self):
        cmd = CommandMapAddress(addresses={'1.2.3.4': 'torproject.org'})
        assert cmd.serialize() == 'MAPADDRESS 1.2.3.4=torproject.org\r\n'

    def test_map_address_error(self):
        with pytest.raises(CommandError, match='No address provided'):
            CommandMapAddress().serialize()

    def test_get_info(self):
        cmd = CommandGetInfo(keywords=['version', 'config-file'])
        assert cmd.serialize() == 'GETINFO version config-file\r\n'

    def test_get_info_error(self):
        with pytest.raises(CommandError, match='No keyword provided'):
            CommandGetInfo().serialize()

    def test_extend_circuit_simple(self):
        cmd = CommandExtendCircuit(circuit=0)
        assert cmd.serialize() == 'EXTENDCIRCUIT 0\r\n'

    def test_extend_circuit_advanced(self):
        cmd = CommandExtendCircuit(
            circuit=12345,
            server_spec=[
                '$b34a4ac3892e41c58709d9c51b3648620a7d5bfe~Test1',
                '$7b70bf914770f022e71a26cbf3d9519dc89f2a9a~Test2',
            ],
            purpose=CircuitPurpose.GENERAL,
        )
        assert cmd.serialize() == (
            'EXTENDCIRCUIT '
            '12345 '
            '$b34a4ac3892e41c58709d9c51b3648620a7d5bfe~Test1,'
            '$7b70bf914770f022e71a26cbf3d9519dc89f2a9a~Test2 '
            'purpose=general'
            '\r\n'
        )

    def test_set_circuit_purpose(self):
        cmd = CommandSetCircuitPurpose(circuit=0, purpose=CircuitPurpose.CONTROLLER)
        assert cmd.serialize() == 'SETCIRCUITPURPOSE 0 purpose=controller\r\n'

    def test_attach_stream(self):
        cmd = CommandAttachStream(circuit=12, stream=2134)
        assert cmd.serialize() == 'ATTACHSTREAM 2134 12\r\n'

    def test_attach_stream_with_hop(self):
        cmd = CommandAttachStream(circuit=12, stream=2134, hop=5)
        assert cmd.serialize() == 'ATTACHSTREAM 2134 12 HOP=5\r\n'

    def test_post_descriptor(self):
        cmd = CommandPostDescriptor(descriptor='This is a descriptor')
        assert cmd.serialize() == '+POSTDESCRIPTOR\r\nThis is a descriptor\r\n.\r\n'

    def test_post_descriptor_advanced(self):
        cmd = CommandPostDescriptor(
            cache=True,
            descriptor='desc',
            purpose=CircuitPurpose.GENERAL,
        )
        assert cmd.serialize() == '+POSTDESCRIPTOR purpose=general cache=yes\r\ndesc\r\n.\r\n'

    def test_redirect_stream(self):
        cmd = CommandRedirectStream(stream=1234, address='127.0.0.1')
        assert cmd.serialize() == 'REDIRECTSTREAM 1234 127.0.0.1\r\n'

    def test_redirect_stream_with_port(self):
        cmd = CommandRedirectStream(stream=1234, address='127.0.0.1', port=8443)
        assert cmd.serialize() == 'REDIRECTSTREAM 1234 127.0.0.1 8443\r\n'

    def test_close_stream(self):
        cmd = CommandCloseStream(stream=1234, reason=CloseStreamReason.TIMEOUT)
        assert cmd.serialize() == 'CLOSESTREAM 1234 7\r\n'

    def test_close_circuit(self):
        cmd = CommandCloseCircuit(circuit=1234)
        assert cmd.serialize() == 'CLOSECIRCUIT 1234\r\n'

    def test_close_circuit_with_flags(self):
        cmd = CommandCloseCircuit(circuit=1234, if_unused=True)
        assert cmd.serialize() == 'CLOSECIRCUIT 1234 IfUnused\r\n'

    def test_quit(self):
        cmd = CommandQuit()
        assert cmd.serialize() == 'QUIT\r\n'

    def test_use_feature(self):
        cmd = CommandUseFeature(features={'VERBOSE_NAMES'})
        assert cmd.serialize() == 'USEFEATURE VERBOSE_NAMES\r\n'

    def test_resolve(self):
        cmd = CommandResolve(addresses=['torproject.org'])
        assert cmd.serialize() == 'RESOLVE torproject.org\r\n'

    def test_resolve_reverse(self):
        cmd = CommandResolve(addresses=['1.1.1.1'], reverse=True)
        assert cmd.serialize() == 'RESOLVE mode=reverse 1.1.1.1\r\n'

    def test_protocol_info(self):
        cmd = CommandProtocolInfo()
        assert cmd.serialize() == 'PROTOCOLINFO\r\n'

    def test_protocol_info_with_version(self):
        cmd = CommandProtocolInfo(version=1)
        assert cmd.serialize() == 'PROTOCOLINFO 1\r\n'

    def test_load_conf(self):
        cmd = CommandLoadConf(text='SocksPort 127.0.0.1:9050\n')
        assert cmd.serialize() == '+LOADCONF\r\nSocksPort 127.0.0.1:9050\r\n\r\n.\r\n'

    def test_take_ownership(self):
        cmd = CommandTakeOwnership()
        assert cmd.serialize() == 'TAKEOWNERSHIP\r\n'

    def test_auth_challenge_bytes(self):
        nonce = secrets.token_bytes(32)
        cmd = CommandAuthChallenge(nonce=nonce)
        assert cmd.serialize() == f'AUTHCHALLENGE SAFECOOKIE {nonce.hex()}\r\n'

    def test_auth_challenge_string(self):
        cmd = CommandAuthChallenge(nonce='A_REAL_NONCE')
        assert cmd.serialize() == 'AUTHCHALLENGE SAFECOOKIE "A_REAL_NONCE"\r\n'

    def test_drop_guards(self):
        cmd = CommandDropGuards()
        assert cmd.serialize() == 'DROPGUARDS\r\n'

    def test_hs_fetch(self):
        cmd = CommandHsFetch(address='facebookcorewwwi')
        assert cmd.serialize() == 'HSFETCH facebookcorewwwi\r\n'

    def test_hs_fetch_with_servers(self):
        address = 'facebookcorewwwi'
        server1 = '$b34a4ac3892e41c58709d9c51b3648620a7d5bfe~Test1'
        server2 = '$7b70bf914770f022e71a26cbf3d9519dc89f2a9a~Test2'
        cmd = CommandHsFetch(
            address=address,
            servers=[
                server1,
                server2,
            ],
        )
        assert cmd.serialize() == f'HSFETCH {address} SERVER={server1} SERVER={server2}\r\n'
