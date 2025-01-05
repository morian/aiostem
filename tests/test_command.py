from __future__ import annotations

import secrets
from base64 import b32decode, b64decode, b64encode

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from pydantic import TypeAdapter
from pydantic_core import PydanticSerializationError

from aiostem.command import (
    CommandAddOnion,
    CommandAttachStream,
    CommandAuthChallenge,
    CommandAuthenticate,
    CommandCloseCircuit,
    CommandCloseStream,
    CommandDelOnion,
    CommandDropGuards,
    CommandDropOwnership,
    CommandDropTimeouts,
    CommandExtendCircuit,
    CommandGetConf,
    CommandGetInfo,
    CommandHsFetch,
    CommandHsPost,
    CommandLoadConf,
    CommandMapAddress,
    CommandOnionClientAuthAdd,
    CommandOnionClientAuthRemove,
    CommandOnionClientAuthView,
    CommandPostDescriptor,
    CommandProtocolInfo,
    CommandQuit,
    CommandRedirectStream,
    CommandResetConf,
    CommandResolve,
    CommandSaveConf,
    CommandSerializer,
    CommandSetCircuitPurpose,
    CommandSetConf,
    CommandSetEvents,
    CommandSignal,
    CommandTakeOwnership,
    CommandUseFeature,
    CommandWord,
)
from aiostem.event import EventWord
from aiostem.exceptions import CommandError
from aiostem.structures import (
    CircuitPurpose,
    DescriptorPurpose,
    HsDescAuthCookie,
    HsDescAuthTypeInt,
    HsDescClientAuthV2,
    LongServerName,
    OnionClientAuthFlags,
    OnionServiceFlags,
    OnionServiceKeyStruct,
    OnionServiceKeyType,
    OnionServiceNewKeyStruct,
    Signal,
    StreamCloseReasonInt,
    VirtualPort,
)
from aiostem.utils import ArgumentKeyword, ArgumentString, QuoteStyle, TrEd25519PrivateKey

VirtualPortAdapter = TypeAdapter(VirtualPort)


class TestCommandSerializer:
    """Check that the command serializer works."""

    def test_default_properties(self):
        ser = CommandSerializer(CommandWord.SETCONF)
        assert ser.command == CommandWord.SETCONF
        assert len(ser.arguments) == 0
        assert ser.body is None

    def test_serialize_argument(self):
        ser = CommandSerializer(CommandWord.SETCONF)
        arg = ArgumentKeyword(None, 'hello', quotes=QuoteStyle.ALWAYS)
        ser.arguments.append(arg)
        assert len(ser.arguments) == 1
        assert ser.serialize() == 'SETCONF "hello"\r\n'

    def test_serialize_simple_body(self):
        ser = CommandSerializer(CommandWord.SETCONF)
        ser.body = 'Hello world'
        assert ser.serialize() == '+SETCONF\r\nHello world\r\n.\r\n'

    def test_serialize_multiline_body(self):
        ser = CommandSerializer(CommandWord.SETCONF)
        ser.body = 'Hello world\n.dot'
        assert ser.serialize() == '+SETCONF\r\nHello world\r\n..dot\r\n.\r\n'

    def test_line_injection(self):
        ser = CommandSerializer(CommandWord.SETCONF)
        ser.arguments.append(ArgumentString('\r\nQUIT'))
        with pytest.raises(CommandError, match='Command injection was detected'):
            ser.serialize()


class TestCommands:
    """Test all commands."""

    def test_set_conf_with_value(self):
        cmd = CommandSetConf(values={'ControlPort': 9872})
        assert cmd.serialize() == 'SETCONF ControlPort=9872\r\n'

    def test_set_conf_with_list(self):
        cmd = CommandSetConf(values={'ControlPort': [9872, 1234]})
        assert cmd.serialize() == 'SETCONF ControlPort=9872 ControlPort=1234\r\n'

    def test_set_conf_with_null(self):
        cmd = CommandSetConf(values={'ControlPort': None})
        assert cmd.serialize() == 'SETCONF ControlPort\r\n'

    def test_set_conf_error(self):
        with pytest.raises(PydanticSerializationError, match='No value provided'):
            CommandSetConf().serialize()

    def test_reset_conf_with_value(self):
        cmd = CommandResetConf(values={'ControlPort': 9872})
        assert cmd.serialize() == 'RESETCONF ControlPort=9872\r\n'

    def test_reset_conf_with_null(self):
        cmd = CommandResetConf(values={'ControlPort': None})
        assert cmd.serialize() == 'RESETCONF ControlPort\r\n'

    def test_reset_conf_error(self):
        with pytest.raises(PydanticSerializationError, match='No value provided'):
            CommandResetConf().serialize()

    def test_get_conf(self):
        cmd = CommandGetConf(keywords=['ControlPort', 'PIDFile'])
        assert cmd.serialize() == 'GETCONF ControlPort PIDFile\r\n'

    def test_set_events_circ(self):
        cmd = CommandSetEvents(events={EventWord.CIRC})
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
        with pytest.raises(PydanticSerializationError, match='No address provided'):
            CommandMapAddress().serialize()

    def test_get_info(self):
        cmd = CommandGetInfo(keywords=['version', 'config-file'])
        assert cmd.serialize() == 'GETINFO version config-file\r\n'

    def test_get_info_error(self):
        with pytest.raises(PydanticSerializationError, match='No keyword provided'):
            CommandGetInfo().serialize()

    def test_extend_circuit_simple(self):
        cmd = CommandExtendCircuit(circuit=0)
        assert cmd.serialize() == 'EXTENDCIRCUIT 0\r\n'

    def test_extend_circuit_advanced(self):
        cmd = CommandExtendCircuit(
            circuit=12345,
            servers=[
                LongServerName.from_string('$b34a4ac3892e41c58709d9c51b3648620a7d5bfe~Test1'),
                LongServerName.from_string('$7b70bf914770f022e71a26cbf3d9519dc89f2a9a~Test2'),
            ],
            purpose=CircuitPurpose.GENERAL,
        )
        assert cmd.serialize() == (
            'EXTENDCIRCUIT '
            '12345 '
            '$B34A4AC3892E41C58709D9C51B3648620A7D5BFE~Test1,'
            '$7B70BF914770F022E71A26CBF3D9519DC89F2A9A~Test2 '
            'purpose=GENERAL'
            '\r\n'
        )

    def test_set_circuit_purpose(self):
        cmd = CommandSetCircuitPurpose(circuit=0, purpose=CircuitPurpose.CONTROLLER)
        assert cmd.serialize() == 'SETCIRCUITPURPOSE 0 purpose=CONTROLLER\r\n'

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
            purpose=DescriptorPurpose.GENERAL,
        )
        assert cmd.serialize() == '+POSTDESCRIPTOR purpose=general cache=yes\r\ndesc\r\n.\r\n'

    def test_redirect_stream(self):
        cmd = CommandRedirectStream(stream=1234, address='127.0.0.1')
        assert cmd.serialize() == 'REDIRECTSTREAM 1234 127.0.0.1\r\n'

    def test_redirect_stream_with_port(self):
        cmd = CommandRedirectStream(stream=1234, address='127.0.0.1', port=8443)
        assert cmd.serialize() == 'REDIRECTSTREAM 1234 127.0.0.1 8443\r\n'

    def test_close_stream(self):
        cmd = CommandCloseStream(stream=1234, reason=StreamCloseReasonInt.TIMEOUT)
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
        assert cmd.serialize() == '+LOADCONF\r\nSocksPort 127.0.0.1:9050\r\n.\r\n'

    def test_take_ownership(self):
        cmd = CommandTakeOwnership()
        assert cmd.serialize() == 'TAKEOWNERSHIP\r\n'

    def test_auth_challenge_bytes(self):
        nonce = secrets.token_bytes(CommandAuthChallenge.NONCE_LENGTH)
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

    def test_add_onion(self):
        port = VirtualPortAdapter.validate_python('80,127.0.0.1:80')
        cmd = CommandAddOnion(
            key=OnionServiceNewKeyStruct(OnionServiceKeyType.ED25519_V3),
            ports=[port],
        )
        adapter = cmd.adapter()
        serial = adapter.dump_python(cmd)
        assert serial == 'ADD_ONION NEW:ED25519-V3 Port=80,127.0.0.1:80\r\n'

    def test_add_onion_bytes(self):
        key = Ed25519PrivateKey.from_private_bytes(secrets.token_bytes(32))
        expanded = TrEd25519PrivateKey().to_expanded_bytes(key)
        expected = b64encode(expanded).decode().rstrip('=')

        port = VirtualPortAdapter.validate_python('80,127.0.0.1:80')
        cmd = CommandAddOnion(key=key, ports=[port])
        assert cmd.serialize() == (f'ADD_ONION ED25519-V3:{expected} Port=80,127.0.0.1:80\r\n')

    @pytest.mark.parametrize(
        ('value', 'type_'),
        [
            ('NEW:BEST', OnionServiceNewKeyStruct),
            (
                (
                    'ED25519-V3:ECum/PYnCBIHwWWmn6AaO29uY4Eq/hDEz6pLUG'
                    'znA0P0ZZKoLzYbJyURXRs0GNUz5aon9y+I3x3GauWJEXymSA'
                ),
                OnionServiceKeyStruct,
            ),
        ],
    )
    def test_add_onion_from_struct(self, value, type_):
        struct = {'key': value}
        adapter = CommandAddOnion.adapter()
        cmd = adapter.validate_python(struct)
        assert isinstance(cmd, CommandAddOnion)
        assert isinstance(cmd.key, type_)

    def test_add_onion_with_client_auth(self):
        auth = HsDescClientAuthV2(
            name='John',
            cookie=HsDescAuthCookie(
                auth_type=HsDescAuthTypeInt.BASIC_AUTH,
                cookie=bytes.fromhex('1a6608bb410a91de47e9b9692058378d'),
            ),
        )
        port = VirtualPortAdapter.validate_python('80,127.0.0.1:80')
        cmd = CommandAddOnion(
            key=OnionServiceNewKeyStruct('BEST'),
            ports=[port],
            flags={OnionServiceFlags.DISCARD_PK},
            max_streams=2,
            client_auth=[auth],
        )
        assert cmd.serialize() == (
            'ADD_ONION NEW:BEST Flags=DiscardPK MaxStreams=2 Port=80,127.0.0.1:80 '
            'ClientAuth=John:GmYIu0EKkd5H6blpIFg3jQA=\r\n'
        )

    def test_add_onion_with_client_auth_v3(self):
        v3_auth_strings = [
            '5BPBXQOAZWPSSXFKOIXHZDRDA2AJT2SWS2GIQTISCFKGVBFWBBDQ====',
            'RC3BHJ6WTBQPRRSMV65XGCZVSYJQZNWBQI3LLFS73VP6NHSIAD2Q====',
        ]
        auth_v3 = []
        for key_b32 in v3_auth_strings:
            auth_v3.append(X25519PublicKey.from_public_bytes(b32decode(key_b32)))

        port = VirtualPortAdapter.validate_python('80,127.0.0.1:80')
        cmd = CommandAddOnion(
            flags={OnionServiceFlags.V3AUTH},
            key=OnionServiceNewKeyStruct('BEST'),
            ports=[port],
            client_auth_v3=auth_v3,
        )
        assert cmd.serialize() == (
            'ADD_ONION NEW:BEST Flags=V3Auth Port=80,127.0.0.1:80 '
            'ClientAuthV3=5BPBXQOAZWPSSXFKOIXHZDRDA2AJT2SWS2GIQTISCFKGVBFWBBDQ '
            'ClientAuthV3=RC3BHJ6WTBQPRRSMV65XGCZVSYJQZNWBQI3LLFS73VP6NHSIAD2Q\r\n'
        )

    def test_add_onion_key_no_port(self):
        cmd = CommandAddOnion(key=OnionServiceNewKeyStruct('BEST'))
        msg = 'You must specify one or more virtual ports'
        with pytest.raises(PydanticSerializationError, match=msg):
            cmd.serialize()

    def test_del_onion(self):
        cmd = CommandDelOnion(address='facebookcorewwwi')
        assert cmd.serialize() == 'DEL_ONION facebookcorewwwi\r\n'

    def test_hs_post(self):
        cmd = CommandHsPost(descriptor='desc')
        assert cmd.serialize() == '+HSPOST\r\ndesc\r\n.\r\n'

    def test_hs_post_with_server(self):
        cmd = CommandHsPost(
            servers=['9695DFC35FFEB861329B9F1AB04C46397020CE31'],
            address='facebookcorewwwi',
            descriptor='desc',
        )
        assert cmd.serialize() == (
            '+HSPOST SERVER=9695DFC35FFEB861329B9F1AB04C46397020CE31 '
            'HSADDRESS=facebookcorewwwi\r\n'
            'desc\r\n.\r\n'
        )

    def test_onion_client_auth_add(self):
        address = 'aiostem26gcjyybsi3tyek6txlivvlc5tczytz52h4srsttknvd5s3qd'
        k64 = 'yPGUxgKaC5ACyEzsdANHJEJzt5DIqDRBlAFaAWWQn0o'
        key = X25519PrivateKey.from_private_bytes(b64decode(k64 + '='))
        cmd = CommandOnionClientAuthAdd(address=address, key=key)
        assert cmd.serialize() == f'ONION_CLIENT_AUTH_ADD {address} x25519:{k64}\r\n'

    def test_onion_client_auth_add_from_struct(self):
        address = 'aiostem26gcjyybsi3tyek6txlivvlc5tczytz52h4srsttknvd5s3qd'
        k64 = 'yPGUxgKaC5ACyEzsdANHJEJzt5DIqDRBlAFaAWWQn0o'
        adapter = CommandOnionClientAuthAdd.adapter()
        cmd = adapter.validate_python({'address': address, 'key': f'x25519:{k64}'})
        assert cmd.serialize() == f'ONION_CLIENT_AUTH_ADD {address} x25519:{k64}\r\n'

    def test_onion_client_auth_add_advanced(self):
        address = 'aiostem26gcjyybsi3tyek6txlivvlc5tczytz52h4srsttknvd5s3qd'
        k64 = 'yPGUxgKaC5ACyEzsdANHJEJzt5DIqDRBlAFaAWWQn0o'
        key = X25519PrivateKey.from_private_bytes(b64decode(k64 + '='))
        cmd = CommandOnionClientAuthAdd(
            address=address,
            key=key,
            nickname='Peter',
            flags={OnionClientAuthFlags.PERMANENT},
        )
        assert cmd.serialize() == (
            f'ONION_CLIENT_AUTH_ADD {address} x25519:{k64} '
            'ClientName=Peter Flags=Permanent\r\n'
        )

    def test_onion_client_auth_remove(self):
        address = 'aiostem26gcjyybsi3tyek6txlivvlc5tczytz52h4srsttknvd5s3qd'
        cmd = CommandOnionClientAuthRemove(address=address)
        assert cmd.serialize() == f'ONION_CLIENT_AUTH_REMOVE {address}\r\n'

    def test_onion_client_auth_view(self):
        cmd = CommandOnionClientAuthView()
        assert cmd.serialize() == 'ONION_CLIENT_AUTH_VIEW\r\n'

    def test_onion_client_auth_view_with_address(self):
        address = 'aiostem26gcjyybsi3tyek6txlivvlc5tczytz52h4srsttknvd5s3qd'
        cmd = CommandOnionClientAuthView(address=address)
        assert cmd.serialize() == f'ONION_CLIENT_AUTH_VIEW {address}\r\n'

    def test_drop_ownership(self):
        cmd = CommandDropOwnership()
        assert cmd.serialize() == 'DROPOWNERSHIP\r\n'

    def test_drop_timeouts(self):
        cmd = CommandDropTimeouts()
        assert cmd.serialize() == 'DROPTIMEOUTS\r\n'
