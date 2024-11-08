from __future__ import annotations

import logging

import pytest

from aiostem.exceptions import ReplyError, ReplyStatusError
from aiostem.protocol import (
    AuthMethod,
    Message,
    OnionServiceKeyType,
    ReplyAddOnion,
    ReplyAuthChallenge,
    ReplyAuthenticate,
    ReplyExtendCircuit,
    ReplyGetConf,
    ReplyGetInfo,
    ReplyMapAddress,
    ReplyOnionClientAuthView,
    ReplyProtocolInfo,
    messages_from_stream,
)

from .test_message import create_stream

# All test coroutines will be treated as marked for asyncio.
pytestmark = pytest.mark.asyncio


async def create_message(lines: list[str]) -> Message:
    """
    Get a single message from the provided lines.

    Args:
        lines: a list of lines to build a stream from.

    Raises:
        RuntimeError: when no message was found.

    Returns:
        The first message extracted from the lines.

    """
    stream = create_stream(lines)
    async for msg in messages_from_stream(stream):
        return msg
    msg = 'Unable to find a message in the provided lines.'
    raise RuntimeError(msg)


class TestReplies:
    """Check that replies are properly parsed."""

    async def test_get_conf(self):
        lines = [
            '250-ControlPort=0.0.0.0:9051',
            '250-Log=notice stdout',
            '250-EntryNode=',
            '250 HashedControlPassword',
        ]
        message = await create_message(lines)
        reply = ReplyGetConf.from_message(message)
        assert len(reply.values) == 4
        assert reply.values['ControlPort'] == '0.0.0.0:9051'
        assert reply.values['Log'] == 'notice stdout'
        assert reply.values['EntryNode'] == ''
        assert reply.values['HashedControlPassword'] is None

    async def test_get_conf_empty(self):
        message = await create_message(['250 OK'])
        reply = ReplyGetConf.from_message(message)
        assert len(reply.values) == 0
        assert reply.status_text == 'OK'
        assert reply.is_success is True

    async def test_get_conf_error(self):
        lines = ['552 Unrecognized configuration key "A"']
        message = await create_message(lines)
        reply = ReplyGetConf.from_message(message)
        with pytest.raises(ReplyStatusError, match='Unrecognized configuration key "A"'):
            reply.raise_for_status()

    async def test_get_conf_multi(self):
        lines = [
            '250-ControlPort=0.0.0.0:9051',
            '250-ControlPort=0.0.0.0:9052',
            '250 ControlPort=0.0.0.0:9053',
        ]
        message = await create_message(lines)
        reply = ReplyGetConf.from_message(message)
        assert isinstance(reply.values['ControlPort'], list)
        assert len(reply.values['ControlPort']) == 3

    async def test_map_address(self):
        lines = [
            '250-127.218.108.43=bogus1.google.com',
            '250 one.one.one.one=1.1.1.1',
        ]
        message = await create_message(lines)
        reply = ReplyMapAddress.from_message(message)
        assert reply.status == 250
        assert reply.status_text is None
        assert len(reply.items) == 2
        assert reply.items[0].original == '127.218.108.43'
        assert reply.items[0].replacement == 'bogus1.google.com'
        assert reply.items[1].original == 'one.one.one.one'
        assert reply.items[1].replacement == '1.1.1.1'

    async def test_map_address_error(self):
        lines = [
            "512-syntax error: invalid address '@@@'",
            '250 one.one.one.one=1.1.1.1',
        ]
        message = await create_message(lines)
        reply = ReplyMapAddress.from_message(message)
        assert reply.status == 512
        assert reply.status_text == "syntax error: invalid address '@@@'"
        assert len(reply.items) == 2
        assert reply.items[0].status == 512
        assert reply.items[0].original is None
        assert reply.items[0].replacement is None
        assert reply.items[1].status == 250
        assert reply.items[1].original == 'one.one.one.one'
        assert reply.items[1].replacement == '1.1.1.1'

    async def test_get_info(self):
        lines = [
            '250-version=0.4.8.12',
            '250+orconn-status=',
            '$4D0F2ADB9CD55C3EBD14823D54B6541B99A51C19~Unnamed CONNECTED',
            '$DCD645A9C7183A893AC4EF0369AAB5ED1ADBD2AF~fifo4ka CONNECTED',
            '$DAC825BBF05D678ABDEA1C3086E8D99CF0BBF112~malene CONNECTED',
            '$CB44E8ED1FAB648275C39756EB1758060C43BCA4~NOTaGlowieRelay CONNECTED',
            '.',
            '250 OK',
        ]
        message = await create_message(lines)
        reply = ReplyGetInfo.from_message(message)
        assert len(reply.values) == 2
        assert set(reply.values) == {'version', 'orconn-status'}

    async def test_get_info_error(self):
        lines = ['552 Not running in server mode']
        message = await create_message(lines)
        reply = ReplyGetInfo.from_message(message)
        assert reply.is_error is True
        assert reply.is_success is False
        assert len(reply.values) == 0

    async def test_extend_circuit(self):
        lines = ['250 EXTENDED 56832']
        message = await create_message(lines)
        reply = ReplyExtendCircuit.from_message(message)
        assert reply.circuit == 56832

    async def test_extend_circuit_error(self):
        lines = ['552 Unknown circuit "12"']
        message = await create_message(lines)
        reply = ReplyExtendCircuit.from_message(message)
        assert reply.status == 552
        assert reply.status_text == 'Unknown circuit "12"'
        assert reply.circuit is None

    async def test_authenticate(self):
        lines = ['250 OK']
        message = await create_message(lines)
        reply = ReplyAuthenticate.from_message(message)
        assert reply.status == 250
        assert reply.status_text == 'OK'

    async def test_protocol_info(self):
        lines = [
            '250-PROTOCOLINFO 1',
            (
                '250-AUTH METHODS=COOKIE,SAFECOOKIE,HASHEDPASSWORD '
                'COOKIEFILE="/run/tor/control.authcookie"'
            ),
            '250-VERSION Tor="0.4.8.12"',
            '250 OK',
        ]
        message = await create_message(lines)
        reply = ReplyProtocolInfo.from_message(message)
        # Is not supposed to raise anything.
        reply.raise_for_status()
        assert reply.protocol_version == 1
        assert reply.tor_version == '0.4.8.12'
        assert AuthMethod.COOKIE in reply.auth_methods

    async def test_protocol_info_error(self):
        message = await create_message(['513 No such version "aa"'])
        reply = ReplyProtocolInfo.from_message(message)
        assert reply.status == 513
        with pytest.raises(ReplyStatusError, match='No such version "aa"'):
            reply.raise_for_status()

    async def test_protocol_info_unknown_line(self, caplog):
        lines = [
            '250-PROTOCOLINFO 1',
            '250-TEST For="science"',
            '250-VERSION Tor="0.4.8.12"',
            '250 OK',
        ]
        message = await create_message(lines)
        with caplog.at_level(logging.INFO, logger='aiostem.protocol'):
            ReplyProtocolInfo.from_message(message)
        assert "No syntax handler for keyword 'TEST'" in caplog.text

    async def test_auth_challenge_parse(self):
        server_hash = '700912005E616BC5558ACDC14B11304B0A03F45C4B1DBD60365FD66033D7276C'
        server_nonce = 'E0BEAB4467F69317B5BEE45B04565F5FF277B896A2DE46A86C99B3999F77CE80'
        line = f'250 AUTHCHALLENGE SERVERHASH={server_hash} SERVERNONCE={server_nonce}'
        message = await create_message([line])
        reply = ReplyAuthChallenge.from_message(message)
        assert reply.status == 250
        assert reply.status_text is None
        assert reply.server_hash == bytes.fromhex(server_hash)
        assert reply.server_nonce == bytes.fromhex(server_nonce)

    async def test_auth_challenge_syntax_error(self):
        line = '512 Wrong number of arguments for AUTHCHALLENGE'
        message = await create_message([line])
        reply = ReplyAuthChallenge.from_message(message)
        assert reply.status == 512
        assert reply.status_text == 'Wrong number of arguments for AUTHCHALLENGE'
        with pytest.raises(ReplyStatusError, match='Wrong number of arguments'):
            reply.raise_for_status()

        cookie = b'e8a05005deb487f5d9a0db9a026d28ad'
        nonce = 'I am a nonce!'
        with pytest.raises(ReplyError, match='server_nonce is not set.'):
            reply.build_client_hash(nonce, cookie)
        with pytest.raises(ReplyError, match='server_nonce is not set.'):
            reply.build_server_hash(nonce, cookie)

    async def test_auth_challenge_error(self):
        client_nonce_str = 'F1BE0456FB2626512D72B06509A16EAAA707B1981F31C9BBAD40A788A0A330A6'
        server_hash = '000912005E616BC5558ACDC14B11304B0A03F45C4B1DBD60365FD66033D7276C'
        server_nonce = 'E0BEAB4467F69317B5BEE45B04565F5FF277B896A2DE46A86C99B3999F77CE80'
        cookie_str = 'E9FDE075EA5C9996F17AB280B3FD69FF6109ECA9369ED824045E8333DB58017A'
        client_nonce = bytes.fromhex(client_nonce_str)
        cookie = bytes.fromhex(cookie_str)

        line = f'250 AUTHCHALLENGE SERVERHASH={server_hash} SERVERNONCE={server_nonce}'
        message = await create_message([line])
        reply = ReplyAuthChallenge.from_message(message)
        with pytest.raises(ReplyError, match='Server hash provided by Tor is invalid'):
            reply.raise_for_server_hash_error(client_nonce, cookie)

    async def test_auth_challenge_success_bytes(self):
        client_nonce_str = 'F1BE0456FB2626512D72B06509A16EAAA707B1981F31C9BBAD40A788A0A330A6'
        server_hash = '700912005E616BC5558ACDC14B11304B0A03F45C4B1DBD60365FD66033D7276C'
        server_nonce = 'E0BEAB4467F69317B5BEE45B04565F5FF277B896A2DE46A86C99B3999F77CE80'
        cookie_str = 'E9FDE075EA5C9996F17AB280B3FD69FF6109ECA9369ED824045E8333DB58017A'
        client_nonce = bytes.fromhex(client_nonce_str)
        cookie = bytes.fromhex(cookie_str)

        line = f'250 AUTHCHALLENGE SERVERHASH={server_hash} SERVERNONCE={server_nonce}'
        message = await create_message([line])
        reply = ReplyAuthChallenge.from_message(message)
        reply.raise_for_server_hash_error(client_nonce, cookie)

        client_hash_str = 'DDC1E1FC978DDF6CD2142EEA62559D026A2F84666B9F6B462224F36B7E9A9C54'
        client_hash = bytes.fromhex(client_hash_str)
        computed = reply.build_client_hash(client_nonce, cookie)
        assert computed == client_hash

    async def test_auth_challenge_success_string(self):
        server_hash = '01BAB534C249A47B46D8CA235683B43D075C134820CAF3C0214DBDE2ADD55ED3'
        server_nonce = '76A744F700967CE08FE7E45797FA54BDCDEBF12F273080EB58562B80DBD02400'
        cookie_str = 'E9FDE075EA5C9996F17AB280B3FD69FF6109ECA9369ED824045E8333DB58017A'
        cookie = bytes.fromhex(cookie_str)
        client_nonce = 'I am a nonce!'

        line = f'250 AUTHCHALLENGE SERVERHASH={server_hash} SERVERNONCE={server_nonce}'
        message = await create_message([line])
        reply = ReplyAuthChallenge.from_message(message)
        reply.raise_for_server_hash_error(client_nonce, cookie)

        client_hash_str = '2E1DA1886E1D4D2695F10290C315877E55D838DAA04757E6D9730420DD39262C'
        client_hash = bytes.fromhex(client_hash_str)
        computed = reply.build_client_hash(client_nonce, cookie)
        assert computed == client_hash

    async def test_add_onion(self):
        lines = [
            '250-ServiceID=xsa5oiu2bpnpvsgec5ti5gqdue4t4uxfmmobqibj5nuwkzxb2krtlgyd',
            '250-PrivateKey=ED25519-V3:wCuCqxopubG0hu7WyeWsZvTa7ipqRCAnIVnghhc0pFvP'
            '6CYUzsZJCNw3bBcuita8Dr59xaUqM2nJBFZRthLTtw==',
            '250 OK',
        ]
        message = await create_message(lines)
        reply = ReplyAddOnion.from_message(message)
        assert reply.key_type == OnionServiceKeyType.ED25519_V3
        assert reply.key.hex() == (
            'c02b82ab1a29b9b1b486eed6c9e5ac66f4daee2a6a4420272159e0861734a45b'
            'cfe82614cec64908dc376c172e8ad6bc0ebe7dc5a52a3369c9045651b612d3b7'
        )

    async def test_add_onion_with_key(self):
        lines = [
            '250-ServiceID=xsa5oiu2bpnpvsgec5ti5gqdue4t4uxfmmobqibj5nuwkzxb2krtlgyd',
            '250 OK',
        ]
        message = await create_message(lines)
        reply = ReplyAddOnion.from_message(message)
        assert reply.key_type is None
        assert reply.key is None

    async def test_add_onion_error(self):
        line = '512 Bad arguments to ADD_ONION: Need at least 1 argument(s)'
        message = await create_message([line])
        reply = ReplyAddOnion.from_message(message)
        with pytest.raises(ReplyStatusError, match='Bad arguments to ADD_ONION:'):
            reply.raise_for_status()

    async def test_onion_client_auth_view(self):
        lines = [
            '250-ONION_CLIENT_AUTH_VIEW',
            (
                '250-CLIENT aiostem26gcjyybsi3tyek6txlivvlc5tczytz52h4srsttknvd5s3qd '
                'x25519:yPGUxgKaC5ACyEzsdANHJEJzt5DIqDRBlAFaAWWQn0o= ClientName=Peter'
            ),
            '250 OK',
        ]
        message = await create_message(lines)
        reply = ReplyOnionClientAuthView.from_message(message)
        assert len(reply.clients) == 1

        client = reply.clients[0]
        assert client.address == 'aiostem26gcjyybsi3tyek6txlivvlc5tczytz52h4srsttknvd5s3qd'
        assert client.name == 'Peter'
        assert len(client.key) == 32
        assert len(client.flags) == 0

    async def test_onion_client_auth_view_error(self):
        line = '512 Invalid v3 address "hjg"'
        message = await create_message([line])
        reply = ReplyOnionClientAuthView.from_message(message)
        with pytest.raises(ReplyStatusError, match='Invalid v3 address "hjg"'):
            reply.raise_for_status()
