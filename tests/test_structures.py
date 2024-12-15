from __future__ import annotations

from base64 import b32encode
from ipaddress import IPv4Address, IPv6Address

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import BaseModel, TypeAdapter, ValidationError

from aiostem.structures import (
    HiddenServiceAddressV2,
    HiddenServiceAddressV3,
    HsDescAuthCookie,
    HsDescAuthTypeInt,
    LongServerName,
    TcpAddressPort,
)

HiddenServiceAdapterV2 = TypeAdapter(HiddenServiceAddressV2)
HiddenServiceAdapterV3 = TypeAdapter(HiddenServiceAddressV3)


class TestHiddenServiceV2:
    @pytest.mark.parametrize(
        'address',
        [
            HiddenServiceAdapterV2.validate_python('facebookcorewwwi.onion'),
            'facebookcorewwwi.onion',
            'facebookcorewwwi',
        ],
    )
    def test_valid_domains(self, address):
        class Model(BaseModel):
            v: HiddenServiceAddressV2

        model = Model(v=address)
        assert model.v == 'facebookcorewwwi'

    @pytest.mark.parametrize(
        ('address', 'errtype'),
        [
            ('facebookcorewww1', 'string_pattern_mismatch'),
            ('facebookcorewww.onion', 'string_pattern_mismatch'),
            ('facebookcorewww', 'string_too_short'),
        ],
    )
    def test_invalid_domains(self, address, errtype):
        class Model(BaseModel):
            v: HiddenServiceAddressV2

        with pytest.raises(ValidationError, match=f'type={errtype}') as exc:
            Model(v=address)

        assert len(exc.value.errors()) == 1, exc.value.errors()
        error = exc.value.errors()[0]
        assert error['type'] == errtype, address


class TestHiddenServiceV3:
    @pytest.mark.parametrize(
        'address',
        [
            HiddenServiceAdapterV3.validate_python(
                'facebookcooa4ldbat4g7iacswl3p2zrf5nuylvnhxn6kqolvojixwid.onion',
            ),
            'facebookcooa4ldbat4g7iacswl3p2zrf5nuylvnhxn6kqolvojixwid.onion',
            'facebookcooa4ldbat4g7iacswl3p2zrf5nuylvnhxn6kqolvojixwid',
        ],
    )
    def test_valid_domains(self, address):
        class Model(BaseModel):
            v: HiddenServiceAddressV3

        model = Model(v=address)
        assert model.v == 'facebookcooa4ldbat4g7iacswl3p2zrf5nuylvnhxn6kqolvojixwid'

    def test_ed25519_public_key(self):
        """Check that the public ed25519 key is correct."""
        address = 'facebookcooa4ldbat4g7iacswl3p2zrf5nuylvnhxn6kqolvojixwid'
        adapter = TypeAdapter(HiddenServiceAddressV3)
        onion = adapter.validate_python(address)
        assert isinstance(onion, HiddenServiceAddressV3)

        pubkey = onion.public_key
        assert isinstance(pubkey, Ed25519PublicKey)

        raw = pubkey.public_bytes_raw()
        prefix = b32encode(raw).decode('ascii').lower()[:31]
        assert address.startswith(prefix) is True

    @pytest.mark.parametrize(
        ('address', 'errtype'),
        [
            (
                'facebookcooa4ldbat4g7iacswl3p2zrf5nuylvnhxn6kqolvojixw1d',
                'string_pattern_mismatch',
            ),
            (
                'facebookcooa4ldbat4g7iacswl3p2zrf5nuylvnhxn6kqol',
                'string_too_short',
            ),
            (
                'facebookcooa4ldbat4g7iacswl3p2zrf5nuylvnhxn6kqolvojixwib',
                'invalid_onion_v3',
            ),
            (
                'facebookcooa4ldbat4g7iacswl3p2zrf5nuylvnhxn6kqolvojixsad',
                'invalid_onion_v3',
            ),
        ],
    )
    def test_invalid_domains(self, address, errtype):
        class Model(BaseModel):
            v: HiddenServiceAddressV3

        with pytest.raises(ValidationError, match=f'type={errtype}') as exc:
            Model(v=address)

        assert len(exc.value.errors()) == 1, exc.value.errors()
        error = exc.value.errors()[0]
        assert error['type'] == errtype, address


HsDescAuthCookieAdapter = TypeAdapter(HsDescAuthCookie)


class TestHsDescAuthCookie:
    @pytest.mark.parametrize(
        ('raw', 'encoded', 'auth_type'),
        [
            ('GmYIu0EKkd5H6blpIFg3jQ', 'GmYIu0EKkd5H6blpIFg3jQA=', 1),
            ('GmYIu0EKkd5H6blpIFg3jQA=', 'GmYIu0EKkd5H6blpIFg3jQA=', 1),
            (
                bytes.fromhex('1a6608bb410a91de47e9b9692058378d00'),
                'GmYIu0EKkd5H6blpIFg3jQA=',
                1,
            ),
            (
                HsDescAuthCookie(
                    auth_type=HsDescAuthTypeInt.BASIC_AUTH,
                    cookie=bytes.fromhex('1a6608bb410a91de47e9b9692058378d'),
                ),
                'GmYIu0EKkd5H6blpIFg3jQA=',
                1,
            ),
            ('GmYIu0EKkd5H6blpIFg3jR', 'GmYIu0EKkd5H6blpIFg3jRA=', 2),
            ('GmYIu0EKkd5H6blpIFg3jRA=', 'GmYIu0EKkd5H6blpIFg3jRA=', 2),
        ],
    )
    def test_parse_then_encode(self, raw, encoded, auth_type):
        auth = HsDescAuthCookieAdapter.validate_python(raw)
        assert int(auth.auth_type) == auth_type
        serial = HsDescAuthCookieAdapter.dump_python(auth)
        assert serial == encoded

    @pytest.mark.parametrize(
        'auth_type',
        [
            HsDescAuthTypeInt.BASIC_AUTH,
            HsDescAuthTypeInt.STEALTH_AUTH,
        ],
    )
    def test_generate(self, auth_type):
        auth = HsDescAuthCookie.generate(auth_type)
        assert auth.auth_type == auth_type
        assert len(auth.cookie) == 16


LongServerNameAdapter = TypeAdapter(LongServerName)


class TestLongServerName:
    @pytest.mark.parametrize(
        ('string', 'nickname'),
        [
            ('$14AE2154A26F1D42C3C3BEDC10D05FDD9F8545BB~Test', 'Test'),
            ('$14AE2154A26F1D42C3C3BEDC10D05FDD9F8545BB', None),
        ],
    )
    def test_parse(self, string, nickname):
        server = LongServerName.from_string(string)
        assert len(server.fingerprint) == 20
        assert server.nickname == nickname

    def test_parse_error(self):
        with pytest.raises(ValueError, match='LongServerName does not start with a'):
            LongServerName.from_string('Hello world')

    @pytest.mark.parametrize(
        ('string', 'nickname'),
        [
            ('$A4DE8349C2089CC471EC12099F87BDD797EBDA8E~Test', 'Test'),
            ('$A4DE8349C2089CC471EC12099F87BDD797EBDA8E', None),
        ],
    )
    def test_serialize(self, string, nickname):
        fp = b'\xa4\xde\x83I\xc2\x08\x9c\xc4q\xec\x12\t\x9f\x87\xbd\xd7\x97\xeb\xda\x8e'
        server = LongServerName(fingerprint=fp, nickname=nickname)
        serial = LongServerNameAdapter.dump_python(server)
        assert serial == string


class TestTcpAddressPort:
    @pytest.mark.parametrize(
        ('string', 'host', 'port'),
        [
            ('127.0.0.1:445', IPv4Address('127.0.0.1'), 445),
            ('[::1]:65432', IPv6Address('::1'), 65432),
        ],
    )
    def test_parse(self, string, host, port):
        target = TcpAddressPort.from_string(string)
        assert target.host == host
        assert target.port == port

    @pytest.mark.parametrize(
        ('string', 'host', 'port'),
        [
            ('127.0.0.1:445', IPv4Address('127.0.0.1'), 445),
            ('[::1]:65432', IPv6Address('::1'), 65432),
        ],
    )
    def test_serialize(self, string, host, port):
        adapter = TypeAdapter(TcpAddressPort)
        target = TcpAddressPort(host=host, port=port)
        serial = adapter.dump_python(target)
        assert serial == string
