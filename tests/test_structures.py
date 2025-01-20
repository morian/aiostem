from __future__ import annotations

import secrets
from base64 import b32encode, b64encode
from ipaddress import IPv4Address, IPv6Address
from typing import TYPE_CHECKING, ClassVar

import pydantic
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from packaging.version import Version
from pydantic import BaseModel, TypeAdapter, ValidationError

from aiostem.exceptions import ReplySyntaxError
from aiostem.structures import (
    HiddenServiceAddressV2,
    HiddenServiceAddressV3,
    HsDescAuthCookie,
    HsDescAuthTypeInt,
    LogSeverity,
    LongServerName,
    OnionClientAuthKey,
    OnionServiceKey,
    OnionServiceKeyStruct,
    StreamTarget,
    TcpAddressPort,
    _parse_block,
)
from aiostem.utils import TrEd25519PrivateKey

if TYPE_CHECKING:
    from collections.abc import Sequence


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

        # Here we have two errors since we are neither and instance nor compatible.
        assert len(exc.value.errors()) == 2, exc.value.errors()
        error = exc.value.errors()[0]
        assert error['type'] == 'is_instance_of', address
        error = exc.value.errors()[1]
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

        assert len(exc.value.errors()) == 2, exc.value.errors()
        error = exc.value.errors()[0]
        assert error['type'] == 'is_instance_of', address
        error = exc.value.errors()[1]
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


class TestLogSeverity:
    ADAPTER = TypeAdapter(LogSeverity)
    TEST_CASES: ClassVar[Sequence[str]] = [
        LogSeverity.ERROR,
        'ERR',
        'ERROR',
        'Error',
        'err',
    ]

    @pytest.mark.parametrize('entry', TEST_CASES)
    def test_log_severity_with_values(self, entry):
        value = self.ADAPTER.validate_python(entry)
        assert value == LogSeverity.ERROR


LongServerNameAdapter = TypeAdapter(LongServerName)


class TestLongServerName:
    ADAPTER = TypeAdapter(LongServerName)

    @pytest.mark.parametrize(
        ('entry', 'nickname'),
        [
            (
                LongServerName(
                    fingerprint=bytes.fromhex('14AE2154A26F1D42C3C3BEDC10D05FDD9F8545BB'),
                    nickname='Test',
                ),
                'Test',
            ),
            ('$14AE2154A26F1D42C3C3BEDC10D05FDD9F8545BB~Test', 'Test'),
            ('$14AE2154A26F1D42C3C3BEDC10D05FDD9F8545BB', None),
        ],
    )
    def test_parse(self, entry, nickname):
        server = self.ADAPTER.validate_python(entry)
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
    ADAPTER = TypeAdapter(TcpAddressPort)

    @pytest.mark.parametrize(
        ('entry', 'host', 'port'),
        [
            (
                TcpAddressPort(
                    host=IPv4Address('127.0.0.1'),
                    port=445,
                ),
                IPv4Address('127.0.0.1'),
                445,
            ),
            ('127.0.0.1:445', IPv4Address('127.0.0.1'), 445),
            ('[::1]:65432', IPv6Address('::1'), 65432),
        ],
    )
    def test_parse(self, entry, host, port):
        target = self.ADAPTER.validate_python(entry)
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
        target = TcpAddressPort(host=host, port=port)
        serial = self.ADAPTER.dump_python(target)
        assert serial == string


class TestStreamTarget:
    ADAPTER = TypeAdapter(StreamTarget)

    def test_ipv4_port(self):
        line = '127.0.0.1:53'
        target = self.ADAPTER.validate_python(line)
        assert target.host == IPv4Address('127.0.0.1')
        assert target.node is None
        assert target.port == 53
        assert str(target) == line

        # Check that the target can be provided again and this is valid.
        assert self.ADAPTER.validate_python(target) == target

    def test_ipv6_port(self):
        line = '[::1]:443'
        target = self.ADAPTER.validate_python(line)
        assert target.host == IPv6Address('::1')
        assert target.node is None
        assert target.port == 443
        assert str(target) == line

    def test_domain_port(self):
        line = 'www.torproject.org:443'
        target = self.ADAPTER.validate_python(line)
        assert target.host == 'www.torproject.org'
        assert target.node is None
        assert target.port == 443
        assert str(target) == line

    def test_ipv4_exit_node(self):
        fphex = '3629DC5393D25D9588F2D613CF4185A98E405C1BFAC747F75A4B4619F47CAEA7'
        line = f'1.1.1.1.${fphex}.exit:443'
        target = self.ADAPTER.validate_python(line)
        assert target.host == IPv4Address('1.1.1.1')
        assert target.node.fingerprint.hex().upper() == fphex
        assert target.port == 443
        assert str(target) == line

    def test_ipv6_exit_node(self):
        fphex = '3629DC5393D25D9588F2D613CF4185A98E405C1BFAC747F75A4B4619F47CAEA7'
        line = f'[::1].${fphex}.exit:443'
        target = self.ADAPTER.validate_python(line)
        assert target.host == IPv6Address('::1')
        assert target.node.fingerprint.hex().upper() == fphex
        assert target.port == 443
        assert str(target) == line


class TestOnionClientAuthKey:
    ADAPTER = TypeAdapter(OnionClientAuthKey)

    def test_parse_and_encode(self):
        value = 'x25519:jPshnLNf+mpeEaBq/xEWjY5A/rnN7El8mRZmA0IyVwc'
        key = self.ADAPTER.validate_python(value)
        assert isinstance(key, X25519PrivateKey)

        serial = self.ADAPTER.dump_python(key)
        assert serial == value

    @pytest.mark.skipif(
        Version(pydantic.__version__) < Version('2.9.0'),
        reason='No UserWarning is emitted on pydantic < 2.9',
    )
    def test_user_warning(self):
        with pytest.warns(UserWarning, match='Unhandled onion client auth key type'):
            self.ADAPTER.dump_python('xxxx')


class TestOnionServiceKey:
    ADAPTER = TypeAdapter(OnionServiceKey)

    def test_parse_with_ed25519(self):
        value = (
            'ED25519-V3:ECum/PYnCBIHwWWmn6AaO29uY4Eq/hDEz6pLUGznA0P0ZZKoLzYbJ'
            'yURXRs0GNUz5aon9y+I3x3GauWJEXymSA=='
        )
        key = self.ADAPTER.validate_python(value)
        assert isinstance(key, OnionServiceKeyStruct)

        serial = self.ADAPTER.dump_python(key)
        assert serial == value.rstrip('=')

    def test_parse_with_rsa1024(self):
        value = (
            'RSA1024:MIICXAIBAAKBgQCdgZ2RL9T2OvYCQ6dDmiWuaxZPsL111BEDEc6HOKDw'
            'E9f9Mu4Oybd48TVMgm9/xSYLBN4gBca75fZX9oqB+umy7gNdRZyeat81YwNZUOb0'
            'Bko6Gfo6nrhssrvGETk6rRjMMRKVkeMDUQYDTF4bo2dKNxEhkmfEUbnZvjPs5E1Z'
            'RQIDAQABAoGAPVXJN02qH8zsGgugainv/JEFGjlYPjc7/LcFdxDtUzBXDumzXJze'
            'zsEXoVi19MqgOvBFU7EMKAWwPabrXxyHvqKCNoR8Iwlz7yozXchre5l87EhgReNR'
            'vGnFaUYYSrJ9vb92ytI9ZDdbf6pxd1cWxzbUghFCxpUZ4k+GmkzNka0CQQDQhLbc'
            'OOS+gc4iAa83XyXD/iJO/gYfNuObI9FOnTKVwxA6Al/TaTGp0Mk35IL1wh07EHxN'
            '7oxSGieqWriGm5ZnAkEAwV85CYRkEC7kxRlMLAjxqyVD8jh/nSvakYqqJRZ2JJdn'
            'jXO20nICowciaFKJvJSC4iU/4w3wcu9beed9ialPcwJAKYy4b0t68ScmbwpM4si3'
            '2sUSCxF9IM0sL2bEt1iFkugKnLSKabMFbWQoJFYJbnUeo/1V96V4GogRrVVkfZYV'
            'MwJAS95BcaN44wSTC2XWhfxoXR683t8d6puXIL1H7k82wTqKDWyWEVFcCXy2Gjow'
            'AkY+Z933h+0jJuUUfeq+TXGZUwJBAL5V289moEjRsqwXn8Eaw5aU/+IRBgnWxXKZ'
            '6mXD8gb5OQ7TLkcfehNHHy3JYEgfrLjZafol/9IGA7tisfp2vPs='
        )
        key = self.ADAPTER.validate_python(value)
        assert isinstance(key, RSAPrivateKey)

        serial = self.ADAPTER.dump_python(key)
        assert serial == value.rstrip('=')

    def test_serialize_ed25519(self):
        key = Ed25519PrivateKey.from_private_bytes(secrets.token_bytes(32))
        expanded = TrEd25519PrivateKey().to_expanded_bytes(key)
        expected = b64encode(expanded).decode().rstrip('=')
        result = self.ADAPTER.dump_python(key)
        assert result == f'ED25519-V3:{expected}'

    @pytest.mark.skipif(
        Version(pydantic.__version__) < Version('2.9.0'),
        reason='No UserWarning is emitted on pydantic < 2.9',
    )
    def test_user_warning(self):
        with pytest.warns(UserWarning, match='Unhandled onion service key type'):
            self.ADAPTER.dump_python('xxxx')


class TestBlockParsing:
    """Checks on our block parsing."""

    LINES: ClassVar[Sequence[str]] = [
        '-----BEGIN MESSAGE-----',
        'SbD0e0NOZ1K5Q7utFGWocGEyLGPi2KFPwniLMZb1VDymcJ7yOILYMk52kxQ+j7Cvjt/1nwdbG0Wk',
        'iBCE0R9y0oXTP9K0A2TG7sLudILSmCP35g9W3XRtYnrJNVIx3OzfKOKIo+j6SLD7xUeP1SBop3jn',
        '6s9Hd2mjPGH27gLRDbvYa3pVgUb495UnvqONbHf50SzzFe+ZsKoJSWG3jhI3Q0Db9nBwK3KLzEtc',
        'HPCshn1ZEPmMrCG3Wk4FkRb8NC6RyrY/k+Tuxem5iwb9bqkX1tqSAeP6q/7o5Q2xm6prMod/Behj',
        'vcvVixkIdFci7uCwaxfmGIUdHUa2hBviDJpX3Q==',
        '-----END MESSAGE-----',
    ]

    def test_invalid_block(self):
        with pytest.raises(ReplySyntaxError, match='Unexpected block start'):
            _parse_block(iter(self.LINES), 'PUBLIC KEY')

    def test_content_inner(self):
        inner = _parse_block(iter(self.LINES), 'MESSAGE', inner=True)
        assert inner == ''.join(self.LINES[1:-1])

    def test_content_outer(self):
        inner = _parse_block(iter(self.LINES), 'MESSAGE', inner=False)
        assert inner == '\n'.join(self.LINES)
