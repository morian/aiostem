from __future__ import annotations

from base64 import b32decode, b64decode
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from pydantic import BaseModel, TypeAdapter, ValidationError

from aiostem.structures import AuthMethod
from aiostem.utils import (
    Base32Encoder,
    Base64Encoder,
    EncodedBytes,
    TrAfterAsTimezone,
    TrBeforeSetToNone,
    TrBeforeStringSplit,
    TrBeforeTimedelta,
    TrEd25519PrivateKey,
    TrEd25519PublicKey,
    TrX25519PrivateKey,
    TrX25519PublicKey,
)


class TestAsTimezone:
    @pytest.mark.parametrize(
        ('raw', 'timezone', 'timestamp'),
        [
            ('2024-12-09T23:10:14+01:00', None, 1733782214),
            ('2024-12-09T23:10:14', UTC, 1733785814),
        ],
    )
    def test_astimezone(self, raw, timezone, timestamp):
        adapter = TypeAdapter(Annotated[datetime, TrAfterAsTimezone(timezone)])
        result = adapter.validate_python(raw)
        assert int(result.timestamp()) == timestamp

    @pytest.mark.parametrize(
        'type_',
        [
            Annotated[int, TrAfterAsTimezone()],
            Annotated[None, TrAfterAsTimezone()],
        ],
    )
    def test_usage_error_on_source_type(self, type_):
        with pytest.raises(TypeError, match='source type is not a datetime'):
            TypeAdapter(type_)

    def test_json_schema(self):
        adapter = TypeAdapter(Annotated[datetime, TrAfterAsTimezone()])
        assert adapter.json_schema() == {'format': 'date-time', 'type': 'string'}


class TestSetToNone:
    ADAPTER_COMPLEX = TypeAdapter(
        Annotated[
            str | None,
            TrBeforeSetToNone({'NULL'}),
            TrBeforeSetToNone({'NIL'}),
        ]
    )
    ADAPTER_SIMPLE = TypeAdapter(
        Annotated[
            str | None,
            TrBeforeSetToNone({'NULL', 'NIL'}),
        ]
    )

    @pytest.mark.parametrize(
        ('entry', 'result'),
        [
            (None, None),
            ('NULL', None),
            ('NIL', None),
            ('ERROR', 'ERROR'),
        ],
    )
    def test_complex(self, entry, result):
        parsed = self.ADAPTER_COMPLEX.validate_python(entry)
        assert parsed == result

    @pytest.mark.parametrize(
        ('entry', 'result'),
        [
            (None, None),
            ('NULL', None),
            ('NIL', None),
            ('ERROR', 'ERROR'),
        ],
    )
    def test_simple(self, entry, result):
        parsed = self.ADAPTER_SIMPLE.validate_python(entry)
        assert parsed == result


class HostPort(BaseModel):
    host: str
    port: int


class TestStringSplit:
    @pytest.mark.parametrize(
        'entry',
        [
            [1, 2, 3, 4],
            '1,2,3,4',
            b'1,2,3,4',
        ],
    )
    def test_with_simple_types_always(self, entry: Any):
        adapter = TypeAdapter(Annotated[list[int], TrBeforeStringSplit()])
        res = adapter.validate_python(entry)
        assert res == [1, 2, 3, 4]

        assert adapter.dump_python(res) == '1,2,3,4'
        assert adapter.dump_json(res) == b'"1,2,3,4"'

    @pytest.mark.parametrize(
        'entry',
        [
            [1, 2, 3, 4],
            '1,2,3,4',
            b'1,2,3,4',
        ],
    )
    def test_with_simple_types_json(self, entry: Any):
        adapter = TypeAdapter(Annotated[list[int], TrBeforeStringSplit(when_used='json')])
        res = adapter.validate_python(entry)
        assert res == [1, 2, 3, 4]

        assert adapter.dump_python(res) == [1, 2, 3, 4]
        assert adapter.dump_json(res) == b'"1,2,3,4"'

    @pytest.mark.parametrize(
        ('entry', 'output'),
        [
            ('COOKIE', [AuthMethod.COOKIE]),
            ('NULL,SAFECOOKIE', [AuthMethod.NULL, AuthMethod.SAFECOOKIE]),
        ],
    )
    def test_with_strenum(self, entry: str, output: list[AuthMethod]):
        adapter = TypeAdapter(Annotated[list[AuthMethod], TrBeforeStringSplit()])
        for item in (entry, output):
            result = adapter.validate_python(item)
            assert result == output
            serial = adapter.dump_python(result)
            assert serial == entry

    def test_with_max_split(self):
        value = 'A,B,C,D'
        adapter = TypeAdapter(Annotated[list[str], TrBeforeStringSplit(maxsplit=1)])
        result = adapter.validate_python(value)
        assert len(result) == 2
        assert result[1] == 'B,C,D'

    @pytest.mark.parametrize(
        ('entry', 'serial'),
        [
            ('localhost:443', 'localhost:443'),
            (
                HostPort(host='localhost', port=443),
                'localhost:443',
            ),
        ],
    )
    def test_with_dict_keys(self, entry, serial):
        adapter = TypeAdapter(
            Annotated[
                HostPort,
                TrBeforeStringSplit(
                    dict_keys=('host', 'port'),
                    maxsplit=1,
                    separator=':',
                ),
            ]
        )
        result = adapter.validate_python(entry)
        assert isinstance(result, HostPort)
        assert result.host == 'localhost'
        assert result.port == 443

        serialized = adapter.dump_python(result)
        assert serialized == serial

    @pytest.mark.parametrize(
        'type_',
        [
            Annotated[int, TrBeforeStringSplit()],
            Annotated[None, TrBeforeStringSplit()],
        ],
    )
    def test_usage_error_as_sequence(self, type_):
        with pytest.raises(TypeError, match='source type is not a collection'):
            TypeAdapter(type_)


class TestTimedelta:
    ADAPTER_SECS = TypeAdapter(Annotated[timedelta, TrBeforeTimedelta(milliseconds=False)])
    ADAPTER_MSECS = TypeAdapter(Annotated[timedelta, TrBeforeTimedelta(milliseconds=True)])

    @pytest.mark.parametrize(
        'entry',
        [
            timedelta(seconds=1234),
            '00:20:34',
            '1234',
            1234,
        ],
    )
    def test_seconds_with_multiple_types(self, entry: Any):
        delta = self.ADAPTER_SECS.validate_python(entry)
        assert int(delta.total_seconds()) == 1234

        serial = self.ADAPTER_SECS.dump_python(delta)
        assert isinstance(serial, float)
        assert int(serial) == 1234

    @pytest.mark.parametrize(
        'entry',
        [
            timedelta(seconds=1.234),
            '00:00:01.234',
            '1234',
            1234,
        ],
    )
    def test_milliseconds_with_multiple_types(self, entry: Any):
        delta = self.ADAPTER_MSECS.validate_python(entry)
        assert int(delta.total_seconds()) == 1

        serial = self.ADAPTER_MSECS.dump_python(delta)
        assert isinstance(serial, float)
        assert int(serial) == 1234

    @pytest.mark.parametrize(
        'type_',
        [
            Annotated[int, TrBeforeTimedelta()],
            Annotated[bytes, TrBeforeTimedelta()],
        ],
    )
    def test_with_error(self, type_):
        with pytest.raises(TypeError, match='source type is not a timedelta'):
            TypeAdapter(type_)


class TestTrEd25519PrivateKey:
    KEY_TYPE = Ed25519PrivateKey
    ADAPTER_RAW = TypeAdapter(Annotated[Ed25519PrivateKey, TrEd25519PrivateKey()])
    ADAPTER_ENC = TypeAdapter(
        Annotated[
            Ed25519PrivateKey,
            EncodedBytes(encoder=Base64Encoder),
            TrEd25519PrivateKey(expanded=False),
        ],
    )
    ADAPTER_EXP = TypeAdapter(
        Annotated[
            Ed25519PrivateKey,
            EncodedBytes(encoder=Base64Encoder),
            TrEd25519PrivateKey(expanded=True),
        ]
    )
    TEST_KEY = 'czJbjz9SLJqx6DVIRe1cWTSWXM4UeYiRNTnAPYGDlMU='
    EXPANDED = (
        '0EqCqB0L1FnKrZwu6ovSwCD3gEfWVxVAAlJiToTI3Ea6fC2IxwcKJt4MCEuc9oQo'
        'kYK+HdXtbc3jIvySyLaNMg'
    )
    EXPECTED = TEST_KEY.rstrip('=')

    @pytest.mark.parametrize(
        'raw',
        [
            EXPECTED,
            TEST_KEY,
            b64decode(TEST_KEY),
            Ed25519PrivateKey.from_private_bytes(b64decode(TEST_KEY)),
        ],
    )
    def test_decode_encode(self, raw):
        key = self.ADAPTER_ENC.validate_python(raw)
        assert isinstance(key, self.KEY_TYPE)

        serial = self.ADAPTER_ENC.dump_python(key)
        assert serial == self.EXPECTED

    def test_expanded_key_parse(self):
        with pytest.raises(ValidationError, match='An Ed25519 private key is 32 bytes long'):
            self.ADAPTER_EXP.validate_python(self.EXPANDED)

    def test_expanded_key_serialize(self):
        key = Ed25519PrivateKey.from_private_bytes(b64decode(self.TEST_KEY))
        ser = self.ADAPTER_EXP.dump_python(key)
        assert ser == self.EXPANDED

    def test_using_raw_bytes(self):
        raw = b64decode(self.TEST_KEY)
        key = self.ADAPTER_RAW.validate_python(raw)
        assert self.ADAPTER_RAW.dump_python(key) == raw


class TestTrEd25519PublicKey:
    KEY_TYPE = Ed25519PublicKey
    ADAPTER_RAW = TypeAdapter(Annotated[Ed25519PublicKey, TrEd25519PublicKey()])
    ADAPTER_ENC = TypeAdapter(
        Annotated[
            Ed25519PublicKey,
            EncodedBytes(encoder=Base32Encoder),
            TrEd25519PublicKey(),
        ],
    )
    TEST_KEY = 'LQGMCX7HKXJZ52KH2U5KABXIUTN6MGIYIVCNQQGMJBRF24QT5UOA===='
    EXPECTED = TEST_KEY.rstrip('=')

    @pytest.mark.parametrize(
        'raw',
        [
            TEST_KEY,
            EXPECTED,
            b32decode(TEST_KEY),
            Ed25519PublicKey.from_public_bytes(b32decode(TEST_KEY)),
        ],
    )
    def test_decode_encode(self, raw):
        key = self.ADAPTER_ENC.validate_python(raw)
        assert isinstance(key, self.KEY_TYPE)

        serial = self.ADAPTER_ENC.dump_python(key)
        assert serial == self.EXPECTED

    def test_using_raw_bytes(self):
        raw = b32decode(self.TEST_KEY)
        key = self.ADAPTER_RAW.validate_python(raw)
        assert self.ADAPTER_RAW.dump_python(key) == raw


class TestTrX25519PrivateKey:
    KEY_TYPE = X25519PrivateKey
    ADAPTER_RAW = TypeAdapter(Annotated[X25519PrivateKey, TrX25519PrivateKey()])
    ADAPTER_ENC = TypeAdapter(
        Annotated[
            X25519PrivateKey,
            EncodedBytes(encoder=Base64Encoder),
            TrX25519PrivateKey(),
        ],
    )
    TEST_KEY = 'yPGUxgKaC5ACyEzsdANHJEJzt5DIqDRBlAFaAWWQn0o='
    EXPECTED = TEST_KEY.rstrip('=')

    @pytest.mark.parametrize(
        'raw',
        [
            EXPECTED,
            TEST_KEY,
            b64decode(TEST_KEY),
            X25519PrivateKey.from_private_bytes(b64decode(TEST_KEY)),
        ],
    )
    def test_decode_encode(self, raw):
        key = self.ADAPTER_ENC.validate_python(raw)
        assert isinstance(key, self.KEY_TYPE)

        serial = self.ADAPTER_ENC.dump_python(key)
        assert serial == self.EXPECTED

    def test_using_raw_bytes(self):
        raw = b64decode(self.TEST_KEY)
        key = self.ADAPTER_RAW.validate_python(raw)
        assert self.ADAPTER_RAW.dump_python(key) == raw

    @pytest.mark.parametrize(
        'type_',
        [
            Annotated[int, TrX25519PrivateKey()],
            Annotated[None, TrX25519PrivateKey()],
        ],
    )
    def test_usage_error_on_source_type(self, type_):
        with pytest.raises(TypeError, match='source type is not a X25519PrivateKey'):
            TypeAdapter(type_)


class TestTrX25519PublicKey:
    KEY_TYPE = X25519PublicKey
    ADAPTER_RAW = TypeAdapter(Annotated[X25519PublicKey, TrX25519PublicKey()])
    ADAPTER_ENC = TypeAdapter(
        Annotated[
            X25519PublicKey,
            EncodedBytes(encoder=Base32Encoder),
            TrX25519PublicKey(),
        ],
    )
    TEST_KEY = 'K2MLQ4S2DS4YCZXDOTOVC45LCLAKKCKN7QVAXPDMOSSYPZBGQSLA===='
    EXPECTED = TEST_KEY.rstrip('=')

    @pytest.mark.parametrize(
        'raw',
        [
            TEST_KEY,
            EXPECTED,
            b32decode(TEST_KEY),
            X25519PublicKey.from_public_bytes(b32decode(TEST_KEY)),
        ],
    )
    def test_decode_encode(self, raw):
        key = self.ADAPTER_ENC.validate_python(raw)
        assert isinstance(key, self.KEY_TYPE)

        serial = self.ADAPTER_ENC.dump_python(key)
        assert serial == self.EXPECTED

    def test_using_raw_bytes(self):
        raw = b32decode(self.TEST_KEY)
        key = self.ADAPTER_RAW.validate_python(raw)
        assert self.ADAPTER_RAW.dump_python(key) == raw
