from __future__ import annotations

from base64 import b64decode
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any

import pytest
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from pydantic import BaseModel, TypeAdapter

from aiostem.structures import AuthMethod
from aiostem.types import X25519PrivateKeyBase64, X25519PublicKeyBase32
from aiostem.utils import (
    TrAfterAsTimezone,
    TrBeforeSetToNone,
    TrBeforeStringSplit,
    TrBeforeTimedelta,
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


class TestTrX25519PrivateKey:
    ADAPTER_BASE64 = TypeAdapter(X25519PrivateKeyBase64)

    @pytest.mark.parametrize(
        ('raw', 'encoded'),
        [
            (
                'yPGUxgKaC5ACyEzsdANHJEJzt5DIqDRBlAFaAWWQn0o',
                'yPGUxgKaC5ACyEzsdANHJEJzt5DIqDRBlAFaAWWQn0o',
            ),
            (
                b64decode('yPGUxgKaC5ACyEzsdANHJEJzt5DIqDRBlAFaAWWQn0o='),
                'yPGUxgKaC5ACyEzsdANHJEJzt5DIqDRBlAFaAWWQn0o',
            ),
            (
                X25519PrivateKey.from_private_bytes(
                    b64decode('yPGUxgKaC5ACyEzsdANHJEJzt5DIqDRBlAFaAWWQn0o='),
                ),
                'yPGUxgKaC5ACyEzsdANHJEJzt5DIqDRBlAFaAWWQn0o',
            ),
        ],
    )
    def test_decode_encode_base64(self, raw, encoded):
        key = self.ADAPTER_BASE64.validate_python(raw)
        assert isinstance(key, X25519PrivateKey)

        serial = self.ADAPTER_BASE64.dump_python(key)
        assert serial == encoded

    def test_using_raw_bytes(self):
        adapter = TypeAdapter(Annotated[X25519PrivateKey, TrX25519PrivateKey()])
        raw = b64decode('yPGUxgKaC5ACyEzsdANHJEJzt5DIqDRBlAFaAWWQn0o=')
        key = adapter.validate_python(raw)
        assert adapter.dump_python(key) == raw

    @pytest.mark.parametrize(
        'type_',
        [
            Annotated[int, TrX25519PrivateKey()],
            Annotated[None, TrX25519PrivateKey()],
        ],
    )
    def test_usage_error_on_source_type(self, type_):
        with pytest.raises(TypeError, match='source type is not a x25519 private key'):
            TypeAdapter(type_)


class TestTrX25519PublicKey:
    @pytest.mark.parametrize(
        ('raw', 'encoded'),
        [
            (
                '5BPBXQOAZWPSSXFKOIXHZDRDA2AJT2SWS2GIQTISCFKGVBFWBBDQ',
                '5BPBXQOAZWPSSXFKOIXHZDRDA2AJT2SWS2GIQTISCFKGVBFWBBDQ',
            ),
            (
                bytes.fromhex(
                    '88b613a7d69860f8c64cafbb730b3596130cb6c18236b5965fdd5fe69e4800f5'
                ),
                'RC3BHJ6WTBQPRRSMV65XGCZVSYJQZNWBQI3LLFS73VP6NHSIAD2Q',
            ),
            (
                X25519PublicKey.from_public_bytes(
                    bytes.fromhex(
                        '5588fdbfea963654702043b7672f78437400b3bf5f6086e557f0d55edaaeecf3'
                    )
                ),
                'KWEP3P7KSY3FI4BAIO3WOL3YIN2ABM57L5QINZKX6DKV5WVO5TZQ',
            ),
        ],
    )
    def test_decode_encode(self, raw, encoded):
        adapter = TypeAdapter(X25519PublicKeyBase32)
        key = adapter.validate_python(raw)
        assert isinstance(key, X25519PublicKey)

        serial = adapter.dump_python(key)
        assert serial == encoded

    def test_using_raw_bytes(self):
        adapter = TypeAdapter(Annotated[X25519PublicKey, TrX25519PublicKey()])
        raw = bytes.fromhex('88b613a7d69860f8c64cafbb730b3596130cb6c18236b5965fdd5fe69e4800f5')
        key = adapter.validate_python(raw)
        assert adapter.dump_python(key) == raw

    @pytest.mark.parametrize(
        'type_',
        [
            Annotated[int, TrX25519PublicKey()],
            Annotated[None, TrX25519PublicKey()],
        ],
    )
    def test_usage_error_on_source_type(self, type_):
        with pytest.raises(TypeError, match='source type is not a x25519 public key'):
            TypeAdapter(type_)
