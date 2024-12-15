from __future__ import annotations

from base64 import b64decode
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any

import pytest
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from pydantic import BaseModel, TypeAdapter

from aiostem.structures import AuthMethod, LogSeverity
from aiostem.types import TimedeltaSeconds, X25519PrivateKeyBase64, X25519PublicKeyBase32
from aiostem.utils import (
    TrAfterAsTimezone,
    TrBeforeLogSeverity,
    TrBeforeStringSplit,
    TrBeforeTimedelta,
    TrWrapX25519PrivateKey,
    TrWrapX25519PublicKey,
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


class TestStringSplit:
    @pytest.mark.parametrize(
        'entry',
        [
            [1, 2, 3, 4],
            '1,2,3,4',
            b'1,2,3,4',
        ],
    )
    def test_with_simple_types(self, entry: Any):
        adapter = TypeAdapter(Annotated[list[int], TrBeforeStringSplit()])
        res = adapter.validate_python(entry)
        assert res == [1, 2, 3, 4]

        assert adapter.dump_python(res) == '1,2,3,4'
        assert adapter.dump_json(res) == b'"1,2,3,4"'

    @pytest.mark.parametrize(
        ('entry', 'output'),
        [
            ('COOKIE', {AuthMethod.COOKIE}),
            ('NULL,SAFECOOKIE', {AuthMethod.NULL, AuthMethod.SAFECOOKIE}),
        ],
    )
    def test_with_strenum(self, entry: str, output: set[AuthMethod]):
        adapter = TypeAdapter(Annotated[set[AuthMethod], TrBeforeStringSplit()])
        for item in (entry, output):
            assert adapter.validate_python(item) == output

    def test_with_max_split(self):
        value = 'A,B,C,D'
        adapter = TypeAdapter(Annotated[list[str], TrBeforeStringSplit(maxsplit=1)])
        result = adapter.validate_python(value)
        assert len(result) == 2
        assert result[1] == 'B,C,D'

    def test_with_dict_keys(self):
        class HostPort(BaseModel):
            host: str
            port: int

        value = 'localhost:443'
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
        result = adapter.validate_python(value)
        assert isinstance(result, HostPort)
        assert result.host == 'localhost'
        assert result.port == 443

    def test_json_schema(self):
        adapter = TypeAdapter(Annotated[tuple[str, int], TrBeforeStringSplit()])
        schema = adapter.json_schema()
        assert schema == {
            'maxItems': 2,
            'maxSplit': -1,
            'minItems': 2,
            'prefixItems': [
                {'type': 'string'},
                {'type': 'integer'},
            ],
            'separator': ',',
            'type': 'string',
        }

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


class TestLogSeverity:
    @pytest.mark.parametrize(
        'entry',
        [
            LogSeverity.ERROR,
            'ERR',
            'ERROR',
            'Error',
            'err',
        ],
    )
    def test_with_multiple_values(self, entry: Any):
        adapter = TypeAdapter(Annotated[LogSeverity, TrBeforeLogSeverity()])
        value = adapter.validate_python(entry)
        assert value == LogSeverity.ERROR


class TestTimedelta:
    @pytest.mark.parametrize(
        'entry',
        [
            timedelta(seconds=1234),
            '1234',
            1234,
        ],
    )
    def test_with_multiple_types(self, entry: Any):
        adapter = TypeAdapter(TimedeltaSeconds)
        delta = adapter.validate_python(entry)
        assert int(delta.total_seconds()) == 1234

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


class TestTrWrapX25519PrivateKey:
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
    def test_decode_encode(self, raw, encoded):
        adapter = TypeAdapter(X25519PrivateKeyBase64)
        key = adapter.validate_python(raw)
        assert isinstance(key, X25519PrivateKey)

        serial = adapter.dump_python(key)
        assert serial == encoded

    @pytest.mark.parametrize(
        'type_',
        [
            Annotated[int, TrWrapX25519PrivateKey()],
            Annotated[None, TrWrapX25519PrivateKey()],
        ],
    )
    def test_usage_error_on_source_type(self, type_):
        with pytest.raises(TypeError, match='source type is not a x25519 private key'):
            TypeAdapter(type_)


class TestTrWrapX25519PublicKey:
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

    @pytest.mark.parametrize(
        'type_',
        [
            Annotated[int, TrWrapX25519PublicKey()],
            Annotated[None, TrWrapX25519PublicKey()],
        ],
    )
    def test_usage_error_on_source_type(self, type_):
        with pytest.raises(TypeError, match='source type is not a x25519 public key'):
            TypeAdapter(type_)
