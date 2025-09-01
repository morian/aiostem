from __future__ import annotations

from base64 import b32decode, b64decode
from datetime import datetime, timedelta, timezone
from typing import Annotated, Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from pydantic import BaseModel, BeforeValidator, TypeAdapter, ValidationError

from aiostem.structures import AuthMethod
from aiostem.utils import (
    Base32Encoder,
    Base64Encoder,
    EncodedBytes,
    TrAfterAsTimezone,
    TrBeforeSetToNone,
    TrBeforeStringSplit,
    TrBeforeTimedelta,
    TrBoolYesNo,
    TrCast,
    TrEd25519PrivateKey,
    TrEd25519PublicKey,
    TrRSAPrivateKey,
    TrRSAPublicKey,
    TrX25519PrivateKey,
    TrX25519PublicKey,
)


class TestAsTimezone:
    @pytest.mark.parametrize(
        ('raw', 'timezone', 'timestamp'),
        [
            ('2024-12-09T23:10:14+01:00', None, 1733782214),
            ('2024-12-09T23:10:14', timezone.utc, 1733785814),
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
    ADAPTER_MINS = TypeAdapter(
        Annotated[
            timedelta,
            TrBeforeTimedelta(unit='minutes', is_float=False),
        ],
    )
    ADAPTER_SECS = TypeAdapter(Annotated[timedelta, TrBeforeTimedelta(unit='seconds')])
    ADAPTER_MSECS = TypeAdapter(Annotated[timedelta, TrBeforeTimedelta(unit='milliseconds')])

    @pytest.mark.parametrize(
        'entry',
        [
            timedelta(minutes=90),
            '01:30:00',
            '90',
            90,
        ],
    )
    def test_minutes_with_multiple_types(self, entry: Any):
        delta = self.ADAPTER_MINS.validate_python(entry)
        assert int(delta.total_seconds()) == 5400

        serial = self.ADAPTER_MINS.dump_python(delta)
        assert isinstance(serial, int)
        assert int(serial) == 90

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
            TrEd25519PrivateKey(expanded=False),
            EncodedBytes(encoder=Base64Encoder),
        ],
    )
    ADAPTER_EXP = TypeAdapter(
        Annotated[
            Ed25519PrivateKey,
            TrEd25519PrivateKey(expanded=True),
            EncodedBytes(encoder=Base64Encoder),
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
            TrEd25519PublicKey(),
            EncodedBytes(encoder=Base32Encoder),
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


class TestTrRSAPrivateKey:
    KEY_TYPE = RSAPrivateKey
    ADAPTER_RAW = TypeAdapter(Annotated[RSAPrivateKey, TrRSAPrivateKey()])
    ADAPTER_ENC = TypeAdapter(
        Annotated[
            RSAPrivateKey,
            TrRSAPrivateKey(),
            EncodedBytes(encoder=Base64Encoder),
        ],
    )
    # This key was generated using ADD_ONION NEW:RSA1024 on Tor 0.4.5.9
    TEST_STRING = (
        'MIICWwIBAAKBgQCkRs9KZFlgLhts7ASor0dUb9RlpKlTNJarif+n041xhCEqGxEt'
        'U23G9SOsYS8L6cIWWw53YJkAzzHc/2qVB8Yxv9dLPT/YwDswHLgUbD6XP1TRtu0i'
        '3jLURDv9tc3tWn7esoMpezs5TPgvwLOxAfTXN332GnDiek+bwvcMxHPBSwIDAQAB'
        'AoGAOWJW1Mi7A8L3Z5QGiJo504AA9MSRNXSAUUmyWYCnvwiFwTyVQn0LMt286WFF'
        'Wub8Gm0SX5cJu2OlKmq6Y3bEv1raLw/MPWEViV8bI9AqttUCDAHGlrFhS3anq8it'
        'ZZpuillaffz+AUX4Od0HUbFaGSnOG89CbAlyq2qTYfyiqTkCQQDO4qGcsH9P/ZNi'
        'kwM+MK+MvkdaKx+dME+lYMbcU/BRfKzTH9ie5y1J6SaA+rMnvMN8uYP/C8D39zwk'
        'J2dnylM/AkEAy0anQbfZqf++6ng7YQpZW/V6uFXlPZaQeXjK4+KnMHslj9lSDUBr'
        'MoLxtP2zIonQqIO52XupBQbVIlGuMiZq9QJAILURqcz5g7LqLyZg198okc6vRyEU'
        'MWym2tVu+vxGPQvB4urg+1Y/AbVbgf6gfkLIgRpvNM4t5sXueyTDo1QITwJASG2B'
        'NMpEFO1Z4gM67QWZ90kNE9cPGhWmnpFqgS4F8iE+rfV55dzZFSNQ6fMnO5wtK43b'
        'z2DfRTo9AMBnt9i2bQJAc3vZmNbslZsiUXp20jmNWzWov+q8Yk5ZP9AZFWJeLCKt'
        'VgSw4x1yEH1Y+pI+3V4arQxaoQ00iNbK3Ticdg0DIw=='
    )
    TEST_BYTES = b64decode(TEST_STRING)
    EXPECTED = TEST_STRING.rstrip('=')

    @pytest.mark.parametrize(
        'raw',
        [
            TEST_STRING,
            TEST_BYTES,
            EXPECTED,
            TrRSAPrivateKey().from_bytes(TEST_BYTES),
        ],
    )
    def test_decode_encode(self, raw):
        key = self.ADAPTER_ENC.validate_python(raw)
        assert isinstance(key, self.KEY_TYPE)

        serial = self.ADAPTER_ENC.dump_python(key)
        assert serial == self.EXPECTED

    def test_using_raw_bytes(self):
        key = self.ADAPTER_RAW.validate_python(self.TEST_BYTES)
        assert self.ADAPTER_RAW.dump_python(key) == self.TEST_BYTES

    def test_using_ed25519_private_key(self):
        key = 'MC4CAQAwBQYDK2VwBCIEIOt6WDTJqbRry3WJ30ZNynCPwLaFQ114NaYr3spHpvVi'
        with pytest.raises(TypeError, match='Loaded key is not a valid RSA private key'):
            self.ADAPTER_ENC.validate_python(key)


class TestTrRSAPublicKey:
    KEY_TYPE = RSAPublicKey
    ADAPTER_RAW = TypeAdapter(Annotated[RSAPublicKey, TrRSAPublicKey()])
    ADAPTER_ENC = TypeAdapter(
        Annotated[
            RSAPublicKey,
            TrRSAPublicKey(),
            EncodedBytes(encoder=Base64Encoder),
        ],
    )
    TEST_STRING = (
        'MIGJAoGBAN87FeyffLsjGGgd6qxVLLoKWG1GXfyu4o6OrRi1a5Mv0bgRmwqfo1O5'
        'g/c7/6JqhNFYd0UNIzyGB2LBHgQJwYTcPTW//Gpn8Dfcysl0gjA4+MLU/xQ/24Vi'
        'bbkL05YLK0AabiedS3Pmm5bzy05xAdRFitK22BeXLYDuRBGrIVejAgMBAAE='
    )
    TEST_BYTES = b64decode(TEST_STRING)
    EXPECTED = TEST_STRING.rstrip('=')

    @pytest.mark.parametrize(
        'raw',
        [
            TEST_STRING,
            TEST_BYTES,
            EXPECTED,
            TrRSAPublicKey().from_bytes(TEST_BYTES),
        ],
    )
    def test_decode_encode(self, raw):
        key = self.ADAPTER_ENC.validate_python(raw)
        assert isinstance(key, self.KEY_TYPE)

        serial = self.ADAPTER_ENC.dump_python(key)
        assert serial == self.EXPECTED

    def test_using_raw_bytes(self):
        key = self.ADAPTER_RAW.validate_python(self.TEST_BYTES)
        assert self.ADAPTER_RAW.dump_python(key) == self.TEST_BYTES

    def test_using_ed25519_private_key(self):
        key = 'MCowBQYDK2VwAyEA5AcvvI6f7k6+VGVxr9KLRrjoHE9CZQGDSj5XnAXDUeY'
        with pytest.raises(TypeError, match='Loaded key is not a valid RSA public key'):
            self.ADAPTER_ENC.validate_python(key)


class TestTrX25519PrivateKey:
    KEY_TYPE = X25519PrivateKey
    ADAPTER_RAW = TypeAdapter(Annotated[X25519PrivateKey, TrX25519PrivateKey()])
    ADAPTER_ENC = TypeAdapter(
        Annotated[
            X25519PrivateKey,
            TrX25519PrivateKey(),
            EncodedBytes(encoder=Base64Encoder),
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
            TrX25519PublicKey(),
            EncodedBytes(encoder=Base32Encoder),
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


class TestTrBoolYesNo:
    ADAPTER = TypeAdapter(Annotated[bool, TrBoolYesNo()])

    @pytest.mark.parametrize(
        ('entry', 'bval', 'serial'),
        [
            ('YES', True, 'yes'),
            (True, True, 'yes'),
            ('NO', False, 'no'),
            (False, False, 'no'),
        ],
    )
    def test_parse_and_encode(self, entry, bval, serial):
        res = self.ADAPTER.validate_python(entry)
        assert res is bval
        ser = self.ADAPTER.dump_python(res)
        assert ser == serial


class TestTrCast:
    ADAPTER_AFTER = TypeAdapter(
        Annotated[
            int,
            BeforeValidator(lambda x: 2 * x),
            TrCast(float, mode='after'),
        ],
    )
    ADAPTER_BEFORE = TypeAdapter(
        Annotated[
            int,
            BeforeValidator(lambda x: 2 * x),
            TrCast(float, mode='before'),
        ],
    )

    def test_after(self):
        r = self.ADAPTER_AFTER.validate_python('12')
        assert isinstance(r, float)
        assert r == 1212.0

    def test_before(self):
        r = self.ADAPTER_BEFORE.validate_python('12')
        assert isinstance(r, int)
        assert r == 24
