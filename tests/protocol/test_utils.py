from __future__ import annotations

from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Address, IPv6Address
from typing import TYPE_CHECKING, Annotated, Any, ClassVar

import pytest
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
from pydantic import BaseModel, TypeAdapter, ValidationError

from aiostem.exceptions import CommandError
from aiostem.protocol import (
    ArgumentKeyword,
    ArgumentString,
    AuthMethod,
    CommandWord,
    LogSeverity,
    LongServerName,
    QuoteStyle,
    TcpAddressPort,
)
from aiostem.protocol.utils import (
    AsTimezone,
    Base32Bytes,
    Base32Encoder,
    Base64Bytes,
    Base64Encoder,
    CommandSerializer,
    EncodedBytes,
    HexBytes,
    HiddenServiceAddressV2,
    HiddenServiceAddressV3,
    LogSeverityTransformer,
    StringSplit,
    TimedeltaSeconds,
    TimedeltaTransformer,
    X25519PublicKeyBase32,
    X25519PublicKeyTransformer,
)

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence


class TestAsTimezone:
    @pytest.mark.parametrize(
        ('raw', 'timezone', 'timestamp'),
        [
            ('2024-12-09T23:10:14+01:00', None, 1733782214),
            ('2024-12-09T23:10:14', UTC, 1733785814),
        ],
    )
    def test_astimezone(self, raw, timezone, timestamp):
        adapter = TypeAdapter(Annotated[datetime, AsTimezone(timezone)])
        result = adapter.validate_python(raw)
        assert int(result.timestamp()) == timestamp

    @pytest.mark.parametrize(
        'type_',
        [
            Annotated[int, AsTimezone()],
            Annotated[None, AsTimezone()],
        ],
    )
    def test_usage_error_on_source_type(self, type_):
        with pytest.raises(TypeError, match='source type is not a datetime'):
            TypeAdapter(type_)


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


class BaseEncoderTest:
    DECODED_VALUE = None
    ENCODED_VALUE = ''
    TEST_CLASS = NotImplemented
    SCHEMA_FORMAT = 'format'
    VALUES: ClassVar[Mapping[str, Sequence[Any]]] = {
        'good': [],
        'fail': [],
    }

    def stub_fail_values(self, value):
        message = f'{self.SCHEMA_FORMAT.capitalize()} decoding error:'
        with pytest.raises(ValidationError, match=message):
            self.TEST_MODEL(v=value)

    def stub_good_values(self, value):
        model = self.TEST_MODEL(v=value)
        assert model.v == self.DECODED_VALUE

    def stub_good_encoding(self, value):
        model = self.TEST_MODEL(v=value)
        assert model.model_dump_json() == '{"v":"' + self.ENCODED_VALUE + '"}'

    def test_schema(self):
        schema = self.TEST_MODEL.model_json_schema()
        if self.SCHEMA_FORMAT is not None:
            assert schema['properties']['v'] == {
                'contentEncoding': self.SCHEMA_FORMAT,
                'format': 'binary',
                'title': 'V',
                'type': 'string',
            }
        else:
            assert schema['properties']['v'] == {'title': 'V', 'type': 'string'}


class BaseHexEncoderTest(BaseEncoderTest):
    DECODED_VALUE = b'These are bytes!'


# Dirty decorator to make our tests dynamic.
# This looks for all 'stub_' methods in our direct parent and wraps this function
# around pytest.mark.parametrize to inject our test values.
def inject_test_values(cls):
    class TestModel(BaseModel):
        v: cls.TEST_CLASS

    for name, method in BaseEncoderTest.__dict__.items():
        if name.startswith('stub_'):
            action = name.split('_')[1]
            values = [(method, value) for value in cls.VALUES.get(action, [])]

            @pytest.mark.parametrize(('method', 'value'), values)
            def wrapper(self, method, value):
                return method(self, value)

            setattr(cls, 'test_' + name[5:], wrapper)

    cls.TEST_MODEL = TestModel

    return cls


class Base32PaddedEncoder(Base32Encoder):
    trim_padding: ClassVar[bool] = False


Base32BytesPadded = Annotated[bytes, EncodedBytes(encoder=Base32PaddedEncoder)]


@inject_test_values
class TestBase32(BaseHexEncoderTest):
    TEST_CLASS = Base32Bytes
    ENCODED_VALUE = 'KRUGK43FEBQXEZJAMJ4XIZLTEE'
    SCHEMA_FORMAT = 'base32'
    VALUES: ClassVar[Mapping[str, Sequence[Any]]] = {
        'fail': [
            'KRUGK43FEBQXEZJAMJ4XIZLTE9',  # Invalid character
        ],
        'good': [
            b'These are bytes!',
            Base32Bytes(b'These are bytes!'),
            'KRUGK43FEBQXEZJAMJ4XIZLTEE',
            'krugk43febqxezjamj4xizltee',
        ],
    }


@inject_test_values
class TestBase32Padded(BaseHexEncoderTest):
    TEST_CLASS = Base32BytesPadded
    ENCODED_VALUE = 'KRUGK43FEBQXEZJAMJ4XIZLTEE======'
    SCHEMA_FORMAT = 'base32'
    VALUES: ClassVar[Mapping[str, Sequence[Any]]] = {
        'fail': [
            'KRUGK43FEBQXEZJAMJ4XIZLTE9',  # Invalid character
            'KRUGK43FEBQXEZJAMJ4XIZLTEE',  # Bad padding
        ],
        'good': [
            b'These are bytes!',
            Base32Bytes(b'These are bytes!'),
            'KRUGK43FEBQXEZJAMJ4XIZLTEE======',
            'krugk43febqxezjamj4xizltee======',
        ],
    }


class Base64PaddedEncoder(Base64Encoder):
    trim_padding: ClassVar[bool] = False


Base64BytesPadded = Annotated[bytes, EncodedBytes(encoder=Base64PaddedEncoder)]


@inject_test_values
class TestBase64(BaseHexEncoderTest):
    TEST_CLASS = Base64Bytes
    ENCODED_VALUE = 'VGhlc2UgYXJlIGJ5dGVzIQ'
    SCHEMA_FORMAT = 'base64'
    VALUES: ClassVar[Mapping[str, Sequence[Any]]] = {
        'good': [
            b'These are bytes!',
            Base64Bytes(b'These are bytes!'),
            'VGhlc2UgYXJlIGJ5dGVzIQ==',
            'VGhlc2UgYXJlIGJ5dGVzIQ',
        ],
        'fail': [
            '=Ghlc2UgYXJlIGJ5dGVzIQ',
        ],
    }


@inject_test_values
class TestBase64Padded(BaseHexEncoderTest):
    TEST_CLASS = Base64BytesPadded
    ENCODED_VALUE = 'VGhlc2UgYXJlIGJ5dGVzIQ=='
    SCHEMA_FORMAT = 'base64'
    VALUES: ClassVar[Mapping[str, Sequence[Any]]] = {
        'good': [
            b'These are bytes!',
            Base64Bytes(b'These are bytes!'),
            'VGhlc2UgYXJlIGJ5dGVzIQ==',
        ],
        'fail': [
            'VGhlc2UgYXJlIGJ5dGVzIQ',
            '=Ghlc2UgYXJlIGJ5dGVzIQ',
        ],
    }


@inject_test_values
class TestHexBytes(BaseHexEncoderTest):
    TEST_CLASS = HexBytes
    ENCODED_VALUE = '54686573652061726520627974657321'
    SCHEMA_FORMAT = 'base16'
    VALUES: ClassVar[Mapping[str, Sequence[Any]]] = {
        'good': [
            b'These are bytes!',
            HexBytes(b'These are bytes!'),
            '54686573652061726520627974657321',
        ],
        'fail': ['54T6'],
    }


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
        adapter = TypeAdapter(Annotated[list[int], StringSplit()])
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
        adapter = TypeAdapter(Annotated[set[AuthMethod], StringSplit()])
        for item in (entry, output):
            assert adapter.validate_python(item) == output

    def test_with_max_split(self):
        value = 'A,B,C,D'
        adapter = TypeAdapter(Annotated[list[str], StringSplit(maxsplit=1)])
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
                StringSplit(dict_keys=('host', 'port'), maxsplit=1, separator=':'),
            ]
        )
        result = adapter.validate_python(value)
        assert isinstance(result, HostPort)
        assert result.host == 'localhost'
        assert result.port == 443

    def test_json_schema(self):
        adapter = TypeAdapter(Annotated[tuple[str, int], StringSplit()])
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
            Annotated[int, StringSplit()],
            Annotated[None, StringSplit()],
        ],
    )
    def test_usage_error_as_sequence(self, type_):
        with pytest.raises(TypeError, match='source type is not a collection'):
            TypeAdapter(type_)


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
        adapter = TypeAdapter(LongServerName)
        server = LongServerName(fingerprint=fp, nickname=nickname)
        serial = adapter.dump_python(server)
        assert serial == string


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
        adapter = TypeAdapter(Annotated[LogSeverity, LogSeverityTransformer()])
        value = adapter.validate_python(entry)
        assert value == LogSeverity.ERROR


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


class TestTimedeltaSeconds:
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
            Annotated[int, TimedeltaTransformer()],
            Annotated[bytes, TimedeltaTransformer()],
        ],
    )
    def test_with_error(self, type_):
        with pytest.raises(TypeError, match='source type is not a timedelta'):
            TypeAdapter(type_)


class TestX25519PublicKeyTransformer:
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
            Annotated[int, X25519PublicKeyTransformer()],
            Annotated[None, X25519PublicKeyTransformer()],
        ],
    )
    def test_usage_error_on_source_type(self, type_):
        with pytest.raises(TypeError, match='source type is not a x25519 public key'):
            TypeAdapter(type_)
