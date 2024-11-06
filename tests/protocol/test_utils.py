from __future__ import annotations

from typing import TYPE_CHECKING, Annotated, Any, ClassVar

import pytest
from pydantic import BaseModel, TypeAdapter, ValidationError

from aiostem.exceptions import CommandError
from aiostem.protocol import (
    ArgumentKeyword,
    ArgumentString,
    AuthMethod,
    CommandWord,
    QuoteStyle,
)
from aiostem.protocol.utils import (
    Base64Bytes,
    Base64Encoder,
    CommandSerializer,
    EncodedBytes,
    HexBytes,
    StringSequence,
)

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence


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
                'format': self.SCHEMA_FORMAT,
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


@inject_test_values
class TestBase64(BaseHexEncoderTest):
    TEST_CLASS = Base64Bytes
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


class Base64TrimmedEncoder(Base64Encoder):
    trim_padding: ClassVar[bool] = True


Base64BytesTrimmed = Annotated[bytes, EncodedBytes(encoder=Base64TrimmedEncoder)]


@inject_test_values
class TestBase64Trimmed(BaseHexEncoderTest):
    TEST_CLASS = Base64BytesTrimmed
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
class TestHexBytes(BaseHexEncoderTest):
    TEST_CLASS = HexBytes
    ENCODED_VALUE = '54686573652061726520627974657321'
    SCHEMA_FORMAT = 'hex'
    VALUES: ClassVar[Mapping[str, Sequence[Any]]] = {
        'good': [
            b'These are bytes!',
            HexBytes(b'These are bytes!'),
            '54686573652061726520627974657321',
        ],
        'fail': ['546' '54T6'],
    }


class TestStringSequence:
    @pytest.mark.parametrize(
        'entry',
        [
            [1, 2, 3, 4],
            '1,2,3,4',
            b'1,2,3,4',
        ],
    )
    def test_with_simple_types(self, entry: Any):
        adapter = TypeAdapter(Annotated[list[int], StringSequence()])
        res = adapter.validate_python(entry)
        assert res == [1, 2, 3, 4]

        assert adapter.dump_python(res) == [1, 2, 3, 4]

    @pytest.mark.parametrize(
        ('entry', 'output'),
        [
            ('COOKIE', {AuthMethod.COOKIE}),
            ('NULL,SAFECOOKIE', {AuthMethod.NULL, AuthMethod.SAFECOOKIE}),
        ],
    )
    def test_with_strenum(self, entry: str, output: set[AuthMethod]):
        adapter = TypeAdapter(Annotated[set[AuthMethod], StringSequence()])
        for item in (entry, output):
            assert adapter.validate_python(item) == output

    def test_json_schema(self):
        adapter = TypeAdapter(Annotated[tuple[str, int], StringSequence()])
        schema = adapter.json_schema()
        assert schema == {
            'maxItems': 2,
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
            Annotated[int, StringSequence()],
            Annotated[bytes, StringSequence()],
        ],
    )
    def test_usage_error(self, type_):
        with pytest.raises(TypeError, match='source type is not a collection'):
            TypeAdapter(type_)
