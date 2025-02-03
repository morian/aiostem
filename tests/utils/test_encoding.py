from __future__ import annotations

from typing import TYPE_CHECKING, Annotated, Any, ClassVar

import pytest
from pydantic import BaseModel, TypeAdapter, ValidationError

from aiostem.types import Base16Bytes, Base32Bytes, Base64Bytes
from aiostem.utils import Base32Encoder, Base64Encoder, EncodedBytes

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence


class BaseEncoderTest:
    DECODED_VALUE = b'These are bytes!'
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

    def test_passthough(self):
        model = self.TEST_MODEL_OR_INT(v=123)
        assert model.model_dump_json() == '{"v":123}'

    def test_json_schema(self):
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


# Dirty decorator to make our tests dynamic.
# This looks for all 'stub_' methods in our direct parent and wraps this function
# around pytest.mark.parametrize to inject our test values.
def inject_test_values(cls):
    class TestModel(BaseModel):
        v: cls.TEST_CLASS

    class TestModelOrInt(BaseModel):
        v: cls.TEST_CLASS | int

    for name, method in BaseEncoderTest.__dict__.items():
        if name.startswith('stub_'):
            action = name.split('_')[1]
            values = [(method, value) for value in cls.VALUES.get(action, [])]

            @pytest.mark.parametrize(('method', 'value'), values)
            def wrapper(self, method, value):
                return method(self, value)

            setattr(cls, 'test_' + name[5:], wrapper)

    cls.TEST_MODEL = TestModel
    cls.TEST_MODEL_OR_INT = TestModelOrInt
    cls.ADAPTER = TypeAdapter(cls.TEST_CLASS)

    return cls


@inject_test_values
class TestBase16Bytes(BaseEncoderTest):
    TEST_CLASS = Base16Bytes
    ENCODED_VALUE = '54686573652061726520627974657321'
    SCHEMA_FORMAT = 'base16'
    VALUES: ClassVar[Mapping[str, Sequence[Any]]] = {
        'good': [
            b'These are bytes!',
            Base16Bytes(b'These are bytes!'),
            '54686573652061726520627974657321',
        ],
        'fail': ['54T6'],
    }


class Base32PaddedEncoder(Base32Encoder):
    trim_padding: ClassVar[bool] = False


Base32BytesPadded = Annotated[bytes, EncodedBytes(encoder=Base32PaddedEncoder)]


@inject_test_values
class TestBase32(BaseEncoderTest):
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
class TestBase32Padded(BaseEncoderTest):
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
class TestBase64(BaseEncoderTest):
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
class TestBase64Padded(BaseEncoderTest):
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
