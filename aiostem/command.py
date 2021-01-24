# -*- coding: utf-8 -*-

import re

from typing import List


class BaseArgument:
    """ Base class for any kind of command argument.
    """

    @staticmethod
    def quote(value) -> str:
        """ Quote `value` so it can be used by Tor's controller.
        """
        return re.sub(r'([\\"])', r'\\\1', value)

    def __str__(self) -> str:
        raise NotImplementedError('__str__() must be implemented by BaseArgument subclass')
# End of class BaseArgument.


class Argument(BaseArgument):
    """ Represents a single non-quoted argument.
    """

    def __init__(self, value: str) -> None:
        self._value = value

    @property
    def value(self) -> str:
        """ Value of this argument.
        """
        return self._value

    def __str__(self) -> str:
        """ This is how this argument appears on the wire.
        """
        return self.value
# End of class Argument.


class QuotedArgument(Argument):
    """ Same as Argument but enclosed in double quotes.
    """

    def __str__(self) -> str:
        """ This is how this argument appears on the wire.
        """
        return '"{}"'.format(self.quote(self.value))
# End of class QuotedArgument.


class KeyArgument(BaseArgument):
    """ Represents a key/value argument.
    """

    def __init__(self, key: str, value: str) -> None:
        self._key = key
        self._value = value

    @property
    def key(self) -> str:
        """ Name of the `key` provided in constructor.
        """
        return self._key

    @property
    def value(self) -> str:
        """ Value provided in the constructor.
        """
        return self._value

    def __str__(self) -> str:
        """ This is how this argument appears on the wire.
        """
        return '{0}={1}'.format(self.key, self.value)
# End of class KeyArgument.


class QuotedKeyArgument(KeyArgument):
    """ Same as KeyArgument but value is enclosed in double quotes.
    """

    def __str__(self) -> str:
        """ This is how this argument appears on the wire.
        """
        return '{0}={1}'.format(self.key, self.quote(self.value))
# End of class QuotedKeyArgument.


class Command:
    """ Generic command that can be sent through a Controller.
    """

    def __init__(self, name: str) -> None:
        self._name = name
        self._args = []  # type: List[BaseArgument]
        self._data = []  # type: List[str]

    def __str__(self) -> str:
        """ Build the full command to send to the controller.
        """
        has_data = bool(len(self._data))
        prefix = '+' if has_data else ''

        items = [prefix + self.name]
        items.extend(map(str, self._args))

        lines = [' '.join(items)]
        if has_data:
            for line in self._data:
                if line.startswith('.'):
                    line = '.' + line
                lines.append(line)
            lines.append('.')
        lines.append('')
        return '\r\n'.join(lines)

    @property
    def arguments(self) -> List[BaseArgument]:
        """ List of arguments in this command.
        """
        return self._args

    @property
    def data(self) -> str:
        """ Full text content of data sent along with this command.
        """
        return '\n'.join(self._data)

    @property
    def name(self) -> str:
        """ Name of the performed command.
        """
        return self._name

    def add_data(self, text: str) -> None:
        """ Append the provided text payload in this command.
        """
        # Split and clean the lines in this text.
        lines = map(lambda l: l.rstrip('\r'), text.split('\n'))
        self._data.extend(lines)

    def add_argument(self, value: str, quoted: bool = False) -> None:
        """ Add a single argument (potentially quoted).
        """
        cls = QuotedArgument if quoted else Argument
        self.add_raw_argument(cls(value))

    def add_key_argument(self, key: str, value: str, quoted: bool = False) -> None:
        """ Add a single key/value argument (potentially quoted).
        """
        cls = QuotedKeyArgument if quoted else KeyArgument
        self.add_raw_argument(cls(key, value))

    def add_raw_argument(self, arg: BaseArgument) -> None:
        """ Add any kind of argument to the list of arguments.
        """
        self._args.append(arg)
# End of class Command.
