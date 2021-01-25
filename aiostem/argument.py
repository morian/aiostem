# -*- coding: utf-8 -*-

import re


def add_quotes(value) -> str:
    """ Quote `value` so it can be used by Tor's controller.
    """
    return re.sub(r'([\\"])', r'\\\1', value)
# End of function add_quotes.


class BaseArgument:
    """ Base class for any kind of command argument.
    """

    def __str__(self) -> str:
        raise NotImplementedError('__str__() must be implemented by BaseArgument subclass')
# End of class BaseArgument.


class SingleArgument(BaseArgument):
    """ Represents a single non-quoted argument.
    """

    def __init__(self, value: str, quoted: bool = False) -> None:
        self._value = value
        self._quoted = quoted

    @property
    def value(self) -> str:
        """ Value of this argument.
        """
        return self._value

    @property
    def quoted(self) -> bool:
        """ Whether this argument is quoted.
        """
        return self._quoted

    def __str__(self) -> str:
        """ This is how this argument appears on the wire.
        """
        if self.quoted:
            return '"{}"'.format(add_quotes(self.value))
        return self.value
# End of class SingleArgument.


class KeywordArgument(BaseArgument):
    """ Represents a keyword argument.
    """

    def __init__(self, keyword: str, value: str, quoted: bool = False) -> None:
        self._keyword = keyword
        self._value = value
        self._quoted = quoted

    @property
    def keyword(self) -> str:
        """ Name of the `keyword` provided in constructor.
        """
        return self._keyword

    @property
    def value(self) -> str:
        """ Value provided in the constructor.
        """
        return self._value

    @property
    def quoted(self) -> bool:
        """ Whether this argument is quoted.
        """
        return self._quoted

    def __str__(self) -> str:
        """ This is how this argument appears on the wire.
        """
        if self.quoted:
            return '{0}={1}'.format(self.keyword, add_quotes(self.value))
        return '{0}={1}'.format(self.keyword, self.value)
# End of class KeywordArgument.
