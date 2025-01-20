from __future__ import annotations

import logging
from collections import OrderedDict
from collections.abc import (
    Iterable,
    Mapping,
    Sequence,
    Set as AbstractSet,
)
from dataclasses import dataclass, field
from enum import IntFlag
from typing import TYPE_CHECKING

from ..exceptions import ReplySyntaxError
from .message import MessageData, MessageLine

if TYPE_CHECKING:
    from .message import BaseMessage

logger = logging.getLogger(__package__)


def _string_indexof(string: str, separators: str) -> int:
    """
    Find the index of any of the provided separator.

    Args:
        string: A string to look into.
        separators: A list of possible separators.

    Returns:
        The index of the found separator.

    """
    idx = len(string)
    for i, c in enumerate(string):
        if c in separators:
            idx = i
            break
    return idx


def _string_unescape(string: str) -> tuple[str, str]:
    """
    Unescape the provided quoted string.

    Args:
        string: The string to unescape, starting with `"`.

    Raises:
        ReplySyntaxError: ``EOF`` was reached before the closing quote.

    Returns:
        A tuple with the parsed value and the remaining string.

    """
    escaping = False
    result = ''
    index = None  # type: int | None

    for i in range(1, len(string)):
        c = string[i]
        if escaping:
            result += c
            escaping = False
        elif c == '\\':
            escaping = True
        elif c == '"':
            index = i
            break
        else:
            result += c

    if index is None:
        msg = 'No double-quote found before the end of string.'
        raise ReplySyntaxError(msg)

    return result, string[index + 1 :]


class ReplySyntaxFlag(IntFlag):
    """All accepted flags for a reply syntax item."""

    #: Capture everything remaining in the last positional argument.
    POS_REMAIN = 1
    #: Enable the parsing of keyword arguments.
    KW_ENABLE = 16
    #: Whether the keyword value can be enclosed with quotes.
    KW_QUOTED = 32
    #: Whether we preserve unknown keyword arguments.
    KW_EXTRA = 64
    #: Keyword arguments can omit their key.
    KW_OMIT_KEYS = 128
    #: Keyword arguments can omit their value.
    KW_OMIT_VALS = 256
    #: Use data from :class:`.MessageData` as a potential KW value.
    KW_USE_DATA = 512
    #: No quoting or escape is performed (whole line is a value).
    KW_RAW = 1024


@dataclass(kw_only=True, slots=True)
class ReplySyntax:
    """
    Describe the syntax of a single reply item.

    Important:
        - :attr:`args_max` is set to ``max(args_max, len(args_map))``.
        - :attr:`args_min` cannot be greater than :attr:`args_max`.
        - :attr:`kwargs_map` must be empty when :data:`~ReplySyntaxFlag.KW_ENABLE` is not set.
        - :attr:`args_min` must be equal to :attr:`args_max` when
          :data:`~ReplySyntaxFlag.KW_ENABLE` is set.
        - :data:`~ReplySyntaxFlag.POS_REMAIN` is mutually exclusive with
          :data:`~ReplySyntaxFlag.KW_ENABLE`.
        - :data:`~ReplySyntaxFlag.KW_QUOTED` is mutually exclusive with
          :data:`~ReplySyntaxFlag.KW_RAW`.

    """

    #: Minimum number of required positional arguments.
    args_min: int = 0
    #: Maximum number of positional arguments.
    args_max: int = 0
    #: List of names for the positional arguments (:obj:`None` to ignore it).
    args_map: Sequence[str | None] = field(default_factory=list)
    #: Correspondance map for keyword arguments.
    kwargs_map: Mapping[str | None, str] = field(default_factory=dict)
    #: These KW mapping keys can hold multiple values.
    kwargs_multi: AbstractSet[str] = field(default_factory=frozenset)
    #: List of parsing flags.
    flags: ReplySyntaxFlag = field(default_factory=lambda: ReplySyntaxFlag(0))

    def __post_init__(self) -> None:
        """Check syntax incompatibilities."""
        args_max = max(self.args_max, len(self.args_map))
        if self.args_min > args_max:
            msg = 'Minimum argument count is greater than the maximum.'
            raise RuntimeError(msg)

        if len(self.kwargs_map) and not (self.flags & ReplySyntaxFlag.KW_ENABLE):
            msg = 'Keywords are disabled but we found items in its map.'
            raise RuntimeError(msg)

        if self.args_min < args_max and (self.flags & ReplySyntaxFlag.KW_ENABLE):
            msg = 'Cannot have optional argument along with keyword arguments.'
            raise RuntimeError(msg)

        # Cannot capture positional remains and enable KW flags
        remain_vs_kw = ReplySyntaxFlag.POS_REMAIN | ReplySyntaxFlag.KW_ENABLE
        if self.flags & remain_vs_kw == remain_vs_kw:
            msg = 'Positional remain and keywords are mutually exclusive.'
            raise RuntimeError(msg)

        # Cannot both omit keys and values.
        omit_keys_vals = ReplySyntaxFlag.KW_OMIT_KEYS | ReplySyntaxFlag.KW_OMIT_VALS
        if self.flags & omit_keys_vals == omit_keys_vals:
            msg = 'KW_OMIT_KEYS and KW_OMIT_VALS are mutually exclusive.'
            raise RuntimeError(msg)

        # Cannot both handle quotes and raw values.
        raw_vs_quoted = ReplySyntaxFlag.KW_RAW | ReplySyntaxFlag.KW_QUOTED
        if self.flags & raw_vs_quoted == raw_vs_quoted:
            msg = 'KW_RAW and KW_QUOTED are mutually exclusive.'
            raise RuntimeError(msg)

        self.args_max = args_max

    def _iter_keywords(
        self,
        string: str,
        data: str | None = None,
    ) -> Iterable[tuple[str | None, str | None]]:
        """
        Iterate the string to extract key and value pairs.

        Note:
            Returned key and value cannot be both set to :obj:`None`.

        Args:
            string: The input string to parse from.
            data: Optional data blob (to used with `KW_USE_DATA`).

        Raises:
            ReplySyntaxError: when the key/value syntax is invalid.

        Yields:
            Pairs of key and values.

        """
        while len(string):
            key = None  # type: str | None
            val = None  # type: str | None
            omit_vals = False

            # Remove any leading space of any kind.
            string = string.lstrip(' \t\r\v\n')

            if len(string) and string[0] != '"':
                idx = _string_indexof(string, ' \t\r\v\n=')
                if idx < len(string) and string[idx] == '=':
                    key = string[:idx]
                    string = string[idx + 1 :]
                elif self.flags & ReplySyntaxFlag.KW_OMIT_VALS:
                    key = string[:idx]
                    string = string[idx:]
                    omit_vals = True

            if key is None and not (self.flags & ReplySyntaxFlag.KW_OMIT_KEYS):
                msg = 'Got a single string without either OMIT_KEYS or OMIT_VALS.'
                raise ReplySyntaxError(msg)

            if not omit_vals:
                if len(string):
                    if self.flags & ReplySyntaxFlag.KW_RAW:
                        val = string
                        string = ''
                    elif string[0] == '"':
                        if not (self.flags & ReplySyntaxFlag.KW_QUOTED):
                            msg = 'Got an unexpected quoted value.'
                            raise ReplySyntaxError(msg)

                        val, string = _string_unescape(string)
                    else:
                        idx = _string_indexof(string, ' \t\r\v\n')
                        val = string[:idx]
                        string = string[idx:]
                elif data is not None and self.flags & ReplySyntaxFlag.KW_USE_DATA:
                    val = data
                else:
                    val = ''

            yield (key, val)

    def parse(
        self,
        message: BaseMessage,
    ) -> Mapping[str, Sequence[str | None] | str | None]:
        """
        Parse the provided message.

        Args:
            message: A message or sub-message to parse with this syntax.

        Returns:
            A map of parsed values.

        """
        # Capture remain as a part of the argument list if told to do so.
        do_remain = bool(self.flags & ReplySyntaxFlag.POS_REMAIN)
        items = message.header.split(' ', maxsplit=self.args_max - int(do_remain))
        if len(items) < self.args_min:
            msg = 'Received too few arguments on the reply.'
            raise ReplySyntaxError(msg)

        result = OrderedDict()  # type: OrderedDict[str, list[str | None] | str | None]
        for i in range(min(len(items), len(self.args_map))):
            key = self.args_map[i]
            if key is not None:
                result[key] = items[i]

        if len(items) > self.args_max:
            remain = items[self.args_max]
            if not (self.flags & ReplySyntaxFlag.KW_ENABLE):
                msg = f"Unexpectedly found remaining data: '{remain}'"
                raise ReplySyntaxError(msg)

            data = message.data if isinstance(message, MessageData) else None
            for original_key, val in self._iter_keywords(remain, data):
                do_include = True
                has_key = original_key in self.kwargs_map
                if has_key:
                    key = self.kwargs_map[original_key]
                elif self.flags & ReplySyntaxFlag.KW_EXTRA:
                    key = original_key
                else:
                    do_include = False

                if do_include and key is not None:
                    if key in self.kwargs_multi:
                        existing = result.setdefault(key, [])
                        if isinstance(existing, list):  # pragma: no branch
                            existing.append(val)
                    else:
                        result[key] = val
                else:
                    logger.info(f'Found an unhandled keyword: {original_key}={val}')

        return result

    def parse_string(
        self,
        string: str,
    ) -> Mapping[str, Sequence[str | None] | str | None]:
        """
        Parse the provided string.

        Args:
            string: A plain header to parse as if it was a message header.

        Returns:
            A map of parsed values.

        """
        return self.parse(MessageLine(status=250, header=string))
