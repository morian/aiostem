"""asynchronous version of the stem library's version getter."""

from __future__ import annotations

import asyncio
import os
import re
from enum import Enum
from functools import lru_cache, total_ordering
from typing import TYPE_CHECKING

from async_lru import alru_cache

from .system import call

if TYPE_CHECKING:
    from collections.abc import Callable, Hashable

VERSION_PATTERN = re.compile(r'^([0-9]+)\.([0-9]+)\.([0-9]+)(\.[0-9]+)?(-\S*)?(( \(\S*\))*)$')

UNDEFINED = '<Undefined_ >'

version = '0.4.4'

# TODO: Reduce globals and contsants for speed and being threadsafe at all costs


@alru_cache(typed=False)
async def get_system_tor_version(tor_cmd='tor') -> Version:
    """
    Queries tor for its version. This is os dependent, only working on linux,
    osx, and bsd.

    :param str tor_cmd: command used to run tor

    :returns: :class:`~aiostem.version.Version` provided by the tor command

    :raises: **IOError** if unable to query or parse the version

    In `aiostem` this is now an `alru_cache` using the `async_lru` library.
    to help remain threadsafe
    """
    version_cmd = f'{tor_cmd} --version'

    try:
        version_output = await call(version_cmd)

    except OSError as exc:
        # make the error message nicer if this is due to tor being unavialable
        if 'No such file or directory' in str(exc):
            if await asyncio.to_thread(os.path.isabs, tor_cmd):
                exc = f"Unable to check tor's version. '{tor_cmd}' doesn't exist."
            else:
                exc = f"Unable to run '{version_cmd}'. Maybe tor isn't in your PATH?"
        raise OSError(exc)

    for line in version_output:
        # output example:
        # Oct 21 07:19:27.438 [notice] Tor v0.2.1.30. This is experimental software.
        # Do not rely on it for strong anonymity. (Running on Linux i686)
        # Tor version 0.2.1.30.
        if line.startswith('Tor version ') and line.endswith('.'):
            try:
                version_str = line[12:-1]
                return Version(version_str)
            except ValueError as exc:
                raise OSError(exc)
    return Version(version_str)


HASH_TYPES = True


def _hash_value(val: Hashable):
    if not HASH_TYPES:
        my_hash = 0
    else:
        # TODO: I hate doing this but until Python 2.x support is dropped we
        # can't readily be strict about bytes vs unicode for attributes. This
        # is because test assertions often use strings, and normalizing this
        # would require wrapping most with to_unicode() calls.
        #

        my_hash = hash(val) if isinstance(val, str) else hash(str(type(val)))

    if isinstance(val, tuple | list):
        for v in val:
            my_hash = (my_hash * 1024) + hash(v)
    elif isinstance(val, dict):
        for k in sorted(val.keys()):
            my_hash = (my_hash * 2048) + (hash(k) * 1024) + hash(val[k])
    else:
        my_hash += hash(val)

    return my_hash


def _hash_attr(obj: Hashable, *attributes, **kwargs):
    """
    Provide a hash value for the given set of attributes.

    :param Object obj: object to be hashed
    :param list attributes: attribute names to take into account
    :param bool cache: persists hash in a '_cached_hash' object attribute
    :param class parent: include parent's hash value
    """
    is_cached = kwargs.get('cache', False)
    parent_class = kwargs.get('parent')
    cached_hash = getattr(obj, '_cached_hash', None)

    if is_cached and cached_hash is not None:
        return cached_hash

    my_hash = parent_class.__hash__(obj) if parent_class else 0
    my_hash = my_hash * 1024 + hash(str(type(obj)))

    for attr in attributes:
        val = getattr(obj, attr)
        my_hash = my_hash * 1024 + _hash_value(val)

    if is_cached:
        obj._cached_hash = my_hash

    return my_hash


@lru_cache
def get_version(version_str: str):
    return Version(version_str)


# An advantage over stem python is the inclusion of total_ordering
@total_ordering
class Version:
    """
    Comparable tor version. These are constructed from strings that conform to
    the 'new' style in the `tor version-spec
    <https://gitweb.torproject.org/torspec.git/tree/version-spec.txt>`_,
    such as "0.1.4" or "0.2.2.23-alpha (git-7dcd105be34a4f44)".

    .. versionchanged:: 1.6.0
       Added all_extra parameter.

    :var int major: major version
    :var int minor: minor version
    :var int micro: micro version
    :var int patch: patch level (**None** if undefined)
    :var str status: status tag such as 'alpha' or 'beta-dev' (**None** if undefined)
    :var str extra: first extra information without its parentheses such as
      'git-8be6058d8f31e578' (**None** if undefined)
    :var list all_extra: all extra information entries, without their parentheses
    :var str git_commit: git commit id (**None** if it wasn't provided)

    :param str version_str: version to be parsed

    :raises: **ValueError** if input isn't a valid tor version
    """

    __slots__ = (
        '_cached_hash',
        'all_extra',
        'extra',
        'git_commit',
        'major',
        'micro',
        'minor',
        'patch',
        'status',
        'version_str',
    )

    def __init__(self, version_str: str):
        self.version_str = version_str
        version_parts = VERSION_PATTERN.match(version_str)

        if version_parts:
            major, minor, micro, patch, status, extra_str, _ = version_parts.groups()

            # The patch and status matches are optional (may be None) and have an extra
            # proceeding period or dash if they exist. Stripping those off.

            if patch:
                patch = int(patch[1:])

            if status:
                status = status[1:]

            self.major = int(major)
            self.minor = int(minor)
            self.micro = int(micro)
            self.patch = patch
            self.status = status
            self.all_extra = (
                [entry[1:-1] for entry in extra_str.strip().split()] if extra_str else []
            )
            self.extra = self.all_extra[0] if self.all_extra else None
            self.git_commit = None

            for extra in self.all_extra:
                if extra and re.match('^git-[0-9a-f]{16}$', extra):
                    self.git_commit = extra[4:]
                    break
        else:
            raise ValueError(f"'{version_str}' isn't aproperly formatted tor version")

    def __str__(self):
        """Provides the string used to construct the version."""
        return self.version_str

    def _compare(self, other: Version, method: Callable[[str, str], bool]):
        """Compares version ordering according to the spec."""
        if not isinstance(other, Version):
            return False

        for attr in ('major', 'minor', 'micro', 'patch'):
            my_version = getattr(self, attr)
            other_version = getattr(other, attr)

            if my_version is None:
                my_version = 0

            if other_version is None:
                other_version = 0

            if my_version != other_version:
                return method(my_version, other_version)

        # According to the version spec...
        #
        #   If we *do* encounter two versions that differ only by status tag, we
        #   compare them lexically as ASCII byte strings.

        my_status = self.status if self.status else ''
        other_status = other.status if other.status else ''

        return method(my_status, other_status)

    def __hash__(self):
        return _hash_attr(self, 'major', 'minor', 'micro', 'patch', 'status', cache=True)

    def __eq__(self, other):
        return self._compare(other, lambda s, o: s == o)

    def __ne__(self, other):
        return not self == other

    def __gt__(self, other):
        """
        Checks if this version meets the requirements for a given feature. We can
        be compared to either a :class:`~aiostem.version.Version` or
        :class:`~aiostem.version._VersionRequirements`.
        """
        if isinstance(other, _VersionRequirements):
            return any(rule(self) for rule in other.rules)

        return self._compare(other, lambda s, o: s > o)

    def __ge__(self, other):
        if isinstance(other, _VersionRequirements):
            return any(rule(self) for rule in other.rules)

        return self._compare(other, lambda s, o: s >= o)


class _VersionRequirements:
    """
    Series of version constraints that can be compared to. For instance, this
    allows for comparisons like 'if I'm greater than version X in the 0.2.2
    series, or greater than version Y in the 0.2.3 series'.

    This is a logical 'or' of the series of rules.
    """

    __slots__ = 'rules'

    def __init__(self):
        self.rules: list[Callable[[Version], bool]] = []

    def greater_than(self, version: Version, inclusive=True):
        """
        Adds a constraint that we're greater than the given version.

        :param stem.version.Version version: version we're checking against
        :param bool inclusive: if comparison is inclusive or not
        """
        if inclusive:
            self.rules.append(lambda v: version <= v)
        else:
            self.rules.append(lambda v: version < v)

    def less_than(self, version: Version, inclusive=True):
        """
        Adds a constraint that we're less than the given version.

        :param stem.version.Version version: version we're checking against
        :param bool inclusive: if comparison is inclusive or not
        """
        if inclusive:
            self.rules.append(lambda v: version >= v)
        else:
            self.rules.append(lambda v: version > v)

    def in_range(
        self,
        from_version: Version,
        to_version: Version,
        from_inclusive: bool = True,
        to_inclusive: bool = False,
    ):
        """
        Adds constraint that we're within the range from one version to another.

        :param aiostem.version.Version from_version: beginning of the comparison range
        :param aiostem.version.Version to_version: end of the comparison range
        :param bool from_inclusive: if comparison is inclusive with the starting version
        :param bool to_inclusive: if comparison is inclusive with the ending version
        """
        self.rules.append(
            lambda v: (
                (from_version <= v < to_version)
                if to_inclusive
                else (from_version <= v <= to_version)
            )
            if from_inclusive
            else (from_version < v < to_version)
        )


safecookie_req = _VersionRequirements()
safecookie_req.in_range(Version('0.2.2.36'), Version('0.2.3.0'))
safecookie_req.greater_than(Version('0.2.3.13'))


class Requirement(Enum):
    """
    Versions Enums Reimplemented in aiohttp-tor and
    now uses a proper class which means it can all get typehinted correctly :).
    """

    AUTH_SAFECOOKIE = safecookie_req
    DESCRIPTOR_COMPRESSION = Version('0.3.1.1-alpha')
    DORMANT_MODE = Version('0.4.0.1-alpha')
    DROPGUARDS = Version('0.2.5.1-alpha')
    EVENT_AUTHDIR_NEWDESCS = Version('0.1.1.10-alpha')
    EVENT_BUILDTIMEOUT_SET = Version('0.2.2.7-alpha')
    EVENT_CIRC_MINOR = Version('0.2.3.11-alpha')
    EVENT_CLIENTS_SEEN = Version('0.2.1.10-alpha')
    EVENT_CONF_CHANGED = Version('0.2.3.3-alpha')
    EVENT_DESCCHANGED = Version('0.1.2.2-alpha')
    EVENT_GUARD = Version('0.1.2.5-alpha')
    EVENT_HS_DESC_CONTENT = Version('0.2.7.1-alpha')
    EVENT_NS = Version('0.1.2.3-alpha')
    EVENT_NETWORK_LIVENESS = Version('0.2.7.2-alpha')
    EVENT_NEWCONSENSUS = Version('0.2.1.13-alpha')
    EVENT_SIGNAL = Version('0.2.3.1-alpha')
    EVENT_STATUS = Version('0.1.2.3-alpha')
    EVENT_STREAM_BW = Version('0.1.2.8-beta')
    EVENT_TRANSPORT_LAUNCHED = Version('0.2.5.0-alpha')
    EVENT_CONN_BW = Version('0.2.5.2-alpha')
    EVENT_CIRC_BW = Version('0.2.5.2-alpha')
    EVENT_CELL_STATS = Version('0.2.5.2-alpha')
    EVENT_TB_EMPTY = Version('0.2.5.2-alpha')
    EVENT_HS_DESC = Version('0.2.5.2-alpha')
    EXTENDCIRCUIT_PATH_OPTIONAL = Version('0.2.2.9')
    FEATURE_EXTENDED_EVENTS = Version('0.2.2.1-alpha')
    FEATURE_VERBOSE_NAMES = Version('0.2.2.1-alpha')
    GETINFO_CONFIG_TEXT = Version('0.2.2.7-alpha')
    GETINFO_GEOIP_AVAILABLE = Version('0.3.2.1-alpha')
    GETINFO_MICRODESCRIPTORS = Version('0.3.5.1-alpha')
    GETINFO_UPTIME = Version('0.3.5.1-alpha')
    HIDDEN_SERVICE_V3 = Version('0.3.3.1-alpha')
    HSFETCH = Version('0.2.7.1-alpha')
    HSFETCH_V3 = Version('0.4.1.1-alpha')
    HSPOST = Version('0.2.7.1-alpha')
    ADD_ONION = Version('0.2.7.1-alpha')
    ADD_ONION_BASIC_AUTH = Version('0.2.9.1-alpha')
    ADD_ONION_NON_ANONYMOUS = Version('0.2.9.3-alpha')
    ADD_ONION_MAX_STREAMS = Version('0.2.7.2-alpha')
    LOADCONF = Version('0.2.1.1')
    MICRODESCRIPTOR_IS_DEFAULT = Version('0.2.3.3')
    SAVECONF_FORCE = Version('0.3.1.1-alpha')
    TAKEOWNERSHIP = Version('0.2.2.28-beta')
    TORRC_CONTROL_SOCKET = Version('0.2.0.30')
    TORRC_PORT_FORWARDING = Version('0.2.3.1-alpha')
    TORRC_DISABLE_DEBUGGER_ATTACHMENT = Version('0.2.3.9')
    TORRC_VIA_STDIN = Version('0.2.6.3-alpha')
    ONION_SERVICE_AUTH_ADD = Version('0.4.6.1-alpha')
