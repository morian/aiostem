from __future__ import annotations

import base64
import hashlib
import re
import types

HS_ADDRESS_SUFFIX = '.onion'
HS_ADDRESS_LENGTH = types.SimpleNamespace()
HS_ADDRESS_LENGTH.V2 = 16
HS_ADDRESS_LENGTH.V3 = 56

HS_V2_ADDRESS_PATTERN = re.compile('^[a-z2-7]{' + str(HS_ADDRESS_LENGTH.V2) + '}$')

HS_V3_ADDRESS_CHECKSUM = b'.onion checksum'
HS_V3_ADDRESS_PATTERN = re.compile('^[a-z2-7]{' + str(HS_ADDRESS_LENGTH.V3) + '}$')


def is_valid_hs_v2_address(address: str) -> bool:
    """
    Tell whether the provided hidden service address v2 is valid.

    Args:
        address: the onion service domain address to check

    Returns:
        Whether the provided onion address v2 is valid.

    """
    match = HS_V2_ADDRESS_PATTERN.match(address)
    return bool(match)


def is_valid_hs_v3_address(address: str) -> bool:
    """
    Tell whether the provided hidden service address v3 is valid.

    This function goes beyond the simple length match as it also performs
    checksum checks against the integrated checksum.

    Args:
        address: the onion service domain address to check

    Returns:
        Whether the provided onion address v3 is valid.

    """
    if HS_V3_ADDRESS_PATTERN.match(address):
        data = base64.b32decode(address.upper())
        pkey = data[00:32]
        csum = data[32:34]
        vers = data[34]
        if vers == 3:
            blob = HS_V3_ADDRESS_CHECKSUM + pkey + b'\x03'
            digest = hashlib.sha3_256(blob).digest()
            return digest.startswith(csum)
    return False


def hs_address_strip_tld(address: str) -> str:
    """
    Strip the Top-Level domain suffix from a hidden service address.

    This function has no effect if the address does not end with `.onion`.

    Args:
        address: a hidden service domain address to strip

    Returns:
        The provided address stripped from its `.onion` TLD suffix.

    """
    if address.endswith(HS_ADDRESS_SUFFIX):
        address = address[: -len(HS_ADDRESS_SUFFIX)]
    return address


def hs_address_version(address: str, allow_suffix: bool = False) -> int:
    """
    Get the hidden service version of the provided address.

    Args:
        address: the onion service domain address to check
        allow_suffix: whether it can end with the `.onion` suffix

    Raises:
        ValueError: when the provided address is invalid

    Returns:
        The hidden service version of the provided address.

    """
    if allow_suffix:
        address = hs_address_strip_tld(address)

    version = None  # type: int | None

    # See https://stackoverflow.com/a/67181772
    match len(address):
        case HS_ADDRESS_LENGTH.V2:
            if is_valid_hs_v2_address(address):
                version = 2
        case HS_ADDRESS_LENGTH.V3:
            if is_valid_hs_v3_address(address):
                version = 3

    if version is None:
        msg = f"Invalid hidden service address '{address}'"
        raise ValueError(msg)
    return version


def is_valid_hs_address(address: str, allow_suffix: bool = False) -> bool:
    """
    Tell whether the provided hidden service address is valid.

    Args:
        address: the onion service domain address to check
        allow_suffix: whether it can end with the `.onion` suffix

    Returns:
        Whether the provided onion address is valid.

    """
    try:
        hs_address_version(address, allow_suffix)
    except ValueError:
        return False
    return True
