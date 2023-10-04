import base64
import hashlib
import re

HS_ADDRESS_SUFFIX = '.onion'
HS_V2_ADDRESS_LENGTH = 16
HS_V2_ADDRESS_PATTERN = re.compile('^[a-z2-7]{' + str(HS_V2_ADDRESS_LENGTH) + '}$')

HS_V3_ADDRESS_CHECKSUM = b'.onion checksum'
HS_V3_ADDRESS_LENGTH = 56
HS_V3_ADDRESS_PATTERN = re.compile('^[a-z2-7]{' + str(HS_V3_ADDRESS_LENGTH) + '}$')


def is_valid_hs_v2_address(address: str) -> bool:
    """Tell whether this address is a valid hidden service v2."""
    match = HS_V2_ADDRESS_PATTERN.match(address)
    return bool(match)


def is_valid_hs_v3_address(address: str) -> bool:
    """Tell whether this address is a valid hidden service v3.

    Here we go beyond the simple match and also check for the integrated checksum.
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
    """Remove the Top-Level domain part of a hidden service."""
    if address.endswith(HS_ADDRESS_SUFFIX):
        address = address[: -len(HS_ADDRESS_SUFFIX)]
    return address


def hs_address_version(address: str, allow_suffix: bool = False) -> int:
    """Get the hidden service version based on its name.

    This returns 2 or 3, or raises a ValueError.
    """
    if allow_suffix:
        address = hs_address_strip_tld(address)
    address_len = len(address)
    version = None

    if address_len == HS_V3_ADDRESS_LENGTH:
        if is_valid_hs_v3_address(address):
            version = 3
    elif address_len == HS_V2_ADDRESS_LENGTH and is_valid_hs_v2_address(address):
        version = 2

    if version is None:
        raise ValueError(f"Invalid hidden service address '{address}'")
    return version


def is_valid_hs_address(address: str, allow_suffix: bool = False) -> bool:
    """Tell whether this hidden service address is valid."""
    try:
        hs_address_version(address, allow_suffix)
    except ValueError:
        return False
    return True
