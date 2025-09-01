from __future__ import annotations

import sys
from typing import TYPE_CHECKING

if sys.version_info >= (3, 11, 0) and not TYPE_CHECKING:
    from enum import StrEnum
    from typing import Self
else:
    from enum import Enum

    from typing_extensions import Self

    class StrEnum(str, Enum):
        """Backport for StrEnum from Python 3.11."""

        __str__ = str.__str__


__all__ = [
    'Self',
    'StrEnum',
]
