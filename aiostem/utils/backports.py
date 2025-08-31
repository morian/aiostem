# Backports for version 3.10
from __future__ import annotations

import sys

if sys.version_info < (3, 11):
    from datetime import timezone
    from enum import Enum

    from typing_extensions import Self

    UTC = timezone.utc

    class StrEnum(str, Enum):
        # XXX: To Ensure Serlization works correctly so some adjustments had to be made.
        def __str__(self) -> str:
            return self._value_

else:
    from datetime import UTC
    from enum import StrEnum
    from typing import Self

__all__ = (
    'UTC',
    'Self',
    'StrEnum',
)
