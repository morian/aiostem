# -*- coding: utf-8 -*-

from typing import Dict, Tuple, Type

from aiostem.response.base import Event, Reply
from aiostem.response.protocolinfo import ProtocolInfoReply


EVENT_MAP: Dict[str, Type[Event]] = {}

REPLY_MAP: Dict[str, Type[Reply]] = {
    'PROTOCOLINFO': ProtocolInfoReply,
}


__all__: Tuple[str, ...] = (
    "ProtocolInfoReply",
    "EVENT_MAP",
    "Event",
    "REPLY_MAP",
    "Reply",
)
