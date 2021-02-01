# -*- coding: utf-8 -*-

from aiostem.message import Message

from aiostem.response.base import Event, UnknownEvent
from aiostem.event.hsdesc import HsDescEvent, HsDescContentEvent
from aiostem.event.network import NetworkLivenessEvent
from aiostem.event.signal import SignalEvent

from typing import Dict, Tuple, Type

EVENT_MAP: Dict[str, Type[Event]] = {
    'HS_DESC': HsDescEvent,
    'HS_DESC_CONTENT': HsDescContentEvent,
    'NETWORK_LIVENESS': NetworkLivenessEvent,
    'SIGNAL': SignalEvent,
}


def event_parser(message: Message) -> Event:
    """ Find the appropriate event class to parse this message.
    """
    parser = EVENT_MAP.get(message.event_type, UnknownEvent)
    return parser(message)
# End of function event_parser.


__all__: Tuple[str, ...] = (
    "NetworkLivenessEvent",
    "SignalEvent",

    "Event",
    "event_parser",
)
