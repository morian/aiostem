# -*- coding: utf-8 -*-

from typing import Dict, Tuple, Type

from aiostem.response.base import Event, Reply
from aiostem.response.authentication import AuthChallengeReply, AuthenticateReply
from aiostem.response.protocolinfo import ProtocolInfoReply
from aiostem.response.simple import HsFetchReply, QuitReply, SetEventsReply, SignalReply


EVENT_MAP: Dict[str, Type[Event]] = {}

REPLY_MAP: Dict[str, Type[Reply]] = {
    'AUTHENTICATE': AuthenticateReply,
    'AUTHCHALLENGE': AuthChallengeReply,
    'HSFETCH': HsFetchReply,
    'PROTOCOLINFO': ProtocolInfoReply,
    'QUIT': QuitReply,
    'SETEVENTS': SetEventsReply,
    'SIGNAL': SignalReply,
}


__all__: Tuple[str, ...] = (
    "AuthenticateReply",
    "AuthChallengeReply",
    "ProtocolInfoReply",
    "QuitReply",
    "SetEventsReply",
    "SignalReply",
    "EVENT_MAP",
    "Event",
    "REPLY_MAP",
    "Reply",
)
