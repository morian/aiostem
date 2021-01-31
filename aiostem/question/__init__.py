# -*- coding: utf-8 -*-

from typing import Tuple
from aiostem.question.base import Query
from aiostem.question.authentication import AuthChallengeQuery, AuthenticateQuery
from aiostem.question.events import SetEventsQuery
from aiostem.question.hsfetch import HsFetchQuery
from aiostem.question.protocolinfo import ProtocolInfoQuery
from aiostem.question.signal import SignalQuery
from aiostem.question.simple import QuitQuery


__all__: Tuple[str, ...] = (
    "AuthChallengeQuery",
    "AuthenticateQuery",
    "HsFetchQuery",
    "ProtocolInfoQuery",
    "QuitQuery",
    "SetEventsQuery",
    "SignalQuery",
    "Query",
)