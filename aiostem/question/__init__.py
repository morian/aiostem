from typing import List

from .authentication import AuthChallengeQuery, AuthenticateQuery
from .base import Query
from .events import SetEventsQuery
from .hsfetch import HsFetchQuery
from .info import GetInfoQuery, ProtocolInfoQuery
from .signal import SignalQuery
from .simple import QuitQuery

__all__: List[str] = [
    'AuthChallengeQuery',
    'AuthenticateQuery',
    'GetInfoQuery',
    'HsFetchQuery',
    'ProtocolInfoQuery',
    'QuitQuery',
    'SetEventsQuery',
    'SignalQuery',
    'Query',
]
