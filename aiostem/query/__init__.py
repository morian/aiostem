from .authentication import AuthChallengeQuery, AuthenticateQuery
from .base import Query
from .events import SetEventsQuery
from .hsfetch import HsFetchQuery
from .info import GetConfQuery, GetInfoQuery, ProtocolInfoQuery
from .signal import SignalQuery
from .simple import QuitQuery

__all__: list[str] = [
    'AuthChallengeQuery',
    'AuthenticateQuery',
    'GetConfQuery',
    'GetInfoQuery',
    'HsFetchQuery',
    'ProtocolInfoQuery',
    'QuitQuery',
    'SetEventsQuery',
    'SignalQuery',
    'Query',
]
