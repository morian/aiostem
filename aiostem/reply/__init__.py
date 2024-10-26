from ..message import Message
from ..query import Query
from .authentication import AuthChallengeReply, AuthenticateReply
from .base import Reply, UnknownReply
from .info import GetConfReply, GetInfoReply, ProtocolInfoReply
from .simple import (
    DropGuardsReply,
    HsFetchReply,
    QuitReply,
    SetConfReply,
    SetEventsReply,
    SignalReply,
)

REPLY_MAP: dict[str, type[Reply]] = {
    'AUTHENTICATE': AuthenticateReply,
    'AUTHCHALLENGE': AuthChallengeReply,
    'DROPGUARDS': DropGuardsReply,
    'GETCONF': GetConfReply,
    'GETINFO': GetInfoReply,
    'HSFETCH': HsFetchReply,
    'PROTOCOLINFO': ProtocolInfoReply,
    'QUIT': QuitReply,
    'SETCONF': SetConfReply,
    'SETEVENTS': SetEventsReply,
    'SIGNAL': SignalReply,
}


def reply_parser(query: Query, message: Message) -> Reply:
    """Find the appropriate reply class to parse message for the provided query."""
    parser = REPLY_MAP.get(query.COMMAND_NAME, UnknownReply)
    return parser(query, message)


__all__ = [
    'REPLY_MAP',
    'AuthChallengeReply',
    'AuthenticateReply',
    'DropGuardsReply',
    'GetConfReply',
    'GetInfoReply',
    'HsFetchReply',
    'ProtocolInfoReply',
    'QuitReply',
    'Reply',
    'SetConfReply',
    'SetEventsReply',
    'SignalReply',
    'reply_parser',
]
