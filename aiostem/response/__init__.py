from typing import Dict, List, Type

from aiostem.message import Message
from aiostem.question import Query
from aiostem.response.authentication import AuthChallengeReply, AuthenticateReply
from aiostem.response.base import Reply, UnknownReply
from aiostem.response.protocolinfo import ProtocolInfoReply
from aiostem.response.simple import HsFetchReply, QuitReply, SetEventsReply, SignalReply

REPLY_MAP: Dict[str, Type[Reply]] = {
    'AUTHENTICATE': AuthenticateReply,
    'AUTHCHALLENGE': AuthChallengeReply,
    'HSFETCH': HsFetchReply,
    'PROTOCOLINFO': ProtocolInfoReply,
    'QUIT': QuitReply,
    'SETEVENTS': SetEventsReply,
    'SIGNAL': SignalReply,
}


def reply_parser(query: Query, message: Message) -> Reply:
    """ Find the appropriate reply class to parse message for the provided query.
    """
    parser = REPLY_MAP.get(query.COMMAND_NAME, UnknownReply)
    return parser(query, message)
# End of function reply_parser.


__all__: List[str] = [
    'AuthChallengeReply',
    'AuthenticateReply',
    'HsFetchReply',
    'ProtocolInfoReply',
    'QuitReply',
    'REPLY_MAP',
    'Reply',
    'SetEventsReply',
    'SignalReply',
    'reply_parser',
]
