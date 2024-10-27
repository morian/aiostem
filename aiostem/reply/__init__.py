from __future__ import annotations

from typing import TYPE_CHECKING

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

if TYPE_CHECKING:
    from collections.abc import Mapping

    from ..message import Message
    from ..query import Query


REPLY_MAP: Mapping[str, type[Reply]] = {
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
    """
    Parse the provided message as a reply to the provided query.

    Args:
        message: received reply message for the query
        query: the original query that was sent

    Returns:
        A reply corresponding to the providing query.

    """
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
