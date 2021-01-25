# -*- coding: utf-8 -*-

from aiostem.response.base import Reply
from aiostem.message import Message


class ProtocolInfoReply(Reply):
    """ Parse a protocol info reply.
    """

    def _message_parse(self, message: Message) -> None:
        super()._message_parse(message)

        # TODO: parse the whole protocol message here!
        #       we may need to perform a status code check (?)
        print(message.midlines)
        print(message.endline)
# End of class ProtocolInfoReply.
