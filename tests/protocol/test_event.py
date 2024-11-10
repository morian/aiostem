from __future__ import annotations

import logging
from datetime import timedelta

import pytest
from pydantic import ValidationError

from aiostem.exceptions import MessageError, ReplySyntaxError
from aiostem.protocol import (
    EventDisconnect,
    EventHsDesc,
    EventHsDescContent,
    EventSignal,
    EventUnknown,
    EventWord,
    EventWordInternal,
    HsDescAction,
    HsDescFailReason,
    LogSeverity,
    Signal,
    StatusActionGeneral,
    event_from_message,
)

from .test_reply import create_message

# All test coroutines will be treated as marked for asyncio.
pytestmark = pytest.mark.asyncio


class TestEvents:
    """Check that events are properly parsed."""

    async def test_error_message_not_event(self):
        message = await create_message(['250 OK'])
        with pytest.raises(MessageError, match='The provided message is not an event!'):
            event_from_message(message)

    async def test_disconnect(self):
        line = '650 DISCONNECT'
        message = await create_message([line])
        event = event_from_message(message)
        assert isinstance(event, EventDisconnect)
        assert event.TYPE == EventWordInternal.DISCONNECT

    async def test_unknown(self):
        line = '650 UNKNOWN "This is a weird message"'
        message = await create_message([line])
        event = event_from_message(message)
        assert isinstance(event, EventUnknown)
        assert event.message == message
        assert event.TYPE is None

    async def test_hs_desc_minimal(self):
        line = (
            '650 HS_DESC REQUESTED facebookcorewwwi NO_AUTH '
            '$F5B58FEE44573C3BFD7D176D918BA5B4057519D7~bistrv1 '
            '6wn4xyr3l2m6g5z3dcnvygul2tozaxli'
        )
        message = await create_message([line])
        event = event_from_message(message)
        assert isinstance(event, EventHsDesc)
        assert event.reason is None

    async def test_hs_desc_advanced(self):
        line = (
            '650 HS_DESC FAILED oftestt7ffa4tt7et5wab7xhnzeooavy2xdmn6dtfa4pot7dk4xhviid '
            'NO_AUTH $14AE2154A26F1D42C3C3BEDC10D05FDD9F8545BB~freeasf '
            'NHN9fUdcd/9nJF6PSF6/IzdqkCiEoCsexfMv+7SGpCQ REASON=NOT_FOUND'
        )
        message = await create_message([line])
        event = event_from_message(message)
        assert isinstance(event, EventHsDesc)
        assert event.action == HsDescAction.FAILED
        assert event.reason == HsDescFailReason.NOT_FOUND

    async def test_hs_desc_content(self):
        lines = [
            '650+HS_DESC_CONTENT facebookcorewwwi 6wn4xyr3l2m6g5z3dcnvygul2tozaxli '
            '$F5B58FEE44573C3BFD7D176D918BA5B4057519D7~bistrv1',
            'STUFFF',
            '.',
            '650 OK',
        ]
        message = await create_message(lines)
        event = event_from_message(message)
        assert isinstance(event, EventHsDescContent)
        assert event.address == 'facebookcorewwwi'
        assert event.descriptor_text == 'STUFFF'

    async def test_hs_desc_content_invalid_syntax(self):
        lines = [
            '650 HS_DESC_CONTENT facebookcorewwwi 6wn4xyr3l2m6g5z3dcnvygul2tozaxli '
            '$F5B58FEE44573C3BFD7D176D918BA5B4057519D7~bistrv1',
        ]
        message = await create_message(lines)
        with pytest.raises(ReplySyntaxError, match="Event 'HS_DESC_CONTENT' has no data"):
            event_from_message(message)

    async def test_log_message_line(self):
        line = '650 DEBUG conn_write_callback(): socket 14 wants to write.'
        message = await create_message([line])
        event = event_from_message(message)
        assert event.message == 'conn_write_callback(): socket 14 wants to write.'
        assert event.severity == LogSeverity.DEBUG

    async def test_log_message_as_data(self):
        lines = [
            '650+WARN',
            'THIS IS A WARNING',
            '> BE WARNED!',
            '.',
            '650 OK',
        ]
        message = await create_message(lines)
        event = event_from_message(message)
        assert event.message == 'THIS IS A WARNING\n> BE WARNED!'
        assert event.severity == LogSeverity.WARN

    async def test_network_liveness(self):
        line = '650 NETWORK_LIVENESS UP'
        message = await create_message([line])
        event = event_from_message(message)
        assert event.status == 'UP'
        assert bool(event.status) is True

    async def test_status_general_clock_jumped(self):
        line = '650 STATUS_GENERAL NOTICE CLOCK_JUMPED TIME=120'
        message = await create_message([line])
        event = event_from_message(message)
        assert event.action == StatusActionGeneral.CLOCK_JUMPED
        assert isinstance(event.arguments.time, timedelta)
        assert int(event.arguments.time.total_seconds()) == 120

    async def test_status_general_dir_all_unreachable(self):
        line = '650 STATUS_GENERAL NOTICE DIR_ALL_UNREACHABLE'
        message = await create_message([line])
        event = event_from_message(message)
        assert event.action == StatusActionGeneral.DIR_ALL_UNREACHABLE
        assert event.arguments is None

    async def test_status_general_unknown_action(self, caplog):
        line = '650 STATUS_GENERAL NOTICE UNKNOWN_ACTION ARG=VAL'
        message = await create_message([line])
        with (
            caplog.at_level(logging.INFO, logger='aiostem.protocol'),
            pytest.raises(ValidationError, match='1 validation error for EventStatusGeneral'),
        ):
            event_from_message(message)
        assert "No syntax handler for action 'UNKNOWN_ACTION'" in caplog.text

    async def test_status_client_bootstrap(self):
        line = '650 STATUS_CLIENT NOTICE BOOTSTRAP PROGRESS=100 TAG=done SUMMARY="Done"'
        message = await create_message([line])
        event = event_from_message(message)
        assert event.arguments.progress == 100
        assert event.arguments.summary == 'Done'
        assert event.arguments.tag == 'done'

    async def test_status_client_dangerous_socks(self):
        line = '650 STATUS_CLIENT WARN DANGEROUS_SOCKS PROTOCOL=SOCKS5 ADDRESS=1.1.1.1:443'
        message = await create_message([line])
        event = event_from_message(message)
        assert event.arguments.address == '1.1.1.1:443'
        assert event.arguments.protocol == 'SOCKS5'

    async def test_status_client_socks_bad_hostname(self):
        line = '650 STATUS_CLIENT WARN SOCKS_BAD_HOSTNAME HOSTNAME="google.exit"'
        message = await create_message([line])
        event = event_from_message(message)
        assert event.arguments.hostname == 'google.exit'

    async def test_signal(self):
        line = '650 SIGNAL RELOAD'
        message = await create_message([line])
        event = event_from_message(message)
        assert isinstance(event, EventSignal)
        assert event.signal == Signal.RELOAD
        assert event.TYPE == EventWord.SIGNAL
