from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Address, IPv6Address

import pytest
from pydantic import ValidationError

from aiostem.event import (
    EventCellStats,
    EventDisconnect,
    EventHsDesc,
    EventHsDescContent,
    EventSignal,
    EventTbEmpty,
    EventUnknown,
    EventWord,
    EventWordInternal,
    event_from_message,
)
from aiostem.exceptions import MessageError, ReplySyntaxError
from aiostem.structures import (
    HsDescAction,
    HsDescFailReason,
    LogSeverity,
    Signal,
    StatusActionGeneral,
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

    async def test_tb_empty_global(self):
        line = '650 TB_EMPTY GLOBAL READ=93 WRITTEN=92 LAST=100'
        message = await create_message([line])
        event = event_from_message(message)
        assert isinstance(event, EventTbEmpty)
        assert event.bucket == 'GLOBAL'
        assert event.conn_id is None
        assert event.last.microseconds == 100000
        assert event.read.microseconds == 93000
        assert event.written.microseconds == 92000

    async def test_tb_empty_orconn(self):
        line = '650 TB_EMPTY ORCONN ID=16 READ=0 WRITTEN=0 LAST=100'
        message = await create_message([line])
        event = event_from_message(message)
        assert isinstance(event, EventTbEmpty)
        assert event.bucket == 'ORCONN'
        assert event.conn_id == 16
        assert event.last.microseconds == 100000
        assert event.read.microseconds == 0
        assert event.written.microseconds == 0

    async def test_cell_stats(self):
        line = (
            '650 CELL_STATS ID=14 OutboundQueue=19403 OutboundConn=15 '
            'OutboundAdded=create_fast:1,relay_early:2 '
            'OutboundRemoved=create_fast:1,relay_early:2 '
            'OutboundTime=create_fast:0,relay_early:10'
        )
        message = await create_message([line])
        event = event_from_message(message)
        assert isinstance(event, EventCellStats)
        assert event.circuit == 14
        assert event.inbound_queue is None
        assert event.outbound_conn == 15
        assert event.outbound_queue == 19403
        assert event.outbound_added['create_fast'] == 1
        assert event.outbound_added['relay_early'] == 2
        assert event.outbound_time['create_fast'].microseconds == 0
        assert event.outbound_time['relay_early'].microseconds == 10000

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
        assert event.severity == LogSeverity.WARNING

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

    async def test_status_general_clock_skew_with_ip(self):
        line = '650 STATUS_GENERAL NOTICE CLOCK_SKEW SKEW=120 SOURCE=OR:1.1.1.1:443'
        message = await create_message([line])
        event = event_from_message(message)
        assert event.action == StatusActionGeneral.CLOCK_SKEW
        assert isinstance(event.arguments.skew, timedelta)
        assert event.arguments.source.name == 'OR'
        assert event.arguments.source.address.host == IPv4Address('1.1.1.1')
        assert event.arguments.source.address.port == 443

    async def test_status_general_clock_skew_with_consensus(self):
        line = '650 STATUS_GENERAL NOTICE CLOCK_SKEW SKEW=120 SOURCE=CONSENSUS'
        message = await create_message([line])
        event = event_from_message(message)
        assert event.action == StatusActionGeneral.CLOCK_SKEW
        assert event.arguments.source.name == 'CONSENSUS'
        assert event.arguments.source.address is None

    async def test_status_general_dir_all_unreachable(self):
        line = '650 STATUS_GENERAL ERR DIR_ALL_UNREACHABLE'
        message = await create_message([line])
        event = event_from_message(message)
        assert event.action == StatusActionGeneral.DIR_ALL_UNREACHABLE
        assert event.arguments is None

    async def test_status_general_unknown_action(self, caplog):
        line = '650 STATUS_GENERAL NOTICE UNKNOWN_ACTION ARG=VAL'
        message = await create_message([line])
        with (
            caplog.at_level(logging.INFO, logger='aiostem'),
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

    async def test_status_client_dangerous_socks_ipv4(self):
        line = '650 STATUS_CLIENT WARN DANGEROUS_SOCKS PROTOCOL=SOCKS5 ADDRESS=1.1.1.1:53'
        message = await create_message([line])
        event = event_from_message(message)
        assert event.arguments.address.host == IPv4Address('1.1.1.1')
        assert event.arguments.address.port == 53
        assert event.arguments.protocol == 'SOCKS5'

    async def test_status_client_dangerous_socks_ipv6(self):
        line = (
            '650 STATUS_CLIENT WARN DANGEROUS_SOCKS PROTOCOL=SOCKS5 '
            'ADDRESS=[2a04:fa87:fffd::c000:426c]:443'
        )
        message = await create_message([line])
        event = event_from_message(message)
        assert event.arguments.address.host == IPv6Address('2a04:fa87:fffd::c000:426c')
        assert event.arguments.address.port == 443
        assert event.arguments.protocol == 'SOCKS5'

    async def test_status_client_socks_bad_hostname(self):
        line = '650 STATUS_CLIENT WARN SOCKS_BAD_HOSTNAME HOSTNAME="google.exit"'
        message = await create_message([line])
        event = event_from_message(message)
        assert event.arguments.hostname == 'google.exit'

    async def test_status_transport_launched(self):
        line = '650 TRANSPORT_LAUNCHED client obfs4 127.0.0.1 1234'
        message = await create_message([line])
        event = event_from_message(message)
        assert event.side == 'client'
        assert event.port == 1234

    async def test_status_pt_log(self):
        line = (
            '650 PT_LOG PT=/usr/bin/obs4proxy SEVERITY=debug '
            'MESSAGE="Connected to bridge A"'
        )
        message = await create_message([line])
        event = event_from_message(message)
        assert event.program == '/usr/bin/obs4proxy'
        assert event.severity == LogSeverity.DEBUG
        assert event.message == 'Connected to bridge A'

    async def test_status_pt_status(self):
        line = (
            '650 PT_STATUS PT=/usr/bin/obs4proxy TRANSPORT=obfs4 '
            'ADDRESS=198.51.100.123:1234 CONNECT=Success'
        )
        message = await create_message([line])
        event = event_from_message(message)
        assert event.program == '/usr/bin/obs4proxy'
        assert event.transport == 'obfs4'
        assert event.values['ADDRESS'] == '198.51.100.123:1234'
        assert event.values['CONNECT'] == 'Success'

    async def test_addr_map_standard(self):
        line = (
            '650 ADDRMAP google.com 142.250.74.110 "2024-12-08 23:00:36" '
            'EXPIRES="2024-12-08 23:00:36" CACHED="NO" STREAMID=109038'
        )
        message = await create_message([line])
        event = event_from_message(message)
        assert event.original == 'google.com'
        assert event.replacement == IPv4Address('142.250.74.110')
        assert event.cached is False

    async def test_addr_map_error(self):
        line = (
            '650 ADDRMAP 2a04:fa87:fffd::c000:426c <error> "2024-12-09 07:24:03" '
            'error=yes EXPIRES="2024-12-09 07:24:03" CACHED="NO" STREAMID=110330'
        )
        message = await create_message([line])
        event = event_from_message(message)
        assert event.original == IPv6Address('2a04:fa87:fffd::c000:426c')
        assert event.replacement is None
        assert isinstance(event.expires, datetime)
        assert event.expires.tzinfo == UTC
        assert event.stream == 110330
        assert event.cached is False

    async def test_addr_map_permanent(self):
        line = '650 ADDRMAP dns.google 8.8.8.8 NEVER CACHED="YES"'
        message = await create_message([line])
        event = event_from_message(message)
        assert event.expires is None
        assert event.cached is True

    async def test_build_timeout_set(self):
        line = (
            '650 BUILDTIMEOUT_SET COMPUTED TOTAL_TIMES=1000 TIMEOUT_MS=815 '
            'XM=283 ALPHA=1.520695 CUTOFF_QUANTILE=0.800000 TIMEOUT_RATE=0.292260 '
            'CLOSE_MS=60000 CLOSE_RATE=0.011098'
        )
        message = await create_message([line])
        event = event_from_message(message)
        assert event.total_times == 1000
        assert event.xm.microseconds == 283000

    async def test_signal(self):
        line = '650 SIGNAL RELOAD'
        message = await create_message([line])
        event = event_from_message(message)
        assert isinstance(event, EventSignal)
        assert event.signal == Signal.RELOAD
        assert event.TYPE == EventWord.SIGNAL
