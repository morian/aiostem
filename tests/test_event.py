from __future__ import annotations

import base64
import gc
import hashlib
import logging
import weakref
from datetime import datetime, timedelta, timezone
from ipaddress import IPv4Address, IPv6Address

import pytest
import pytest_asyncio
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from pydantic import ValidationError

from aiostem.event import (
    EventBandwidth,
    EventCellStats,
    EventCirc,
    EventCircBW,
    EventCircMinor,
    EventClientsSeen,
    EventConfChanged,
    EventConnBW,
    EventDescChanged,
    EventDisconnect,
    EventGuard,
    EventHsDesc,
    EventHsDescContent,
    EventNewConsensus,
    EventNewDesc,
    EventOrConn,
    EventSignal,
    EventStream,
    EventStreamBW,
    EventTbEmpty,
    EventUnknown,
    EventWord,
    EventWordInternal,
    event_from_message,
)
from aiostem.exceptions import CryptographyError, MessageError, ReplySyntaxError
from aiostem.structures import (
    CircuitEvent,
    HiddenServiceAddressV3,
    HsDescAction,
    HsDescFailReason,
    HsDescV2,
    HsDescV3,
    LogSeverity,
    LongServerName,
    Signal,
    StatusActionGeneral,
)
from aiostem.utils import MessageData, TrRSAPublicKey

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

    async def test_desc_changed(self):
        message = await create_message(['650 DESCCHANGED'])
        event = event_from_message(message)
        assert isinstance(event, EventDescChanged)

    async def test_guard(self):
        line = (
            '650 GUARD ENTRY $669E9D3CF2C1BF3A9E7A0B7FD89F8B4B5E1EF516~PalestineWillBeFree NEW'
        )
        message = await create_message([line])
        event = event_from_message(message)
        assert isinstance(event, EventGuard)
        assert event.name.nickname == 'PalestineWillBeFree'
        assert event.type == 'ENTRY'
        assert event.status == 'NEW'

    async def test_clients_seen(self):
        line = (
            '650 CLIENTS_SEEN TimeStarted="2008-12-25 23:50:43" '
            'CountrySummary=us=16,de=8,uk=8 '
            'IPVersions=v4=16,v6=40'
        )
        message = await create_message([line])
        event = event_from_message(message)
        assert isinstance(event, EventClientsSeen)
        assert isinstance(event.time, datetime)
        assert len(event.countries) == 3
        assert len(event.ip_versions) == 2
        assert event.countries['us'] == 16
        assert event.ip_versions['v6'] == 40

    async def test_stream_bw(self):
        line = '650 STREAM_BW 207187 20600 0 2025-01-04T21:29:50.985239'
        message = await create_message([line])
        event = event_from_message(message)
        assert isinstance(event, EventStreamBW)
        assert isinstance(event.time, datetime)
        assert event.stream == 207187
        assert event.written == 20600
        assert event.read == 0

    @pytest.mark.parametrize('verb', ['NEWCONSENSUS', 'NS'])
    async def test_consensus_no_data(self, verb):
        message = await create_message([f'650 {verb}'])
        with pytest.raises(ReplySyntaxError, match='has no data attached to it'):
            event_from_message(message)

    async def test_new_consensus_with_data(self):
        lines = [
            '650+NEWCONSENSUS',
            (
                'r eisbaer AGHSKv0fBtTm81AGvT2cIdeYHqk W3YydCbm7DgcoHQxlxbjmJoCpWA '
                '2038-01-01 00:00:00 109.70.100.70 9002 0'
            ),
            'a [2a03:e600:100::70]:9002',
            's Exit Fast Running Stable Valid',
            'w Bandwidth=40000',
            (
                'r WishMaster ASPb4bj4Hgs1B5TP5K4XLhL9pAE 3z7CNbMYDiOzzHUoHc7hjUtkJc4 '
                '2038-01-01 00:00:00 31.192.107.132 443 0'
            ),
            's Fast Running Stable V2Dir Valid',
            'w Bandwidth=1100',
            (
                'r artikel10ber116 /9C5SdBnbxB2uySP5ABl0tpGVQk ZthfzyM7LX7XdlCW7gJvxZJ6O6U '
                '2038-01-01 00:00:00 185.220.101.29 9004 0'
            ),
            '',  # This extra new-line is on purpose to make sure we skip it!
            'a [2a0b:f4c2::29]:9004',
            's Exit Fast Running Stable Valid',
            'w Bandwidth=44000',
            'p accept 20-21,80,443,853,873,989-990,1194,2086,3690,5222',
            '.',
            '650 OK',
        ]
        message = await create_message(lines)
        event = event_from_message(message)
        assert isinstance(event, EventNewConsensus)
        assert len(event.routers) == 3
        assert event.routers[0].bandwidth == 40000
        assert len(event.routers[0].flags) == 5
        assert len(event.routers[0].addresses) == 1
        assert event.routers[0].port_policy is None
        assert event.routers[0].dir_port is None
        assert event.routers[2].port_policy.policy == 'accept'
        assert len(event.routers[2].port_policy.ports) == 10

    async def test_conf_changed_empty(self):
        lines = ['650-CONF_CHANGED', '650 OK']
        message = await create_message(lines)
        event = event_from_message(message)
        assert isinstance(event, EventConfChanged)
        assert len(event) == 0

    async def test_conf_changed(self):
        lines = [
            '650-CONF_CHANGED',
            '650-SocksPort=unix:/run/tor/socks WorldWritable ExtendedErrors RelaxDirModeCheck',
            '650-SocksPort=0.0.0.0:9050',
            '650 OK',
        ]
        message = await create_message(lines)
        event = event_from_message(message)
        assert isinstance(event, EventConfChanged)
        assert len(event) == 1
        assert len(event['SocksPort']) == 2
        assert event['SocksPort'][1] == '0.0.0.0:9050'

    async def test_circ_minor(self):
        line = (
            '650 CIRC_MINOR 261373 PURPOSE_CHANGED '
            '$E6FA2613FA6325F83FAFF643C315DA725BC372B9~NowhereDOTmoe,'
            '$9E42073401F6B4046983C9AA027DDB1538587B93~ellenatfims,'
            '$76BACC90CBA71714918554156CAABE955E7A940F~Quetzalcoatl '
            'BUILD_FLAGS=NEED_CAPACITY,NEED_UPTIME PURPOSE=CONFLUX_LINKED '
            'TIME_CREATED=2025-01-04T17:52:34.407938 OLD_PURPOSE=CONFLUX_UNLINKED'
        )
        message = await create_message([line])
        event = event_from_message(message)
        assert isinstance(event, EventCircMinor)
        assert isinstance(event.time_created, datetime)
        assert event.event == CircuitEvent.PURPOSE_CHANGED
        assert len(event.path) == 3

    async def test_circ_minor_no_path(self):
        line = (
            '650 CIRC_MINOR 27329 PURPOSE_CHANGED '
            'BUILD_FLAGS=NEED_CAPACITY,NEED_UPTIME PURPOSE=MEASURE_TIMEOUT '
            'TIME_CREATED=2025-01-16T17:55:02.368535 OLD_PURPOSE=CONFLUX_UNLINKED'
        )
        message = await create_message([line])
        event = event_from_message(message)
        assert isinstance(event, EventCircMinor)
        assert event.path is None

    async def test_conn_bw(self):
        line = '650 CONN_BW ID=123 TYPE=EXIT READ=234 WRITTEN=345'
        message = await create_message([line])
        event = event_from_message(message)
        assert isinstance(event, EventConnBW)
        assert event.conn_id == 123
        assert event.conn_type == 'EXIT'
        assert event.read == 234
        assert event.written == 345

    async def test_circ_bw(self):
        line = (
            '650 CIRC_BW ID=261239 READ=0 WRITTEN=509 TIME=2025-01-04T17:13:43.979647 '
            'DELIVERED_READ=0 OVERHEAD_READ=0 DELIVERED_WRITTEN=153 OVERHEAD_WRITTEN=345'
        )
        message = await create_message([line])
        event = event_from_message(message)
        assert isinstance(event, EventCircBW)
        assert isinstance(event.time, datetime)
        assert event.read == 0
        assert event.written == 509
        assert event.written_delivered == 153
        assert event.written_overhead == 345
        assert event.slow_start is None

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
        assert event.outbound_conn_id == 15
        assert event.outbound_queue == 19403
        assert event.outbound_added['create_fast'] == 1
        assert event.outbound_added['relay_early'] == 2
        assert event.outbound_time['create_fast'].microseconds == 0
        assert event.outbound_time['relay_early'].microseconds == 10000

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

    async def test_circuit_launched(self):
        line = (
            '650 CIRC 267807 LAUNCHED BUILD_FLAGS=IS_INTERNAL,NEED_CAPACITY,NEED_UPTIME '
            'PURPOSE=HS_VANGUARDS TIME_CREATED=2025-01-04T23:55:46.318138'
        )
        message = await create_message([line])
        event = event_from_message(message)
        assert isinstance(event, EventCirc)
        assert event.circuit == 267807
        assert event.status == 'LAUNCHED'
        assert event.purpose == 'HS_VANGUARDS'
        assert len(event.build_flags) == 3
        assert isinstance(event.time_created, datetime)

    async def test_circuit_hs_pow(self):
        line = (
            '650 CIRC 267807 LAUNCHED BUILD_FLAGS=IS_INTERNAL,NEED_CAPACITY,NEED_UPTIME '
            'PURPOSE=HS_VANGUARDS HS_POW=v1,2 TIME_CREATED=2025-01-04T23:55:46.318138'
        )
        message = await create_message([line])
        event = event_from_message(message)
        assert isinstance(event, EventCirc)
        assert event.hs_pow.type == 'v1'
        assert event.hs_pow.effort == 2

    async def test_circuit_closed(self):
        line = (
            '650 CIRC 288979 CLOSED '
            '$F50CF02A0E6A9D9B25F7EB220FC26F7BD1B74999~flowjob02,'
            '$1814DBD5E7E1839CA3F43847683A08F3BF3D5C91~isodiapher,'
            '$745732BEBB6CD9344B6828481229F14F19E1C464~Unfixed1,'
            '$1214952C0357904505AAE425D48D84131064E9AC~cakesnwaffles '
            'BUILD_FLAGS=IS_INTERNAL,NEED_CAPACITY,NEED_UPTIME PURPOSE=HS_CLIENT_INTRO '
            'HS_STATE=HSCI_DONE '
            'REND_QUERY=facebookcooa4ldbat4g7iacswl3p2zrf5nuylvnhxn6kqolvojixwid '
            'TIME_CREATED=2025-01-05T21:54:19.138927 REASON=FINISHED'
        )
        message = await create_message([line])
        event = event_from_message(message)
        assert isinstance(event, EventCirc)
        assert event.circuit == 288979
        assert event.status == 'CLOSED'
        assert event.rend_query == 'facebookcooa4ldbat4g7iacswl3p2zrf5nuylvnhxn6kqolvojixwid'
        assert event.reason == 'FINISHED'
        assert len(event.path) == 4

    async def test_stream_new(self):
        line = (
            '650 STREAM 210420 NEW 0 1.1.1.1:53 SOURCE_ADDR=172.18.0.1:54640 '
            'PURPOSE=USER CLIENT_PROTOCOL=SOCKS4 NYM_EPOCH=16 SESSION_GROUP=-11 '
            'ISO_FIELDS=SOCKS_USERNAME,SOCKS_PASSWORD,CLIENTADDR,SESSION_GROUP,NYM_EPOCH'
        )
        message = await create_message([line])
        event = event_from_message(message)
        assert isinstance(event, EventStream)
        assert event.status == 'NEW'
        assert event.stream == 210420
        assert event.target.host == IPv4Address('1.1.1.1')
        assert event.target.node is None
        assert event.target.port == 53
        assert event.nym_epoch == 16
        assert event.session_group == -11
        assert len(event.iso_fields) == 5

    async def test_stream_closed(self):
        line = (
            '650 STREAM 210427 CLOSED 282747 '
            '94.16.31.131.$0B4190C676FAAD34EB2DCB9A288939476CEBCF32.exit:443 '
            'REASON=END REMOTE_REASON=DONE CLIENT_PROTOCOL=UNKNOWN NYM_EPOCH=0 '
            'SESSION_GROUP=-2 ISO_FIELDS=SESSION_GROUP'
        )
        message = await create_message([line])
        event = event_from_message(message)
        assert isinstance(event, EventStream)
        assert event.status == 'CLOSED'
        assert event.stream == 210427
        assert event.circuit == 282747
        assert event.target.host == IPv4Address('94.16.31.131')
        assert event.target.node is not None
        assert event.target.port == 443
        assert event.nym_epoch == 0
        assert event.session_group == -2
        assert len(event.iso_fields) == 1

    async def test_or_conn(self):
        line = (
            '650 ORCONN '
            '$427526EBD012CFE50FCFFCBFE221EFFE199AFA8C~portugesecartel '
            'CLOSED REASON=DONE ID=205906'
        )
        message = await create_message([line])
        event = event_from_message(message)
        assert isinstance(event, EventOrConn)
        assert event.status == 'CLOSED'
        assert event.reason == 'DONE'
        assert event.conn_id == 205906

    async def test_bandwidth(self):
        message = await create_message(['650 BW 1670343 1936996'])
        event = event_from_message(message)
        assert isinstance(event, EventBandwidth)
        assert event.read == 1670343
        assert event.written == 1936996

    async def test_new_desc(self):
        line = (
            '650 NEWDESC '
            '$F5B58FEE44573C3BFD7D176D918BA5B4057519D7~bistrv1 '
            '$14AE2154A26F1D42C3C3BEDC10D05FDD9F8545BB~freeasf'
        )
        message = await create_message([line])
        event = event_from_message(message)
        assert isinstance(event, EventNewDesc)
        assert len(event.servers) == 2
        for server in event.servers:
            assert isinstance(server, LongServerName)

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
            '650 PT_LOG PT=/usr/bin/obs4proxy SEVERITY=debug MESSAGE="Connected to bridge A"'
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
        assert event.expires.tzinfo == timezone.utc
        assert event.stream == 110330
        assert event.cached is False
        assert event.error == 'yes'

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


class TestHsDescriptors:
    """Check parsing of onion descriptors."""

    @pytest.fixture(scope='session')
    def hs_desc_v2_lines(self):
        address = 'facebookcorewwwi'
        path = f'tests/samples/{address}/content.txt'
        with open(path) as fp:
            return list(map(str.rstrip, fp))

    @pytest_asyncio.fixture(scope='function')
    async def hs_desc_v2_event(self, hs_desc_v2_lines):
        message = await create_message(hs_desc_v2_lines)
        return event_from_message(message)

    @pytest.fixture(scope='session')
    def hs_desc_v3_lines(self):
        address = 'facebookcooa4ldbat4g7iacswl3p2zrf5nuylvnhxn6kqolvojixwid'
        path = f'tests/samples/{address}/content.txt'
        with open(path) as fp:
            return list(map(str.rstrip, fp))

    @pytest_asyncio.fixture(scope='function')
    async def hs_desc_v3_event(self, hs_desc_v3_lines):
        message = await create_message(hs_desc_v3_lines)
        return event_from_message(message)

    @pytest.fixture(scope='session')
    def hs_desc_v3_auth_lines(self):
        address = 'vakp3s3f4f5uopzvzsczsumurwrawuc5sexvjxqgzng6untov3gc5lyd'
        path = f'tests/samples/{address}/content.txt'
        with open(path) as fp:
            return list(map(str.rstrip, fp))

    @pytest_asyncio.fixture(scope='function')
    async def hs_desc_v3_auth_event(self, hs_desc_v3_auth_lines):
        message = await create_message(hs_desc_v3_auth_lines)
        return event_from_message(message)

    async def test_hs_desc_v2(self, hs_desc_v2_event):
        event = hs_desc_v2_event
        assert isinstance(event, EventHsDescContent)
        assert event.address == 'facebookcorewwwi'
        assert isinstance(event.descriptor, HsDescV2)

        # Check general purpose fields from the descriptor.
        desc = event.descriptor
        assert desc.protocol_versions == {2, 3}
        assert desc.version == 2

        # Check that the key matches the domain name!
        pubkey = TrRSAPublicKey().to_bytes(desc.permanent_key)
        digest = hashlib.sha1(pubkey).digest()  # noqa: S324
        computed = base64.b32encode(digest[:10]).decode('ascii')
        assert computed.lower() == event.address

        # Parse and get a list of introduction points.
        intros = desc.introduction_points()
        assert len(intros) == 10

        first_intro = intros[0]
        assert first_intro.ip == IPv4Address('212.74.233.20')
        assert first_intro.onion_port == 9101

        desc.raise_for_invalid_signature()

    async def test_hs_desc_v2_signature_error(self, hs_desc_v2_event):
        assert isinstance(hs_desc_v2_event, EventHsDescContent)
        descriptor = hs_desc_v2_event.descriptor
        descriptor.signature = bytes.fromhex(
            '028da11bc35e2baff1ea80054370d471fe716d3fb3428299517225e1458d271e'
            '06cb8bcf94282b46bbbf728d834d637ccea3f0db42c0283a598d1d69beab0ad6'
            '4403fbed851d5e305d8be95c98d94c7547570041d3a0f8c57760d20e9122d537'
            'a283f18542df04aeb0acc6feac219285586d71f0d12e20bf3becd97e17ec1761'
        )
        msg = 'Decrypted certificate signature has an invalid format'
        with pytest.raises(CryptographyError, match=msg):
            descriptor.raise_for_invalid_signature()

    async def test_hs_desc_v2_intro_errors(self, hs_desc_v2_event):
        msg = 'Authentication cookie for V2 descriptor is not yet implemented'
        with pytest.raises(NotImplementedError, match=msg):
            hs_desc_v2_event.descriptor.introduction_points('password')

    async def test_hs_desc_v3(self, hs_desc_v3_event):
        address = 'facebookcooa4ldbat4g7iacswl3p2zrf5nuylvnhxn6kqolvojixwid'
        event = hs_desc_v3_event

        assert isinstance(event, EventHsDescContent)
        assert isinstance(event.descriptor, HsDescV3)
        assert event.address == address

        # Check general purpose fields from the descriptor.
        desc = event.descriptor
        assert desc.hs_descriptor == 3
        assert desc.revision == 2602216024
        assert int(desc.lifetime.total_seconds()) == 10800

        # Additional checks on the signing certificate.
        signing_cert = desc.signing_cert
        assert signing_cert.expired is True

        signing_key = signing_cert.signing_key
        assert signing_key is not None

        signing_cert.raise_for_invalid_signature(signing_key)
        desc.raise_for_invalid_signature()

        layer1 = desc.decrypt_layer1(event.address)
        assert len(layer1.auth_clients) == 16

        layer2 = desc.decrypt_layer2(event.address)
        assert layer2.single_service is True

        # Check introduction points.
        assert len(layer2.introduction_points) == 10
        for intro in layer2.introduction_points:
            intro.auth_key_cert.raise_for_invalid_signature(intro.auth_key_cert.signing_key)
            intro.enc_key_cert.raise_for_invalid_signature(intro.enc_key_cert.signing_key)

        # Check a random link specifier in our structure.
        links = layer2.introduction_points[2].link_specifiers
        assert links[0].host == IPv4Address('193.142.147.204')
        assert links[0].port == 9200

    async def test_hs_desc_v3_cache(self, hs_desc_v3_auth_event, hs_desc_v3_event):
        desc1 = HsDescV3.from_text(hs_desc_v3_event.descriptor_text)
        desc2 = HsDescV3.from_text(hs_desc_v3_auth_event.descriptor_text)
        info1 = desc1.decrypt_layer1.cache_info()
        info2 = desc2.decrypt_layer1.cache_info()
        assert info1.currsize == 0
        assert info2.currsize == 0

        for _ in range(2):
            desc1.decrypt_layer1(hs_desc_v3_event.address)
            desc2.decrypt_layer1(hs_desc_v3_auth_event.address)
            info1 = desc1.decrypt_layer1.cache_info()
            info2 = desc2.decrypt_layer1.cache_info()
            assert info1.currsize == 1
            assert info2.currsize == 1

    async def test_hs_desc_v3_cache_gc(self, hs_desc_v3_event):
        """Check that the descriptor is properly garbage collected."""
        desc = HsDescV3.from_text(hs_desc_v3_event.descriptor_text)
        desc.decrypt_layer2(hs_desc_v3_event.address)
        desc_ref = weakref.ref(desc)
        assert desc_ref() == desc

        desc = None
        gc.collect()
        assert desc_ref() is None

    async def test_hs_desc_v3_auth_no_key(self, hs_desc_v3_auth_event):
        """Check with an encrypted descriptor but with no key."""
        desc = hs_desc_v3_auth_event.descriptor
        assert desc.hs_descriptor == 3
        assert desc.revision == 2634456021

        layer1 = desc.decrypt_layer1(hs_desc_v3_auth_event.address)
        assert len(layer1.auth_clients) == 16

        with pytest.raises(CryptographyError, match='Invalid MAC, something is corrupted!'):
            desc.decrypt_layer2(hs_desc_v3_auth_event.address)

    async def test_hs_desc_v3_no_signature(self, hs_desc_v3_lines):
        message = await create_message(hs_desc_v3_lines)

        # Alter the input message to filter out the signature part (at the end).
        lines = []
        for line in message.items[0].data.splitlines():
            if line.startswith('signature '):
                break
            lines.append(line)

        # Replace the message data by a new message we are creating.
        msgdata = MessageData(
            status=message.items[0].status,
            header=message.items[0].header,
            data='\n'.join(lines),
        )
        message.items.clear()
        message.items.append(msgdata)

        # Check that we get an error because there is no signature.
        event = event_from_message(message)
        msg = 'No signature found on the HsV3 descriptor'
        with pytest.raises(ReplySyntaxError, match=msg):
            event.descriptor  # noqa: B018

    async def test_hs_desc_v3_signature_error(self, hs_desc_v3_event):
        hs_desc_v3_event.descriptor.signature = b'abcdf'
        with pytest.raises(CryptographyError, match='Descriptor has an invalid signature'):
            hs_desc_v3_event.descriptor.raise_for_invalid_signature()

    async def test_hs_desc_v3_no_signing_cert_key(self, hs_desc_v3_event):
        # Clear all extensions (including the one holding the signing key).
        hs_desc_v3_event.descriptor.signing_cert.key = None
        hs_desc_v3_event.descriptor.raise_for_invalid_signature()

    async def test_hs_desc_v3_cert_no_signing_key(self, hs_desc_v3_event):
        # Clear all extensions (including the one holding the signing key).
        hs_desc_v3_event.descriptor.signing_cert.extensions.clear()
        with pytest.raises(ReplySyntaxError, match='No signing key found in the descriptor'):
            hs_desc_v3_event.descriptor.decrypt_layer1(hs_desc_v3_event.address)

    async def test_hs_desc_v3_bad_decrypt_addr(self, hs_desc_v3_event):
        addr_str = '2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion'
        address = HiddenServiceAddressV3.from_string(addr_str)
        with pytest.raises(CryptographyError, match='Invalid MAC, something is corrupted!'):
            hs_desc_v3_event.descriptor.decrypt_layer1(address)

    async def test_hs_desc_v3_auth_with_valid_key(self, hs_desc_v3_auth_event):
        """Check with an encrypted descriptor but with a valid key."""
        hexkey = 'D8D9ABB522BBC0A2E35CCDDD6B4CECF2FB4D51F7698EC8D1E0F2A1D81D340950'
        key = X25519PrivateKey.from_private_bytes(bytes.fromhex(hexkey))
        desc = hs_desc_v3_auth_event.descriptor
        layer2 = desc.decrypt_layer2(hs_desc_v3_auth_event.address, key)
        assert len(layer2.introduction_points) == 3
        assert layer2.single_service is False

    async def test_hs_desc_v3_auth_with_invalid_key(self, hs_desc_v3_event):
        addr_str = 'facebookcooa4ldbat4g7iacswl3p2zrf5nuylvnhxn6kqolvojixwid.onion'
        address = HiddenServiceAddressV3.from_string(addr_str)
        msg = 'No client matching the secret key was found in the descriptor'
        with pytest.raises(CryptographyError, match=msg):
            hs_desc_v3_event.descriptor.decrypt_layer2(address, X25519PrivateKey.generate())
