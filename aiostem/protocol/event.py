from __future__ import annotations

from enum import StrEnum


class Event(StrEnum):
    """All possible events to subscribe to."""

    #: Circuit status changed
    CIRC = 'CIRC'
    #: Stream status changed
    STREAM = 'STREAM'
    #: OR Connection status changed
    ORCONN = 'ORCONN'
    #: Bandwidth used in the last second
    BW = 'BW'
    #: Debug log message
    DEBUG = 'DEBUG'
    #: Info log message
    INFO = 'INFO'
    #: Notice log message
    NOTICE = 'NOTICE'
    #: Warning log message
    WARN = 'WARN'
    #: Error log message
    ERR = 'ERR'
    #: New descriptors available
    NEWDESC = 'NEWDESC'
    #: New Address mapping
    ADDRMAP = 'ADDRMAP'
    #: Descriptors uploaded to us in our role as authoritative dirserver
    AUTHDIR_NEWDESCS = 'AUTHDIR_NEWDESCS'
    #: Our descriptor changed
    DESCCHANGED = 'DESCCHANGED'
    #: General status event
    STATUS_GENERAL = 'STATUS_GENERAL'
    #: Client status event
    STATUS_CLIENT = 'STATUS_CLIENT'
    #: Server status event
    STATUS_SERVER = 'STATUS_SERVER'
    #: Our set of guard nodes has changed
    GUARD = 'GUARD'
    #: Network status has changed
    NS = 'NS'
    #: Bandwidth used on an application stream
    STREAM_BW = 'STREAM_BW'
    #: Per-country client stats
    CLIENTS_SEEN = 'CLIENTS_SEEN'
    #: New consensus networkstatus has arrived
    NEWCONSENSUS = 'NEWCONSENSUS'
    #: New circuit buildtime has been set
    BUILDTIMEOUT_SET = 'BUILDTIMEOUT_SET'
    #: Signal received
    SIGNAL = 'SIGNAL'
    #: Configuration changed
    CONF_CHANGED = 'CONF_CHANGED'
    #: Circuit status changed slightly
    CIRC_MINOR = 'CIRC_MINOR'
    #: Pluggable transport launched
    TRANSPORT_LAUNCHED = 'TRANSPORT_LAUNCHED'
    #: Bandwidth used on an OR or DIR or EXIT connection
    CONN_BW = 'CONN_BW'
    #: Bandwidth used by all streams attached to a circuit
    CIRC_BW = 'CIRC_BW'
    #: Per-circuit cell stats
    CELL_STATS = 'CELL_STATS'
    #: Token buckets refilled
    TB_EMPTY = 'TB_EMPTY'
    #: HiddenService descriptors
    HS_DESC = 'HS_DESC'
    #: HiddenService descriptors content
    HS_DESC_CONTENT = 'HS_DESC_CONTENT'
    #: Network liveness has changed
    NETWORK_LIVENESS = 'NETWORK_LIVENESS'
    #: Pluggable Transport Logs
    PT_LOG = 'PT_LOG'
    #: Pluggable Transport Status
    PT_STATUS = 'PT_STATUS'
