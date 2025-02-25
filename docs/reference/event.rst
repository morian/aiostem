:tocdepth: 3

Events
======

.. currentmodule:: aiostem.event

This page describes all the possible events and their parser implementation, received though
the callbacks registered by :meth:`.Controller.add_event_handler`. Note that all unknown events
will received an :class:`EventUnknown`, containing the raw :class:`.Message` received.


Base classes
------------

.. autoclass:: Event
   :undoc-members:
   :members:

.. autoclass:: EventLog
   :exclude-members: SYNTAX, __init__, from_message
   :undoc-members:
   :members:

.. autoclass:: EventSimple
   :undoc-members:
   :members:

.. autoclass:: EventStatus
   :exclude-members: SYNTAX, SUBSYNTAXES, __init__, from_message
   :undoc-members:
   :members:


Library events
--------------

This event is hooked on the event system provided and works in a similar way but is
only handled internally by this library.

.. autoclass:: EventDisconnect
   :exclude-members: __init__, from_message
   :members:


Circuit events
--------------

.. autoclass:: EventAddrMap
   :exclude-members: SYNTAX, __init__, from_message
   :members:

.. autoclass:: EventBuildTimeoutSet
   :exclude-members: SYNTAX, __init__, from_message
   :members:

.. autoclass:: EventCirc
   :exclude-members: SYNTAX, __init__, from_message
   :members:

.. autoclass:: EventCircBW
   :exclude-members: SYNTAX, __init__, from_message
   :members:

.. autoclass:: EventCircMinor
   :exclude-members: SYNTAX, __init__, from_message
   :members:

.. autoclass:: EventConnBW
   :exclude-members: SYNTAX, __init__, from_message
   :members:

.. autoclass:: EventStream
   :exclude-members: SYNTAX, __init__, from_message
   :members:

.. autoclass:: EventStreamBW
   :exclude-members: SYNTAX, __init__, from_message
   :members:


Hidden service events
---------------------

.. autoclass:: EventHsDesc
   :exclude-members: SYNTAX, __init__, from_message
   :undoc-members:
   :members:

.. autoclass:: EventHsDescContent
   :exclude-members: SYNTAX, __init__, from_message
   :undoc-members:
   :members:


Log events
----------

.. autoclass:: EventLogDebug
   :members:

.. autoclass:: EventLogInfo
   :members:

.. autoclass:: EventLogNotice
   :members:

.. autoclass:: EventLogWarn
   :members:

.. autoclass:: EventLogErr
   :members:


Status events
-------------

.. autoclass:: EventBaseNetworkStatus
   :exclude-members: SYNTAX, __init__, from_message
   :members:

.. autoclass:: EventDescChanged
   :exclude-members: SYNTAX, __init__, from_message
   :members:

.. autoclass:: EventGuard
   :exclude-members: SYNTAX, __init__, from_message
   :members:

.. autoclass:: EventNetworkLiveness
   :exclude-members: SYNTAX, __init__, from_message
   :members:

.. autoclass:: EventNetworkStatus
   :exclude-members: SYNTAX, __init__, from_message
   :members:

.. autoclass:: EventNewConsensus
   :exclude-members: SYNTAX, __init__, from_message
   :members:

.. autoclass:: EventNewDesc
   :exclude-members: SYNTAX, __init__, from_message
   :members:

.. autoclass:: EventOrConn
   :exclude-members: SYNTAX, __init__, from_message
   :members:

.. autoclass:: EventStatusGeneral
   :members: TYPE, action, arguments

.. autoclass:: EventStatusClient
   :members: TYPE, action, arguments

.. autoclass:: EventStatusServer
   :members: TYPE, action, arguments


Pluggable transport events
--------------------------

.. autoclass:: EventPtLog
   :exclude-members: SYNTAX, __init__, from_message
   :members:

.. autoclass:: EventPtStatus
   :exclude-members: SYNTAX, __init__, from_message
   :members:

.. autoclass:: EventTransportLaunched
   :exclude-members: SYNTAX, __init__, from_message
   :members:


Stats events
------------

.. autoclass:: EventBandwidth
   :exclude-members: SYNTAX, __init__, from_message
   :members:

.. autoclass:: EventCellStats
   :exclude-members: SYNTAX, __init__, from_message
   :members:

.. autoclass:: EventClientsSeen
   :exclude-members: SYNTAX, __init__, from_message
   :members:

.. autoclass:: EventTbEmpty
   :exclude-members: SYNTAX, __init__, from_message
   :members:


Misc. events
------------

.. autoclass:: EventConfChanged
   :exclude-members: SYNTAX, __init__, from_message
   :members:

.. autoclass:: EventSignal
   :exclude-members: SYNTAX, __init__, from_message
   :members:


Helpers
-------

.. autoclass:: EventUnknown
   :exclude-members: __init__, from_message
   :members:

.. autofunction:: event_from_message


Event enumeration
-----------------

.. autoclass:: EventWord
   :undoc-members:
   :members:

.. autoclass:: EventWordInternal
   :undoc-members:
   :members:
