:tocdepth: 3

Events
======

.. currentmodule:: aiostem.protocol.event


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


Event classes
-------------

.. autoclass:: EventHsDesc
   :exclude-members: SYNTAX, __init__, from_message
   :undoc-members:
   :members:

.. autoclass:: EventHsDescContent
   :exclude-members: SYNTAX, __init__, from_message
   :undoc-members:
   :members:

.. autoclass:: EventNetworkLiveness
   :exclude-members: SYNTAX, __init__, from_message
   :members:

.. autoclass:: EventSignal
   :exclude-members: SYNTAX, __init__, from_message
   :members:


Event logs
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


Helpers
-------

.. autofunction:: event_from_message


Event enumeration
-----------------

.. autoclass:: EventWord
   :undoc-members:
   :members:

.. autoclass:: EventWordInternal
   :undoc-members:
   :members:
