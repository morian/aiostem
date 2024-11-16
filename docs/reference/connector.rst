Connector
=========

.. currentmodule:: aiostem.connector

These helper classes are either used directly or indirectly to help with connecting to the
control port. They simply provide a ``connect`` method returning a full-duplex link as a
:class:`tuple` of :class:`~asyncio.StreamReader` and :class:`~asyncio.StreamWriter`.

You can easily create your own and then provide it to the :class:`.Controller`, for instance
this can be handy to pass through a socks proxy or establish a TLS connection.


Base connector
--------------

This is a base abstract class for all connectors, derive your own connector from this class!

.. autoclass:: ControlConnector
   :members:


TCP connector
-------------

.. autodata:: DEFAULT_CONTROL_HOST
.. autodata:: DEFAULT_CONTROL_PORT

.. autoclass:: ControlConnectorPort
   :members:

   .. automethod:: __init__


Unix socket connector
---------------------

.. autodata:: DEFAULT_CONTROL_PATH

.. autoclass:: ControlConnectorPath
   :members:

   .. automethod:: __init__
