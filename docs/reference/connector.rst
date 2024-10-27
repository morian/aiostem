Connector
=========

.. currentmodule:: aiostem.connector

These classes are used to help with the connection to the remote Tor server
trough its control port, providing a simple `connect` method returning a full-duplex link.

Base connector
--------------

.. autoclass:: ControlConnector
   :no-show-inheritance:
   :members:


TCP connector
-------------

.. autoclass:: ControlConnectorPort
   :members:

   .. automethod:: __init__


Unix socket connector
---------------------

.. autoclass:: ControlConnectorPath
   :members:

   .. automethod:: __init__
