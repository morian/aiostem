01. Connection
==============

.. currentmodule:: aiostem

There are several ways to connect to Tor's control port, depending on the daemon configuration.
Tor configuration is out of this scope, to find out how to configure the control port, please
have a look at the `torrc manpage`_ and specifically the ``ControlPort`` option.

.. _torrc manpage: https://manpages.debian.org/bookworm/tor/torrc.5.en.html

This service typically listens on port ``TCP/9051`` or on a local UNIX socket (on Linux).


TCP port connection
-------------------

The following code shows how to connect to the control port through the TCP local port:

.. literalinclude:: ../../examples/connect_from_port.py
   :caption: examples/connect_from_port.py
   :emphasize-lines: 12
   :linenos:

This code uses :meth:`.Controller.from_port`, which is a helper method to create a new client
(a controller) from pair of host and port.

This is what the output of this script looks like:

.. code-block:: console

   $ python examples/connect_from_port.py
   [>] Connecting to localhost on port 9051
   [+] Connected to Tor v0.4.8.13


Socket file connection
----------------------

The following code is an alternative version connecting through a local socket file:

.. literalinclude:: ../../examples/connect_from_socket.py
   :caption: examples/connect_from_socket.py
   :emphasize-lines: 12
   :linenos:

This code uses :meth:`.Controller.from_path`, which is another helper method used to
create a controller for a socket file. This code also uses :meth:`.Controller.protocol_info`
which is one of the rare commands you can run while not authenticated.
This is intended here to get the version of the remote Tor daemon.

This is what the output of this script looks like:

.. code-block:: console

   $ python examples/connect_from_socket.py
   [>] Connecting to /run/tor/control
   [+] Connected to Tor v0.4.8.13

When available, you should probably prefer this version since local sockets have less overhead
over a full TCP connection.


Advanced connection
-------------------

:meth:`.Controller.from_port` and :meth:`.Controller.from_path` are only wrappers using
classes derived from :class:`.ControlConnector`.
Users can build new sub-classes for custom uses, such as providing support for TLS or any
kind of proxy. A :class:`.Controller` only requires the connector to provide
:meth:`~.ControlConnector.connect` which returns a :class:`tuple` of
:class:`asyncio.StreamReader` and :class:`asyncio.StreamWriter`.

The following code connects to the TCP port using :class:`.ControlConnectorPort`:

.. literalinclude:: ../../examples/connect_with_connector.py
   :caption: examples/connect_with_connector.py
   :emphasize-lines: 11,14
   :linenos:
