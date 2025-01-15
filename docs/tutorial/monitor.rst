05. Monitor
===========

.. currentmodule:: aiostem

A :class:`.Monitor` is an optional helper that uses commands and events on your back to query
for the status of Tor and get notified by any change. This can be used for example on startup
to ensure that Tor is ready to operate before we perform any other action.

Additionally it can be used to stop or cancel asyncio tasks when Tor is no longer able
to perform in good conditions (this occurs on network issues for example).

.. literalinclude:: ../../examples/monitor.py
   :caption: examples/monitor.py
   :emphasize-lines: 18-21
   :linenos:

Running this code should print the following output:

.. code-block:: console

   $ python examples/monitor.py
   [>] Connecting to localhost on port 9051
   [+] Controller is healthy!
   ControllerStatus(bootstrap=100, has_circuits=True, has_dir_info=True, net_liveness=True)
