04. Events
==========

.. currentmodule:: aiostem

Events are, besides of commands the other major way to get data from Tor.
You can subscribe to events and get asynchronous notifications until you disable the event.


List of events
--------------

The following code displays the list of all events supported by your Tor:

.. literalinclude:: ../../examples/events_list.py
   :caption: examples/events_list.py
   :linenos:

All events handled by this library are described on :class:`.EventWord`.
Additionally, we also have support for events that are internal to this library, documented
on :class:`.EventWordInternal`. Currently only :attr:`~.EventWordInternal.DISCONNECT` is
supported, providing a way to be notified when the controller has been disconnected from the
remote Tor daemon (this may happen when Tor is shutting down for example).


Subscribe to events
-------------------

Event subscription and unsubscription are handled by :meth:`~.Controller.add_event_handler`
and :meth:`~.Controller.del_event_handler`. These functions register a callback you provide,
and ask Tor for the associated events using :meth:`~.Controller.set_events`. Do not call this
method by yourself, as this is supposed to be handled by our event manager.

The following example generates events on demand through :meth:`~.Controller.resolve`, which
performs a DNS resolution for the provided domain(s). Its results cannot be provided back
immediately, so they are provided as an :attr:`~.EventWord.ADDRMAP`, parsed through
:class:`~.EventAddrMap`.

.. literalinclude:: ../../examples/events_resolve.py
   :caption: examples/events_resolve.py
   :emphasize-lines: 10-12,28-29
   :linenos:

Its intended use is as follow:

.. code-block:: console

   $ python examples/events_resolve.py google.com
   [>] Connecting to localhost on port 9051
   google.com is located at 142.251.39.110

The callback method provided here can be either synchronous or asynchronous, but you need
to take extra care here since the callback methods run directly from the stream reader task.
If you need extract time, consider putting items in an :class:`asyncio.Queue` and handle
events in a separate task.
