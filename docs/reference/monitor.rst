Monitor
=======

.. currentmodule:: aiostem.monitor

The monitor is an optional object provided by this library that can be used on top of an
existing :class:`.Controller` to get notified when the global status of the Tor daemon changes.

.. autoclass:: Monitor
   :no-show-inheritance:
   :members:

   .. automethod:: __init__
   .. automethod:: __aenter__
   .. automethod:: __aexit__


.. autoclass:: ControllerStatus
   :no-show-inheritance:
   :members:
