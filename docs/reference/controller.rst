Controller
==========

This is the main client you will use to perform queries and get responses from the Tor daemon.
It also allows the registration of methods or functions to be called later when an event occurs,
as Tor also sends back asynchronous events for various purposes.

.. currentmodule:: aiostem.controller

.. autoclass:: Controller
   :no-show-inheritance:
   :members:

   .. automethod:: __init__
   .. automethod:: __aenter__
   .. automethod:: __aexit__
