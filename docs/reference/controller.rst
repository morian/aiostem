Controller
==========

.. currentmodule:: aiostem.controller

.. py:class:: Controller
    :no-typesetting:


:class:`Controller` is the main client that connects to Tor's control port.
It is used to send commands, read the corresponding replies and receive events from Tor.



Create and connect
------------------

.. class:: Controller
   :no-index:

   .. automethod:: from_path
   .. automethod:: from_port
   .. automethod:: __init__
   .. automethod:: __aenter__
   .. automethod:: __aexit__


Properties
----------

.. class:: Controller
   :no-index:

   .. autoproperty:: authenticated
   .. autoproperty:: connected
   .. autoproperty:: entered


Unauthenticated commands
------------------------

.. class:: Controller
   :no-index:

   .. automethod:: auth_challenge
   .. automethod:: authenticate
   .. automethod:: protocol_info
   .. automethod:: quit


Event management
----------------

.. autodata:: EventCallbackType

.. class:: Controller
   :no-index:

   .. automethod:: add_event_handler
   .. automethod:: del_event_handler
   .. automethod:: set_events


Common commands
---------------

.. class:: Controller
   :no-index:

   .. automethod:: drop_guards
   .. automethod:: get_conf
   .. automethod:: get_info
   .. automethod:: set_conf
   .. automethod:: hs_fetch
   .. automethod:: signal


Generic request
---------------

.. class:: Controller
   :no-index:

   .. automethod:: request
