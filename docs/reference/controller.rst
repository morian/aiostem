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


Configuration commands
----------------------

.. class:: Controller
   :no-index:

   .. automethod:: get_conf
   .. automethod:: load_conf
   .. automethod:: reset_conf
   .. automethod:: save_conf
   .. automethod:: set_conf


Hidden services commands
------------------------

.. class:: Controller
   :no-index:

   .. automethod:: add_onion
   .. automethod:: del_onion

   .. automethod:: hs_fetch
   .. automethod:: hs_post

   .. automethod:: onion_client_auth_add
   .. automethod:: onion_client_auth_remove
   .. automethod:: onion_client_auth_view


Streams and circuits
--------------------

.. class:: Controller
   :no-index:

   .. automethod:: close_circuit
   .. automethod:: extend_circuit
   .. automethod:: set_circuit_purpose

   .. automethod:: attach_stream
   .. automethod:: close_stream
   .. automethod:: redirect_stream

   .. automethod:: post_descriptor
   .. automethod:: drop_guards
   .. automethod:: drop_timeouts


Control commands
----------------

.. class:: Controller
   :no-index:

   .. automethod:: drop_ownership
   .. automethod:: take_ownership

   .. automethod:: map_address
   .. automethod:: resolve

   .. automethod:: get_info
   .. automethod:: signal


Generic request
---------------

.. class:: Controller
   :no-index:

   .. automethod:: request
