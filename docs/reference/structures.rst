:tocdepth: 3

Structures
==========

.. currentmodule:: aiostem.structures

This package provides many common structures generally used in :class:`.Command`,
:class:`.Reply` or :class:`.Event`.


Common classes
--------------

.. autoclass:: AuthMethod
   :undoc-members:
   :members:

.. autoclass:: CircuitPurpose
   :undoc-members:
   :members:

.. autoclass:: CloseStreamReason
   :undoc-members:
   :members:

.. autoclass:: Feature
   :undoc-members:
   :members:

.. autoclass:: LivenessStatus
   :undoc-members:
   :members:

   .. automethod:: __bool__

.. autoclass:: LongServerName
   :no-show-inheritance:
   :special-members: __str__
   :undoc-members:
   :members:

.. autoclass:: LogSeverity
   :undoc-members:
   :members:

.. autoclass:: Signal
   :undoc-members:
   :members:

.. autoclass:: TcpAddressPort
   :no-show-inheritance:
   :special-members: __str__
   :undoc-members:
   :members:

.. autoclass:: VirtualPortTarget
   :no-show-inheritance:
   :undoc-members:
   :members:

.. autodata:: VirtualPort


Hidden services
---------------

.. autoclass:: HiddenServiceVersion
   :undoc-members:
   :members:

.. autoclass:: BaseHiddenServiceAddress
   :members:
.. autoclass:: HiddenServiceAddressV2
   :members:
.. autoclass:: HiddenServiceAddressV3
   :members:

.. autodata:: HiddenServiceAddress


Hidden Service structures
-------------------------

.. autoclass:: HsDescAction
   :undoc-members:
   :members:

.. autoclass:: HsDescAuthTypeInt
   :undoc-members:
   :members:

.. autoclass:: HsDescAuthTypeStr
   :undoc-members:
   :members:

.. autoclass:: HsDescAuthCookie
   :undoc-members:
   :members:

.. autoclass:: HsDescClientAuth
   :undoc-members:
   :members:

.. autodata:: HsDescClientAuthV2

.. autoclass:: HsDescFailReason
   :undoc-members:
   :members:

.. autoclass:: OnionClientAuthFlags
   :undoc-members:
   :members:

.. autoclass:: OnionClientAuthKey
   :no-show-inheritance:
   :undoc-members:
   :members:

.. autoclass:: OnionClientAuthKeyType
   :undoc-members:
   :members:

.. autoclass:: OnionServiceFlags
   :undoc-members:
   :members:

.. autoclass:: OnionServiceKeyType
   :undoc-members:
   :members:


Client status
-------------

These :func:`~dataclasses.dataclass` structures are specific for each action of each event.

.. autoclass:: StatusActionClient
   :members:

.. autoclass:: StatusClientBootstrap
   :no-show-inheritance:
   :undoc-members:
   :members:

.. autoclass:: StatusClientCircuitNotEstablished
   :no-show-inheritance:
   :undoc-members:
   :members:

.. autoclass:: StatusClientDangerousPort
   :no-show-inheritance:
   :undoc-members:
   :members:

.. autoclass:: StatusClientDangerousSocks
   :no-show-inheritance:
   :undoc-members:
   :members:

.. autoclass:: StatusClientSocksUnknownProtocol
   :no-show-inheritance:
   :undoc-members:
   :members:

.. autoclass:: StatusClientSocksBadHostname
   :no-show-inheritance:
   :undoc-members:
   :members:


Server status
-------------

.. autoclass:: ClockSkewSource
   :no-show-inheritance:
   :members:

.. autoclass:: StatusActionServer
   :members:

.. autoclass:: ExternalAddressResolveMethod
   :undoc-members:
   :members:

.. autoclass:: StatusServerExternalAddress
   :no-show-inheritance:
   :undoc-members:
   :members:

.. autoclass:: StatusServerCheckingReachability
   :no-show-inheritance:
   :undoc-members:
   :members:

.. autoclass:: StatusServerReachabilitySucceeded
   :no-show-inheritance:
   :undoc-members:
   :members:

.. autoclass:: StatusServerReachabilityFailed
   :no-show-inheritance:
   :undoc-members:
   :members:

.. autoclass:: StatusServerNameserverStatus
   :no-show-inheritance:
   :undoc-members:
   :members:

.. autoclass:: StatusServerBadServerDescriptor
   :no-show-inheritance:
   :undoc-members:
   :members:

.. autoclass:: StatusServerAcceptedServerDescriptor
   :no-show-inheritance:
   :undoc-members:
   :members:

.. autoclass:: StatusServerHibernationStatus
   :no-show-inheritance:
   :undoc-members:
   :members:


General status
--------------

.. autoclass:: StatusActionGeneral
   :members:

.. autoclass:: StatusGeneralBug
   :no-show-inheritance:
   :undoc-members:
   :members:

.. autoclass:: StatusGeneralClockJumped
   :no-show-inheritance:
   :undoc-members:
   :members:

.. autoclass:: StatusGeneralClockSkew
   :no-show-inheritance:
   :undoc-members:
   :members:

.. autoclass:: StatusGeneralDangerousVersionReason
   :undoc-members:
   :members:

.. autoclass:: StatusGeneralDangerousVersion
   :no-show-inheritance:
   :undoc-members:
   :members:

.. autoclass:: StatusGeneralTooManyConnections
   :no-show-inheritance:
   :undoc-members:
   :members:

