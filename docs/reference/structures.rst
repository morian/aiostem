:tocdepth: 3

Structures
==========

.. currentmodule:: aiostem.structures

This package provides many common structures generally used in :class:`.Command`,
:class:`.Reply` or :class:`.Event`.


Enumerations
------------

These classes are used to enumerate various items such as list of purposes, error reasons,
available flags, authentication methods, etc...

.. autoclass:: AuthMethod
   :undoc-members:
   :members:

.. autoclass:: CircuitBuildFlags
   :undoc-members:
   :members:

.. autoclass:: CircuitCloseReason
   :undoc-members:
   :members:

.. autoclass:: CircuitEvent
   :undoc-members:
   :members:

.. autoclass:: CircuitHiddenServiceState
   :undoc-members:
   :members:

.. autoclass:: CircuitPurpose
   :undoc-members:
   :members:

.. autoclass:: CircuitStatus
   :undoc-members:
   :members:

.. autoclass:: OrConnCloseReason
   :undoc-members:
   :members:

.. autoclass:: DescriptorPurpose
   :undoc-members:
   :members:

.. autoclass:: Feature
   :undoc-members:
   :members:

.. autoclass:: GuardEventStatus
   :undoc-members:
   :members:

.. autoclass:: LivenessStatus
   :undoc-members:
   :members:

.. autoclass:: LogSeverity
   :undoc-members:
   :members:

.. autoclass:: RemapSource
   :undoc-members:
   :members:

.. autoclass:: RouterFlags
   :undoc-members:
   :members:

.. autoclass:: Signal
   :undoc-members:
   :members:

.. autoclass:: StreamClientProtocol
   :undoc-members:
   :members:

.. autoclass:: StreamCloseReason
   :undoc-members:
   :members:

.. autoclass:: StreamCloseReasonInt
   :undoc-members:
   :members:

.. autoclass:: StreamPurpose
   :undoc-members:
   :members:

.. autoclass:: StreamStatus
   :undoc-members:
   :members:

   .. automethod:: __bool__


Helper classes
--------------

These are annotated structures generally built from a single string.

.. autoclass:: LongServerName
   :no-show-inheritance:
   :special-members: __str__
   :undoc-members:
   :members:

.. autoclass:: PortPolicy
   :no-show-inheritance:
   :undoc-members:
   :members:

.. autoclass:: PortRange
   :no-show-inheritance:
   :undoc-members:
   :members:

.. autoclass:: RouterStatus
   :no-show-inheritance:
   :undoc-members:
   :members:

.. autoclass:: StreamTarget
   :no-show-inheritance:
   :undoc-members:
   :members:

.. autoclass:: TcpAddressPort
   :no-show-inheritance:
   :special-members: __str__
   :undoc-members:
   :members:

.. autoclass:: VersionRange
   :no-show-inheritance:
   :undoc-members:
   :members:

.. autoclass:: VirtualPortTarget
   :no-show-inheritance:
   :undoc-members:
   :members:

.. autodata:: VirtualPort


Ed25519 certificates
--------------------

.. autoclass:: Ed25519Certificate
   :undoc-members:
   :members:

.. autoclass:: Ed25519CertificateV1
   :undoc-members:
   :members:

.. autoclass:: Ed25519CertPurpose
   :undoc-members:
   :members:

.. autoclass:: Ed25519CertExtensionFlags
   :members:
.. autoclass:: Ed25519CertExtensionType
   :members:

.. autoclass:: BaseEd25519CertExtension
   :members:

.. autoclass:: Ed25519CertExtensionSigningKey
   :members:

.. autoclass:: Ed25519CertExtensionUnkown
   :members:


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

.. autoclass:: HsDescBase
   :no-show-inheritance:
   :members:

.. autoclass:: HsDescClientAuth
   :undoc-members:
   :members:

.. autodata:: HsDescClientAuthV2

.. autodata:: HsDescClientAuthV3

.. autoclass:: HsDescV2
   :undoc-members:
   :members:

.. autoclass:: HsDescV3
   :undoc-members:
   :members:

.. autoclass:: HsDescV3AuthClient
   :undoc-members:
   :members:

.. autoclass:: HsDescV3FlowControl
   :undoc-members:
   :members:

.. autoclass:: HsDescV3Layer
   :undoc-members:
   :members:

.. autoclass:: HsDescV3Layer1
   :undoc-members:
   :members:

.. autoclass:: HsDescV3Layer2
   :undoc-members:
   :members:

.. autoclass:: HsDescFailReason
   :undoc-members:
   :members:

.. autoclass:: HsIntroPointV2
   :undoc-members:
   :members:

.. autoclass:: HsIntroPointV3
   :undoc-members:
   :members:

.. autoclass:: OnionClientAuthKeyStruct
   :no-show-inheritance:
   :undoc-members:
   :members:

.. autoclass:: OnionClientAuth
   :no-show-inheritance:
   :undoc-members:
   :members:

.. autoclass:: OnionClientAuthFlags
   :undoc-members:
   :members:

.. autoclass:: OnionClientAuthKeyType
   :undoc-members:
   :members:

.. autoclass:: OnionRouterConnStatus
   :undoc-members:
   :members:

.. autoclass:: OnionServiceFlags
   :undoc-members:
   :members:

.. autoclass:: OnionServiceKeyType
   :undoc-members:
   :members:

.. autoclass:: OnionServiceKeyStruct
   :no-show-inheritance:
   :undoc-members:
   :members:

.. autoclass:: OnionServiceNewKeyStruct
   :no-show-inheritance:
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


Reply data
----------

These are directly part of the replies when a command has been successful.

.. autoclass:: ReplyDataAddOnion
   :no-show-inheritance:
   :members:

.. autoclass:: ReplyDataAuthChallenge
   :no-show-inheritance:
   :members:

.. autoclass:: ReplyDataExtendCircuit
   :no-show-inheritance:
   :members:

.. autoclass:: ReplyDataMapAddressItem
   :no-show-inheritance:
   :members:

.. autoclass:: ReplyDataOnionClientAuthView
   :no-show-inheritance:
   :members:

.. autoclass:: ReplyDataProtocolInfo
   :no-show-inheritance:
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

