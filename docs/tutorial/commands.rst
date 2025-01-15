03. Run commands
================

.. currentmodule:: aiostem

We now have a working and authenticated controller, this means that we can run commands
and get the appropriate results. This chapter aims to play with some useful commands and
find out how to deal with them.

All commands have an immediate reply and are thus synchronous with the daemon.
When a command cannot reply immediately (such as :meth:`.Controller.resolve`), its result
is sent as an :class:`.Event` (more on this on the next chapter).

An index of all commands is available on :class:`.CommandWord`, each documented with the
controller method, the command structure and the associated reply.


Read configuration options
--------------------------

Let's begin with a simple and useful command, implemented on the controller on
:meth:`~.Controller.get_conf`, which allows for reading on configuration values.
This method builds a :class:`.CommandGetConf` object out of the provided arguments,
and pass it to :meth:`.Controller.request` which serializes the command using
:meth:`.Command.serialize`. A matching :class:`.ReplyGetConf` is received and de-serialized
from Tor, and then provided back to the caller.

.. literalinclude:: ../../examples/get_conf.py
   :caption: examples/get_conf.py
   :emphasize-lines: 18
   :linenos:

Now we can execute the provided code as follow:

.. code-block:: console

   $ python examples/get_conf.py ControlPort ControlSocket
   [>] Connecting to localhost on port 9051
   ControlPort=0.0.0.0:9051
   ControlSocket=/run/tor/control WorldWritable RelaxDirModeCheck

Replies for :attr:`~.CommandWord.GETCONF` and :attr:`~.CommandWord.GETINFO` behave as a
dictionary, which means that you can get the values directly from the reply object itself.
Note that multiple values can be returned for a configuration option, because configuration
entries can be provided more than once, and can be requested more than once too.

Also note that we always check for the reply status after running a command, in case Tor does
not like what we provided. Some status helpers are provided by the :class:`.BaseReply` class.


Read server information
-----------------------

Here is another useful command, that is used to read internal values from Tor, and implemented
through :meth:`.Controller.get_info` (using :class:`.CommandGetInfo`), and returning
:class:`.ReplyGetInfo`.

Tor provides a `list of recognized keys`_ so we know what to ask using this method, alternatively
you can also use :meth:`~.Controller.get_info` with the argument ``info/names``.

.. _list of recognized keys: https://spec.torproject.org/control-spec/commands.html#getinfo

.. literalinclude:: ../../examples/get_info.py
   :caption: examples/get_info.py
   :emphasize-lines: 18
   :linenos:

Now we can execute the provided code as follow:

.. code-block:: console

   $ python examples/get_info.py uptime events/names features/names signal/names status/version/recommended
   [>] Connecting to localhost on port 9051
   uptime=5979001
   events/names=CIRC CIRC_MINOR STREAM ORCONN BW DEBUG INFO NOTICE WARN ERR NEWDESC ADDRMAP DESCCHANGED NS STATUS_GENERAL STATUS_CLIENT STATUS_SERVER GUARD STREAM_BW CLIENTS_SEEN NEWCONSENSUS BUILDTIMEOUT_SET SIGNAL CONF_CHANGED CONN_BW CELL_STATS CIRC_BW TRANSPORT_LAUNCHED HS_DESC HS_DESC_CONTENT NETWORK_LIVENESS
   features/names=VERBOSE_NAMES EXTENDED_EVENTS
   signal/names=RELOAD HUP SHUTDOWN DUMP USR1 DEBUG USR2 HALT TERM INT NEWNYM CLEARDNSCACHE HEARTBEAT ACTIVE DORMANT
   status/version/recommended=0.4.8.4,0.4.8.5,0.4.8.6,0.4.8.7,0.4.8.8,0.4.8.9,0.4.8.10,0.4.8.11,0.4.8.12,0.4.8.13,0.4.9.1-alpha
   net/listeners/socks="0.0.0.0:9050" "unix:/run/tor/socks"


.. code-block:: console

   $ python examples/get_info.py md/name/moria1 version
   [>] Connecting to localhost on port 9051
   md/name/moria1=
   onion-key
   -----BEGIN RSA PUBLIC KEY-----
   MIGJAoGBAOO0/GtV+HDARgSJPw+aVDqjoFghsboxzyk1VRasc9Z+va5xdpeSMrNp
   GCmzvRmQq2wPJCh/TNRU6ykbgCHr4+HGg0uXx2yoEy7Nw3BZYXrCeBpFwzCM/2Gp
   xu+I3zVjLop/ivTNkve9D24DAeud2jpVqhQibV5SNRsQTozMXO0/AgMBAAE=
   -----END RSA PUBLIC KEY-----
   ntor-onion-key C33fH78uZcMwWu9TrOa4WjhQXdqD0ScmjsAxL1kBjVo
   id ed25519 qpL/LxLYVEXghU76iG3LsSI/UW7MBpIROZK0AB18560
   
   version=0.4.8.12

Note that all gathered values are provided as strings and are never interpreted.
While this may change in the future, implementing, parsing and keeping up with the new keys
is a lot of work!


Create an onion service
-----------------------

Now we'll cover a more complex command, implemented in the controller
by :meth:`~.Controller.add_onion`, using :class:`.CommandAddOnion` and getting back
a :class:`.ReplyAddOnion` object. This command is a little bit different from the others
already covered here since it uses and returns complex structures.

First let's start with a simple working example:

.. literalinclude:: ../../examples/add_onion.py
   :caption: examples/add_onion.py
   :emphasize-lines: 20,21
   :linenos:

This is what the output looks like when running this command:

.. code-block:: console

   $ ./examples/add_onion.py 80,127.0.0.1:80
   [>] Connecting to localhost on port 9051
   Running port forwards on msqlioga6iyclapyjccuxtwfu6763gb3uqgqfiq3q64jefr4cupznead.onion
   > Press enter to stop the service

The onion domain here is not persisted, that's why it only works while the script is running.
The argument means that we want our port 80 on the onion domain to be redirected on port 80
on localhost (multiple redirections can be provided here). The onion domain is generated, either
by Tor or by the library itself due to cryptography differences between Tor and ``aiostem`` on
ed25519 signing keys.

Now let's see how we can use alternative parameters, first for the onion key.
We provided ``NEW:BEST`` which means that we want a new key with the best available algorithm.
We could have written the following code instead, using :class:`.OnionServiceNewKeyStruct`:

.. code-block:: python

   from aiostem.structures import OnionServiceNewKeyStruct
   ...

   async def main():
       ....
       async with Controller.from_port(host, int(port)) as ctrl:
           ...
           key = OnionServiceNewKeyStruct('BEST')
           reply = await ctrl.add_onion(key, sys.argv[1:])

Instead of ``BEST`` we could also use an entry from :class:`.OnionServiceKeyType`.

Alternatively, we can also provide a specific key, either generated or loaded using
:class:`~cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PrivateKey`:

.. code-block:: python

   from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
   ...

   async def main():
       ....
       async with Controller.from_port(host, int(port)) as ctrl:
           ...
           key = Ed25519PrivateKey.generate()
           reply = await ctrl.add_onion(key, sys.argv[1:])


The same logic applies for :class:`.VirtualPortTarget`, which is a structured way
to set the list of redirections for the new onion we are building:

.. code-block:: python

   from ipaddress import IPv4Address
   from aiostem.structures import TcpAddressPort, VirtualPortTarget
   ...

   async def main():
       ....
       async with Controller.from_port(host, int(port)) as ctrl:
           ...
           key = 'NEW:BEST'
           targets = [
               VirtualPortTarget(
                   port=80,
                   target=TcpAddressPort(
                       host=IPv4Address('127.0.0.1'),
                       port=80,
                   ),
               ),
           ]
           reply = await ctrl.add_onion(key, targets)

