02. Authentication
==================

.. currentmodule:: aiostem

First off, there are roughly three commands you can use without being authenticated.
You can either :meth:`~.Controller.authenticate`, :meth:`~.Controller.protocol_info` or
:meth:`~.Controller.quit`.


Authentication methods
----------------------

:meth:`.Controller.protocol_info`, when successful provides a :class:`.ReplyProtocolInfo`,
which contains important authentication information, such as the list of authorized
authentication methods and the path to the cookie file used in most of these authentication
methods.

Configuration for authentication methods is quite out of our scope here, but feel free
to take a look at the `torrc manpage`_, especially options ``HashedControlPassword`` and
``CookieAuthentication``. Password hash can be generated with the following command:

.. _torrc manpage: https://manpages.debian.org/bookworm/tor/torrc.5.en.html

.. code-block:: console

   $ tor --hash-password aiostem
   16:431FE41EE9A6D2D8600C0F92F71A03D0A8C4E40EC1BBCC84716C95F022


The following code can be used to list available authentication methods
for the target Tor daemon, and the cookie file used for :attr:`~.AuthMethod.COOKIE`
and :attr:`~.AuthMethod.SAFECOOKIE`. It uses :meth:`.Controller.protocol_info` to get
this information.

The full list of known authentication methods is documented on :class:`.AuthMethod`.

.. literalinclude:: ../../examples/authentication_listing.py
   :caption: examples/authentication_listing.py
   :linenos:

Note here that we use :meth:`~.BaseReply.raise_for_status` here to ensure that the
command was successful before we go on with :attr:`.ReplyProtocolInfo.data`.

This code, when executed provides an output such as follows:

.. code-block:: console

   $ python examples/authentication_listing.py
   [>] Connecting to localhost on port 9051
   [+] List of allowed authentication methods:
    * COOKIE
    * SAFECOOKIE
    * HASHEDPASSWORD
   [+] Path to the cookie file: /run/tor/control.authcookie


Password authentication
-----------------------

This method covers :attr:`.AuthMethod.HASHEDPASSWORD` and is the one related to
``HashedControlPassword`` from the configuration file.
This is the only secure available method when dealing with Tor running on a remote host.

The following code authenticates with a password using :meth:`.Controller.authenticate`:

.. literalinclude:: ../../examples/authenticate_with_password.py
   :caption: examples/authenticate_with_password.py
   :emphasize-lines: 14
   :linenos:

You can set the password directly from the environment:

.. code-block:: console

   $ AIOSTEM_PASS=aiostem python examples/authenticate_with_password.py
   [>] Connecting to localhost on port 9051
   [+] Authentication successful!

You can also check that when a wrong password is supplied,
:meth:`~.BaseReply.raise_for_status` raises a :exc:`.ReplyStatusError` error with
a meaningful message (provided by Tor).


Cookie file authentication
--------------------------

:meth:`.Controller.authenticate` does more under the hood. First it calls
:meth:`.Controller.protocol_info` and get the list of available authentication methods.

Then, depending on the available methods, its behavior changes:

- When :attr:`~.AuthMethod.NULL` is available, it does the authentication by itself.
- When a password is supplied and :attr:`~.AuthMethod.HASHEDPASSWORD` is available,
  a password authentication is performed and the password is transmitted in clear-text.
- Otherwise, it first tries :attr:`~.AuthMethod.SAFECOOKIE` if available, or
  :attr:`~.AuthMethod.COOKIE`.

:attr:`~.AuthMethod.COOKIE` is a simple proof that we can read the file located at
:attr:`.ReplyDataProtocolInfo.auth_cookie_file`, by transmitting its content.

:attr:`~.AuthMethod.SAFECOOKIE` uses a HMAC so we can provide a proof that we have read the
file content without transmitting the content itself. For this to work,
:meth:`~.Controller.authenticate` calls :meth:`~.Controller.auth_challenge` under the hood
with a random nonce generated using :func:`secrets.token_bytes`. The server hash is then
checked using :attr:`.ReplyDataAuthChallenge.raise_for_server_hash_error` and eventually
client authentication is performed.

In the end, any password-less authentication can be performed with the following code:

.. literalinclude:: ../../examples/authenticate_without_password.py
   :caption: examples/authenticate_without_password.py
   :emphasize-lines: 13
   :linenos:

Note that your user obviously requires the proper permissions to read the cookie file.
You can use a group-readable cookie file using ``CookieAuthFileGroupReadable`` in ``torrc``.
