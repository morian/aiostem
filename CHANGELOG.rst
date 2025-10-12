=========
Changelog
=========

The format is based on `Keep a Changelog`_ and this project adheres to `Semantic Versioning`_.

.. _Keep a Changelog: https://keepachangelog.com/en/1.0.0/
.. _Semantic Versioning: https://semver.org/spec/v2.0.0.html


0.4.6 (2025-10-13)
==================

Added
-----
- Bring support for Python 3.14 released on october 7th, 2025.


0.4.5 (2025-09-02)
==================

Added
-----
- Brought back support for Python 3.10 as suggested by @Vizonex


0.4.4 (2025-05-04)
==================

Added
-----
- `CONFLUX_ID` and `CONFLUX_RTT` are now handled on `EventCirc`, following its implementation
  starting from Tor v0.4.8.15 (ticket 40872).


0.4.3 (2025-04-06)
==================

Fixed
-----
- Provide compatibility with `pydantic 2.11+` (which broke some structures).

Changed
-------
- Classes `Ed25519Certificate`, `BaseEd25519CertExtension`, `HsDescAuthCookie`, `LongServerName`,
  `TcpAddressPort` and their potential subclasses now inherit from `BaseModel`, switched from
  being a simple `dataclass`, needed following a change in pydantic.


0.4.2 (2025-03-16)
==================

Fixed
-----
- `HsDescV3`'s caches are now bound on instance to avoid memory leaks due to bad usage.


0.4.1 (2025-03-09)
==================

Added
-----
- `EncodedBase` and `EncoderProtocol` are now exported by `aiostem.utils`.

Changed
-------
- Enhanced discriminator for `HiddenServiceAddress`.
- Simplify pydantic schema for `TrGenericKey`.


0.4.0 (2025-02-01)
==================

This is a major rework of this library as the whole underlying implementation has changed.
All internal helpers were moved to `aiostem.utils` and were re-implemented, using pydantic_
for serialization, deserialization and data validation.

This refactoring breaks all previous APIs although the `Controller` stays quite familiar.

Added
-----
- Builders for all known commands as of ``Tor v0.4.8.13``
- Parsers for all events and replies as of ``Tor v0.4.8.13``
- Complete sphinx documentation with tutorials and examples
- First public release (both on Github and Pypi)
- Docstrings for all methods and structures
- Support for Python 3.13
- Test cases for all commands, methods and parsers

Changed
-------
- `Controller.event_unsubscribe` was renamed to `Controller.del_event_handler`
- `Controller.event_subscribe` was renamed to `Controller.add_event_handler`

Removed
-------
- Dependencies on aiofiles_ and stem_ were removed after refactoring
- The whole extra part of this library, including the `aiostem-hsscan` part
- Debian and ubuntu packages are no longer provided
- Dropped support for python 3.10 and lower

.. _aiofiles: https://pypi.org/project/aiofiles/
.. _pydantic: https://pypi.org/project/pydantic/
.. _stem: https://stem.torproject.org/


0.3.1 (2024-02-04)
==================

Fixed
-----
- Fix request hanging after Controller disconnects

Updated
-------
- Use an `AsyncExitStack` to handle the context manager
- Be more strict in coding style thanks to ruff_'s strictness


0.3.0 (2024-01-28)
==================

Added
-----
- Add a Monitor helper class to check Tor status

Updated
-------
- Improved code coverage

Removed
-------
- Drop support for Debian 11
- Drop support for python 3.9


0.2.10 (2024-01-21)
===================

Updated
-------
- `hsscan` now set tor controller as active before running scans
- Message can now take one or multiple lines as argument
- Python tasks now have names and cancel reasons
- Greatly improve tests and code coverage

Removed
-------
- Removed the EXTENDED flag on `SETEVENTS` (deprecated by Tor)


0.2.9 (2023-10-08)
===================

Added
-----
- Added support for Python 3.12

Fixed
-----
- Fix bad license classifier in project
- Many typing and linting issues

Updated
-------
- Use ruff_ as a linter!

.. _ruff: https://docs.astral.sh/ruff/


0.2.8 (2022-11-20)
===================

Fixed
-----
- Added missing exports for some event entries


0.2.7 (2022-10-25)
===================

Added
-----
- Compatibility with Python 3.11
- Added support for `DROPGUARDS` command


0.2.6 (2022-04-17)
==================

Fixed
-----
- Restore compatibility with python 3.7


0.2.5 (2022-04-13)
==================

Added
-----
- Add support for `SETCONF` command


0.2.4 (2022-03-06)
==================

Added
-----
- Add a way to parse keyword arguments with a whole line in messages


0.2.3 (2022-02-21)
==================

Added
-----
- Add controller support for `GETCONF` commands
- Rename question to query and response to reply in the API


0.2.2 (2022-02-20)
==================

Updated
-------
- Controller now accepts both synchronous and asynchronous event callbacks


0.2.1 (2022-01-21)
==================

Fixed
-----
- Packaging that was excluding the whole library


0.2.0 (2022-01-21)
==================

Added
-----
- Added some automated tests and coverage (also fixes a few bugs)
- Added support for `GETINFO` commands (rewrote the message parser)

Misc
----
- General code quality improved thanks to multiple linters


0.1.2 (2021-09-19)
==================

Added
-----
- Add compatibility with Python 3.9

Updated
-------
- Updated the build system
