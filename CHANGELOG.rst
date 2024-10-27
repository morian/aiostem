=========
Changelog
=========

The format is based on `Keep a Changelog`_ and this project adheres to `Semantic Versioning`_.

.. _Keep a Changelog: https://keepachangelog.com/en/1.0.0/
.. _Semantic Versioning: https://semver.org/spec/v2.0.0.html


0.4.0 (UNRELEASED)
==================

Added
-----
- Added a premilinary sphinx documentation
- Added support for Python 3.13
- Many docstrings for all common APIs

Removed
-------
- Drop support for python 3.10 and lower


0.3.1 (2024-02-04)
==================

Fixed
-----
- Fix request hanging aftrer Controller disconnect

Updated
-------
- Use an `AsyncExitStack` to handle the context manager
- Be more strict in coding style thanks to ruff's strictness


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
- hsscan now set tor controller as active before running scans
- Message can now take one or multiple lines as argument
- Python tasks now have names and cancel reasons
- Greatly improve tests and code coverage

Removed
-------
- Remove EXTENDED flag on SETEVENTS (deprecated by Tor)


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
- Use `ruff` as a linter!


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
