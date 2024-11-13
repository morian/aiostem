Dependencies
============

.. _dependencies:


Runtime dependencies
--------------------

``aiostem`` would not be possible withou the following great projects:

- `cryptography`_: to encrypt and decrypt descriptors and many other things
- `pydantic`_: to convert and validate data received from the controller

.. _cryptography: https://github.com/pyca/cryptography
.. _pydantic: https://github.com/pydantic/pydantic


Development dependencies
------------------------

.. literalinclude:: ../../tests/requirements-linting.txt
   :caption: Linting requirements
   :language: text

.. literalinclude:: ../../tests/requirements-testing.txt
   :caption: Testing requirements
   :language: text

.. literalinclude:: ../../docs/requirements.txt
   :caption: Documentation requirements
   :language: text
