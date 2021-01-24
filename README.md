Asynchronous Tor controller library for asyncio and Python.

[[_TOC_]]


# Installation

Aiostem was tested successfully with Python 3.7 and Python 3.8.

The best way to install it is by creating a dedicated `virtualenv` using the `virtualenv`
package from python. Note that this might require the installation of distribution specific
packages such as `python3-virtualenv` or `python3-pip`.

First create the target `virtualenv` and source the environment:
```console
$ python3 -m virtualenv venv/
$ source venv/bin/activate
```

Then you can install Aiostem inside the environment from the wheel package, source distribution
or from sources using `setup.py` (provided):

```console
(venv) $ pip install dist/aiostem-*.whl
```

```console
(venv) $ pip install .
```

Should anything fail at this point, and still within the container you can install the exact
dependencies that were used during the development phase and provided in `requirements.txt`:

```console
(venv) $ pip -r requirements.txt
```

