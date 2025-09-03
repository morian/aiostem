# Based off stem.util.system

from __future__ import annotations

import asyncio
import enum
import os
import platform
import threading
from typing import TYPE_CHECKING, Any, overload
from functools import lru_cache
from ..types import _T

if TYPE_CHECKING:
    from pathlib import Path


# Sentinal Value for call function
_UNDEFINED = enum.Enum('_UNDEFINED', 'UNDEFINED')
UNDEFINED = _UNDEFINED.UNDEFINED

class CallError(OSError):
    """
    Error response when making a system call. This is an **OSError** subclass
    with additional information about the process. Depending on the nature of the
    error not all of these attributes will be available.

    :var str msg: exception string
    :var str command: command that was ran
    :var int exit_status: exit code of the process
    :var float runtime: time the command took to run
    :var str stdout: stdout of the process
    :var str stderr: stderr of the process
    """

    __slots__ = ('msg', 'command', 'exit_status', 'runtime', 'stdout', 'stderr')

    def __init__(
        self,
        msg: str,
        command: str,
        exit_status: int,
        runtime: float,
        stdout: str,
        stderr: str,
    ):
        self.msg = msg
        self.command = command
        self.exit_status = exit_status
        self.runtime = runtime
        self.stdout = stdout
        self.stderr = stderr

    def __str__(self):
        return self.msg


def is_windows():
    """
    Checks if we are running on Windows.

    :returns: **bool** to indicate if we're on Windows
    """

    return platform.system() == 'Windows'


def is_mac():
    """
    Checks if we are running on Mac OSX.

    :returns: **bool** to indicate if we're on a Mac
    """

    return platform.system() == 'Darwin'


def is_gentoo():
    """
    Checks if we're running on Gentoo.

    :returns: **bool** to indicate if we're on Gentoo
    """

    return os.path.exists('/etc/gentoo-release')


def is_slackware():
    """
    Checks if we are running on a Slackware system.

    :returns: **bool** to indicate if we're on a Slackware system
    """

    return os.path.exists('/etc/slackware-version')


def is_bsd():
    """
    Checks if we are within the BSD family of operating systems. This currently
    recognizes Macs, FreeBSD, and OpenBSD but may be expanded later.

    :returns: **bool** to indicate if we're on a BSD OS
    """

    return platform.system() in ('Darwin', 'FreeBSD', 'OpenBSD', 'NetBSD')


# Overloads for typehinting when SENTINAL value is in use.
@overload
async def call(
    command: str | list[str],
    default: _T,
    ignore_exit_status: bool = False,
    timeout: float | None = None,
    cwd: bytes | str | 'Path' | None = None,
    env: dict[str, Any] | None = None,
) -> _T | list[str]: ...


@overload
async def call(
    command: str | list[str],
    default: _UNDEFINED,
    ignore_exit_status: bool = False,
    timeout: float | None = None,
    cwd: bytes | str | 'Path' | None = None,
    env: dict[str, Any] | None = None,
) -> list[str]: ...


async def call(
    command: str | list[str],
    default: _UNDEFINED | _T = _UNDEFINED,
    ignore_exit_status: bool = False,
    timeout: float | None = None,
    cwd: bytes | str | 'Path' | None = None,
    env: dict[str, Any] | None = None,
) -> _T | list[str]:
    """
    Issues a command in a subprocess, blocking until completion and returning the
    results. This is not actually ran in a shell so pipes and other shell syntax
    are not permitted.

    :param str,list command: command to be issued
    :param object default: response if the query fails
    :param bool ignore_exit_status: reports failure if our command's exit status
        was non-zero
    :param float timeout: maximum seconds to wait, blocks indefinitely if
        **None**
    :param dict env: environment variables

    :returns: **list** with the lines of output from the command

    :raises:
    * **CallError** if this fails and no default was provided
    * **asyncio.TimeoutError** if the timeout is reached without a default
    """
    loop = asyncio.get_event_loop()

    if isinstance(command, str):
        command_list = command.split(' ')
    else:
        command_list = list(map(str, command))

    exit_status, runtime, stdout, stderr = None, None, None, None
    start_time = loop.time()

    try:
        is_shell_command = command_list[0] == 'ulimit'

        process = await (
            asyncio.subprocess.create_subprocess_exec(
                *command_list,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=cwd,
                env=env,
            )
            if is_shell_command
            else asyncio.subprocess.create_subprocess_shell(
                ' '.join(command) if isinstance(command, list) else command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=cwd,
                env=env,
            )
        )

        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout)
        stdout, stderr = stdout.strip(), stderr.strip()
        runtime = loop.time() - start_time

        exit_status = await process.wait()

        if not ignore_exit_status and exit_status != 0:
            raise OSError('%s returned exit status %i' % (command, exit_status))

        if stdout:
            return stdout.decode('utf-8', 'replace').splitlines()
        else:
            return []

    # There really isn't a point to using CallTimeoutError since
    # it seems that was just a python 2 backport.
    except TimeoutError:
        if default != UNDEFINED:
            return default
        else:
            raise

    except OSError as exc:
        if default != UNDEFINED:
            return default
        else:
            raise CallError(
                str(exc), ' '.join(command_list), exit_status, runtime, stdout, stderr
            )



CMD_AVAILABLE_CACHE = {}

def _is_available(command:str):

    if ' ' in command:
        command = command[:command.find(' ')]

    if command == 'ulimit':
        return True  # we can't actually look it up, so hope the shell really provides it...
    elif 'PATH' not in os.environ:
        return False  # lacking a path will cause find_executable() to internally fail

    cmd_exists = False

    for path in os.environ['PATH'].split(os.pathsep):
        cmd_path = os.path.join(path, command)

        if is_windows() and not cmd_path.endswith('.exe'):
            cmd_path += '.exe'

        if os.path.exists(cmd_path) and os.access(cmd_path, os.X_OK):
            cmd_exists = True
            break

    return cmd_exists

lru_is_avalible = lru_cache(typed=False, maxsize=128)(_is_available)

# XXX: _is_available is not entirely async so we need to thread it.

async def is_avalible(command:str, cached:bool = True):
    """
    Checks the current PATH to see if a command is available or not. If more
    than one command is present (for instance "ls -a | grep foo") then this
    just checks the first.

    Note that shell (like cd and ulimit) aren't in the PATH so this lookup will
    try to assume that it's available. This only happends for recognized shell
    commands (those in SHELL_COMMANDS).

    :param str command: command to search for
    :param bool cached: makes use of available cached results if **True**

    :returns: **True** if an executable we can use by that name exists in the
      PATH, **False** otherwise
    """
    return await asyncio.to_thread(_is_available if not cached else lru_is_avalible, command=command)



