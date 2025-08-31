import asyncio
import os
import sys
from shlex import split
from typing import Any, Optional, Union

import async_timeout

UNDEFINED = '<Undefined_ >'

PIPE = asyncio.subprocess.PIPE


class CallError(Exception):
    pass


async def call(
    command: Union[str, list[str]],
    # To remain asynchronous and threadsafe I just moved the whole string in here
    default='<Undefined_ >',
    ignore_exit_status=False,
    timeout: Optional[int] = None,
    cwd: Optional[Union[str, bytes]] = None,
    env: Optional[dict[str, Any]] = None,
):
    """
    call(command, default = UNDEFINED, ignore_exit_status = False)

    Issues a command in a subprocess, blocking until completion and returning the
    results. This is not actually ran in a shell so pipes and other shell syntax
    are not permitted.

    .. versionchanged:: 1.5.0
       Providing additional information upon failure by raising a CallError. This
       is a subclass of OSError, providing backward compatibility.

    .. versionchanged:: 1.5.0
       Added env argument.

    .. versionchanged:: 1.6.0
       Added timeout and cwd arguments.

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
      * **TimeoutError** if the timeout is reached without a default via async_timeout
    """

    if isinstance(command, str):
        command_list = split(command, posix=False)
    else:
        command_list = list(map(str, command))

    process = exit_status = stdout = stderr = None
    try:
        if command_list[0] == 'ulimit':
            process = await asyncio.subprocess.create_subprocess_shell(
                command_list, stdout=PIPE, stderr=PIPE, cwd=cwd, env=env, shell=True
            )
        else:
            process = await asyncio.subprocess.create_subprocess_exec(
                *command_list,
                stdout=PIPE,
                stderr=PIPE,
                cwd=cwd,
                env=env,
                shell=False,
            )
        async with async_timeout.timeout(timeout):
            stdout, stderr = await process.communicate()
        stdout, stderr = stdout.strip(), stderr.strip()

        exit_status = await process.wait()
        if not ignore_exit_status and exit_status != 0:
            raise OSError('%s returned exit status %i' % (command, exit_status))

        return stdout.decode('utf-8', 'replace').splitlines() if stdout else []
    except Exception as exc:
        if not process.returncode:
            # TimeoutError if no returncode so we kill instead
            process.kill()

        if default == '<Undefined_ >':
            raise CallError(str(exc), ' '.join(command_list), exit_status) from exc
        else:
            return default


CMD_AVAILABLE_CACHE = {}


def is_available(command: str, cached: bool = True):
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

    if ' ' in command:
        command = command[: command.find(' ')]

    if command == 'ulimit':
        return True  # we can't actually look it up, so hope the shell really provides it...
    elif cached and command in CMD_AVAILABLE_CACHE:
        return CMD_AVAILABLE_CACHE[command]
    elif 'PATH' not in os.environ:
        return False  # lacking a path will cause find_executable() to internally fail

    cmd_exists = False

    for path in os.environ['PATH'].split(os.pathsep):
        cmd_path = os.path.join(path, command)

        if sys.platform == 'win32' and not cmd_path.endswith('.exe'):
            cmd_path += '.exe'

        if os.path.exists(cmd_path) and os.access(cmd_path, os.X_OK):
            cmd_exists = True
            break

    CMD_AVAILABLE_CACHE[command] = cmd_exists
    return cmd_exists
