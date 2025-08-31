"""
Helper functions for working with tor as a process.

:NO_TORRC:
  when provided as a torrc_path tor is ran with a blank configuration

:DEFAULT_INIT_TIMEOUT:
  number of seconds before we time out our attempt to start a tor instance

**Module Overview:**

::

  launch_tor             - starts up a tor process
  launch_tor_with_config - starts a tor process with a custom torrc
"""

# Copyright 2011-2019, Damian Johnson and The Tor Project
# See LICENSE for licensing information

# Modified by Vizonex, 2025

from __future__ import annotations

import asyncio
import os
import re
import tempfile
import typing as t  # Only reason for "t" prefix is due to the number of objects needed.
from contextlib import suppress
from functools import wraps

import async_timeout
from aiofiles import open as aopen
from aiosignal import Signal

from . import system, version

if t.TYPE_CHECKING:
    from types import TracebackType

    from .types import P

NO_TORRC = '<no torrc>'
DEFAULT_INIT_TIMEOUT = 90


class MessageHandler:
    """
    A Special handler for aiosteam for
    handling callbacks related to launching tor.
    """

    def __init__(self) -> None:
        """Initalizes MessageHandler."""
        self._on_message: Signal[str] = Signal(self)

    @property
    def on_message(self):
        """
        Called when a message is being sent from launching tor::

            from aiostem.process import launch_tor_with_config, MessageHandler

            events = MessageHandler()

            @events.on_message
            async def on_message(msg:str):
                print(f"message: {msg}")

            events.freeze()

        """
        return self._on_message

    @property
    def frozen(self) -> bool:
        """Determines if events were already frozen."""
        return self._on_message.frozen

    def freeze(self) -> None:
        """Freezes the events."""
        self.on_message.freeze()

    async def send(self, msg: str) -> None:
        """Sends message to different events if provided."""
        return await self.on_message.send(msg)


Process = asyncio.subprocess.Process


class _ProcessContextManager(t.Coroutine[t.Any, t.Any, Process]):
    """Inspired by aiohttp's technqiues but for handling tor processes."""

    __slots__ = ('_coro', '_resp')

    def __init__(self, coro: t.Coroutine[asyncio.Future[t.Any], None, Process]) -> None:
        self._coro: t.Coroutine[asyncio.Future[t.Any], None, Process] = coro

    def send(self, arg: None) -> asyncio.Future[t.Any]:
        return self._coro.send(arg)

    def throw(self, *args: t.Any, **kwargs: t.Any) -> asyncio.Future[Process]:
        return self._coro.throw(*args, **kwargs)

    def close(self) -> None:
        return self._coro.close()

    def __await__(self) -> t.Generator[t.Any, None, Process]:
        return self._coro.__await__()

    def __iter__(self) -> t.Generator[t.Any, None, Process]:
        return self.__await__()

    async def __aenter__(self) -> Process:
        self._resp: Process = await self._coro
        return self._resp

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        # Terminate even if process was already finished beforehand.
        with suppress(Exception):
            self._resp.terminate()


def _wrap_process(
    func: t.Callable[P, t.Coroutine[t.Any, t.Any, asyncio.subprocess.Process]],
):
    """
    Wrap a process launching function to be used via await
    or asynchronous context manager.
    """

    @wraps(func)
    def wrapper(*args: P.args, **kwargs: P.kwargs) -> _ProcessContextManager:
        return _ProcessContextManager(func(*args, **kwargs))

    return wrapper


@_wrap_process
async def launch_tor(
    tor_cmd: str = 'tor',
    args: list[str] | None = None,
    torrc_path: str | None = None,
    completion_percent: int = 100,
    init_msg_handler: MessageHandler | None = None,
    timeout: float | None = DEFAULT_INIT_TIMEOUT,
    take_ownership: bool = False,
    close_output: bool = True,
    stdin: str | bytes | None = None,
) -> Process:
    """
    Initializes a tor process. This blocks until initialization completes or we
    error out.

    If tor's data directory is missing or stale then bootstrapping will include
    making several requests to the directory authorities which can take a little
    while. Usually this is done in 50 seconds or so, but occasionally calls seem
    to get stuck, taking well over the default timeout.

    **To work to must log at NOTICE runlevel to stdout.** It does this by
    default, but if you have a 'Log' entry in your torrc then you'll also need
    'Log NOTICE stdout'.

    Note: The timeout argument does not work on Windows or when outside the
    main thread, and relies on the global state of the signal module.

    .. versionchanged:: 1.6.0
       Allowing the timeout argument to be a float.

    .. versionchanged:: 1.7.0
       Added the **close_output** argument.

    :param str tor_cmd: command for starting tor
    :param list args: additional arguments for tor
    :param str torrc_path: location of the torrc for us to use
    :param int completion_percent: percent of bootstrap completion at which
      this'll return
    :param MessageHandler | None init_msg_handler: optional functor that will be provided with
      tor's initialization stdout as we get it
    :param int timeout: time after which the attempt to start tor is aborted, no
      timeouts are applied if **None**
    :param bool take_ownership: asserts ownership over the tor process so it
      aborts if this python process terminates or a :class:`~stem.control.Controller`
      we establish to it disconnects
    :param bool close_output: closes tor's stdout and stderr streams when
      bootstrapping is complete if true
    :param str | bytes | None stdin: content to provide on stdin

    :returns: **subprocess.Popen** instance for the tor subprocess

    :raises: **OSError** if we either fail to create the tor process or reached a
      timeout without success
    """
    if args is None:
        args = []
    if init_msg_handler and not init_msg_handler.frozen:
        # Freeze now and not later...
        init_msg_handler.freeze()

    # sanity check that we got a tor binary

    if os.path.sep in tor_cmd:
        # got a path (either relative or absolute), check what it leads to
        if os.path.isdir(tor_cmd):
            raise OSError(f"'{tor_cmd}' is a directory, not the tor executable")
        if not os.path.isfile(tor_cmd):
            raise OSError(f"'{tor_cmd}' doesn't exist")
    elif not system.is_available(tor_cmd):
        raise OSError(f"'{tor_cmd}' Doesn't exit")

    # double check that we have a torrc to work with
    if torrc_path not in (None, NO_TORRC) and not os.path.exists(torrc_path):
        raise OSError(f"torrc doesn't exist ({torrc_path})")

    # starts a tor subprocess, raising an OSError if it fails
    runtime_args, temp_file = [tor_cmd], None

    if args:
        runtime_args.extend(args)

    if torrc_path:
        runtime_args.append('-f')
        if torrc_path == NO_TORRC:
            temp_file = (
                await asyncio.to_thread(tempfile.mkstemp, prefix='empty-torrc-', text=True)
            )[1]
            runtime_args.append(temp_file)
        else:
            runtime_args.append(torrc_path)

    if take_ownership:
        runtime_args += ['__OwningControllerProcess', str(os.getpid())]

    tor_process = None

    try:
        tor_process = await asyncio.subprocess.create_subprocess_exec(
            *runtime_args,
            stdout=asyncio.subprocess.PIPE,
            stdin=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        if stdin:
            # send asynchronously
            tor_process.stdin.write(stdin.encode('utf-8') if isinstance(stdin, str) else stdin)
            await tor_process.stdin.drain()

        # we can use async_timeout as a backport for earlier versions of Python 3
        async with async_timeout.timeout(timeout):
            bootstrap_line = re.compile('Bootstrapped ([0-9]+)%')
            problem_line = re.compile('\\[(warn|err)\\] (.*)$')
            last_problem = 'Timed out'

            while True:
                # Tor's stdout will be read as ASCII bytes. This is fine for python 2, but
                # in python 3 that means it'll mismatch with other operations (for instance
                # the bootstrap_line.search() call later will fail).

                init_line = (
                    (await tor_process.stdout.readline()).decode('utf-8', 'replace').strip()
                )

                # this will provide empty results if the process is terminated

                if not init_line:
                    tor_process.terminate()
                    raise OSError(f'Process terminated: {last_problem}')

                # provide the caller with the initialization message if they want it

                if init_msg_handler:
                    await init_msg_handler.send(init_line)

                # return the process if we're done with bootstrapping

                bootstrap_match = bootstrap_line.search(init_line)
                problem_match = problem_line.search(init_line)

                if bootstrap_match and int(bootstrap_match.group(1)) >= completion_percent:
                    return tor_process
                if problem_match:
                    runlevel, msg = problem_match.groups()

                    if 'see warnings above' not in msg:
                        if ': ' in msg:
                            msg = msg.split(': ')[-1].strip()

                        last_problem = msg
    except Exception:
        if tor_process:
            tor_process.kill()  # don't leave a lingering process
            await tor_process.wait()
        raise  # Raise exception from before
    finally:
        if temp_file:
            with suppress(Exception):
                # protect from failing...
                await asyncio.shield(asyncio.to_thread(os.remove, temp_file))


@_wrap_process
async def launch_tor_with_config(
    config: dict[str, list[str | int] | str | int],
    tor_cmd: str = 'tor',
    completion_percent=100,
    init_msg_handler: MessageHandler | None = None,
    timeout: float | None = DEFAULT_INIT_TIMEOUT,
    take_ownership: bool = False,
    close_output: bool = True,
) -> Process:
    """
    Initializes a tor process, like :func:`~stem.process.launch_tor`, but with a
    customized configuration. This writes a temporary torrc to disk, launches
    tor, then deletes the torrc.

    For example...

    ::

      tor_process = aiostem.process.launch_tor_with_config(
        config = {
          'ControlPort': '2778',
          'Log': [
            'NOTICE stdout',
            'ERR file /tmp/tor_error_log',
          ],
        },
      )

      # Or this way which is encouraged over await
        async with aiostem.process.launch_tor_with_config(
            config = {
              'ControlPort': '2778',
              'Log': [
                'NOTICE stdout',
                'ERR file /tmp/tor_error_log',
              ],
            },
        ) as tor_process: ...


    :param dict config: configuration options, such as
      "{'ControlPort': '9051'}" values can either be a
      **str** or **list of str** if for multiple values
    :param str tor_cmd: command for starting tor
    :param int completion_percent: percent of bootstrap completion at which
      this'll return
    :param functor init_msg_handler: optional functor that will be provided with
      tor's initialization stdout as we get it
    :param float timeout: time after which the attempt to start tor is aborted, no
      timeouts are applied if **None**
    :param bool take_ownership: asserts ownership over the tor process so it
      aborts if this python process terminates or a :class:`~stem.control.Controller`
      we establish to it disconnects
    :param bool close_output: closes tor's stdout and stderr streams when
      bootstrapping is complete if true

    :returns: **asyncio.subprocess.Process** instance for the tor subprocess

    :raises: **OSError | asyncio.TimeoutError** if we either fail to create
        the tor process or reached a timeout without success
    """
    # TODO: Drop this version check when tor 0.2.6.3 or higher is the only game
    # in town.

    try:
        use_stdin = (
            await version.get_system_tor_version(tor_cmd)
        ) >= version.Requirement.TORRC_VIA_STDIN
    except OSError:
        use_stdin = False

    # we need to be sure that we're logging to stdout to figure out when we're
    # done bootstrapping

    if 'Log' in config:
        # Transformed to a frozenset for extra speed
        stdout_options = {'DEBUG stdout', 'INFO stdout', 'NOTICE stdout'}

        # if were not using Multidict (although encouraged over other ways)
        # revert to the older system of dict[str, list[...]]
        if isinstance(config['Log'], str):
            config['Log'] = [config['Log']]

        has_stdout = False

        for log_config in config['Log']:
            if log_config in stdout_options:
                has_stdout = True
                break

        if not has_stdout:
            config['Log'].append('NOTICE stdout')

    config_str = ''

    for key, values in config.items():
        if isinstance(values, str | int):
            config_str += f'{key} {values}\n'
        else:
            for value in values:
                if isinstance(value, str | int):
                    config_str += f'{key} {value}\n'
                else:
                    raise TypeError(f'{value!r} Is an unacceptable type')

    if use_stdin:
        return await launch_tor(
            tor_cmd,
            ['-f', '-'],
            None,
            completion_percent,
            init_msg_handler,
            timeout,
            take_ownership,
            close_output,
            stdin=config_str,
        )
    torrc_fd, torrc_path = await asyncio.to_thread(
        tempfile.mkstemp, prefix='torrc-', text=True
    )

    try:
        # make async with aiofiles.open as 'aopen'
        async with aopen(torrc_path, 'w') as torrc_file:
            await torrc_file.write(config_str)

        return await launch_tor(
            tor_cmd,
            # prevents tor from erroring out due to a missing torrc if it gets a sighup
            ['__ReloadTorrcOnSIGHUP', '0'],
            torrc_path,
            completion_percent,
            init_msg_handler,
            timeout,
            take_ownership,
        )
    finally:
        with suppress(Exception):
            await asyncio.shield(asyncio.to_thread(os.close, torrc_fd))
            await asyncio.shield(asyncio.to_thread(os.remove, torrc_path))
