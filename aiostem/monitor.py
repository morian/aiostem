from __future__ import annotations

import asyncio
import logging
from asyncio import Condition, Lock
from contextlib import suppress
from dataclasses import dataclass
from typing import TYPE_CHECKING, ClassVar

from .event import NetworkLivenessEvent, StatusClientEvent
from .exception import ControllerError, ResponseError
from .message import Message

if TYPE_CHECKING:
    from asyncio import Task  # noqa: F401
    from types import TracebackType

    from typing_extensions import Self

    from .controller import Controller

logger = logging.getLogger(__package__)


@dataclass(slots=True)
class ControllerStatus:
    """Keep track of the Controller's status."""

    bootstrap: int = 0
    has_circuits: bool = False
    has_dir_info: bool = False
    net_liveness: bool = False

    def healthcheck(self) -> bool:
        """Whether we can run the workers."""
        return bool(
            self.bootstrap == 100
            and self.has_dir_info
            and (self.has_circuits or self.net_liveness),
        )


class Monitor:
    """Check and run the worker manager."""

    DEFAULT_DORMANT_TIMEOUT: ClassVar[int] = 24 * 3600

    def __init__(
        self,
        controller: Controller,
        *,
        keepalive: bool = True,
    ) -> None:
        """Create a new instance of a Tor checker.

        `keepalive` tells whether we should run a task to keep Tor 'ACTIVE'.
        """
        self._condition = Condition()
        self._controller = controller
        self._do_keepalive = keepalive
        self._lock = Lock()
        self._entered = False
        self._status = ControllerStatus()
        self._task_keepalive = None  # type: Task[None] | None

    async def _task_keepalive_run(self) -> None:
        """Triggered when we need to perform regular actions."""
        reply = await self._controller.get_conf('DormantClientTimeout')
        try:
            value = int(reply.values['DormantClientTimeout'])
            logger.debug("Config 'DormantClientTimeout' is set to %d", value)
        except (KeyError, ValueError):  # pragma: no cover
            value = self.DEFAULT_DORMANT_TIMEOUT

        delay = 0.95 * value
        while True:
            logger.info("Sending the 'ACTIVE' signal to the controller")
            await self._controller.signal('ACTIVE')
            await asyncio.sleep(delay)

    async def _fetch_controller_status(self) -> bool:
        """Perform a full check on the controller's status."""
        info = await self._controller.get_info(
            'network-liveness',
            'status/bootstrap-phase',
            'status/circuit-established',
            'status/enough-dir-info',
        )
        # Build a fake message to create an event-like object.
        # This avoids all the manual parsing of this thing...
        message = Message('650 STATUS_CLIENT ' + info.values['status/bootstrap-phase'])

        self._status.bootstrap = int(StatusClientEvent(message).arguments['PROGRESS'])
        self._status.has_circuits = bool(info.values['status/circuit-established'] == '1')
        self._status.has_dir_info = bool(info.values['status/enough-dir-info'] == '1')
        self._status.net_liveness = bool(info.values['network-liveness'] == 'up')

        return self.is_healthy

    async def _on_ctrl_liveness_status(self, event: NetworkLivenessEvent) -> None:
        """Triggered when a new 'NETWORK_LIVENESS' event occurs."""
        statuses = {'UP': True, 'DOWN': False}
        status = statuses.get(event.network_status)
        if status is not None:  # pragma: no branch
            async with self._condition:
                logger.debug('Network liveness: %s', event.network_status)
                self._status.net_liveness = status
                self._condition.notify_all()

    async def _on_ctrl_client_status(self, event: StatusClientEvent) -> None:
        """Triggered when a new 'STATUS_CLIENT' event occurs.

        Note that this is an event handler executed in the receive loop from the controller.
        You cannot perform new controller requests from here, use a queue or something else.
        """
        match event.action:
            case 'BOOTSTRAP':
                progress = event.arguments.get('PROGRESS')
                if progress is not None:  # pragma: no branch
                    with suppress(ValueError):
                        self._status.bootstrap = int(progress)
            case 'CIRCUIT_ESTABLISHED':
                self._status.has_circuits = True
            case 'CIRCUIT_NOT_ESTABLISHED':
                self._status.has_circuits = False
            case 'ENOUGH_DIR_INFO':
                self._status.has_dir_info = True
            case 'NOT_ENOUGH_DIR_INFO':
                self._status.has_dir_info = False
            case _:
                # We are not not interested in this event.
                return

        # Maybe we need to do something about the current working state.
        async with self._condition:
            logger.debug('ClientStatus: %s %s', event.action, event.arguments)
            self._condition.notify_all()

    async def _begin(self) -> None:
        """Start this monitor instance."""
        if self._entered:
            raise RuntimeError('Monitor is already running!')

        await self._controller.event_subscribe(
            'STATUS_CLIENT',
            self._on_ctrl_client_status,  # type: ignore[arg-type]
        )
        await self._controller.event_subscribe(
            'NETWORK_LIVENESS',
            self._on_ctrl_liveness_status,  # type: ignore[arg-type]
        )
        keepalive = None

        if self._do_keepalive:  # pragma: no branch
            # Only enable the keep alive task when it is needed.
            # This option was introduced in Tor `0.4.6.2`.
            try:
                reply = await self._controller.get_conf('DormantTimeoutEnabled')
                dormant = bool(reply.values.get('DormantTimeoutEnabled', True))
            except ResponseError:  # pragma: no cover
                dormant = True

            if dormant:  # pragma: no branch
                keepalive = asyncio.create_task(
                    self._task_keepalive_run(),
                    name='aiostem.monitor.keepalive',
                )

        self._task_keepalive = keepalive

        async with self._condition:
            # Fetch the initial controller status to build our self._status.
            await self._fetch_controller_status()
            self._condition.notify_all()

        self._entered = True

    async def __aenter__(self) -> Self:
        """Enter the monitor context."""
        async with self._lock:
            try:
                await self._begin()
            except BaseException:
                await self._close()
                raise
        return self

    async def _close(self) -> None:
        """Close everything so this monitor can exit properly."""
        # Maybe the controller is no longer available.
        with suppress(ControllerError):
            await self._controller.event_unsubscribe(
                'STATUS_CLIENT',
                self._on_ctrl_client_status,  # type: ignore[arg-type]
            )
        with suppress(ControllerError):
            await self._controller.event_unsubscribe(
                'NETWORK_LIVENESS',
                self._on_ctrl_liveness_status,  # type: ignore[arg-type]
            )

        tasks = []
        if self._task_keepalive is not None:
            tasks.append(self._task_keepalive)
        for task in tasks:
            task.cancel('Monitor is closing')
        if len(tasks):
            await asyncio.gather(*tasks, return_exceptions=True)

        self._task_keepalive = None
        self._entered = False

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> bool:
        """Exit this monitor, propagate any error."""
        async with self._lock:
            await self._close()
        return False

    @property
    def is_healthy(self) -> bool:
        """Tells whether the controller is healthy."""
        return self._status.healthcheck()

    @property
    def status(self) -> ControllerStatus:
        """Get the current controller status."""
        return self._status

    async def wait_for_error(self, timeout: float | None = None) -> ControllerStatus:
        """Wait until the controller stops being healthy."""
        async with self._condition:
            while self._status.healthcheck():
                await asyncio.wait_for(self._condition.wait(), timeout)
        return self._status

    async def wait_until_ready(self, timeout: float | None = None) -> ControllerStatus:
        """Wait until the controller is ready and healthy."""
        async with self._condition:
            while not self._status.healthcheck():
                await asyncio.wait_for(self._condition.wait(), timeout)
        return self._status
