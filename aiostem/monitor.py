from __future__ import annotations

import asyncio
import logging
from asyncio import Condition, Task
from contextlib import AsyncExitStack, suppress
from dataclasses import dataclass
from typing import TYPE_CHECKING, ClassVar

from .event import Event, NetworkLivenessEvent, StatusClientEvent
from .exception import ControllerError, ResponseError
from .message import Message

if TYPE_CHECKING:
    from types import TracebackType
    from typing import Self

    from .controller import Controller

logger = logging.getLogger(__package__)


@dataclass(slots=True)
class ControllerStatus:
    """
    Keep track of the Controller's status.

    It is used to keep track of various status parameters from Tor's daemon.
    """

    #: Tor's bootstrap progress status (in percent).
    bootstrap: int = 0

    #: Whether Tor has established circuits.
    has_circuits: bool = False

    #: Whether Tor has enough directory information.
    has_dir_info: bool = False

    #: Whether Tor has a working network.
    net_liveness: bool = False

    def healthcheck(self) -> bool:
        """
        Tell whether we are healthy enough to run workers.

        Returns:
            A boolean value that tells whether we are healthy or not.

        """
        return bool(
            self.bootstrap == 100
            and self.has_dir_info
            and (self.has_circuits or self.net_liveness),
        )


class Monitor:
    """Monitor controller's status."""

    DEFAULT_DORMANT_TIMEOUT: ClassVar[int] = 24 * 3600

    def __init__(
        self,
        controller: Controller,
        *,
        keepalive: bool = True,
    ) -> None:
        """
        Create a new instance of a monitor to check for Tor's daemon status.

        Args:
            controller: a controller connected to Tor's daemon

        Keyword Args:
            keepalive: whether we should run a task to keep Tor in `ACTIVE` mode.

        """
        self._context = None  # type: AsyncExitStack | None
        self._condition = Condition()
        self._controller = controller
        self._do_keepalive = keepalive
        self._status = ControllerStatus()

    async def __aenter__(self) -> Self:
        """
        Start the controller's monitoring.

        This subscribes to relevant events from the controller and optionally starts
        the keep-alive task used to ensure that Tor always stay `ACTIVE`. This later
        part is important if you don't plan on using the socks port but will only
        use the control port.

        Raises:
            RuntimeError: when the controller has already been entered

        Returns:
            The exact same :class:`Monitor` object.

        """
        if self.is_entered:
            msg = 'Monitor is already running!'
            raise RuntimeError(msg)

        controller = self._controller
        context = await AsyncExitStack().__aenter__()
        try:
            # Get notified when a 'STATUS_CLIENT' event occurs.
            await controller.event_subscribe('STATUS_CLIENT', self._on_ctrl_client_status)
            context.push_async_callback(
                controller.event_unsubscribe, 'STATUS_CLIENT', self._on_ctrl_client_status
            )

            # Get notified when a 'NETWORK_LIVENESS' event occurs.
            await controller.event_subscribe('NETWORK_LIVENESS', self._on_ctrl_liveness_status)
            context.push_async_callback(
                controller.event_unsubscribe, 'NETWORK_LIVENESS', self._on_ctrl_liveness_status
            )

            if self._do_keepalive:  # pragma: no branch
                # Only enable the keep alive task when it is needed.
                # This option was introduced in Tor `0.4.6.2`.
                try:
                    reply = await self._controller.get_conf('DormantTimeoutEnabled')
                    dormant = bool(reply.values.get('DormantTimeoutEnabled', True))
                except ResponseError:  # pragma: no cover
                    dormant = True

                if dormant:  # pragma: no branch
                    task_keepalive = asyncio.create_task(
                        self._keepalive_task(),
                        name='aiostem.monitor.keepalive',
                    )

                    async def cancel_keepalive(task: Task[None]) -> None:
                        task.cancel('Monitor is closing')
                        await asyncio.gather(task, return_exceptions=True)

                    context.push_async_callback(cancel_keepalive, task_keepalive)

            await self._fetch_controller_status()
        except BaseException:  # pragma: no cover
            await context.aclose()
            raise
        else:
            self._context = context
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> bool:
        """
        Exit the monitor's context and unregister from the underlying events.

        Returns:
            :obj:`False` to let any exception flow through the call stack.

        """
        context = self._context
        try:
            if context is not None:
                with suppress(ControllerError):
                    await context.__aexit__(exc_type, exc_val, exc_tb)
        finally:
            self._context = None

        # Do not prevent the original exception from going further.
        return False

    async def _keepalive_task(self) -> None:
        """
        Keep the Tor daemon in an `ALIVE` state.

        This is needed when the user does not plan on using the socks socket
        but still needs to send commands regularly through the control port.
        """
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
        """
        Fetch and update our view of the controller's status.

        Returns:
            Whether the underlying Tor daemon is healthy.

        """
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

    async def _on_ctrl_liveness_status(self, event: Event) -> None:
        """Handle a `NETWORK_LIVENESS` event."""
        if isinstance(event, NetworkLivenessEvent):  # pragma: no branch
            statuses = {'UP': True, 'DOWN': False}
            status = statuses.get(event.network_status)
            if status is not None:  # pragma: no branch
                async with self._condition:
                    logger.debug('Network liveness: %s', event.network_status)
                    self._status.net_liveness = status
                    self._condition.notify_all()

    async def _on_ctrl_client_status(self, event: Event) -> None:
        """
        Handle a 'STATUS_CLIENT' event.

        Note that this is an event handler executed in the receive loop from the controller.
        You cannot perform new controller requests from here, use a queue or something else.
        """
        if isinstance(event, StatusClientEvent):  # pragma: no branch
            async with self._condition:
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
                        # We are not not interested in other events.
                        # This also means that our status hasn't changed.
                        return

                # Maybe we need to do something about the current working state.
                logger.debug('ClientStatus: %s %s', event.action, event.arguments)
                self._condition.notify_all()

    @property
    def is_entered(self) -> bool:
        """Tell whether the monitor context is currently entered."""
        return bool(self._context is not None)

    @property
    def is_healthy(self) -> bool:
        """Tell whether the underlying controller is healthy."""
        return self._status.healthcheck()

    @property
    def status(self) -> ControllerStatus:
        """Get the current controller status."""
        return self._status

    async def wait_for_error(self) -> ControllerStatus:
        """
        Wait until the controller stops being healthy.

        Returns:
            The current controller's status.

        """
        async with self._condition:
            while self._status.healthcheck():
                await self._condition.wait()
        return self._status

    async def wait_until_ready(self) -> ControllerStatus:
        """
        Wait until the controller is ready and healthy.

        Returns:
            The current controller's status.

        """
        async with self._condition:
            while not self._status.healthcheck():
                await self._condition.wait()
        return self._status
