from __future__ import annotations

import asyncio
import dataclasses

import pytest

from aiostem import ControllerStatus, Monitor
from aiostem.event import Event, NetworkLivenessEvent, StatusClientEvent, event_parser
from aiostem.message import Message

# All test coroutines will be treated as marked.
pytestmark = pytest.mark.asyncio


class FakeMonitor(Monitor):
    """Provide a direct access to internal methods to make mypy happy."""

    event_until_ready = asyncio.Event()
    event_for_error = asyncio.Event()

    async def on_ctrl_client_status(self, event: StatusClientEvent) -> None:
        await self._on_ctrl_client_status(event)

    async def on_ctrl_liveness_status(self, event: NetworkLivenessEvent) -> None:
        await self._on_ctrl_liveness_status(event)

    async def wait_until_ready(self) -> ControllerStatus:
        self.event_until_ready.set()
        return await super().wait_until_ready()

    async def wait_for_error(self) -> ControllerStatus:
        self.event_for_error.set()
        return await super().wait_for_error()


def build_event(line: str) -> Event:
    return event_parser(Message(line))


class TestMonitor:
    @pytest.mark.timeout(5)
    async def test_monitor_not_entered(self, controller):
        monitor = Monitor(controller)
        assert monitor.is_healthy is False
        assert monitor.is_entered is False

        status = await monitor.wait_for_error()
        assert isinstance(status, ControllerStatus), type(status)
        assert status.healthcheck() is False
        assert status == monitor.status

        await monitor.__aexit__(None, None, None)
        assert monitor.is_entered is False

    @pytest.mark.timeout(5)
    async def test_monitor_entered(self, controller):
        async with Monitor(controller) as monitor:
            with pytest.raises(RuntimeError, match='is already running'):
                await monitor.__aenter__()

    @pytest.mark.timeout(5)
    async def test_monitor_keepalive_signal(self, controller):
        async with Monitor(controller, keepalive=True):
            await controller.has_received_active.wait()
            assert controller.last_signals == ['ACTIVE']

    @pytest.mark.timeout(5)
    async def test_monitor_events(self, controller):
        monitor = FakeMonitor(controller)

        # Check that we can properly handle PROGRESS messages sent by the controller.
        assert monitor.status.bootstrap == 0
        event = build_event('650 STATUS_CLIENT NOTICE BOOTSTRAP PROGRESS=100')
        assert isinstance(event, StatusClientEvent)
        await monitor.on_ctrl_client_status(event)
        assert monitor.status.bootstrap == 100

        # Check that we can properly handle CIRCUIT_ESTABLISHED events.
        assert monitor.status.has_circuits is False
        event = build_event('650 STATUS_CLIENT NOTICE CIRCUIT_ESTABLISHED')
        await monitor.on_ctrl_client_status(event)
        assert monitor.status.has_circuits is True

        # Check that we can properly handle ENOUGH_DIR_INFO events.
        assert monitor.status.has_dir_info is False
        event = build_event('650 STATUS_CLIENT NOTICE ENOUGH_DIR_INFO')
        await monitor.on_ctrl_client_status(event)
        assert monitor.status.has_dir_info is True

        # We now have enough to tell that we are in a healthy state.
        assert monitor.is_healthy is True
        status = await monitor.wait_until_ready()
        assert status == monitor.status

        assert monitor.status.net_liveness is False
        event = build_event('650 NETWORK_LIVENESS UP')
        assert isinstance(event, NetworkLivenessEvent)
        await monitor.on_ctrl_liveness_status(event)
        assert monitor.status.net_liveness is True
        assert monitor.is_healthy is True

        event = build_event('650 STATUS_CLIENT NOTICE CIRCUIT_NOT_ESTABLISHED')
        await monitor.on_ctrl_client_status(event)
        assert monitor.status.has_circuits is False
        assert monitor.is_healthy is True

        event = build_event('650 STATUS_CLIENT NOTICE NOT_ENOUGH_DIR_INFO')
        await monitor.on_ctrl_client_status(event)
        assert monitor.status.has_dir_info is False
        assert monitor.is_healthy is False

        old_status = dataclasses.replace(monitor.status)
        event = build_event('650 STATUS_CLIENT NOTICE NOT_A_VALID_ITEM')
        await monitor.on_ctrl_client_status(event)
        assert monitor.status == old_status

    @pytest.mark.timeout(5)
    async def test_monitor_wait_methods(self, controller):
        monitor = FakeMonitor(controller)
        monitor.status.bootstrap = 100
        monitor.status.has_dir_info = True

        assert monitor.is_healthy is False
        task = asyncio.create_task(monitor.wait_until_ready())
        await monitor.event_until_ready.wait()
        await asyncio.sleep(0.05)

        event = build_event('650 NETWORK_LIVENESS UP')
        assert isinstance(event, NetworkLivenessEvent)
        await monitor.on_ctrl_liveness_status(event)
        status = await task
        assert status.healthcheck() is True, status

        task = asyncio.create_task(monitor.wait_for_error())
        await monitor.event_for_error.wait()
        await asyncio.sleep(0.05)

        event = build_event('650 NETWORK_LIVENESS DOWN')
        assert isinstance(event, NetworkLivenessEvent)
        await monitor.on_ctrl_liveness_status(event)
        status = await task
        assert status.healthcheck() is False, status
