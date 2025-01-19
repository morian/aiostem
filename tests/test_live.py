from __future__ import annotations

import logging
from collections.abc import Sequence

import pytest
from pydantic import TypeAdapter

from aiostem.event import EventBaseNetworkStatus
from aiostem.structures import RouterStatus

# All test coroutines will be treated as marked for asyncio.
pytestmark = pytest.mark.asyncio


class TestLiveData:
    """Test with live data issued by Tor."""

    @pytest.mark.timeout(10)
    async def test_network_status(self, controller, caplog):
        """
        Check the network statuses of onion routers.

        This means that we are (still) able to parse network statuses produced
        by Tor and that their format does not contain unknown directives.

        """
        reply = await controller.get_info('ns/all')
        reply.raise_for_status()

        adapter = TypeAdapter(Sequence[RouterStatus])
        with caplog.at_level(logging.WARNING, logger='aiostem'):
            data = EventBaseNetworkStatus.parse_router_statuses(reply['ns/all'])
            results = adapter.validate_python(data)

        assert len(caplog.records) == 0
        assert len(results) > 0
