import asyncio

import pytest
import pytest_asyncio

from aiostem.event import HsDescContentEvent
from aiostem.extra import (
    HiddenServiceChecker,
    HiddenServiceFetchError,
    HiddenServiceFetchRequest,
)

# All test coroutines will be treated as marked.
pytestmark = pytest.mark.asyncio
CHECKER_CONCURRENCY = 2


@pytest_asyncio.fixture
async def checker(controller):
    async with HiddenServiceChecker(controller, concurrency=CHECKER_CONCURRENCY) as checker:
        yield checker


class TestHiddenServiceChecker:
    async def test_entered(self, controller, checker):
        assert checker.controller == controller
        assert checker.concurrency == 2

    @pytest.mark.timeout(5)
    async def test_good_request(self, checker):
        address = 'facebookcorewwwi'
        loop = asyncio.get_running_loop()
        future = loop.create_future()

        async def callback(req, res):
            future.set_result(res)

        request = HiddenServiceFetchRequest(address, callback)
        assert request.version == 2

        await checker.queue.put(request)

        res = await asyncio.ensure_future(future)
        assert isinstance(res, HsDescContentEvent)
        assert res.address == address

    @pytest.mark.timeout(5)
    async def test_fail_request(self, checker):
        address = 'oftestt7ffa4tt7et5wab7xhnzeooavy2xdmn6dtfa4pot7dk4xhviid'
        loop = asyncio.get_running_loop()
        future = loop.create_future()

        async def callback(req, res):
            future.set_result(res)

        request = HiddenServiceFetchRequest(address, callback)
        assert request.version == 3

        await checker.queue.put(request)

        # with pytest.raises(HiddenServiceFetchError, match='NOT_FOUND'):
        res = await asyncio.ensure_future(future)
        assert isinstance(res, HiddenServiceFetchError)
        assert 'NOT_FOUND' in str(res)

    @pytest.mark.timeout(5)
    async def test_timeout_request(self, checker):
        address = 'oftesttvle6fl3fidtuqevrs3dzeynsvaejdrcxjpwxvzms76ug3cdqd'
        loop = asyncio.get_running_loop()
        future = loop.create_future()

        async def callback(req, res):
            future.set_result(res)

        request = HiddenServiceFetchRequest(address, callback, timeout=0.1)
        await checker.queue.put(request)

        res = await asyncio.ensure_future(future)
        assert isinstance(res, HiddenServiceFetchError)
        assert 'TIMEOUT' in str(res)

    @pytest.mark.timeout(5)
    async def test_exception_request(self, controller, checker):
        address = 'oftesttvle6fl3fidtuqevrs3dzeynsvaejdrcxjpwxvzms76ug3cdqd'
        loop = asyncio.get_running_loop()
        future = loop.create_future()
        controller.raise_enabled = True

        async def callback(req, res):
            future.set_result(res)

        request = HiddenServiceFetchRequest(address, callback)
        await checker.queue.put(request)

        res = await asyncio.ensure_future(future)
        assert isinstance(res, Exception)
        assert 'pytest exception!' in str(res)

    async def test_cancelled_request(self, controller):
        address = 'oftesttvle6fl3fidtuqevrs3dzeynsvaejdrcxjpwxvzms76ug3cdqd'
        loop = asyncio.get_running_loop()
        future = loop.create_future()

        async def callback(req, res):
            future.set_result(res)

        async with HiddenServiceChecker(
            controller,
            concurrency=CHECKER_CONCURRENCY,
        ) as checker:
            request = HiddenServiceFetchRequest(address, callback)
            await checker.queue.put(request)
            await asyncio.sleep(0.2)

        res = await asyncio.ensure_future(future)
        assert isinstance(res, HiddenServiceFetchError)
        assert 'CANCELLED' in str(res)
