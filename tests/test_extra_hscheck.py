from __future__ import annotations

import asyncio

import pytest
import pytest_asyncio
from stem.descriptor.hidden_service import HiddenServiceDescriptorV2

from aiostem.event import HsDescContentEvent
from aiostem.exception import ProtocolError
from aiostem.extra import (
    HiddenServiceChecker,
    HiddenServiceFetchError,
    HiddenServiceFetchRequest,
)
from aiostem.message import Message

from .conftest import CONTROLLER_HS_RESULTS

CHECKER_CONCURRENCY = 2


@pytest_asyncio.fixture
async def checker(controller):
    async with HiddenServiceChecker(controller, concurrency=CHECKER_CONCURRENCY) as checker:
        yield checker


class TestHsDescriptors:
    def test_hddesc(self):
        domain = 'oftestt7ffa4tt7et5wab7xhnzeooavy2xdmn6dtfa4pot7dk4xhviid'
        result = CONTROLLER_HS_RESULTS[domain]
        descriptor = result.descriptors[0]
        assert descriptor.auth_type == 'NO_AUTH'
        assert descriptor.descriptor_id == 'NHN9fUdcd/9nJF6PSF6/IzdqkCiEoCsexfMv+7SGpCQ'
        assert descriptor.replica is None
        assert (
            descriptor.index
            == 'DE4B45474E4597865D4C98FBC2C157786909CA2062536EC5792CBEFB0D83F35B'
        )

    def test_hsdesc_content(self):
        domain = 'facebookcorewwwi'
        result = CONTROLLER_HS_RESULTS[domain]
        content = result.contents[0]
        assert content.descriptor_id == '6wn4xyr3l2m6g5z3dcnvygul2tozaxli'

        stem_desc_1 = content.descriptor
        assert isinstance(stem_desc_1, HiddenServiceDescriptorV2)
        assert content.descriptor == stem_desc_1

    def test_hsdesc_content_error(self):
        line = [
            '650',
            'HS_DESC_CONTENT',
            'facebookcorewwwi',
            '6wn4xyr3l2m6g5z3dcnvygul2tozaxli',
            '$F5B58FEE44573C3BFD7D176D918BA5B4057519D7~bistrv1',
        ]
        message = Message(' '.join(line))
        with pytest.raises(ProtocolError, match='Event HS_DESC_CONTENT contains nothing.'):
            HsDescContentEvent(message)


@pytest.mark.asyncio
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
