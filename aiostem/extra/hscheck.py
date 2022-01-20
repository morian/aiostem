from __future__ import annotations

import asyncio
import contextlib
from asyncio import CancelledError, TimeoutError
from types import TracebackType
from typing import (
    TYPE_CHECKING,
    Any,
    Callable,
    Coroutine,
    Dict,
    List,
    Optional,
    Type,
    Union,
    cast,
)

from aiostem.controller import Controller
from aiostem.event import Event, HsDescContentEvent, HsDescEvent
from aiostem.exception import AiostemError
from aiostem.util import hs_address_strip_tld, hs_address_version


class HiddenServiceFetchError(AiostemError):
    """An error that occured when fetching a Hidden Service descriptor."""


class HiddenServiceDirRequest:
    """Tracker for an individual request on a single directory."""

    def __init__(self) -> None:
        """Initialize a new directory request tracker."""
        self.event = None  # type: Optional[HsDescContentEvent]
        self.status = None  # type: Optional[bool]

    @property
    def failed(self) -> bool:
        """Whether this descriptor request has failed."""
        return bool(self.status is False)

    @property
    def succeeded(self) -> bool:
        """Whether this request succeeded."""
        return bool(self.status is True and self.event is not None)


class HiddenServiceCheckEntry:
    """Handles the information received for a given onion domain."""

    # Consider this descriptor failed after this number of failures.
    # Typical requests send up to 6 requests to different HS directories.
    FAIL_COUNT_LIMIT: int = 3

    def __init__(self) -> None:
        """Tracker for all requests sent on behalf of the same request."""
        loop = asyncio.get_running_loop()
        future = loop.create_future()

        self._future = future
        self._requests = {}  # type: Dict[str, HiddenServiceDirRequest]
        self._fail_count = 0
        self._fail_reason = None  # type: Optional[str]

    @property
    def future(self) -> asyncio.Future[Optional[HsDescContentEvent]]:
        """Future completed when this entry has been completed."""
        return self._future

    def _info_failed(self, event: HsDescEvent) -> None:
        """Handle a descriptor fetch failure."""
        # Record the first fail reason to raise a potential error.
        if not self._fail_reason:
            self._fail_reason = event.reason

        # Set the status of our pending request (if any).
        # `req` can be None here because event.directory = 'UNKNOWN'.
        # This probably means that our query was rejected by Tor itself.
        req = self._requests.get(event.directory)
        if req:
            req.status = False

        fail_count = self._fail_count + 1
        if not req or fail_count >= self.FAIL_COUNT_LIMIT:
            if not self._future.done():
                exc = HiddenServiceFetchError(self._fail_reason)
                self._future.set_exception(exc)
        self._fail_count = fail_count

    def _info_received(self, event: HsDescEvent) -> None:
        """Handle a descriptor fetch success (we have the info)."""
        req = self._requests.get(event.directory)
        if req:
            if req.event is not None and not self._future.done():
                self._future.set_result(req.event)
            req.status = True

    def _info_requested(self, event: HsDescEvent) -> None:
        """Tor tells us that a new request was performed."""
        self._requests[event.directory] = HiddenServiceDirRequest()

    def add_info(self, event: HsDescEvent) -> None:
        """Provide new information for this entry."""
        action_fn = {
            'FAILED': self._info_failed,
            'RECEIVED': self._info_received,
            'REQUESTED': self._info_requested,
        }

        handler = action_fn.get(event.action)
        if handler:
            handler(event)

    def add_data(self, event: HsDescContentEvent) -> None:
        """Handle a new descriptor content that has arrived."""
        req = self._requests.get(event.directory)
        if req and not req.failed:
            if req.status is True and not self._future.done():
                self._future.set_result(event)
            req.event = event

    def cancel(self) -> bool:
        """Cancel this entry (we are no longer interrested in it)."""
        return self._future.cancel()


class HiddenServiceChecker:
    """Used to fetch a stream of hidden service descriptors."""

    DEFAULT_CONCURRENCY: int = 10

    def __init__(
        self,
        controller: Controller,
        concurrency: int = DEFAULT_CONCURRENCY,
        queue: Optional[asyncio.Queue[HiddenServiceFetchRequest]] = None,
    ) -> None:
        """Create a new hidden service checker.

        `controller` is a connected and authenticated controller.
        `concurrency` is the number of workers we want to spawn.
        `queue` is the optional queue used to provide requests.
        """
        if queue is None:
            queue = asyncio.Queue()

        self._concurrency = concurrency
        self._controller = controller
        self._requests = {}  # type: Dict[str, List[HiddenServiceCheckEntry]]
        self._queue = queue
        self._workers = []  # type: List[asyncio.Task[None]]

    @property
    def controller(self) -> Controller:
        """Get the controller in use for this checker."""
        return self._controller

    @property
    def concurrency(self) -> int:
        """Get the number of concurrent workers running."""
        return self._concurrency

    @property
    def queue(self) -> asyncio.Queue[HiddenServiceFetchRequest]:
        """Get the hidden service request queue."""
        return self._queue

    async def _event_info_cb(self, event: Event) -> None:
        """Handle received descriptor event (received/created/requested)."""
        if isinstance(event, HsDescEvent):
            entries = self._requests.get(event.address)
            if entries:
                for entry in entries:
                    entry.add_info(event)

    async def _event_data_cb(self, event: Event) -> None:
        """Handle received descriptor content."""
        if isinstance(event, HsDescContentEvent):
            entries = self._requests.get(event.address)
            if entries:
                for entry in entries:
                    entry.add_data(event)

    async def _request_post(self, address: str) -> HiddenServiceCheckEntry:
        """Perform and register a hidden service fetch request."""
        entry = HiddenServiceCheckEntry()
        entries = self._requests.setdefault(address, [])
        entries.append(entry)

        try:
            await self._controller.hs_fetch(address)
        except BaseException:
            entries.remove(entry)
            if not entries:
                self._requests.pop(address)
            entry.cancel()
            raise
        return entry

    def _request_discard(self, address: str, entry: HiddenServiceCheckEntry) -> None:
        """Discard a pending hidden service fetch request.

        This needs to be called when we no longer want to be notified.
        """
        entries = self._requests.get(address, [])
        if entry in entries:
            entries.remove(entry)
            if not entries:
                self._requests.pop(address)
            entry.cancel()

    async def _worker_entry(self) -> None:
        """Get request from the queue and perform the request."""
        while True:
            req = await self.queue.get()
            try:
                entry = await self._request_post(req.address)
                try:
                    res = cast(
                        Union[Exception, HsDescContentEvent],
                        await asyncio.wait_for(entry.future, req.timeout),
                    )
                finally:
                    self._request_discard(req.address, entry)
            # These handlers are here to convert expected errors to HiddenServiceFetchError.
            except TimeoutError:
                res = HiddenServiceFetchError('TIMEOUT')
            except CancelledError:
                res = HiddenServiceFetchError('CANCELLED')
                raise
            except Exception as exc:
                res = exc
            finally:
                try:
                    if callable(req.callback):
                        await req.callback(req, res)
                # CancelledError is based on Exception on Python3.7.
                except CancelledError:
                    raise
                except Exception:
                    pass
                finally:
                    self.queue.task_done()

    async def begin(self) -> None:
        """Start the worker tasks, subscribe to the controller."""
        for _ in range(self.concurrency):
            worker = asyncio.create_task(self._worker_entry())
            self._workers.append(worker)

        await self.controller.event_subscribe('HS_DESC', self._event_info_cb)
        await self.controller.event_subscribe('HS_DESC_CONTENT', self._event_data_cb)

    async def close(self) -> None:
        """Cancel the worker tasks."""
        with contextlib.suppress(AiostemError):
            await self.controller.event_unsubscribe('HS_DESC', self._event_info_cb)
            await self.controller.event_unsubscribe('HS_DESC_CONTENT', self._event_data_cb)
        self._requests.clear()

        try:
            for worker in self._workers:
                worker.cancel()
            await asyncio.wait(self._workers, return_when=asyncio.ALL_COMPLETED)
        finally:
            self._workers.clear()

    async def __aenter__(self) -> HiddenServiceChecker:
        """Spawn the workers and start the show."""
        await self.begin()
        return self

    async def __aexit__(
        self,
        exc_cls: Optional[Type[BaseException]],
        exc_val: Optional[BaseException],
        exc_tb: Optional[TracebackType],
    ) -> None:
        """Exit Checker's context."""
        await self.close()


if TYPE_CHECKING:
    HsCallbackResponseType = Union[HsDescContentEvent, Exception]
    HiddenServiceFetchCallback = Callable[
        ['HiddenServiceFetchRequest', HsCallbackResponseType], Coroutine[Any, Any, None]
    ]


class HiddenServiceFetchRequest:
    """Describe a single a hidden service request.

    It is meant to be queued to the HiddenServiceChecker's queue.
    """

    DEFAULT_TIMEOUT: int = 60

    def __init__(
        self,
        address: str,
        callback: Optional[HiddenServiceFetchCallback],
        timeout: int = DEFAULT_TIMEOUT,
    ) -> None:
        """Initialize a new hidden service fetch request."""
        address = hs_address_strip_tld(address)
        version = hs_address_version(address)
        self._address = address
        self._callback = callback
        self._timeout = timeout
        self._version = version

    @property
    def address(self) -> str:
        """Address of the onion domain that needs to be fetched."""
        return self._address

    @property
    def callback(self) -> Optional[HiddenServiceFetchCallback]:
        """Asynchronous callable triggered on success, failure or timeout."""
        return self._callback

    @property
    def timeout(self) -> int:
        """How long should the worker wait for an answer."""
        return self._timeout

    @property
    def version(self) -> int:
        """Version of the hidden service address."""
        return self._version
