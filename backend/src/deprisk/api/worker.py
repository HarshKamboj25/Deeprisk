"""Bounded in-process worker pool for asynchronous scan execution."""

import asyncio
import logging
from collections.abc import Awaitable, Callable
from uuid import UUID

logger = logging.getLogger(__name__)

ScanHandler = Callable[[UUID], Awaitable[None]]


class WorkerPoolError(RuntimeError):
    """Raised when a scan cannot be accepted by the worker pool."""


class ScanWorkerPool:
    """Execute scan jobs using a bounded number of asynchronous workers."""

    def __init__(
        self,
        handler: ScanHandler,
        *,
        worker_count: int = 2,
        queue_size: int = 8,
    ) -> None:
        if worker_count < 1:
            raise ValueError("worker_count must be at least 1.")
        if queue_size < 1:
            raise ValueError("queue_size must be at least 1.")

        self._handler = handler
        self._queue: asyncio.Queue[UUID | None] = asyncio.Queue(maxsize=queue_size)
        self._worker_count = worker_count
        self._tasks: list[asyncio.Task[None]] = []
        self._started = False
        self._accepting = False

    @property
    def is_accepting(self) -> bool:
        """Whether the pool currently accepts new jobs."""

        return self._accepting

    @property
    def queued_jobs(self) -> int:
        """Number of jobs waiting for a worker."""

        return self._queue.qsize()

    async def start(self) -> None:
        """Start the configured worker tasks."""

        if self._started:
            raise WorkerPoolError("Worker pool is already started.")

        self._started = True
        self._accepting = True
        self._tasks = [
            asyncio.create_task(
                self._worker_loop(),
                name=f"deprisk-scan-worker-{index + 1}",
            )
            for index in range(self._worker_count)
        ]

    def submit(self, scan_id: UUID) -> None:
        """Queue a scan without blocking the API request."""

        if not self._started or not self._accepting:
            raise WorkerPoolError("Worker pool is not accepting jobs.")

        try:
            self._queue.put_nowait(scan_id)
        except asyncio.QueueFull as exc:
            raise WorkerPoolError("Scan queue is full.") from exc

    async def submit_wait(self, scan_id: UUID) -> None:
        """Queue a scan while waiting for available capacity."""

        if not self._started or not self._accepting:
            raise WorkerPoolError("Worker pool is not accepting jobs.")

        await self._queue.put(scan_id)

    async def stop(self) -> None:
        """Stop accepting jobs and finish all accepted work."""

        if not self._started:
            return

        self._accepting = False

        await self._queue.join()

        for _ in self._tasks:
            await self._queue.put(None)

        await asyncio.gather(*self._tasks)

        self._tasks.clear()
        self._started = False

    async def _worker_loop(self) -> None:
        """Process queued scans until the shutdown sentinel is received."""

        while True:
            scan_id = await self._queue.get()

            try:
                if scan_id is None:
                    return

                try:
                    await self._handler(scan_id)
                except Exception:
                    logger.exception(
                        "Unhandled worker error for scan %s",
                        scan_id,
                    )
            finally:
                self._queue.task_done()
