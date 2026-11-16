"""Tests for the bounded asynchronous scan worker pool."""

import asyncio
from uuid import uuid4

import pytest

from deprisk.api.worker import ScanWorkerPool, WorkerPoolError


def test_worker_pool_processes_submitted_jobs():
    async def scenario():
        processed = []
        completed = asyncio.Event()

        async def handler(scan_id):
            processed.append(scan_id)

            if len(processed) == 3:
                completed.set()

        pool = ScanWorkerPool(handler, worker_count=2)

        await pool.start()

        scan_ids = [uuid4() for _ in range(3)]

        for scan_id in scan_ids:
            pool.submit(scan_id)

        await asyncio.wait_for(completed.wait(), timeout=2)
        await pool.stop()

        assert set(processed) == set(scan_ids)
        assert len(processed) == 3
        assert not pool.is_accepting

    asyncio.run(scenario())


def test_worker_pool_respects_concurrency_limit():
    async def scenario():
        active = 0
        maximum_active = 0
        processed = 0
        all_processed = asyncio.Event()

        async def handler(scan_id):
            nonlocal active, maximum_active, processed

            active += 1
            maximum_active = max(maximum_active, active)

            await asyncio.sleep(0.02)

            active -= 1
            processed += 1

            if processed == 6:
                all_processed.set()

        pool = ScanWorkerPool(handler, worker_count=2, queue_size=8)

        await pool.start()

        for _ in range(6):
            pool.submit(uuid4())

        await asyncio.wait_for(all_processed.wait(), timeout=3)
        await pool.stop()

        assert maximum_active == 2
        assert active == 0
        assert processed == 6

    asyncio.run(scenario())


def test_worker_pool_rejects_jobs_when_queue_is_full():
    async def scenario():
        handler_started = asyncio.Event()
        release_handler = asyncio.Event()

        async def handler(scan_id):
            handler_started.set()
            await release_handler.wait()

        pool = ScanWorkerPool(handler, worker_count=1, queue_size=1)

        await pool.start()

        pool.submit(uuid4())
        await asyncio.wait_for(handler_started.wait(), timeout=2)

        pool.submit(uuid4())

        with pytest.raises(WorkerPoolError, match="queue is full"):
            pool.submit(uuid4())

        release_handler.set()
        await pool.stop()

    asyncio.run(scenario())


def test_worker_pool_continues_after_handler_failure(caplog):
    async def scenario():
        processed = []
        completed = asyncio.Event()
        first_id = uuid4()
        second_id = uuid4()

        async def handler(scan_id):
            processed.append(scan_id)

            if scan_id == first_id:
                raise RuntimeError("simulated scan failure")

            completed.set()

        pool = ScanWorkerPool(handler, worker_count=1)

        await pool.start()
        pool.submit(first_id)
        pool.submit(second_id)

        await asyncio.wait_for(completed.wait(), timeout=2)
        await pool.stop()

        assert processed == [first_id, second_id]
        assert "Unhandled worker error" in caplog.text

    asyncio.run(scenario())


def test_worker_pool_shutdown_waits_for_accepted_jobs():
    async def scenario():
        handler_started = asyncio.Event()
        release_handler = asyncio.Event()
        handler_finished = asyncio.Event()

        async def handler(scan_id):
            handler_started.set()
            await release_handler.wait()
            handler_finished.set()

        pool = ScanWorkerPool(handler, worker_count=1)

        await pool.start()
        pool.submit(uuid4())

        await asyncio.wait_for(handler_started.wait(), timeout=2)

        shutdown = asyncio.create_task(pool.stop())

        await asyncio.sleep(0)

        assert not shutdown.done()
        assert not pool.is_accepting

        release_handler.set()
        await asyncio.wait_for(shutdown, timeout=2)

        assert handler_finished.is_set()
        assert not pool.is_accepting

    asyncio.run(scenario())


@pytest.mark.parametrize(
    ("worker_count", "queue_size"),
    [
        (0, 1),
        (-1, 1),
        (1, 0),
        (1, -1),
    ],
)
def test_worker_pool_rejects_invalid_capacity(worker_count, queue_size):
    async def handler(scan_id):
        return None

    with pytest.raises(ValueError):
        ScanWorkerPool(
            handler,
            worker_count=worker_count,
            queue_size=queue_size,
        )


def test_worker_pool_rejects_submission_before_start():
    async def handler(scan_id):
        return None

    pool = ScanWorkerPool(handler)

    with pytest.raises(WorkerPoolError, match="not accepting"):
        pool.submit(uuid4())


def test_worker_pool_rejects_duplicate_start():
    async def scenario():
        async def handler(scan_id):
            return None

        pool = ScanWorkerPool(handler)

        await pool.start()

        with pytest.raises(WorkerPoolError, match="already started"):
            await pool.start()

        await pool.stop()

    asyncio.run(scenario())


def test_submit_wait_waits_for_queue_capacity():
    async def scenario():
        from uuid import uuid4

        from deprisk.api.worker import ScanWorkerPool

        first_started = asyncio.Event()
        release_first = asyncio.Event()
        processed = []

        async def handler(scan_id):
            if scan_id == first_id:
                first_started.set()
                await release_first.wait()
            processed.append(scan_id)

        first_id = uuid4()
        second_id = uuid4()
        third_id = uuid4()

        pool = ScanWorkerPool(
            handler,
            worker_count=1,
            queue_size=1,
        )

        await pool.start()

        try:
            pool.submit(first_id)
            await asyncio.wait_for(first_started.wait(), timeout=1)

            pool.submit(second_id)

            waiting_submission = asyncio.create_task(pool.submit_wait(third_id))

            await asyncio.sleep(0)
            assert not waiting_submission.done()

            release_first.set()

            await asyncio.wait_for(waiting_submission, timeout=1)
            await pool.stop()

            assert processed == [first_id, second_id, third_id]

        finally:
            release_first.set()
            await pool.stop()

    asyncio.run(scenario())
