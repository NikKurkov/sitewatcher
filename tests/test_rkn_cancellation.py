import asyncio
import threading

import pytest

from sitewatcher.checks.rkn_block_sqlite import _in_thread


@pytest.mark.parametrize('failure', [False, True])
@pytest.mark.parametrize('cancellations', [1, 2])
def test_repeated_cancellation_drains_thread_and_keeps_cancellation(failure, cancellations):
    async def run():
        loop = asyncio.get_running_loop()
        entered = asyncio.Event()
        release = threading.Event()
        finished = threading.Event()

        def work():
            loop.call_soon_threadsafe(entered.set)
            release.wait(5)
            finished.set()
            if failure:
                raise ValueError('Parsing failed while cancelled')

        async def next_turn():
            done = asyncio.Event()
            loop.call_soon(done.set)
            await done.wait()

        task = asyncio.create_task(_in_thread(work))
        await entered.wait()
        try:
            for _ in range(cancellations):
                task.cancel()
                await next_turn()
            assert not task.done()
        finally:
            release.set()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert finished.is_set()

    asyncio.run(run())
