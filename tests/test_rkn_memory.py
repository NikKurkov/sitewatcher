"""A complete registry must not be materialized as Python strings and sets."""
import asyncio
from datetime import datetime, timezone
from email.utils import format_datetime
import tracemalloc

import httpx

from sitewatcher.checks import rkn_block_sqlite as rkn
from sitewatcher.checks.base import Status
from sitewatcher.config import RknConfig


def test_large_streamed_registry_has_bounded_python_memory(tmp_path, monkeypatch):
    monkeypatch.setattr(rkn, '_MIN_DOMAINS', 1)
    monkeypatch.setattr(rkn, '_MIN_IPS', 1)

    class Domains(httpx.AsyncByteStream):
        async def __aiter__(self):
            for start in range(0, 100_000, 1000):
                yield ''.join(f'd{i:06}.example\n' for i in range(start, start + 1000)).encode()

    def handler(request):
        headers = {'Last-Modified': format_datetime(datetime.now(timezone.utc), usegmt=True)}
        if request.url.path.endswith('domains.lst'):
            return httpx.Response(200, stream=Domains(), headers=headers)
        return httpx.Response(200, text='192.0.2.1\n', headers=headers)

    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            check = rkn.RknBlockCheck('d099999.example', client,
                                     RknConfig(index_db_path=str(tmp_path / 'index.db')))
            return await check.run()

    tracemalloc.start()
    try:
        result = asyncio.run(run())
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    assert result.status is Status.CRIT
    assert result.metrics['matched'] == 'd099999.example'
    assert peak < 12 * 1024 * 1024, f'Python heap peak: {peak / 1024 / 1024:.1f} MiB'
