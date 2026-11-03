import asyncio
import ipaddress
from types import SimpleNamespace
from unittest.mock import AsyncMock

import dns.exception

from sitewatcher.checks import traceroute
from sitewatcher.checks.base import Status


class FakeProcess:
    def __init__(self, output=b"", hang=False, returncode=0):
        self.stdout = asyncio.StreamReader()
        self.stdout.feed_data(output)
        if not hang:
            self.stdout.feed_eof()
        self.returncode = None
        self.exit_code = returncode
        self.hang = hang
        self.killed = False
        self.reaped = False
        self.stopped = asyncio.Event()

    def kill(self):
        self.killed = True
        self.stdout.feed_eof()
        self.stopped.set()

    async def wait(self):
        if self.hang:
            await self.stopped.wait()
        self.returncode = -9 if self.killed else self.exit_code
        self.reaped = True
        return self.returncode


def install_process(monkeypatch, process):
    monkeypatch.setattr(traceroute.shutil, "which", lambda _: "/usr/bin/traceroute")
    spawn = AsyncMock(return_value=process)
    monkeypatch.setattr(traceroute.asyncio, "create_subprocess_exec", spawn)
    monkeypatch.setattr(traceroute, "_resolve_hostname", AsyncMock())
    return spawn


def test_parse_numeric_ipv4_ipv6_stars_and_icmp_annotations():
    hops = traceroute._parse_hops("""traceroute to example (192.0.2.1), 24 hops max
 1  10.0.0.1  0.222 ms
 2  *
 3  2001:db8::1  12.300 ms !H
 4  192.0.2.1  13 ms !X
 4  192.0.2.2  13 ms
25  192.0.2.4  22 ms
bad output
""")
    assert hops == [
        {"ttl": 1, "ip": "10.0.0.1", "hostname": None, "rtt_ms": 0.222},
        {"ttl": 2, "ip": None, "hostname": None, "rtt_ms": None},
        {"ttl": 3, "ip": "2001:db8::1", "hostname": None, "rtt_ms": 12.3},
        {"ttl": 4, "ip": "192.0.2.1", "hostname": None, "rtt_ms": 13.0},
    ]


def test_probe_literal_target_arguments_and_metrics(monkeypatch):
    async def scenario():
        process = FakeProcess(b" 1 192.0.2.1 0.2 ms\n")
        spawn = install_process(monkeypatch, process)
        result = await traceroute.TracerouteCheck("192.0.2.1").run()
        assert result.status == Status.OK
        assert result.metrics["reached"] is True
        assert result.metrics["truncated"] is False
        assert set(result.metrics) == {
            "destination_ip", "method", "hops", "reached", "truncated",
            "captured_at", "duration_ms",
        }
        assert result.metrics["method"] == "udp"
        assert result.metrics["captured_at"].endswith("+00:00")
        args, kwargs = spawn.call_args
        assert args == (
            "/usr/bin/traceroute", "-4", "-n", "-q", "1", "-m", "24",
            "-w", "1", "-N", "4", "--", "192.0.2.1",
        )
        assert kwargs["stderr"] == asyncio.subprocess.DEVNULL
        assert process.reaped
    asyncio.run(scenario())


def test_partial_timeout_is_observation_and_child_reaped(monkeypatch):
    async def scenario():
        process = FakeProcess(b" 1 10.0.0.1 1 ms\n 2 *\n", hang=True)
        install_process(monkeypatch, process)
        monkeypatch.setattr(traceroute, "TOTAL_TIMEOUT", 0.01)
        result = await traceroute.TracerouteCheck("192.0.2.1").run()
        assert result.status == Status.OK
        assert result.metrics["hops"][0]["ip"] == "10.0.0.1"
        assert result.metrics["truncated"] is True
        assert result.metrics["reached"] is False
        assert process.killed and process.reaped
    asyncio.run(scenario())


def test_cancel_kills_and_reaps(monkeypatch):
    async def scenario():
        process = FakeProcess(hang=True)
        spawn = install_process(monkeypatch, process)
        task = asyncio.create_task(traceroute.TracerouteCheck("192.0.2.1").run())
        while not spawn.called:
            await asyncio.sleep(0)
        await asyncio.sleep(0)
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        else:
            raise AssertionError("Cancellation must propagate")
        assert process.killed and process.reaped
    asyncio.run(scenario())


def test_output_limit_kills_and_preserves_partial(monkeypatch):
    async def scenario():
        process = FakeProcess(b" 1 10.0.0.1 1 ms\n" + b"x" * 100000, hang=True)
        install_process(monkeypatch, process)
        result = await traceroute.TracerouteCheck("192.0.2.1").run()
        assert result.status == Status.OK
        assert result.metrics["truncated"] is True
        assert process.killed and process.reaped
    asyncio.run(scenario())


def test_missing_tool_and_no_responses_are_unknown(monkeypatch):
    monkeypatch.setattr(traceroute.shutil, "which", lambda _: None)
    result = asyncio.run(traceroute.TracerouteCheck("192.0.2.1").run())
    assert result.status == Status.UNKNOWN
    assert result.metrics["error"] == "tool_unavailable"
    async def scenario():
        install_process(monkeypatch, FakeProcess(b"1 *\n2 *\n"))
        result = await traceroute.TracerouteCheck("192.0.2.1").run()
        assert result.status == Status.UNKNOWN
        assert result.metrics["error"] == "no_responses"
    asyncio.run(scenario())


def test_dns_a_then_aaaa_and_ipv6_arguments(monkeypatch):
    async def scenario():
        spawn = install_process(monkeypatch, FakeProcess(b"1 2001:db8::1 1 ms\n"))
        resolve = AsyncMock(side_effect=[
            dns.exception.DNSException(), [SimpleNamespace(address="2001:db8::1")],
        ])
        monkeypatch.setattr(traceroute.dns.asyncresolver, "resolve", resolve)
        result = await traceroute.TracerouteCheck("example.test").run()
        assert [call.args[1] for call in resolve.call_args_list] == ["A", "AAAA"]
        assert spawn.call_args.args[1] == "-6"
        assert ipaddress.ip_address(result.metrics["destination_ip"]).version == 6
        assert result.metrics["reached"]
    asyncio.run(scenario())


def test_dns_failure_prevents_subprocess(monkeypatch):
    async def scenario():
        spawn = install_process(monkeypatch, FakeProcess())
        monkeypatch.setattr(traceroute.dns.asyncresolver, "resolve", AsyncMock(
            side_effect=dns.exception.DNSException()
        ))
        result = await traceroute.TracerouteCheck("bad.test; command").run()
        assert result.status == Status.UNKNOWN
        assert result.metrics["error"] == "dns_failed"
        spawn.assert_not_called()
    asyncio.run(scenario())


def test_ptr_is_optional_and_bounded(monkeypatch):
    async def scenario():
        hop = {"ip": "192.0.2.1", "hostname": None}
        resolve = AsyncMock(return_value=[SimpleNamespace(target="router.example.test.")])
        monkeypatch.setattr(traceroute.dns.asyncresolver, "resolve", resolve)
        await traceroute._resolve_hostname(hop)
        assert hop["hostname"] == "router.example.test"
        assert resolve.call_args.kwargs["lifetime"] == traceroute.PTR_TIMEOUT
        async def slow(*args, **kwargs):
            await asyncio.sleep(10)
        monkeypatch.setattr(traceroute, "PTR_TIMEOUT", 0.01)
        monkeypatch.setattr(traceroute.dns.asyncresolver, "resolve", slow)
        hop["hostname"] = None
        await traceroute._resolve_hostname(hop)
        assert hop["hostname"] is None
    asyncio.run(scenario())


def test_maximum_hop_limit_marks_unreached_route_truncated(monkeypatch):
    async def scenario():
        install_process(monkeypatch, FakeProcess(b"1 10.0.0.1 1 ms\n24 *\n"))
        result = await traceroute.TracerouteCheck("192.0.2.1").run()
        assert result.status == Status.OK
        assert result.metrics["truncated"] is True
    asyncio.run(scenario())


def test_cancel_during_creation_reaps_spawned_child(monkeypatch):
    async def scenario():
        process = FakeProcess(hang=True)
        started = asyncio.Event()
        release = asyncio.Event()
        async def spawn(*args, **kwargs):
            started.set()
            await release.wait()
            return process
        install_process(monkeypatch, process)
        monkeypatch.setattr(traceroute.asyncio, "create_subprocess_exec", spawn)
        task = asyncio.create_task(traceroute.TracerouteCheck("192.0.2.1").run())
        await started.wait()
        task.cancel()
        release.set()
        try:
            await task
        except asyncio.CancelledError:
            pass
        else:
            raise AssertionError("Cancellation must propagate")
        assert process.killed and process.reaped
    asyncio.run(scenario())
