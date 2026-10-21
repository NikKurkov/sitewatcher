# Reliability verification — 2026-10-21

## Scope

Runtime checkpoint: `23c9a11`. Long-running workload checkpoints are listed below.
All data and service responses used below were synthetic. These checks did not
send real Telegram messages, probe monitored production domains or deploy changes.

The initial Ponytail simplification (`594437d`) removed 461 net source lines
before the reliability work and dashboard additions. The final feature set adds
code, but introduces no new runtime dependency: the viewer uses the standard
library and plain HTML/CSS; existing dispatcher/storage boundaries are retained.

## Regression and installation checks

| Environment | SQLite | Result |
| --- | --- | --- |
| Python 3.12.12 | 3.50.4 | 473 tests passed |
| Python 3.13.12 | 3.50.4 | 473 tests passed |
| Python 3.14.8 | 3.54.0 | 473 tests passed |
| Installed wheel, Python 3.14.8, PTB 22.4 | 3.54.0 | 473 tests passed |
| Installed Docker package, Python 3.12.14 | 3.46.1 | 473 tests passed |

Ruff and `git diff --check` passed. Container tests ran without external network
access, as the nonroot application user, with a read-only root filesystem and a
temporary writable `/tmp`. Tests imported the installed package rather than the
source checkout. The 55 package files in both image locations matched the verified
wheel byte for byte. Native loopback TLS/proxy, streaming-body limits and cancellation
were exercised; Telegram routing used the real PTB application with a mocked HTTP
transport.

The minimum Telegram version was checked independently: PTB 22.3 failed native
polling startup on Python 3.14, while 22.4 passed the complete suite. The declared
minimum is now 22.4, which includes the [upstream event-loop startup fix](https://github.com/python-telegram-bot/python-telegram-bot/blob/v22.4/src/telegram/ext/_application.py).
Native local origin/proxy servers also confirmed that `TELEGRAM_PROXY` covers
both `getMe` and `getUpdates`. Maintenance barrier tests verified that the event
loop remains responsive while cleanup and compaction run in worker threads.

Reproduce the source checks in an activated development environment:

```bash
pip install -e '.[dev]'
pytest
ruff check sitewatcher tests
git diff --check
```

A wheel installed into a new environment outside the checkout passed CLI
diagnostics, HTML/CSS/JSON serving, owner isolation and SIGTERM shutdown. A
disposable Compose installation retained its SQLite data across container
restarts and exited cleanly on both stops. Synthetic private YAML, environment,
SQLite/sidecar and compressed-cache canaries were absent from the built image.

## Browser checks

Chromium checks at 1440, 390 and 320 CSS pixels found no horizontal page overflow.
Native detail expansion, search/status filtering, accessible control names and
refresh pause worked. Screenshots contain example domains only. The viewer shows
saved results; its health endpoint checks storage availability, not site health.

## Storage and recovery

- A deterministic 500-domain CSV round trip preserved effective settings,
  including Unicode/newline keywords, empty port lists and explicit zero values.
- An online SQLite backup completed while another connection committed history.
  The restored copy contained 501 complete three-result batches, owner settings,
  alert state and chat destination. Integrity and foreign-key checks passed.
  The documented backup creates mode `0600` and refuses an existing destination.
- A second online backup ran with six active HTTP readers and a concurrent writer.
  Its 68.88 MiB restored copy contained 1,000 domains and 256,154 history rows;
  integrity/foreign-key checks and the 500-domain owner snapshot passed.
  Backup plus validation took 0.99 seconds on this machine.
- Native read-only diagnostic locking was checked with a deterministic reader/
  writer barrier. The reader blocked WAL truncation until its integrity check
  finished. The former immutable-reader shortcut could falsely report corruption
  during concurrent checkpoints; SQLite reader metadata is now allowed.
- Three writers were killed with SIGKILL after an uncommitted history insertion,
  domain/settings creation or settings update. Reopening the database preserved
  committed state, exposed no partial changes and allowed subsequent writes.
- Concurrent settings changes, SQL failures and removed domains have dedicated
  regression coverage. Corrupt overrides fail closed and support explicit reset.
- A two-process notification experiment at the final runtime checkpoint saved a
  critical result while Telegram delivery failed. A fresh application retried it
  from SQLite with zero new probes, delivered once and preserved state on the next
  tick. Both processes closed every client and exited cleanly.
- Single-domain check regressions cover forced cache bypass with all supported
  flags before or after the domain, including the suffix form shown in `/help`.
- History transition regressions cover recurring incidents separated by recovery,
  requested onset/recovery filters, interleaved streams and deterministic ordering
  of rows saved in the same second. Transition search retains its 1,000-row bound.

## Measured reporting performance

A synthetic database with 500 visible domains and 4,365,002 history rows compared
the legacy query with the latest-history index and bounded native seeks. Results
were identical, including a newest-ID row with an older timestamp.

| Measurement | Legacy | Indexed |
| --- | ---: | ---: |
| Complete snapshot median | 349.50 ms | 22.17 ms |
| SQL median | 329.80 ms | 7.64 ms |
| Per-reader median with six concurrent SQL readers | 435.84 ms | 121.83 ms |

The index added 151.12 MiB (14.4%) and took 2.23 seconds to build on this machine.
A separate warm-storage write comparison measured approximately 7–8% overhead
(20–24 microseconds per three-result batch). These are local synthetic
measurements, not production latency or physical-disk durability guarantees.

The viewer retains a read-only fallback for older databases without the index.
The monitoring process builds the index during initialization; allow disk space
and a writer lock when upgrading a large database.

## Sustained concurrency

A one-hour synthetic workload ran six HTTP readers alongside continuous history
writes, with 500 visible domains and 240,000 starting history rows. It completed
without errors and with SQLite integrity `ok`. The last checkpoint at 3,593
seconds recorded 57,750 reads and 32,047 writes, p50 242.5 ms and p95 283.5 ms.
Those counters precede shutdown slightly; they are not exact final totals.
Sampled memory, thread, descriptor and WAL sizes fluctuated within a stable
range during the final minutes. A second run at checkpoint `baa014f` completed
3,600.98 seconds with exactly 57,924 reads and 32,075 writes, no errors and final
integrity `ok`; p50 was 241.8 ms and p95 278.6 ms. Its result records start/finish
times and source hashes. Later history-command, diagnostic-locking and force-flag
corrections do not change the snapshot or write paths exercised by this workload. Thirty resource samples during the second run
recorded RSS 83.8–103.1 MiB, 9–15 threads, 5–31 descriptors and WAL size 0–111,272
bytes. These are observed ranges, not a general memory bound.

A separate 30-minute native Telegram polling run completed 5,986 `getUpdates`
calls, all 55 planned command updates and 30 scheduled runs. It delivered 38
problem/recovery alerts across two owners, preserved owner isolation, closed all
33 HTTP clients and stopped cleanly; integrity and foreign-key checks passed.
Telegram and page responses came from an in-process mock transport with ambient
proxy settings disabled. This exercised the actual PTB application, router,
JobQueue, dispatcher, storage and notification path without external sends.
The launch-time checkpoint was `baa014f`, inferred from the recorded launch and
Git commit times; file hashes were not captured at launch. Later history-command,
diagnostic-locking and force-flag corrections were covered by the final regression
suite, rather than this long-running process.

## Operational limits

Use one monitoring process per database. The optional viewer binds IPv4 loopback
and requires a fixed positive owner; use an SSH tunnel for another host.
Page-body limits apply to the three page checks, not registry/reputation feeds.
Unsupported encodings produce unknown results. Suppressed-alert summaries remain
in memory; incident transitions persist and can be retried after restart.

At the final local installation check, this checkout had no Telegram token or
default monitoring database. The running demonstration uses a separate synthetic
database; production monitoring was not started.

Real Telegram credentials, external API quotas, public DNS, firewall rules and
deployment behavior still require verification in the intended environment.
See [operations and recovery](operations.md) before upgrading or restoring data.
