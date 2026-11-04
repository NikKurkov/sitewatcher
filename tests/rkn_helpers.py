"""Small on-disk registry snapshots used by publication/concurrency tests."""
from datetime import datetime, timezone
import ipaddress
from pathlib import Path
import sqlite3
import tempfile
import os
from sitewatcher.checks.rkn_block_sqlite import RegistryData


def registry_data(folder, domains, networks=None, *, source='antifilter', updated=None):
    networks = networks or {ipaddress.IPv4Network('192.0.2.1')}
    fd, name = tempfile.mkstemp(dir=folder, suffix='.sqlite')
    os.close(fd)
    with sqlite3.connect(name) as db:
        db.execute('CREATE TABLE domains(domain TEXT PRIMARY KEY)')
        db.execute('CREATE TABLE networks(start INTEGER,end INTEGER,PRIMARY KEY(start,end))')
        db.executemany('INSERT INTO domains VALUES (?)', ((d,) for d in domains))
        db.executemany('INSERT INTO networks VALUES (?,?)',
                       ((int(n.network_address), int(n.broadcast_address))
                        for n in ipaddress.collapse_addresses(networks)))
    return RegistryData(Path(name), source, updated or datetime.now(timezone.utc),
                        len(domains), len(networks))
