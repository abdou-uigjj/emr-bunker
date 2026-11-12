"""Canary stores - the tripwires.

A canary is a decoy the attacker must step on: fake patient rows inside
the real table and honeypot files inside the real documents folder. The
agent polls digests; any drift means somebody touched the decoys.

Decoys are rows like any other (is_decoy=1 is the only marker), so an
attacker sweeping the table with offset windows will encrypt decoy rows
long before they finish the real chart room.
"""

from __future__ import annotations

import hashlib
import os
import sqlite3
from pathlib import Path
from typing import NamedTuple


class TamperSignal(NamedTuple):
    """Raised evidence that a decoy changed."""

    source: str          # store name that caught it, e.g. "sqlite-patients"
    canary_id: str       # which decoy
    expected: str        # digest the agent armed with
    observed: str        # digest seen now
    detail: str = ""


def digest_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class CanaryStore:
    """A set of decoys the agent can re-digest on demand."""

    name = "canary"

    def decoys(self) -> list:
        """Return [(canary_id, digest), ...] for every decoy."""
        raise NotImplementedError

    def observe(self, canary_id: str) -> str:
        """Current digest of one decoy."""
        raise NotImplementedError


class SqliteCanaryStore(CanaryStore):
    """Decoy rows inside the patients table of the EMR database."""

    def __init__(self, db_path: str, table: str = "patients",
                 marker_column: str = "is_decoy", name: str = "sqlite"):
        self.db_path = str(db_path)
        self.table = table
        self.marker_column = marker_column
        self.name = name

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.db_path)

    def decoys(self) -> list:
        out = []
        con = self._connect()
        try:
            rows = con.execute(
                f"SELECT id, mrn, name, diagnosis FROM {self.table} "
                f"WHERE {self.marker_column} = 1 ORDER BY id"
            ).fetchall()
        finally:
            con.close()
        for rid, mrn, name, diagnosis in rows:
            payload = f"{mrn}|{name}|{diagnosis}".encode()
            out.append((f"row:{rid}", digest_bytes(payload)))
        return out

    def observe(self, canary_id: str) -> str:
        rid = int(canary_id.split(":", 1)[1])
        con = self._connect()
        try:
            row = con.execute(
                f"SELECT mrn, name, diagnosis FROM {self.table} WHERE id = ?",
                (rid,),
            ).fetchone()
        finally:
            con.close()
        if row is None:
            return "GONE"
        payload = f"{row[0]}|{row[1]}|{row[2]}".encode()
        return digest_bytes(payload)


class FileCanaryStore(CanaryStore):
    """Honeypot files in the documents folder."""

    def __init__(self, directory: str, name: str = "files"):
        self.dir = Path(directory)
        self.name = name

    def decoys(self) -> list:
        out = []
        for p in sorted(self.dir.glob("*.pdf")):
            out.append((f"file:{p.name}", digest_bytes(p.read_bytes())))
        return out

    def observe(self, canary_id: str) -> str:
        fname = canary_id.split(":", 1)[1]
        p = self.dir / fname
        if not p.exists():
            return "GONE"
        return digest_bytes(p.read_bytes())


class MysqlCanaryStore(CanaryStore):
    """Decoy rows in a MySQL-backed EMR (used by the mysql engine)."""

    def __init__(self, connection_factory, table: str = "patients",
                 name: str = "mysql"):
        self._cf = connection_factory
        self.table = table
        self.name = name

    def decoys(self) -> list:
        con = self._cf()
        try:
            with con.cursor() as cur:
                cur.execute(
                    f"SELECT id, mrn, name, diagnosis FROM {self.table} "
                    f"WHERE is_decoy = 1 ORDER BY id"
                )
                rows = cur.fetchall()
        finally:
            con.close()
        return [
            (f"row:{r[0]}",
             digest_bytes(f"{r[1]}|{r[2]}|{r[3]}".encode()))
            for r in rows
        ]

    def observe(self, canary_id: str) -> str:
        rid = int(canary_id.split(":", 1)[1])
        con = self._cf()
        try:
            with con.cursor() as cur:
                cur.execute(
                    f"SELECT mrn, name, diagnosis FROM {self.table} "
                    f"WHERE id = %s", (rid,)
                )
                row = cur.fetchone()
        finally:
            con.close()
        if row is None:
            return "GONE"
        return digest_bytes(f"{row[0]}|{row[1]}|{row[2]}".encode())


class MultiStore(CanaryStore):
    """Fan a check across every store; name carries the winner."""

    def __init__(self, stores: list):
        self.stores = stores
        self.name = "+".join(s.name for s in stores)

    def decoys(self) -> list:
        out = []
        for s in self.stores:
            out.extend(s.decoys())
        return out

    def observe(self, canary_id: str) -> str:
        kind, _, _ = canary_id.partition(":")
        for s in self.stores:
            prefix = "row" if hasattr(s, "table") or "sqlite" in s.name \
                or "mysql" in s.name else "file"
            if kind == prefix:
                return s.observe(canary_id)
        return "GONE"


def write_honeypots(directory: str, count: int = 4) -> None:
    """Seed honeypot 'scanned referral' PDFs a ransomware crew loves."""
    d = Path(directory)
    d.mkdir(parents=True, exist_ok=True)
    for i in range(1, count + 1):
        p = d / f"referral-2026-{i:04d}.pdf"
        if not p.exists():
            body = (
                b"%PDF-1.4\n% ghost-box honeypot referral scan\n"
                + os.urandom(48).hex().encode() + b"\n"
                + f"referral scan {i}\n".encode()
            )
            p.write_bytes(body)
            os.chmod(p, 0o640)
