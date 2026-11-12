"""SQLite engine - the clinic-in-a-box backend.

Runs anywhere python runs: one database file for the chart room, one
folder of 'scanned referral' documents. The attacker encrypts patient
rows in offset sweeps and the documents folder, exactly the shape a
real ransomware crew works: mass-row encryption first, file shares next.

Isolation is file-mode lockout (the app user loses write on the db and
the documents tree), the snapshot is a full sqlite dump plus the
documents, and the replica is rebuilt into a separate directory and
opened through a read-only URI.
"""

from __future__ import annotations

import hashlib
import io
import os
import random
import shutil
import sqlite3
import zipfile
from pathlib import Path

from ..core import Proof
from .local import Engine
from canary.stores import (
    FileCanaryStore, MultiStore, SqliteCanaryStore, write_honeypots,
)

LOCKED_FILE_MODE = 0o440
LOCKED_DIR_MODE = 0o550
WORK_DIR_MODE = 0o770

FIRST = ("Ahmed", "Grace", "Yusuf", "Marta", "Chidi", "Lena", "Omar",
         "Sofia", "Tariq", "Ines")
LAST = ("Ben Ali", "Okafor", "Novak", "Haddad", "Muller", "Silva",
        "Chowdhury", "Trabelsi", "Rossi", "Adeyemi")
DIAG = ("type-2 diabetes", "stage-1 hypertension", "asthma",
        "anemia", "migraine", "hypothyroidism", "gerd", "arthritis")

DECOY_IDS = (37, 62, 87, 112, 137, 162, 187, 199)


def running_as_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0


class SqliteAttacker:
    """Scripted adversary: sweeps patient rows, then the documents."""

    def __init__(self, engine: "SqliteEngine"):
        self.engine = engine
        self.rows_encrypted = 0
        self.files_encrypted = 0

    def try_write(self) -> bool:
        """Can the attacker still write to the primary db?"""
        try:
            con = sqlite3.connect(self.engine.db_path)
            try:
                con.execute("CREATE TABLE IF NOT EXISTS _attack_probe (x)")
                con.commit()
                con.execute("DROP TABLE _attack_probe")
                con.commit()
                return True
            finally:
                con.close()
        except sqlite3.OperationalError:
            return False

    def encrypt_mass(self, offset: int = 0, count: int = 50) -> int:
        """Encrypt a window of patient rows, ransomware-style."""
        con = sqlite3.connect(self.engine.db_path)
        try:
            rows = con.execute(
                "SELECT id FROM patients ORDER BY id LIMIT ? OFFSET ?",
                (count, offset),
            ).fetchall()
            for (rid,) in rows:
                blob = hashlib.sha256(f"enc-{rid}".encode()).hexdigest()
                con.execute(
                    "UPDATE patients SET name = ?, diagnosis = ? "
                    "WHERE id = ?",
                    (f"ENC:{blob[:12]}", "RAISED", rid),
                )
            con.commit()
        finally:
            con.close()
        self.rows_encrypted += len(rows)
        return len(rows)

    def encrypt_documents(self) -> int:
        """Encrypt every document in place."""
        n = 0
        for p in sorted(Path(self.engine.documents_dir).glob("*")):
            if p.is_file():
                data = p.read_bytes()
                p.write_bytes(b"ENC[" + hashlib.sha256(data).digest()
                              + b"]" + data[:16])
                n += 1
        self.files_encrypted += n
        return n


class SqliteEngine(Engine):
    """Nine-primitive engine over one sqlite file + a documents folder."""

    kind = "sqlite"

    def __init__(self, root: str):
        self.root = Path(root)
        self.db_path = str(self.root / "clinic.db")
        self.documents_dir = str(self.root / "documents")
        self.replica_dir = self.root / "replica"
        self._clean_meta: dict = {}
        self._replica_ro_uri: str = ""

    # ------------------------------------------------------------------
    # 1. seed
    # ------------------------------------------------------------------
    def seed(self, patients: int = 200, canaries: int = 8) -> None:
        """Build the fake EMR. Wipes and rebuilds the tree."""
        _unlock_tree(self.root)
        shutil.rmtree(self.root, ignore_errors=True)
        self.root.mkdir(parents=True, exist_ok=True)
        os.chmod(self.root, WORK_DIR_MODE)
        Path(self.documents_dir).mkdir(parents=True, exist_ok=True)

        con = sqlite3.connect(self.db_path)
        try:
            con.execute(
                "CREATE TABLE patients ("
                " id INTEGER PRIMARY KEY, mrn TEXT NOT NULL,"
                " name TEXT NOT NULL, dob TEXT NOT NULL,"
                " diagnosis TEXT NOT NULL, is_decoy INTEGER DEFAULT 0)"
            )
            rng = random.Random(20261112)
            decoys = set(DECOY_IDS[:canaries])
            for i in range(1, patients + 1):
                con.execute(
                    "INSERT INTO patients (id, mrn, name, dob, diagnosis,"
                    " is_decoy) VALUES (?,?,?,?,?,?)",
                    (
                        i,
                        f"MRN-{i:06d}",
                        f"{rng.choice(FIRST)} {rng.choice(LAST)}",
                        f"19{rng.randint(40, 99)}-{rng.randint(1, 12):02d}"
                        f"-{rng.randint(1, 28):02d}",
                        rng.choice(DIAG),
                        1 if i in decoys else 0,
                    ),
                )
            con.commit()
        finally:
            con.close()

        write_honeypots(self.documents_dir, count=4)

    # ------------------------------------------------------------------
    # 2. content fingerprint
    # ------------------------------------------------------------------
    def content_hash(self) -> str:
        con = sqlite3.connect(f"file:{self.db_path}?mode=ro", uri=True)
        try:
            rows = con.execute(
                "SELECT id, mrn, name, diagnosis FROM patients "
                "ORDER BY id"
            ).fetchall()
        finally:
            con.close()
        h = hashlib.sha256()
        for r in rows:
            h.update(f"{r[0]}|{r[1]}|{r[2]}|{r[3]}\n".encode())
        for p in sorted(Path(self.documents_dir).glob("*")):
            if p.is_file():
                h.update(p.name.encode())
                h.update(p.read_bytes())
        return h.hexdigest()

    # ------------------------------------------------------------------
    # 3. canary store (rows + honeypot files)
    # ------------------------------------------------------------------
    def canary_store(self) -> MultiStore:
        return MultiStore([
            SqliteCanaryStore(self.db_path, name="sqlite-patients"),
            FileCanaryStore(self.documents_dir, name="documents"),
        ])

    # ------------------------------------------------------------------
    # 4. attacker
    # ------------------------------------------------------------------
    def attacker(self) -> SqliteAttacker:
        return SqliteAttacker(self)

    # ------------------------------------------------------------------
    # 5. snapshot (seal time)
    # ------------------------------------------------------------------
    def snapshot_bytes(self) -> bytes:
        """Zip of the sql dump + every document. Restorable as-is."""
        con = sqlite3.connect(self.db_path)
        try:
            dump = "\n".join(con.iterdump())
        finally:
            con.close()
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("dump.sql", dump)
            for p in sorted(Path(self.documents_dir).glob("*")):
                if p.is_file():
                    zf.write(p, f"documents/{p.name}")
        return buf.getvalue()

    # ------------------------------------------------------------------
    # 6. isolate
    # ------------------------------------------------------------------
    def isolate(self) -> None:
        """File-mode lockout: the attacker loses write everywhere."""
        os.chmod(self.db_path, LOCKED_FILE_MODE)
        for p in Path(self.documents_dir).glob("*"):
            if p.is_file():
                os.chmod(p, LOCKED_FILE_MODE)
        os.chmod(self.documents_dir, LOCKED_DIR_MODE)

    # ------------------------------------------------------------------
    # 7. isolation proofs
    # ------------------------------------------------------------------
    def isolation_proofs(self) -> list:
        proofs = []
        if running_as_root():
            proofs.append(Proof(
                "attacker-write-denied", False,
                "running as root - file lockout is not enforceable",
            ))
            return proofs
        attacker = SqliteAttacker(self)
        denied = not attacker.try_write()
        proofs.append(Proof(
            "attacker-write-denied", denied,
            "write to primary db fails" if denied
            else "attacker can still write the primary",
        ))
        locked = (os.stat(self.db_path).st_mode & 0o222) == 0
        proofs.append(Proof(
            "primary-locked", locked,
            f"db mode {oct(os.stat(self.db_path).st_mode & 0o777)}",
        ))
        return proofs

    # ------------------------------------------------------------------
    # 8. restore replica
    # ------------------------------------------------------------------
    def restore_replica(self, clean: dict, clean_bytes: bytes) -> None:
        """Rebuild the break-glass replica from a sealed baseline."""
        self._clean_meta = clean.get("meta", {})
        shutil.rmtree(self.replica_dir, ignore_errors=True)
        self.replica_dir.mkdir(parents=True, exist_ok=True)

        rep_db = self.replica_dir / "clinic.db"
        rep_docs = self.replica_dir / "documents"
        rep_docs.mkdir(parents=True, exist_ok=True)

        con = sqlite3.connect(str(rep_db))
        try:
            with zipfile.ZipFile(io.BytesIO(clean_bytes)) as zf:
                con.executescript(zf.read("dump.sql").decode())
                for name in zf.namelist():
                    if name.startswith("documents/"):
                        (rep_docs / Path(name).name).write_bytes(
                            zf.read(name)
                        )
            con.commit()
        finally:
            con.close()

        os.chmod(str(rep_db), LOCKED_FILE_MODE)
        for p in rep_docs.glob("*"):
            os.chmod(p, LOCKED_FILE_MODE)
        os.chmod(str(rep_docs), LOCKED_DIR_MODE)
        self._replica_ro_uri = f"file:{rep_db}?mode=ro"

    # ------------------------------------------------------------------
    # 9. replica proofs
    # ------------------------------------------------------------------
    def replica_proofs(self) -> list:
        proofs = []
        want = self._clean_meta.get("content_hash", "")
        got = self._replica_content_hash()
        proofs.append(Proof(
            "replica-hash-match", bool(want) and got == want,
            f"replica {got[:12]} vs sealed {want[:12]}" if want
            else "no content_hash in the sealed baseline meta",
        ))
        ro_ok = False
        if not running_as_root():
            try:
                con = sqlite3.connect(self._replica_ro_uri, uri=True)
                try:
                    con.execute("CREATE TABLE _probe (x)")
                except sqlite3.OperationalError:
                    ro_ok = True
                finally:
                    con.close()
            except sqlite3.OperationalError:
                ro_ok = True
        writable_bits = os.stat(self.replica_dir / "clinic.db").st_mode
        proofs.append(Proof(
            "replica-read-only", ro_ok and (writable_bits & 0o222) == 0,
            "write via ro-uri refused and file modes are locked"
            if ro_ok else "replica accepted a write",
        ))
        return proofs

    # ------------------------------------------------------------------
    def _replica_content_hash(self) -> str:
        con = sqlite3.connect(self._replica_ro_uri, uri=True)
        try:
            rows = con.execute(
                "SELECT id, mrn, name, diagnosis FROM patients ORDER BY id"
            ).fetchall()
        finally:
            con.close()
        h = hashlib.sha256()
        for r in rows:
            h.update(f"{r[0]}|{r[1]}|{r[2]}|{r[3]}\n".encode())
        for p in sorted((self.replica_dir / "documents").glob("*")):
            if p.is_file():
                h.update(p.name.encode())
                h.update(p.read_bytes())
        return h.hexdigest()

    # ------------------------------------------------------------------
    def wipe(self) -> None:
        _unlock_tree(self.root)
        shutil.rmtree(self.root, ignore_errors=True)


def _unlock_tree(root: Path) -> None:
    if not root.exists():
        return
    for p in [root, *root.rglob("*")]:
        try:
            os.chmod(p, 0o700 if p.is_dir() else 0o600)
        except OSError:
            pass
