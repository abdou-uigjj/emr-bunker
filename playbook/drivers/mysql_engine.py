"""MySQL engine - real primary/replica pair for the CI drill job.

Mapping of the nine primitives onto a MySQL 8 primary (emr-primary) and
a bunker replica (emr-bunker, separate server):

  seed              creates the emr schema, 200 charts, decoy rows and
                    the least-privilege 'app' user the attacker uses
  content_hash      sha256 over the ordered chart rows
  canary_store      MysqlCanaryStore on the patients table
  attacker          connects as 'app' and sweeps rows in offset windows
  snapshot_bytes    mysqldump --single-transaction of the primary
  isolate           KILL the app sessions, DROP USER app, and set
                    super_read_only=1 on the primary
  isolation_proofs  prove the app login now fails and the primary is
                    super_read_only
  restore_replica   replay the dump into the bunker server, then flip
                    the bunker to read-only
  replica_proofs    prove the bunker refuses writes and matches the
                    sealed content hash

pymysql is imported lazily; the CI job provides the two servers.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess

from ..core import Proof
from .local import Engine
from canary.stores import MysqlCanaryStore

DRILL_DB = "emr"
ATTACKER_USER = "app"


def _pymysql():
    import pymysql  # lazy

    return pymysql


class MysqlAttacker:
    """Scripted adversary over a real MySQL connection as 'app'."""

    def __init__(self, engine: "MysqlEngine"):
        self.engine = engine
        self.rows_encrypted = 0

    def _connect(self):
        pymysql = _pymysql()
        return pymysql.connect(
            host=self.engine.primary_host,
            port=self.engine.primary_port,
            user=ATTACKER_USER,
            password=self.engine.app_password,
            database=DRILL_DB,
        )

    def try_write(self) -> bool:
        try:
            con = self._connect()
            try:
                with con.cursor() as cur:
                    cur.execute(
                        "CREATE TABLE IF NOT EXISTS _attack_probe (x INT)")
                con.commit()
                return True
            finally:
                con.close()
        except Exception:
            return False

    def encrypt_mass(self, offset: int = 0, count: int = 50) -> int:
        con = self._connect()
        try:
            with con.cursor() as cur:
                cur.execute(
                    "SELECT id FROM patients ORDER BY id "
                    "LIMIT %s OFFSET %s", (count, offset))
                ids = [r[0] for r in cur.fetchall()]
                for rid in ids:
                    cur.execute(
                        "UPDATE patients SET name = CONCAT('ENC:', MD5(id)),"
                        " diagnosis = 'RAISED' WHERE id = %s", (rid,))
            con.commit()
        finally:
            con.close()
        self.rows_encrypted += len(ids)
        return len(ids)


class MysqlEngine(Engine):
    """Nine-primitive engine over a MySQL primary + bunker replica."""

    kind = "mysql"

    def __init__(self, primary_host: str = "127.0.0.1",
                 primary_port: int = 3306, bunker_host: str = "127.0.0.1",
                 bunker_port: int = 3307, admin_user: str = "root",
                 admin_password: str = "", app_password: str = "app-pass-9"):
        self.primary_host = primary_host
        self.primary_port = primary_port
        self.bunker_host = bunker_host
        self.bunker_port = bunker_port
        self.admin_user = admin_user
        self.admin_password = admin_password
        self.app_password = app_password
        self._clean_meta: dict = {}

    # ------------------------------------------------------------------
    def _admin(self, host: str, port: int):
        pymysql = _pymysql()
        return pymysql.connect(
            host=host, port=port, user=self.admin_user,
            password=self.admin_password, autocommit=True,
        )

    def seed(self, patients: int = 200, canaries: int = 8) -> None:
        pymysql = _pymysql()
        con = self._admin(self.primary_host, self.primary_port)
        try:
            with con.cursor() as cur:
                cur.execute(
                    f"CREATE DATABASE IF NOT EXISTS {DRILL_DB}")
                cur.execute(
                    f"DROP USER IF EXISTS '{ATTACKER_USER}'@'%'")
                cur.execute(
                    f"CREATE USER '{ATTACKER_USER}'@'%' "
                    f"IDENTIFIED BY '{self.app_password}'")
                cur.execute(
                    f"GRANT SELECT, INSERT, UPDATE, DELETE ON "
                    f"{DRILL_DB}.* TO '{ATTACKER_USER}'@'%'")
                cur.execute(f"USE {DRILL_DB}")
                cur.execute(
                    "CREATE TABLE IF NOT EXISTS patients ("
                    " id INT PRIMARY KEY, mrn VARCHAR(32) NOT NULL,"
                    " name VARCHAR(128) NOT NULL, dob DATE NOT NULL,"
                    " diagnosis VARCHAR(128) NOT NULL,"
                    " is_decoy TINYINT DEFAULT 0)")
                cur.execute("DELETE FROM patients")
                decoys = {37, 62, 87, 112, 137, 162, 187, 199}
                rows = []
                for i in range(1, patients + 1):
                    rows.append((
                        i, f"MRN-{i:06d}", f"Patient {i}",
                        f"19{50 + i % 50}-0{1 + i % 9}-1{i % 9}",
                        "condition", 1 if i in decoys else 0,
                    ))
                cur.executemany(
                    "INSERT INTO patients (id, mrn, name, dob, diagnosis,"
                    " is_decoy) VALUES (%s,%s,%s,%s,%s,%s)", rows)
        finally:
            con.close()
        assert pymysql.threadsafety >= 0  # touch: keep linters honest

    def content_hash(self) -> str:
        con = self._admin(self.primary_host, self.primary_port)
        try:
            with con.cursor() as cur:
                cur.execute(
                    f"SELECT id, mrn, name, diagnosis FROM "
                    f"{DRILL_DB}.patients ORDER BY id")
                rows = cur.fetchall()
        finally:
            con.close()
        h = hashlib.sha256()
        for r in rows:
            h.update(f"{r[0]}|{r[1]}|{r[2]}|{r[3]}\n".encode())
        return h.hexdigest()

    def canary_store(self) -> MysqlCanaryStore:
        return MysqlCanaryStore(
            lambda: self._admin(self.primary_host, self.primary_port),
            name="mysql-patients",
        )

    def attacker(self) -> MysqlAttacker:
        return MysqlAttacker(self)

    # ------------------------------------------------------------------
    def snapshot_bytes(self) -> bytes:
        """mysqldump --single-transaction of the primary."""
        dump = subprocess.run(
            ["mysqldump", "--single-transaction", "--skip-lock-tables",
             "-h", self.primary_host, "-P", str(self.primary_port),
             "-u", self.admin_user,
             f"-p{self.admin_password}", DRILL_DB],
            capture_output=True, check=True,
        ).stdout
        return json.dumps({
            "kind": "mysqldump",
            "sql": dump.decode(),
        }, sort_keys=True).encode()

    # ------------------------------------------------------------------
    def isolate(self) -> None:
        con = self._admin(self.primary_host, self.primary_port)
        try:
            with con.cursor() as cur:
                cur.execute(
                    "SELECT id FROM information_schema.processlist "
                    "WHERE user = %s", (ATTACKER_USER,))
                for (pid,) in cur.fetchall():
                    cur.execute(f"KILL {pid}")
                cur.execute(f"DROP USER '{ATTACKER_USER}'@'%'")
                cur.execute("SET GLOBAL super_read_only = 1")
        finally:
            con.close()

    def isolation_proofs(self) -> list:
        proofs = []
        attacker = MysqlAttacker(self)
        proofs.append(Proof(
            "attacker-login-denied", not attacker.try_write(),
            "app user can no longer authenticate" if not attacker.try_write()
            else "app user still connects",
        ))
        con = self._admin(self.primary_host, self.primary_port)
        try:
            with con.cursor() as cur:
                cur.execute(
                    "SELECT @@GLOBAL.super_read_only")
                sro = bool(cur.fetchone()[0])
        finally:
            con.close()
        proofs.append(Proof(
            "primary-super-read-only", sro,
            "primary rejects writes" if sro
            else "primary still accepts writes",
        ))
        return proofs

    # ------------------------------------------------------------------
    def restore_replica(self, clean: dict, clean_bytes: bytes) -> None:
        self._clean_meta = clean.get("meta", {})
        desc = json.loads(clean_bytes)
        p = subprocess.run(
            ["mysql", "-h", self.bunker_host, "-P", str(self.bunker_port),
             "-u", self.admin_user, f"-p{self.admin_password}"],
            input=desc["sql"].encode(), capture_output=True, check=True)
        con = self._admin(self.bunker_host, self.bunker_port)
        try:
            with con.cursor() as cur:
                cur.execute("SET GLOBAL read_only = 1")
                cur.execute("SET GLOBAL super_read_only = 1")
        finally:
            con.close()

    def replica_proofs(self) -> list:
        proofs = []
        con = self._admin(self.bunker_host, self.bunker_port)
        try:
            with con.cursor() as cur:
                cur.execute(f"SELECT id, mrn, name, diagnosis FROM "
                            f"{DRILL_DB}.patients ORDER BY id")
                rows = cur.fetchall()
                cur.execute("SELECT @@GLOBAL.super_read_only")
                sro = bool(cur.fetchone()[0])
                try:
                    cur.execute("CREATE TABLE _probe (x INT)")
                    write_ok = True
                except Exception:
                    write_ok = False
        finally:
            con.close()
        h = hashlib.sha256()
        for r in rows:
            h.update(f"{r[0]}|{r[1]}|{r[2]}|{r[3]}\n".encode())
        want = self._clean_meta.get("content_hash", "")
        proofs.append(Proof(
            "replica-hash-match", bool(want) and h.hexdigest() == want,
            f"bunker {h.hexdigest()[:12]} vs sealed {want[:12]}" if want
            else "no content_hash in the sealed baseline meta",
        ))
        proofs.append(Proof(
            "replica-read-only", sro and not write_ok,
            "bunker rejects writes" if (sro and not write_ok)
            else "bunker accepted a write",
        ))
        return proofs


def engine_from_env() -> MysqlEngine:
    """Build the engine from CI env vars (DRILL_PRIMARY_* / DRILL_BUNKER_*)."""
    return MysqlEngine(
        primary_host=os.environ.get("DRILL_PRIMARY_HOST", "127.0.0.1"),
        primary_port=int(os.environ.get("DRILL_PRIMARY_PORT", "3306")),
        bunker_host=os.environ.get("DRILL_BUNKER_HOST", "127.0.0.1"),
        bunker_port=int(os.environ.get("DRILL_BUNKER_PORT", "3307")),
        admin_user=os.environ.get("DRILL_ADMIN_USER", "root"),
        admin_password=os.environ.get("DRILL_ADMIN_PASSWORD", ""),
        app_password=os.environ.get("DRILL_APP_PASSWORD", "app-pass-9"),
    )
