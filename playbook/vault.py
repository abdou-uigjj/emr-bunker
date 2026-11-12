"""SealedVault - write-once incident evidence, HMAC-chained.

Why this exists: the response playbook's decisions must be reconstructable
after the fact. A ransomware crew (or a sued clinic, or a curious admin)
must not be able to rewrite what was recorded. So every record is:

  * content-addressed  - sha256 of the bytes, stored beside the entry
  * write-once         - sealing a label twice is refused
  * chained            - entry_hmac = HMAC(key, prev || label || sha256
                         || size || meta), so dropping, reordering or
                         editing any entry breaks every later entry
  * key-gated          - records sealed with the wrong key fail closed

Failures are loud and verifiable: vault.verify() walks the whole chain and
re-hashes every blob. Anything off returns False with a reason, never a
partial pass.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import shutil
import stat
import time
from pathlib import Path

GENESIS = "0" * 64
MIN_KEY_BYTES = 32

BLOB_DIR_MODE = 0o750
BLOB_MODE = 0o440


def _canon(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


class VaultTampered(Exception):
    """Raised when read/verify hits an integrity failure."""


class SealedVault:
    """Append-only, HMAC-chained evidence store on plain disk."""

    def __init__(self, root: str | os.PathLike, key: bytes):
        if not isinstance(key, (bytes, bytearray)) or len(key) < MIN_KEY_BYTES:
            raise ValueError(
                f"vault key must be at least {MIN_KEY_BYTES} bytes"
            )
        self.root = Path(root)
        self.key = bytes(key)
        self.blob_dir = self.root / "blobs"
        self.manifest_path = self.root / "manifest.json"
        self.blob_dir.mkdir(parents=True, exist_ok=True, mode=BLOB_DIR_MODE)
        os.chmod(self.blob_dir, BLOB_DIR_MODE)
        if not self.manifest_path.exists():
            self.manifest_path.write_text("[]")

    # ------------------------------------------------------------------
    # key material
    # ------------------------------------------------------------------
    def _entry_hmac(self, prev_hmac: str, label: str, digest: str,
                    size: int, meta: dict) -> str:
        msg = "|".join([prev_hmac, label, digest, str(size), _canon(meta)])
        return hmac.new(self.key, msg.encode(), hashlib.sha256).hexdigest()

    # ------------------------------------------------------------------
    # writing
    # ------------------------------------------------------------------
    def seal(self, label: str, data: bytes, meta: dict | None = None) -> dict:
        """Seal one record. Write-once: a second seal of `label` refuses."""
        if not label or "/" in label or "\\" in label or label.startswith("."):
            raise ValueError(f"unsafe label {label!r}")
        if self.has(label):
            raise ValueError(f"label {label!r} already sealed")
        meta = meta or {}
        entries = self.entries()
        prev = entries[-1]["entry_hmac"] if entries else GENESIS
        digest = hashlib.sha256(data).hexdigest()
        size = len(data)
        entry = {
            "label": label,
            "sha256": digest,
            "size": size,
            "meta": meta,
            "prev_hmac": prev,
            "sealed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        entry["entry_hmac"] = self._entry_hmac(prev, label, digest, size, meta)

        blob = self.blob_dir / f"{label}.bin"
        tmp = self.blob_dir / f".{label}.tmp"
        tmp.write_bytes(data)
        os.chmod(tmp, BLOB_MODE)
        os.replace(tmp, blob)

        entries.append(entry)
        self._write_manifest(entries)
        return entry

    def _write_manifest(self, entries: list) -> None:
        tmp = self.root / ".manifest.tmp"
        tmp.write_text(json.dumps(entries, indent=1))
        os.replace(tmp, self.manifest_path)

    # ------------------------------------------------------------------
    # reading
    # ------------------------------------------------------------------
    def entries(self) -> list:
        return json.loads(self.manifest_path.read_text())

    def has(self, label: str) -> bool:
        return any(e["label"] == label for e in self.entries())

    def get(self, label: str) -> dict:
        for e in self.entries():
            if e["label"] == label:
                return e
        raise KeyError(label)

    def read(self, label: str) -> bytes:
        """Return the sealed bytes for `label`, verifying them first."""
        entry = self.get(label)
        blob = self.blob_dir / f"{label}.bin"
        if not blob.exists():
            raise VaultTampered(f"blob for {label!r} is missing")
        data = blob.read_bytes()
        if hashlib.sha256(data).hexdigest() != entry["sha256"]:
            raise VaultTampered(f"blob for {label!r} does not match its seal")
        return data

    def latest(self) -> dict:
        entries = self.entries()
        if not entries:
            raise KeyError("vault is empty")
        return entries[-1]

    # ------------------------------------------------------------------
    # verification
    # ------------------------------------------------------------------
    def verify(self) -> tuple[bool, str]:
        """Walk the whole chain. Returns (ok, reason)."""
        prev = GENESIS
        for e in self.entries():
            want = self._entry_hmac(
                prev, e["label"], e["sha256"], e["size"], e["meta"]
            )
            if e.get("prev_hmac") != prev:
                return False, f"chain break before {e['label']!r}"
            if not hmac.compare_digest(e["entry_hmac"], want):
                return False, f"entry_hmac mismatch at {e['label']!r}"
            blob = self.blob_dir / f"{e['label']}.bin"
            if not blob.exists():
                return False, f"missing blob {e['label']!r}"
            data = blob.read_bytes()
            if hashlib.sha256(data).hexdigest() != e["sha256"]:
                return False, f"blob hash mismatch at {e['label']!r}"
            if len(data) != e["size"]:
                return False, f"blob size mismatch at {e['label']!r}"
            prev = e["entry_hmac"]
        return True, "ok"


def unlock_tree(root: str | os.PathLike) -> None:
    """Make a vault tree (and everything beside it) removable again."""
    root = Path(root)
    if not root.exists():
        return
    for p in [root, *root.rglob("*")]:
        try:
            if p.is_dir():
                os.chmod(p, 0o700)
            else:
                os.chmod(p, 0o600)
        except OSError:
            pass


def wipe(root: str | os.PathLike) -> None:
    """Force-remove a vault tree (drills start from a clean vault)."""
    unlock_tree(root)
    shutil.rmtree(root, ignore_errors=True)
