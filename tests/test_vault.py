import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from playbook.vault import GENESIS, SealedVault, VaultTampered, wipe  # noqa: E402


def fresh(tmp_path):
    root = tmp_path / "vault"
    return SealedVault(root, key=b"k" * 48)


def test_seal_and_read_roundtrip(tmp_path):
    v = fresh(tmp_path)
    v.seal("baseline", b"snapshot-bytes", meta={"kind": "baseline"})
    assert v.read("baseline") == b"snapshot-bytes"
    ok, why = v.verify()
    assert ok, why


def test_labels_are_write_once(tmp_path):
    v = fresh(tmp_path)
    v.seal("baseline", b"one")
    with pytest.raises(ValueError):
        v.seal("baseline", b"two")


def test_blob_tamper_fails_verify(tmp_path):
    v = fresh(tmp_path)
    v.seal("baseline", b"payload")
    blob = v.blob_dir / "baseline.bin"
    blob.chmod(0o644)  # an attacker with chmod gets this far...
    blob.write_bytes(b"payload-tampered")
    ok, why = v.verify()
    assert not ok
    assert "hash mismatch" in why
    with pytest.raises(VaultTampered):
        v.read("baseline")


def test_chain_reorder_fails(tmp_path):
    v = fresh(tmp_path)
    v.seal("a", b"aaa")
    v.seal("b", b"bbb")
    entries = v.entries()
    entries[0], entries[1] = entries[1], entries[0]
    v._write_manifest(entries)
    ok, why = v.verify()
    assert not ok


def test_chain_drop_fails(tmp_path):
    v = fresh(tmp_path)
    v.seal("a", b"aaa")
    v.seal("b", b"bbb")
    entries = [e for e in v.entries() if e["label"] != "a"]
    v._write_manifest(entries)
    ok, why = v.verify()
    assert not ok
    assert "chain break" in why or "entry_hmac mismatch" in why


def test_wrong_key_fails_closed(tmp_path):
    root = tmp_path / "vault"
    SealedVault(root, key=b"k" * 48).seal("baseline", b"payload")
    other = SealedVault(root, key=b"j" * 48)
    ok, why = other.verify()
    assert not ok
    assert "entry_hmac mismatch" in why


def test_short_key_refused(tmp_path):
    with pytest.raises(ValueError):
        SealedVault(tmp_path / "v", key=b"short")


def test_genesis_and_meta_roundtrip(tmp_path):
    v = fresh(tmp_path)
    entry = v.seal("baseline", b"payload", meta={"content_hash": "abc"})
    assert entry["prev_hmac"] == GENESIS
    assert v.get("baseline")["meta"]["content_hash"] == "abc"
