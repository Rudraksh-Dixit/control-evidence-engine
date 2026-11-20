from __future__ import annotations

from pathlib import Path

from cee.attest import add_attestation, load_registry
from cee.evidence import canonical_bytes, content_hash


def test_canonical_hash_is_stable() -> None:
    first = {"b": 2, "a": [1, 2, 3]}
    second = {"a": [1, 2, 3], "b": 2}
    assert canonical_bytes(first) == canonical_bytes(second)
    assert content_hash(first) == content_hash(second)
    assert content_hash({"a": 1}) != content_hash({"a": 2})


def test_manual_attestation_roundtrip_and_tamper(tmp_path: Path) -> None:
    policy = tmp_path / "policy.md"
    policy.write_text("# Policy\nApproved.\n", encoding="utf-8")
    registry = tmp_path / "manual_evidence" / "index.json"

    entry = add_attestation(
        registry_path=registry,
        control_id="A.5.1",
        source_file=policy,
        note="Approved by the board",
        attested_by="Rudraksh",
    )
    assert entry["control_id"] == "A.5.1"
    assert len(entry["sha256"]) == 64

    grouped = load_registry(registry)
    assert grouped["A.5.1"][0]["valid"] is True
    assert grouped["A.5.1"][0]["note"] == "Approved by the board"

    stored = registry.parent / entry["file"]
    stored.write_text("tampered", encoding="utf-8")
    grouped = load_registry(registry)
    assert grouped["A.5.1"][0]["valid"] is False
