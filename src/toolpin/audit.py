"""Hash-chained JSONL audit of digests (never raw arguments). Optional Ed25519 signatures."""

from __future__ import annotations

import hashlib
import json
import threading
import time
from pathlib import Path
from typing import Any

GENESIS = "0" * 64


def _h(body: dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()


class AuditLog:
    def __init__(self, path: str | Path | None = None, signing_key: Any = None) -> None:
        self.path = Path(path) if path else None
        self.key = signing_key  # cryptography Ed25519PrivateKey or None
        self.entries: list[dict[str, Any]] = []
        self._lock = threading.Lock()
        if self.path and self.path.exists():
            self.entries = [json.loads(x) for x in self.path.read_text().splitlines() if x.strip()]

    def append(self, principal: str, tool: str, decision: str, policy_id: str, reason: str,
               args_digest: str, extra: dict[str, Any] | None = None) -> dict[str, Any]:
        with self._lock:
            e: dict[str, Any] = {
                "seq": len(self.entries), "time": time.time(), "principal": principal,
                "tool": tool, "decision": decision, "policy_id": policy_id, "reason": reason,
                "args_digest": args_digest, "extra": extra or {},
                "prev": self.entries[-1]["hash"] if self.entries else GENESIS,
            }
            e["hash"] = _h(e)
            if self.key is not None:
                e["sig"] = self.key.sign(e["hash"].encode()).hex()
            self.entries.append(e)
            if self.path:
                with self.path.open("a") as f:
                    f.write(json.dumps(e, sort_keys=True) + "\n")
            return e


def verify_entries(entries: list[dict[str, Any]], public_key: Any = None,
                   expected_head: str | None = None) -> tuple[bool, str]:
    prev = GENESIS
    for i, e in enumerate(entries):
        body = {k: v for k, v in e.items() if k not in {"hash", "sig"}}
        if e.get("seq") != i or e.get("prev") != prev:
            return False, f"entry {i}: chain broken"
        if _h(body) != e.get("hash"):
            return False, f"entry {i}: content hash mismatch"
        if public_key is not None:
            try:
                public_key.verify(bytes.fromhex(e.get("sig", "")), e["hash"].encode())
            except Exception:
                return False, f"entry {i}: bad or missing signature"
        prev = e["hash"]
    if expected_head is not None and prev != expected_head:
        return False, "head mismatch (truncated or replaced)"
    return True, f"ok: {len(entries)} entries"


def verify_file(path: str | Path, public_key: Any = None, expected_head: str | None = None):
    try:
        entries = [json.loads(x) for x in Path(path).read_text().splitlines() if x.strip()]
    except (OSError, json.JSONDecodeError) as e:
        return False, f"unreadable: {e}"
    return verify_entries(entries, public_key, expected_head)
