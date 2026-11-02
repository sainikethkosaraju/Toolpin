"""Out-of-band approval for clients that cannot do MRTR (or when policy prefers it).
An operator runs `toolpin approve-call REF` on a trusted machine. An approval is one-shot and
bound to (principal, tool, canonical-args hash)."""

from __future__ import annotations

import json
import secrets
import time
from collections.abc import Callable
from pathlib import Path

from toolpin.canonical import args_hash


class OutOfBandApprovals:
    def __init__(self, path: str | Path | None = None, ttl: float = 900.0,
                 clock: Callable[[], float] = time.time) -> None:
        self.path = Path(path) if path else None
        self.ttl, self.clock = ttl, clock
        self.data: dict[str, dict] = {}
        if self.path and self.path.exists():
            self.data = json.loads(self.path.read_text() or "{}")

    def _save(self) -> None:
        if self.path:
            self.path.write_text(json.dumps(self.data, indent=1, sort_keys=True))

    def _reload(self) -> None:
        if self.path and self.path.exists():
            self.data = json.loads(self.path.read_text() or "{}")

    def request(self, principal: str, tool: str, arguments: dict | None) -> str:
        self._reload()
        h = args_hash(arguments)
        for ref, r in self.data.items():  # reuse a live pending request for the same call
            if (r["principal"], r["tool"], r["args"], r["status"]) == (principal, tool, h, "pending") \
                    and r["exp"] > self.clock():
                return ref
        ref = secrets.token_hex(4)
        self.data[ref] = {"principal": principal, "tool": tool, "args": h, "status": "pending",
                          "exp": self.clock() + self.ttl}
        self._save()
        return ref

    def approve(self, ref: str) -> bool:
        self._reload()
        r = self.data.get(ref)
        if not r or r["status"] != "pending" or r["exp"] < self.clock():
            return False
        r["status"] = "approved"
        self._save()
        return True

    def consume(self, principal: str, tool: str, arguments: dict | None) -> bool:
        self._reload()
        h = args_hash(arguments)
        for _ref, r in self.data.items():
            if (r["principal"], r["tool"], r["args"], r["status"]) == (principal, tool, h, "approved") \
                    and r["exp"] >= self.clock():
                r["status"] = "used"
                self._save()
                return True
        return False
