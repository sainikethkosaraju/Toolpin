"""Call counts, output size caps and a per-tool circuit breaker."""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass, field


@dataclass
class Budgets:
    max_calls_per_tool: int | None = None
    max_total_calls: int | None = None
    max_output_bytes: int | None = None
    breaker_threshold: int = 5  # consecutive failures that open the breaker
    breaker_cooldown: float = 30.0
    clock: Callable[[], float] = time.monotonic
    _calls: dict[str, int] = field(default_factory=dict)
    _fails: dict[str, int] = field(default_factory=dict)
    _open_until: dict[str, float] = field(default_factory=dict)

    def check(self, tool: str) -> str | None:
        if self.clock() < self._open_until.get(tool, 0.0):
            return "circuit breaker open"
        if self.max_total_calls is not None and sum(self._calls.values()) >= self.max_total_calls:
            return "total call budget exhausted"
        if self.max_calls_per_tool is not None and self._calls.get(tool, 0) >= self.max_calls_per_tool:
            return "per-tool call budget exhausted"
        return None

    def record(self, tool: str, ok: bool) -> None:
        self._calls[tool] = self._calls.get(tool, 0) + 1
        if ok:
            self._fails[tool] = 0
            return
        self._fails[tool] = self._fails.get(tool, 0) + 1
        if self._fails[tool] >= self.breaker_threshold:
            self._open_until[tool] = self.clock() + self.breaker_cooldown
            self._fails[tool] = 0

    def check_output(self, size: int) -> str | None:
        if self.max_output_bytes is not None and size > self.max_output_bytes:
            return f"output of {size} bytes exceeds cap {self.max_output_bytes}"
        return None
