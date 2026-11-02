"""Sandboxed spawn of an upstream MCP server with a logged launch record.

Layers (each independently optional, none a complete sandbox on its own):
  * scrubbed environment: only allow-listed variables pass; anything that looks like a credential
    is dropped unless named in `pass_env` (a deliberate, logged decision);
  * resource limits + no_new_privs via the launcher (memory, CPU, open files, processes, no core dumps);
  * optional bubblewrap (`bwrap`) for filesystem/PID/IPC/UTS (and optionally network) isolation.
HONEST LIMIT: rlimits and env scrubbing contain accidents and casual abuse; they are not a
security boundary against a determined malicious server. Use bwrap/containers for that."""
from __future__ import annotations

import hashlib
import os
import re
import shutil
import sys
import time
from dataclasses import dataclass, field
from typing import Any

from mcp import StdioServerParameters

SECRETISH = re.compile(r"(key|token|secret|passw|credential|auth|cookie|session)", re.I)
DEFAULT_ALLOW = ("PATH", "LANG", "LC_ALL", "TZ", "PYTHONPATH", "VIRTUAL_ENV", "SYSTEMROOT")


@dataclass
class Sandbox:
    env_allow: tuple[str, ...] = DEFAULT_ALLOW
    pass_env: tuple[str, ...] = ()            # explicit exceptions, recorded in the launch record
    cwd: str | None = None
    as_mb: int | None = 1024
    cpu_s: int | None = 600
    nofile: int | None = 256
    nproc: int | None = 128
    bwrap: bool = False
    bwrap_net: bool = True                    # False: --unshare-net
    extra_env: dict[str, str] = field(default_factory=dict)

    def scrub(self, environ: dict[str, str] | None = None) -> dict[str, str]:
        src = os.environ if environ is None else environ
        out = {k: v for k, v in src.items() if k in self.env_allow and not SECRETISH.search(k)}
        out.update({k: src[k] for k in self.pass_env if k in src})
        out.update(self.extra_env)
        return out

    def argv(self, command: str, args: list[str]) -> tuple[str, list[str]]:
        launcher = [sys.executable, "-m", "toolpin.proxy.launch"]
        for flag, val in (("--as-mb", self.as_mb), ("--cpu-s", self.cpu_s), ("--nofile", self.nofile),
                          ("--nproc", self.nproc)):
            if val:
                launcher += [flag, str(val)]
        inner = [*launcher, "--", command, *args]
        if self.bwrap:
            if not shutil.which("bwrap"):
                raise RuntimeError("bwrap requested but not installed; refusing to silently run unsandboxed")
            cwd = self.cwd or os.getcwd()
            wrap = ["bwrap", "--die-with-parent", "--unshare-pid", "--unshare-ipc", "--unshare-uts",
                    "--ro-bind", "/", "/", "--dev", "/dev", "--proc", "/proc", "--tmpfs", "/tmp",
                    "--bind", cwd, cwd]
            if not self.bwrap_net:
                wrap.append("--unshare-net")
            inner = [*wrap, *inner]
        return inner[0], inner[1:]

    def params(self, command: str, args: list[str] | None = None) -> StdioServerParameters:
        cmd, argv = self.argv(command, list(args or []))
        return StdioServerParameters(command=cmd, args=argv, env=self.scrub(), cwd=self.cwd)

    def launch_record(self, command: str, args: list[str] | None = None, environ: dict[str, str] | None = None,
                      ) -> dict[str, Any]:
        """What was launched, with what authority. Values of environment variables are never recorded."""
        src = os.environ if environ is None else environ
        dropped = sorted(k for k in src if k not in self.scrub(dict(src)))
        return {
            "argv_sha256": hashlib.sha256("\0".join([command, *(args or [])]).encode()).hexdigest(),
            "command": command, "cwd": self.cwd or os.getcwd(),
            "env_passed": sorted(self.scrub(dict(src))), "env_dropped_count": len(dropped),
            "env_explicit": list(self.pass_env),
            "limits": {"as_mb": self.as_mb, "cpu_s": self.cpu_s, "nofile": self.nofile, "nproc": self.nproc},
            "bwrap": self.bwrap, "bwrap_net": self.bwrap_net if self.bwrap else None, "time": time.time(),
        }
