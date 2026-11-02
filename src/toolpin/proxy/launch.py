"""Sandboxed launcher: applies resource limits and no-new-privileges, then exec()s the real server.
Run as `python -m toolpin.proxy.launch --as-mb 512 --cpu-s 60 --nofile 128 --nproc 64 -- cmd args...`.
The environment is whatever the parent passed (already scrubbed); this process adds no secrets."""
from __future__ import annotations

import argparse
import os
import resource
import sys


def apply_limits(as_mb: int | None, cpu_s: int | None, nofile: int | None, nproc: int | None) -> None:
    def lim(which: int, value: int | None) -> None:
        if value is not None:
            resource.setrlimit(which, (value, value))
    lim(resource.RLIMIT_AS, as_mb * 1024 * 1024 if as_mb else None)
    lim(resource.RLIMIT_CPU, cpu_s)
    lim(resource.RLIMIT_NOFILE, nofile)
    lim(resource.RLIMIT_NPROC, nproc)
    lim(resource.RLIMIT_CORE, 0)
    if sys.platform.startswith("linux"):
        import ctypes
        libc = ctypes.CDLL(None, use_errno=True)
        PR_SET_NO_NEW_PRIVS = 38
        if libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
            raise OSError(ctypes.get_errno(), "prctl(PR_SET_NO_NEW_PRIVS) failed")


def main(argv: list[str] | None = None) -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--as-mb", type=int); p.add_argument("--cpu-s", type=int)
    p.add_argument("--nofile", type=int); p.add_argument("--nproc", type=int)
    p.add_argument("cmd", nargs=argparse.REMAINDER)
    a = p.parse_args(argv)
    cmd = a.cmd[1:] if a.cmd and a.cmd[0] == "--" else a.cmd
    if not cmd:
        sys.exit("no command")
    apply_limits(a.as_mb, a.cpu_s, a.nofile, a.nproc)
    os.execvp(cmd[0], cmd)


if __name__ == "__main__":
    main()
