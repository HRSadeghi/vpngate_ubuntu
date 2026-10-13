"""Running-application scanner for split tunneling (per-app bypass).

Groups /proc entries by process name (comm) with the executable path where readable.
Only same-user processes are visible to the unprivileged app; the root helper moves
every matching PID (including other users') into the bypass cgroup."""

from __future__ import annotations

import os
from dataclasses import dataclass, field


@dataclass
class RunningApp:
    name: str                 # process name (comm) — the match key sent to the helper
    path: str = ""            # executable path when readable
    pids: list[int] = field(default_factory=list)

    @property
    def display(self) -> str:
        return self.name

    @property
    def detail(self) -> str:
        n = len(self.pids)
        processes = "process" if n == 1 else "processes"
        return self.path or f"{n} {processes}"


def list_running_apps(exclude_self: bool = True) -> list[RunningApp]:
    """Snapshot of the running applications, most processes first."""
    apps: dict[str, RunningApp] = {}
    me = os.getpid()
    try:
        entries = os.listdir("/proc")
    except OSError:
        return []
    for entry in entries:
        if not entry.isdigit():
            continue
        pid = int(entry)
        if exclude_self and pid == me:
            continue
        try:
            with open(f"/proc/{entry}/comm", "rb") as f:
                comm = f.read().decode("utf-8", "replace").strip()
        except OSError:
            continue
        if not comm:
            continue
        path = ""
        try:
            path = os.readlink(f"/proc/{entry}/exe")
        except OSError:
            pass
        key = comm.lower()
        info = apps.setdefault(key, RunningApp(name=comm))
        info.pids.append(pid)
        if path and not info.path:
            info.path = path
    return sorted(apps.values(), key=lambda a: (-len(a.pids), a.name.lower()))