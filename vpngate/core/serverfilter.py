"""Server list filtering (port of ServerFilter.swift)."""

from __future__ import annotations

from .serverlist import VPNServer


class ServerFilter:
    def __init__(self) -> None:
        self.search = ""
        self.country = "All"
        self.favorites_only = False
        self.favorites: set[str] = set()
        # Hide servers that keep logs longer than this many weeks (None = show all).
        self.max_log_weeks: int | None = None

    def apply(self, servers: list[VPNServer]) -> list[VPNServer]:
        out = []
        for s in servers:
            if self.country != "All" and s.countryLong != self.country:
                continue
            if self.favorites_only and s.id not in self.favorites:
                continue
            if self.max_log_weeks is not None:
                # unknown retention is treated as "too long"
                w = ServerFilter.log_weeks(s.logType)
                if w is None or w > self.max_log_weeks:
                    continue
            if self.search:
                search = self.search.lower()
                hit = any(search in x.lower() for x in
                          (s.hostName, s.ip, s.countryLong, s.operatorName))
                if not hit:
                    continue
            out.append(s)
        return out

    @staticmethod
    def log_weeks(s: str) -> int | None:
        """'2weeks' → 2, '3months' → 13, '1year' → 52, 'no'/'none'/'0' → 0, unparseable → None."""
        t = s.lower().strip()
        if t in ("no", "none", "nolog", "0"):
            return 0
        digits = ""
        for c in t:
            if c.isdigit():
                digits += c
            else:
                break
        if not digits:
            return None
        try:
            n = int(digits)
        except ValueError:
            return None
        unit = t[len(digits):].strip()
        if unit in ("day", "days"):
            return (n + 6) // 7
        if unit in ("week", "weeks"):
            return n
        if unit in ("month", "months"):
            return n * 52 // 12 + (0 if n * 52 % 12 == 0 else 1)
        if unit in ("year", "years"):
            return n * 52
        return None