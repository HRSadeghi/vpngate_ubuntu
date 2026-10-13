"""A tiny multicast event: multiple listeners, one emit (the Combine objectWillChange
equivalent). Listeners may be removed with the returned unsubscribe function."""

from __future__ import annotations

from typing import Callable, List


class Event:
    def __init__(self) -> None:
        self._listeners: List[Callable[[], None]] = []

    def connect(self, listener: Callable[[], None]) -> Callable[[], None]:
        """Registers a listener; returns a function that removes it again."""
        self._listeners.append(listener)

        def disconnect() -> None:
            try:
                self._listeners.remove(listener)
            except ValueError:
                pass
        return disconnect

    def emit(self) -> None:
        for listener in list(self._listeners):
            try:
                listener()
            except Exception:
                import traceback
                traceback.print_exc()