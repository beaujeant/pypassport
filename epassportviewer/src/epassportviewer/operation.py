"""Process-wide ownership for stateful card protocol operations."""

from __future__ import annotations

import threading
from contextlib import contextmanager


class CardBusy(RuntimeError):
    pass


class OperationCoordinator:
    """Reject interleaved GUI/MCP workflows while permitting nested calls."""

    def __init__(self, publish):
        self._lock = threading.RLock()
        self._state_lock = threading.Lock()
        self._owner = ""
        self._owner_thread: int | None = None
        self._depth = 0
        self._publish = publish

    @property
    def owner(self) -> str:
        with self._state_lock:
            return self._owner

    @contextmanager
    def operation(self, owner: str):
        thread_id = threading.get_ident()
        with self._state_lock:
            nested = self._owner_thread == thread_id
            busy_owner = self._owner
        if not nested and not self._lock.acquire(blocking=False):
            raise CardBusy(f"Card operation already in progress: {busy_owner or 'another operation'}")
        if nested:
            self._lock.acquire()
        with self._state_lock:
            previous_owner = self._owner
            self._owner = owner
            self._owner_thread = thread_id
            self._depth += 1
        self._publish("busy", owner)
        try:
            yield
        finally:
            with self._state_lock:
                self._depth -= 1
                if self._depth:
                    self._owner = previous_owner
                else:
                    self._owner = ""
                    self._owner_thread = None
            self._lock.release()
            self._publish("busy", self.owner)
