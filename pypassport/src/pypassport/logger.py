"""Callback-based logger that dispatches log messages to registered listeners."""

from typing import Callable, Optional


class Logger:
    """Lightweight logger that notifies registered listener callbacks.

    Listeners are callables with the signature ``(name: str, msg: str) -> None``.
    """

    def __init__(self, name: str) -> None:
        self._name = name
        self._listeners: list[Callable[[str, str], None]] = []

    def register(self, fct: Callable[[str, str], None]) -> None:
        """Register a callback to receive log messages."""
        self._listeners.append(fct)

    def unregister(self, fct: Callable[[str, str], None]) -> None:
        """Remove a previously registered callback."""
        self._listeners.remove(fct)

    def log(self, msg: str, name: Optional[str] = None) -> None:
        """Dispatch *msg* to all registered listeners.

        If *name* is given it overrides the instance name for this call.
        """
        effective_name = name if name is not None else self._name
        for listener in self._listeners:
            listener(effective_name, msg)
