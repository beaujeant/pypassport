"""PC/SC reader discovery helpers.

The protocol/parser modules can be used without a physical reader, so pyscard
is loaded only when a caller asks for PC/SC access.  Install
``pypassport[reader]`` when using these functions against real hardware.
"""

from __future__ import annotations

import logging
from typing import Any


class ReaderException(Exception):
    """Raised when PC/SC support is unavailable or reader selection fails."""


def _load_pcsc() -> tuple[Any, Any]:
    try:
        from smartcard.System import readers  # type: ignore[import-untyped]
        from smartcard.pcsc import PCSCExceptions  # type: ignore[import-untyped]
    except ImportError as exc:
        raise ReaderException(
            "PC/SC reader support requires the optional 'pypassport[reader]' extra and a platform PC/SC service."
        ) from exc
    return readers, PCSCExceptions


def _is_pcsc_exception(exc: BaseException, name: str) -> bool:
    try:
        from smartcard.Exceptions import CardConnectionException, NoCardException  # type: ignore[import-untyped]
    except ImportError:
        return False

    exception_type = {
        "CardConnectionException": CardConnectionException,
        "NoCardException": NoCardException,
    }[name]
    return isinstance(exc, exception_type)


def is_no_card_exception(exc: BaseException) -> bool:
    """Return whether *exc* is pyscard's ``NoCardException``."""

    return _is_pcsc_exception(exc, "NoCardException")


def is_card_connection_exception(exc: BaseException) -> bool:
    """Return whether *exc* is pyscard's ``CardConnectionException``."""

    return _is_pcsc_exception(exc, "CardConnectionException")


def list_readers() -> list[Any]:
    """Return the available PC/SC readers.

    A missing PC/SC service is treated as an empty reader list, matching the
    GUI's expected behavior.  A missing pyscard installation is different: it
    raises :class:`ReaderException` with an actionable install hint.
    """

    readers, pcsc_exceptions = _load_pcsc()
    try:
        available = list(readers())
    except Exception as exc:
        establish_context_error = getattr(pcsc_exceptions, "EstablishContextException", None)
        if establish_context_error is not None and isinstance(exc, establish_context_error):
            logging.error("PC/SC smart card service not available")
            return []
        raise

    logging.info("Available reader(s): %s", available)
    return available


def get_reader(index: int | str | None = None) -> Any | None:
    """Return a connection for one reader, or ``None`` when none match.

    ``index`` may be an integer position or the reader's string name.  When it
    is omitted, the first available reader is selected.
    """

    available = list_readers()
    if not available:
        logging.error("No reader identified")
        return None

    if index is None:
        logging.info("Default (first) reader selected: %s", available[0])
        return available[0].createConnection()

    if isinstance(index, int):
        try:
            selected = available[index]
        except IndexError:
            logging.error("No reader at index %s", index)
            return None
        logging.info("Reader %s selected", selected)
        return selected.createConnection()

    if isinstance(index, str):
        for candidate in available:
            if str(candidate) == index:
                logging.info("Reader %s selected", candidate)
                return candidate.createConnection()
        logging.error("Reader %r not found", index)
        return None

    raise TypeError(f"reader selector must be an int, str, or None, got {type(index).__name__}")
