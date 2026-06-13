"""APDU interception — a Burp-style proxy for the smartcard channel.

This module exposes a process-wide :class:`Interceptor` singleton that the
ISO 7816 transport consults for *every* command APDU, **before** Secure
Messaging wrapping is applied.  It lets a caller (typically the GUI) pause,
inspect, edit, forward or drop commands in flight without the chip ever
seeing the original bytes.

Two complementary mechanisms are provided:

* **Interactive interception** (``enabled = True``): a synchronous
  ``callback`` is invoked with the cleartext :class:`APDUCommand`.  The
  callback returns the command to send (possibly edited) or ``None`` to drop
  it.  This is what powers the GUI "Intercept" tab, which blocks the calling
  thread until the user clicks Forward or Drop.

* **Match-&-replace rules** (applied when ``enabled = False``): a small table
  of :class:`Rule` objects that rewrite commands automatically, so common
  edits don't need a manual click on every transaction.

The interceptor operates purely on cleartext command APDUs.  Secure
Messaging (SSC increment, MAC, encryption) happens *after* interception in
:meth:`pypassport.iso7816.ISO7816.transmit`, so editing here changes exactly
what the chip authenticates and decrypts.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Callable, Optional

from pypassport.singleton import Singleton

if TYPE_CHECKING:  # avoid a circular import at runtime (iso7816 imports us)
    from pypassport.iso7816 import APDUCommand


# Header fields that a rule may match on or replace.  ``data``/``le`` are body
# fields; ``lc`` is recomputed automatically when ``data`` is replaced.
_FIELDS = ("cla", "ins", "p1", "p2", "lc", "data", "le")


class Rule:
    """A single match-&-replace rule applied to a command APDU.

    ``match`` maps field names (``cla``, ``ins``, ``p1``, ``p2``, ``data`` …)
    to the hex string they must equal for the rule to fire.  A field absent
    from ``match`` is a wildcard.  ``replace`` maps field names to the hex
    string to substitute.  Matching is case-insensitive; replacement values
    are stored verbatim.
    """

    def __init__(
        self,
        match: Optional[dict] = None,
        replace: Optional[dict] = None,
        enabled: bool = True,
        name: str = "",
    ):
        self.match = {k: v for k, v in (match or {}).items() if v not in (None, "")}
        self.replace = {k: v for k, v in (replace or {}).items() if v is not None}
        self.enabled = enabled
        self.name = name

    def matches(self, apdu: "APDUCommand") -> bool:
        for field, value in self.match.items():
            if getattr(apdu, field, "").lower() != value.lower():
                return False
        return True

    def apply(self, apdu: "APDUCommand") -> "APDUCommand":
        """Return a new APDUCommand with the rule's replacements applied."""
        from pypassport.iso7816 import APDUCommand

        fields = {f: getattr(apdu, f) for f in _FIELDS}
        fields.update(self.replace)
        # If the data field changed but Lc was not explicitly overridden, let
        # the APDUCommand constructor recompute Lc from the new data length.
        if "data" in self.replace and "lc" not in self.replace:
            fields["lc"] = ""
        return APDUCommand(**fields)

    def __repr__(self) -> str:
        label = f" {self.name!r}" if self.name else ""
        return f"<Rule{label} match={self.match} replace={self.replace} enabled={self.enabled}>"


class Interceptor(Singleton):
    """Process-wide APDU interceptor consulted by the ISO 7816 transport.

    Defaults to a transparent no-op: ``enabled`` is ``False`` and no rules are
    registered, so :meth:`intercept` returns its argument unchanged and the
    transport behaves exactly as if the interceptor did not exist.
    """

    # ``Singleton`` only overrides ``__new__``; ``__init__`` would otherwise run
    # (and wipe state) on every ``Interceptor()`` call, so guard it.
    def __init__(self):
        if getattr(self, "_initialized", False):
            return
        self._initialized = True
        self.enabled: bool = False
        self.callback: Optional[Callable[["APDUCommand"], Optional["APDUCommand"]]] = None
        self.rules: list[Rule] = []
        # Bounded log of recent decisions, newest last. Each entry is a dict
        # with keys ``apdu`` (str), ``action`` and optional ``result`` (str).
        self.history: list[dict] = []
        self.history_limit: int = 200

    # -- decision -----------------------------------------------------------

    def intercept(self, apdu: "APDUCommand") -> Optional["APDUCommand"]:
        """Decide what to do with a cleartext command APDU.

        * When interactive interception is active (``enabled`` and a
          ``callback`` is registered) the callback decides: it returns the
          command to send (possibly edited) or ``None`` to drop it.
        * Otherwise the match-&-replace rules are applied and the resulting
          command is returned (rules never drop).

        Returning ``None`` instructs the transport to short-circuit: the card
        is never touched and Secure Messaging state is left untouched.
        """
        if self.enabled and self.callback is not None:
            result = self.callback(apdu)
            if result is None:
                self._record(apdu, "drop")
            elif result is apdu:
                self._record(apdu, "forward")
            else:
                self._record(apdu, "edit", result)
            return result

        result = self._apply_rules(apdu)
        if result is not apdu:
            self._record(apdu, "rule", result)
        return result

    def _apply_rules(self, apdu: "APDUCommand") -> "APDUCommand":
        result = apdu
        for rule in self.rules:
            if rule.enabled and rule.matches(result):
                result = rule.apply(result)
        return result

    def _record(self, apdu, action, result=None):
        entry = {"apdu": str(apdu), "action": action}
        if result is not None:
            entry["result"] = str(result)
        self.history.append(entry)
        if len(self.history) > self.history_limit:
            del self.history[: -self.history_limit]
        logging.debug(f"Interceptor {action}: {entry}")

    # -- convenience --------------------------------------------------------

    def add_rule(self, rule: Rule) -> None:
        self.rules.append(rule)

    def clear_rules(self) -> None:
        self.rules.clear()

    def reset(self) -> None:
        """Restore the transparent no-op default state."""
        self.enabled = False
        self.callback = None
        self.rules.clear()
        self.history.clear()
