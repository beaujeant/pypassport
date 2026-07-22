import dataclasses
import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Callable, Optional


@dataclass
class APDUTransaction:
    # Cleartext request fields
    request_cla: str
    request_ins: str
    request_p1: str
    request_p2: str
    request_lc: str
    request_data: str
    request_le: str
    # Cleartext response fields
    response_data: str
    response_sw1: int
    response_sw2: int
    # Metadata
    sm_active: bool
    sm_type: str  # "" | "3DES" | "AES"
    source: str  # {"read", "forge", "intercept", "security", "fuzz", "tool", "imported"}
    # Wire-level bytes actually exchanged over PC/SC. When SM is active these
    # carry the protected frame (87/97/8E DOs) and the raw response+SW before
    # unprotect; when SM is off they match the cleartext request/response.
    wire_request_hex: str = ""
    wire_response_hex: str = ""
    timestamp: datetime = field(default_factory=datetime.now)
    # User annotations (set from the Traffic tab). Purely descriptive: they
    # never affect transport and are view-only metadata on the record.
    comment: str = ""  # free-text note shown in the Traffic list
    color: str = ""  # row highlight colour (hex string, e.g. "#ffd6e7") or ""


class APDUHistory:
    _instance: Optional["APDUHistory"] = None

    def __init__(self):
        self._entries: List[APDUTransaction] = []
        self._listeners: List[Callable] = []

    @classmethod
    def get(cls) -> "APDUHistory":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def record(self, tx: APDUTransaction) -> None:
        self._entries.append(tx)
        for cb in self._listeners:
            try:
                cb(tx)
            except Exception:
                logging.exception("APDUHistory listener %r raised an exception", cb)

    def delete(self, index: int) -> None:
        del self._entries[index]

    def clear(self) -> None:
        self._entries.clear()

    def add_listener(self, cb: Callable) -> None:
        self._listeners.append(cb)

    def remove_listener(self, cb: Callable) -> None:
        if cb in self._listeners:
            self._listeners.remove(cb)

    def __iter__(self):
        return iter(list(self._entries))

    def __len__(self):
        return len(self._entries)

    def __getitem__(self, index: int) -> APDUTransaction:
        return self._entries[index]

    # ------------------------------------------------------------------ #
    # Serialisation — used to save/restore a research session             #
    # ------------------------------------------------------------------ #

    def to_list(self) -> List[dict]:
        """Serialise every transaction to a list of JSON-friendly dicts.

        ``dataclasses.asdict`` copies all fields verbatim; the only value that
        is not JSON-serialisable is ``timestamp``, which is rendered as an ISO
        8601 string so :meth:`from_list` can parse it back.
        """
        items = []
        for tx in self._entries:
            d = dataclasses.asdict(tx)
            d["timestamp"] = tx.timestamp.isoformat()
            items.append(d)
        return items

    def from_list(self, items: List[dict], source: Optional[str] = None) -> None:
        """Replace the history with transactions parsed from :meth:`to_list`.

        ``timestamp`` strings are parsed back into ``datetime``; a missing or
        malformed value falls back to "now". When ``source`` is given it
        overrides every record's source — the session-load path passes
        ``"imported"`` so restored traffic is clearly distinguished from live
        captures. Unknown keys are ignored and malformed records are skipped
        so a hand-edited file can't abort the whole load. Listeners are not
        notified: this is a bulk replace, so callers refresh their views once.
        """
        field_names = {f.name for f in dataclasses.fields(APDUTransaction)}
        entries: List[APDUTransaction] = []
        for item in items:
            if not isinstance(item, dict):
                logging.warning("Skipping non-dict APDU record: %r", item)
                continue
            kwargs = {k: v for k, v in item.items() if k in field_names}
            ts = kwargs.get("timestamp")
            if isinstance(ts, str):
                try:
                    kwargs["timestamp"] = datetime.fromisoformat(ts)
                except ValueError:
                    kwargs["timestamp"] = datetime.now()
            elif not isinstance(ts, datetime):
                kwargs.pop("timestamp", None)  # let the default factory supply one
            if source is not None:
                kwargs["source"] = source
            try:
                entries.append(APDUTransaction(**kwargs))
            except TypeError as e:
                logging.warning("Skipping malformed APDU record %r: %s", item, e)
        self._entries = entries
