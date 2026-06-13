import logging
from dataclasses import dataclass, field, asdict, fields as dataclass_fields
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
    sm_type: str   # "" | "3DES" | "AES"
    source: str    # {"tool", "forge", "imported", "replay"}
    # Wire-level bytes actually exchanged over PC/SC. When SM is active these
    # carry the protected frame (87/97/8E DOs) and the raw response+SW before
    # unprotect; when SM is off they match the cleartext request/response.
    wire_request_hex: str = ""
    wire_response_hex: str = ""
    timestamp: datetime = field(default_factory=datetime.now)
    # User annotations (set from the Traffic tab). Purely descriptive: they
    # never affect transport and are view-only metadata on the record.
    comment: str = ""   # free-text note shown in the Traffic list
    color: str = ""     # row highlight colour (hex string, e.g. "#ffd6e7") or ""


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

    def to_list(self) -> List[dict]:
        """Serialise every recorded transaction to JSON-friendly dicts.

        Each transaction is dumped via ``dataclasses.asdict`` with its
        ``timestamp`` rendered as an ISO-8601 string so the result round-trips
        through ``json.dump`` and back through :meth:`from_list`.
        """
        out: List[dict] = []
        for tx in self._entries:
            d = asdict(tx)
            d["timestamp"] = tx.timestamp.isoformat()
            out.append(d)
        return out

    def from_list(self, items, source: Optional[str] = "imported") -> None:
        """Replace the history with transactions rebuilt from :meth:`to_list`.

        ``timestamp`` strings are parsed back into ``datetime`` objects; an
        absent or malformed timestamp falls back to now. Unknown keys are
        ignored so a record saved by a newer format never breaks the load. When
        ``source`` is given (the default ``"imported"``) every restored
        transaction is relabelled with it, marking them as not-from-this-card;
        pass ``source=None`` to preserve each record's saved source.
        """
        valid = {f.name for f in dataclass_fields(APDUTransaction)}
        entries: List[APDUTransaction] = []
        for item in items:
            kwargs = {k: v for k, v in item.items() if k in valid}
            ts = kwargs.get("timestamp")
            if isinstance(ts, str):
                try:
                    kwargs["timestamp"] = datetime.fromisoformat(ts)
                except ValueError:
                    kwargs["timestamp"] = datetime.now()
            elif not isinstance(ts, datetime):
                kwargs.pop("timestamp", None)
            if source is not None:
                kwargs["source"] = source
            try:
                entries.append(APDUTransaction(**kwargs))
            except TypeError:
                logging.warning("Skipping malformed APDU transaction record: %r", item)
        self._entries = entries

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
