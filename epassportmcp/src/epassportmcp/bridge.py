"""Private local IPC bridge between Codex/Claude and ePassportViewer.

The desktop application owns the controller, reader and protocol state.  The
stdio MCP process only forwards bounded JSON messages to this endpoint.
"""

from __future__ import annotations

import getpass
import hashlib
import json
import logging
import os
import sys
import tempfile
import threading
import uuid
from contextlib import nullcontext
from multiprocessing import AuthenticationError
from multiprocessing.connection import Client, Listener
from pathlib import Path
from typing import Any, Mapping

_MAX_REQUEST = 1024 * 1024
_MAX_RESPONSE = 32 * 1024 * 1024


class ViewerUnavailable(RuntimeError):
    """Raised when the MCP bridge cannot reach a running viewer."""


def endpoint() -> tuple[str, str]:
    """Return the per-user local endpoint and multiprocessing family."""

    if sys.platform == "win32":
        username = getpass.getuser().replace("\\", "_").replace("/", "_")
        return rf"\\.\pipe\epassportviewer-mcp-{username}", "AF_PIPE"
    configured = os.environ.get("EPASSPORT_VIEWER_SOCKET", "").strip()
    if configured:
        return str(Path(configured).expanduser()), "AF_UNIX"
    # GUI launchers commonly set XDG_RUNTIME_DIR while MCP clients spawned by
    # editors/desktop apps do not. Using that environment value therefore
    # makes the two halves select different sockets even though they run as the
    # same user. Select the conventional per-user Linux runtime directory
    # directly, independently of the launch environment, with a portable
    # fallback elsewhere.
    linux_runtime = Path("/run/user") / str(os.getuid())
    runtime = (
        linux_runtime
        if sys.platform.startswith("linux") and linux_runtime.is_dir()
        else Path(tempfile.gettempdir())
    )
    return str(runtime / f"epassportviewer-mcp-{os.getuid()}.sock"), "AF_UNIX"


def _capability_path(address: str) -> Path:
    if sys.platform == "win32":
        username = getpass.getuser().encode()
        suffix = hashlib.sha256(username).hexdigest()[:16]
        return Path(tempfile.gettempdir()) / f"epassportviewer-mcp-{suffix}.cap"
    return Path(address + ".cap")


def _read_authkey(address: str) -> bytes:
    try:
        value = _capability_path(address).read_bytes()
    except OSError as exc:
        raise ViewerUnavailable("ePassportViewer MCP assistance is not enabled") from exc
    if len(value) != 32:
        raise ViewerUnavailable("ePassportViewer MCP capability is invalid; restart the viewer")
    return value


class ViewerMCPClient:
    """One-request client used by the Codex-launched stdio MCP bridge."""

    def __init__(self):
        self._connection = None
        self._lock = threading.Lock()

    def request(self, operation: str, arguments: Mapping[str, Any] | None = None) -> dict[str, Any]:
        packet = {
            "version": 1,
            "id": uuid.uuid4().hex,
            "operation": operation,
            "arguments": dict(arguments or {}),
        }
        encoded = json.dumps(packet, separators=(",", ":")).encode()
        if len(encoded) > _MAX_REQUEST:
            raise ValueError("Viewer MCP request is too large")
        address, family = endpoint()
        try:
            with self._lock:
                if self._connection is None:
                    self._connection = Client(address, family=family, authkey=_read_authkey(address))
                connection = self._connection
                connection.send_bytes(encoded)
                reply = connection.recv_bytes(_MAX_RESPONSE)
        except (OSError, EOFError, AuthenticationError) as exc:
            try:
                if self._connection is not None:
                    self._connection.close()
            finally:
                self._connection = None
            raise ViewerUnavailable(
                "ePassportViewer is not running or its local MCP bridge is unavailable; start/restart the GUI"
            ) from exc
        try:
            decoded = json.loads(reply)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ViewerUnavailable("ePassportViewer returned an invalid MCP bridge response") from exc
        if not isinstance(decoded, dict):
            raise ViewerUnavailable("ePassportViewer returned a non-object MCP bridge response")
        return decoded


class ViewerMCPHost:
    """Local endpoint hosted by the running desktop application."""

    def __init__(self, viewer: Any):
        # Keep the stdio side a transport-only process: the controller and all
        # pypassport protocol code are imported only by the GUI-owned host.
        from .controller import PassportController

        self.viewer = viewer
        self.controller = PassportController()
        self.controller.bind_to_viewer()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._listener: Listener | None = None
        self._connection = None
        self._ready = threading.Event()
        self._authkey = os.urandom(32)
        self._startup_error: str | None = None

    @property
    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive() and self._listener is not None

    def start(self) -> None:
        if self.is_running:
            return
        if self._thread is not None and self._thread.is_alive():
            raise ViewerUnavailable("ePassportViewer MCP endpoint is still starting")
        self._thread = None
        self._stop.clear()
        self._ready.clear()
        self._startup_error = None
        self._authkey = os.urandom(32)
        self._thread = threading.Thread(target=self._serve, name="epassportviewer-mcp", daemon=True)
        self._thread.start()
        if not self._ready.wait(2):
            self.stop()
            raise ViewerUnavailable("Timed out while starting the ePassportViewer MCP endpoint")
        if self._startup_error is not None:
            error = self._startup_error
            self._thread.join(timeout=1)
            self._thread = None
            raise ViewerUnavailable(error)
        if not self.is_running:
            self._thread = None
            raise ViewerUnavailable("ePassportViewer MCP endpoint stopped during startup")

    def stop(self) -> None:
        thread = self._thread
        if thread is None:
            return
        self._stop.set()
        connection = self._connection
        if connection is not None:
            connection.close()
        else:
            address, family = endpoint()
            try:
                wake = Client(address, family=family, authkey=_read_authkey(address))
                wake.close()
            except (OSError, AuthenticationError, ViewerUnavailable):
                pass
        thread.join(timeout=1)
        listener = self._listener
        if thread is not None and thread.is_alive() and listener is not None:
            try:
                listener.close()
            except OSError:
                pass
        self._thread = None

    def _serve(self) -> None:
        address, family = endpoint()
        listener = None
        capability: Path | None = None
        owns_capability = False
        try:
            if family == "AF_UNIX":
                socket_path = Path(address)
                capability_path = _capability_path(address)
                socket_path.parent.mkdir(parents=True, exist_ok=True)
                if socket_path.exists():
                    if not socket_path.is_socket():
                        raise ViewerUnavailable(f"MCP endpoint path is occupied by a non-socket file: {address}")
                    try:
                        existing = Client(address, family=family, authkey=_read_authkey(address))
                    except (OSError, AuthenticationError, ViewerUnavailable):
                        socket_path.unlink()
                        try:
                            capability_path.unlink()
                        except OSError:
                            pass
                    else:
                        existing.close()
                        raise ViewerUnavailable("Another running ePassportViewer already owns the MCP endpoint")
                else:
                    try:
                        capability_path.unlink()
                    except OSError:
                        pass
            listener = Listener(address, family=family, authkey=self._authkey)
            self._listener = listener
            capability = _capability_path(address)
            descriptor = os.open(capability, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            try:
                os.write(descriptor, self._authkey)
            finally:
                os.close(descriptor)
            owns_capability = True
            self._ready.set()
            if family == "AF_UNIX":
                Path(address).chmod(0o600)
            while not self._stop.is_set():
                try:
                    connection = listener.accept()
                except AuthenticationError:
                    logging.warning("Rejected an unauthenticated local ePassportViewer MCP connection")
                    continue
                except (OSError, EOFError):
                    break
                self._connection = connection
                self._viewer_event("connected", True)
                try:
                    while not self._stop.is_set():
                        request = connection.recv_bytes(_MAX_REQUEST)
                        response = self._dispatch(request)
                        encoded_response = json.dumps(response, separators=(",", ":")).encode()
                        if len(encoded_response) > _MAX_RESPONSE:
                            response = {
                                "ok": False,
                                "error": {
                                    "code": "response_too_large",
                                    "message": "Use bounded evidence chunks for this MCP result",
                                },
                            }
                            encoded_response = json.dumps(response, separators=(",", ":")).encode()
                        connection.send_bytes(encoded_response)
                except (OSError, EOFError):
                    pass
                finally:
                    self._connection = None
                    try:
                        connection.close()
                    except OSError:
                        pass
                    self._viewer_event("connected", False)
        except Exception as exc:
            self._startup_error = str(exc)
            logging.error("Could not start the ePassportViewer MCP endpoint: %s", exc)
        finally:
            self._ready.set()
            self._listener = None
            if listener is not None:
                try:
                    listener.close()
                except OSError:
                    pass
            if owns_capability and capability is not None:
                try:
                    capability.unlink()
                except OSError:
                    pass

    def _viewer_event(self, kind: str, value: Any) -> None:
        publish = getattr(self.viewer, "publish_mcp_event", None)
        if publish is not None:
            publish(kind, value)

    def _dispatch(self, encoded: bytes) -> dict[str, Any]:
        from .catalog import ACTION_SPECS
        from .controller import ActionError

        arguments: Mapping[str, Any] = {}
        try:
            packet = json.loads(encoded)
            if not isinstance(packet, Mapping) or packet.get("version") != 1:
                raise ValueError("invalid bridge request")
            operation = str(packet.get("operation", ""))
            arguments = packet.get("arguments", {})
            if not isinstance(arguments, Mapping):
                raise ValueError("invalid bridge arguments")
            label = f": {arguments.get('action')}" if operation == "action" else ""
            logging.info("MCP assistant requested %s%s", operation, label)
            if operation == "action":
                action = str(arguments.get("action", ""))
                action_arguments = arguments.get("arguments")
                spec = ACTION_SPECS.get(action)
                approve = getattr(self.viewer, "approve_mcp_action", None)
                if spec is not None and approve is not None and self._requires_approval(action, action_arguments):
                    if not approve(action, spec.card_effect):
                        raise ActionError("viewer_denied", "The user did not approve this MCP action")
            elif operation not in {"list", "recommend"}:
                raise ValueError("unknown bridge operation")

            coordinator = getattr(self.viewer, "card_operation", None)
            owner = f"MCP: {arguments.get('action')}" if operation == "action" else f"MCP: {operation}"
            context = coordinator(owner) if coordinator is not None else nullcontext()
            with context:
                self._pull_viewer_session()
                source_before = None
                if operation == "action" and self.controller.iso7816 is not None:
                    source_before = self.controller.iso7816.source
                    self.controller.iso7816.source = "mcp"
                try:
                    if operation == "list":
                        result = self.controller.list_actions(**arguments)
                    elif operation == "recommend":
                        result = self.controller.recommend(**arguments)
                    else:
                        result = self.controller.execute(action, action_arguments)
                finally:
                    if source_before is not None and self.controller.iso7816 is not None:
                        self.controller.iso7816.source = source_before
                    if operation == "action":
                        self._push_viewer_session(action)
                        self._viewer_event("action", action)
            return result
        except ActionError as exc:
            return self.controller.error_payload(str(arguments.get("action", "")), exc)
        except Exception as exc:
            if type(exc).__name__ == "CardBusy":
                return {"ok": False, "error": {"code": "viewer_busy", "message": str(exc)}}
            return {"ok": False, "error": {"code": "bridge_error", "message": str(exc)}}
    @staticmethod
    def _requires_approval(action: str, arguments: Any) -> bool:
        arguments = arguments if isinstance(arguments, Mapping) else {}
        if action in {
            "session.authenticate",
            "session.reset",
            "session.close",
            "fuzz.run",
            "apdu.clear_history",
            "case.import_snapshot",
            "case.export_snapshot",
        }:
            return True
        if action == "apdu.transmit":
            return True
        if action == "security.access_matrix":
            return True
        if action in {"security.chip_authentication", "security.terminal_authentication", "security.conformance"}:
            return True
        if action.startswith("attack."):
            return action != "attack.aa_compare" and not (
                action == "attack.bac_bruteforce" and arguments.get("mode") == "offline"
            )
        return False

    def _pull_viewer_session(self) -> None:
        passport = getattr(self.viewer, "ep", None)
        iso = passport.iso7816 if passport is not None else getattr(self.viewer, "iso7816", None)
        if iso is None and getattr(self.viewer, "reader", None) is not None:
            iso = self.viewer.ensure_iso7816()
        if passport is not self.controller.passport:
            self.controller._reset_capture_state(clear_offline=False)
        self.controller.connection = iso.reader_connection if iso is not None else getattr(self.viewer, "reader", None)
        self.controller.iso7816 = iso
        self.controller.passport = passport
        name = str(getattr(self.viewer, "_reader_name", ""))
        if not name and self.controller.connection is not None and hasattr(self.controller.connection, "getReader"):
            name = str(self.controller.connection.getReader())
        self.controller.reader_name = name
        self.controller._mrz = getattr(self.viewer, "_mcp_mrz", None)
        self.controller._can = getattr(self.viewer, "_mcp_can", None)
        if passport is not None:
            self.controller._access_control = getattr(passport, "access_control", None)
            self.controller._access_mode = getattr(passport, "_ac_mode", self.controller._access_mode)
        else:
            self.controller._access_control = None

    def _push_viewer_session(self, action: str) -> None:
        iso = self.controller.iso7816
        self.viewer.reader = iso.reader_connection if iso is not None else self.controller.connection
        self.viewer.iso7816 = iso
        self.viewer.ep = self.controller.passport
        if action == "session.authenticate":
            self.viewer._mcp_mrz = self.controller._mrz
            self.viewer._mcp_can = self.controller._can
        mrz = getattr(self.viewer, "_mcp_mrz", None)
        if self.controller.passport is not None and mrz is not None:
            self.viewer._ep_signature = (
                (mrz.doc_number[0], mrz.date_of_birth[0], mrz.date_of_expiry[0]),
                self.controller._can,
            )
        elif self.controller.passport is None:
            self.viewer._ep_signature = None
