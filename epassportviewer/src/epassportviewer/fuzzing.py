"""APDU fuzzing workbench embedded in the Security tab."""

from __future__ import annotations

import json
import logging
import queue
import threading
import tkinter as tk
from collections.abc import Callable, Sequence
from functools import partial
from pathlib import Path
from tkinter import filedialog, ttk
from typing import Any

from pypassport.fuzzing import (
    DEFAULT_STRATEGIES,
    STRATEGY_LABELS,
    FuzzCase,
    FuzzResult,
    generate_fuzz_cases,
    run_fuzz_campaign,
    summarize_fuzz_results,
)
from pypassport.iso7816 import APDUCommand

from . import theme
from .apdu_format import describe_apdu_fields, parse_apdu, parse_apdu_lenient


_CHANNELS = {
    "Current channel": "current",
    "Plaintext": "plaintext",
}
_RESET_POLICIES = {
    "Never": ("never", "raw"),
    "Raw reset before campaign": ("before_campaign", "raw"),
    "Raw reset before each case": ("before_each", "raw"),
    "Re-auth before each case": ("before_each", "reauth"),
}


class FuzzingPane:
    def __init__(self, main, parent, owner, probes: Sequence[Any]):
        self.main = main
        self.root = main.root
        self.owner = owner
        self.parent = parent
        self.probes = tuple(probes)
        self._cases: list[FuzzCase] = []
        self._results: list[FuzzResult] = []
        self._tree_mode = "cases"
        self._stop_event: threading.Event | None = None
        self._queue: queue.Queue[Callable[[], None]] = queue.Queue()

        self._build_ui()
        self.root.after(100, self._drain)

    def _build_ui(self):
        config = ttk.LabelFrame(self.parent, text=" Campaign ", padding=8)
        config.pack(fill="x", padx=4, pady=4)

        seed_row = ttk.Frame(config)
        seed_row.pack(fill="x", pady=(0, 4))
        ttk.Label(seed_row, text="Seed:").pack(side="left")
        self._seed_preset = tk.StringVar(value="Custom")
        values = ["Custom"] + [probe.name for probe in self.probes]
        preset = ttk.Combobox(seed_row, textvariable=self._seed_preset, values=values, state="readonly", width=24)
        preset.pack(side="left", padx=(4, 8))
        preset.bind("<<ComboboxSelected>>", self._on_seed_preset)
        self._seed = tk.StringVar(value="0084000008")
        ttk.Entry(seed_row, textvariable=self._seed).pack(side="left", fill="x", expand=True, padx=(0, 8))
        self._seed_label = tk.StringVar(value="Get Challenge")
        ttk.Label(seed_row, text="Name:").pack(side="left")
        ttk.Entry(seed_row, textvariable=self._seed_label, width=24).pack(side="left", padx=(4, 0))

        run_row = ttk.Frame(config)
        run_row.pack(fill="x", pady=(0, 4))
        ttk.Label(run_row, text="Channel:").pack(side="left")
        self._channel = tk.StringVar(value="Current channel")
        ttk.Combobox(
            run_row,
            textvariable=self._channel,
            values=list(_CHANNELS),
            state="readonly",
            width=18,
        ).pack(side="left", padx=(4, 10))
        ttk.Label(run_row, text="Reset:").pack(side="left")
        self._reset_policy = tk.StringVar(value="Never")
        ttk.Combobox(
            run_row,
            textvariable=self._reset_policy,
            values=list(_RESET_POLICIES),
            state="readonly",
            width=26,
        ).pack(side="left", padx=(4, 10))
        ttk.Label(run_row, text="Repeat:").pack(side="left")
        self._repeat_each = tk.StringVar(value="1")
        ttk.Spinbox(run_row, from_=1, to=1000, textvariable=self._repeat_each, width=6).pack(side="left", padx=(4, 10))
        ttk.Label(run_row, text="Delay ms:").pack(side="left")
        self._delay_ms = tk.StringVar(value="0")
        ttk.Spinbox(run_row, from_=0, to=60000, textvariable=self._delay_ms, width=7).pack(side="left", padx=(4, 10))
        ttk.Label(run_row, text="Max cases:").pack(side="left")
        self._max_cases = tk.StringVar(value="256")
        ttk.Spinbox(run_row, from_=1, to=65536, textvariable=self._max_cases, width=8).pack(side="left", padx=(4, 0))

        strategy_frame = ttk.LabelFrame(config, text=" Mutations ", padding=6)
        strategy_frame.pack(fill="x", pady=(2, 4))
        self._strategies: dict[str, tk.BooleanVar] = {}
        for index, (strategy, label) in enumerate(STRATEGY_LABELS.items()):
            var = tk.BooleanVar(value=strategy in DEFAULT_STRATEGIES)
            self._strategies[strategy] = var
            row_index, column_index = divmod(index, 4)
            ttk.Checkbutton(strategy_frame, text=label, variable=var).grid(
                row=row_index,
                column=column_index,
                sticky="w",
                padx=(0, 18),
                pady=1,
            )
        for column_index in range(4):
            strategy_frame.columnconfigure(column_index, weight=1)

        option_row = ttk.Frame(config)
        option_row.pack(fill="x")
        self._include_state_changing = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            option_row,
            text="Include state-changing INS in sweeps",
            variable=self._include_state_changing,
        ).pack(side="left")
        ttk.Button(option_row, text="Generate", command=self._generate).pack(side="right", padx=(4, 0))
        ttk.Button(option_row, text="Run", command=self._run, style="Accent.TButton").pack(side="right", padx=4)
        self._stop_button = ttk.Button(option_row, text="Stop", command=self._stop, state="disabled")
        self._stop_button.pack(side="right", padx=4)
        ttk.Button(option_row, text="Send selected to Forge", command=self._send_selected_to_forge).pack(
            side="right", padx=4
        )
        ttk.Button(option_row, text="Export results", command=self._export).pack(side="right", padx=4)

        self._campaign_status = tk.StringVar(value="Generate a campaign from a seed APDU.")
        ttk.Label(self.parent, textvariable=self._campaign_status, style="Muted.TLabel").pack(
            fill="x", padx=8, pady=(0, 4)
        )

        paned = ttk.Panedwindow(self.parent, orient="horizontal")
        paned.pack(fill="both", expand=True, padx=4, pady=(0, 4))
        left = ttk.Frame(paned)
        right = ttk.Frame(paned)
        paned.add(left, weight=4)
        paned.add(right, weight=2)

        columns = ("id", "family", "mutation", "apdu", "sw", "ms", "class")
        self._tree = ttk.Treeview(left, columns=columns, show="headings", selectmode="browse")
        for column_id, heading, width, stretch in (
            ("id", "#", 48, False),
            ("family", "Family", 116, False),
            ("mutation", "Mutation", 220, True),
            ("apdu", "APDU", 300, True),
            ("sw", "SW", 62, False),
            ("ms", "ms", 72, False),
            ("class", "Class", 110, False),
        ):
            self._tree.heading(column_id, text=heading)
            self._tree.column(column_id, width=width, stretch=stretch)
        self._tree.tag_configure("interesting", background="#FFF6D8")
        self._tree.tag_configure("success", background=theme.OK_BG)
        self._tree.tag_configure("error", background=theme.ERR_BG)
        self._tree.pack(side="left", fill="both", expand=True)
        scroll = ttk.Scrollbar(left, orient="vertical", command=self._tree.yview)
        scroll.pack(side="right", fill="y")
        self._tree.configure(yscrollcommand=scroll.set)
        self._tree.bind("<<TreeviewSelect>>", self._on_select)
        self._tree.bind("<Double-1>", lambda _event: self._send_selected_to_forge())

        self._summary = tk.Text(right, height=10, wrap="word", state="disabled")
        theme.style_text(self._summary)
        self._summary.pack(fill="both", expand=True, pady=(0, 4))
        self._detail = tk.Text(right, wrap="none", state="disabled")
        theme.style_text(self._detail)
        self._detail.pack(fill="both", expand=True)

    def load_seed(self, raw_hex: str, *, label: str = ""):
        self._seed.set(raw_hex.replace(" ", "").upper())
        self._seed_label.set(label or self._describe_seed(raw_hex))
        self._seed_preset.set("Custom")
        self._generate()

    def _on_seed_preset(self, _event=None):
        selected = self._seed_preset.get()
        if selected == "Custom":
            return
        for probe in self.probes:
            if probe.name == selected:
                self._seed.set(probe.apdu)
                self._seed_label.set(probe.name)
                self._channel.set("Plaintext" if probe.channel == "Plaintext" else "Current channel")
                self._generate()
                return

    def _selected_strategies(self) -> list[str]:
        return [name for name, var in self._strategies.items() if var.get()]

    def _parse_int(self, value: str, label: str, *, minimum: int, maximum: int) -> int | None:
        try:
            parsed = int(value)
        except ValueError:
            self._set_status(f"{label} must be an integer.")
            return None
        if not minimum <= parsed <= maximum:
            self._set_status(f"{label} must be between {minimum} and {maximum}.")
            return None
        return parsed

    def _seed_command(self) -> APDUCommand | None:
        raw = self._seed.get().strip()
        if not raw:
            self._set_status("Enter a seed APDU first.")
            return None
        try:
            fields = parse_apdu(raw)
        except ValueError:
            try:
                fields = parse_apdu_lenient(raw)
            except ValueError as exc:
                self._set_status(f"Invalid seed APDU: {exc}")
                return None
        return APDUCommand(**fields)

    def _generate(self):
        seed = self._seed_command()
        if seed is None:
            return
        max_cases = self._parse_int(self._max_cases.get(), "Max cases", minimum=1, maximum=65536)
        if max_cases is None:
            return
        self._cases = generate_fuzz_cases(
            seed,
            self._selected_strategies(),
            max_cases=max_cases,
            include_state_changing=self._include_state_changing.get(),
        )
        self._results = []
        self._tree_mode = "cases"
        self._tree.delete(*self._tree.get_children())
        for case in self._cases:
            self._insert_case(case)
        self._set_text(self._summary, self._case_summary())
        self._set_text(self._detail, "Select a generated case to inspect it.")
        self._set_status(f"Generated {len(self._cases)} APDU cases.")

    def _insert_case(self, case: FuzzCase):
        self._tree.insert(
            "",
            "end",
            iid=f"case-{case.case_id}",
            values=(case.case_id, case.family, case.mutation, case.raw_hex, "", "", ""),
        )

    def _run(self):
        if not self._cases:
            self._generate()
        if not self._cases:
            return
        if not self._ensure_reader():
            return
        if not self.owner._begin_operation("Running APDU fuzz campaign..."):
            return

        repeat_each = self._parse_int(self._repeat_each.get(), "Repeat", minimum=1, maximum=1000)
        delay_ms = self._parse_int(self._delay_ms.get(), "Delay", minimum=0, maximum=60000)
        if repeat_each is None or delay_ms is None:
            self.owner._finish()
            return

        reset_name = self._reset_policy.get()
        reset_policy, reset_kind = _RESET_POLICIES[reset_name]
        creds = self.owner._credentials() if reset_kind == "reauth" else None
        if reset_kind == "reauth" and creds is None:
            self.owner._finish()
            return

        cases = list(self._cases)
        channel = _CHANNELS[self._channel.get()]
        self._results = []
        self._tree_mode = "results"
        self._tree.delete(*self._tree.get_children())
        self._stop_event = threading.Event()
        self._stop_button.configure(state="normal")
        self._set_text(self._summary, "Campaign running...")
        self._set_text(self._detail, "Select a result to inspect it.")

        def worker():
            try:
                with self.main.card_operation("GUI: APDU fuzz campaign"):
                    if reset_kind == "reauth":
                        assert creds is not None
                        mrz, can = creds
                        ep = self.main.get_passport(mrz, can)
                        iso = ep.iso7816
                    else:
                        ep = None
                        iso = self.main.ensure_iso7816()
                    iso.source = "fuzz"
                    reset_callback = self._build_reset_callback(iso, reset_kind, creds, ep=ep)
                    results = run_fuzz_campaign(
                        iso,
                        cases,
                        channel=channel,
                        repeat_each=repeat_each,
                        delay_ms=delay_ms,
                        reset_policy=reset_policy,
                        reset_callback=reset_callback,
                        stop_event=self._stop_event,
                        on_result=lambda result: self._post(partial(self._append_result, result)),
                        source="fuzz",
                    )
                self._post(partial(self._finish_run, results))
            except Exception as exc:
                logging.exception("Fuzz campaign failed")
                self._post(partial(self._show_run_error, str(exc)))
            finally:
                self._post(self.owner._finish)

        threading.Thread(target=worker, daemon=True).start()

    def _build_reset_callback(self, iso, reset_kind: str, creds, *, ep=None):
        if reset_kind == "raw":
            return iso.rst_connection_raw
        if reset_kind != "reauth":
            return None

        def reauth():
            mrz, can = creds
            passport = ep or self.main.get_passport(mrz, can)
            if passport.iso7816 is not iso:
                raise RuntimeError("Re-authentication switched to a different ISO7816 channel.")
            passport.iso7816.source = "fuzz"
            iso.rst_connection_raw()
            passport.open(can=can)

        return reauth

    def _append_result(self, result: FuzzResult):
        self._results.append(result)
        tags = []
        if result.error:
            tags.append("error")
        elif result.interesting:
            tags.append("interesting")
        elif result.classification == "success":
            tags.append("success")
        self._tree.insert(
            "",
            "end",
            iid=f"result-{len(self._results) - 1}",
            values=(
                result.case.case_id,
                result.case.family,
                result.case.mutation,
                result.case.raw_hex,
                result.status_word or "ERR",
                f"{result.elapsed_ms:.2f}",
                result.classification,
            ),
            tags=tuple(tags),
        )
        self._set_status(f"Running APDU fuzz campaign... {len(self._results)} result(s)")

    def _finish_run(self, results: list[FuzzResult]):
        self._results = results
        self._stop_button.configure(state="disabled")
        self._stop_event = None
        summary = summarize_fuzz_results(results)
        self._set_text(self._summary, self._format_summary(summary))
        self._set_status(
            f"Campaign complete: {summary['total']} executions, "
            f"{summary['interesting_count']} interesting, {summary['error_count']} transport errors."
        )
        self._refresh_result_tags()

    def _refresh_result_tags(self):
        for index, result in enumerate(self._results):
            iid = f"result-{index}"
            if not self._tree.exists(iid):
                continue
            tags: tuple[str, ...]
            if result.error:
                tags = ("error",)
            elif result.interesting:
                tags = ("interesting",)
            elif result.classification == "success":
                tags = ("success",)
            else:
                tags = ()
            self._tree.item(iid, tags=tags)

    def _show_run_error(self, error: str):
        self._stop_button.configure(state="disabled")
        self._stop_event = None
        self._set_status(f"Fuzz campaign failed: {error}")

    def _stop(self):
        if self._stop_event is not None:
            self._stop_event.set()
            self._set_status("Stopping APDU fuzz campaign...")

    def _ensure_reader(self):
        if not self.main.reader:
            self.main.get_reader()
        if not self.main.reader:
            self._set_status("No reader connected.")
            return False
        return True

    def _on_select(self, _event=None):
        selected = self._tree.selection()
        if not selected:
            return
        iid = selected[-1]
        if iid.startswith("case-"):
            case = self._cases[int(iid.split("-", 1)[1]) - 1]
            self._set_text(self._detail, json.dumps(case.to_dict(), indent=2, sort_keys=True))
            return
        result = self._results[int(iid.split("-", 1)[1])]
        self._set_text(self._detail, json.dumps(result.to_dict(), indent=2, sort_keys=True))

    def _selected_case(self) -> FuzzCase | None:
        selected = self._tree.selection()
        if not selected:
            return None
        iid = selected[-1]
        if iid.startswith("case-"):
            return self._cases[int(iid.split("-", 1)[1]) - 1]
        return self._results[int(iid.split("-", 1)[1])].case

    def _send_selected_to_forge(self):
        case = self._selected_case()
        if case is None or not hasattr(self.root, "forge_pane"):
            return
        self.root.forge_pane.load_apdu(case.raw_hex, label=case.mutation)
        self.root.main_notebook.select(self.root.forge_tab)

    def _export(self):
        if not self._cases:
            self._set_status("Generate a campaign before exporting.")
            return
        path = filedialog.asksaveasfilename(
            title="Export fuzz campaign",
            defaultextension=".json",
            filetypes=[("JSON", "*.json"), ("All files", "*.*")],
        )
        if not path:
            return
        payload = {
            "seed": self._seed.get().strip().upper(),
            "seed_label": self._seed_label.get().strip(),
            "strategies": self._selected_strategies(),
            "channel": _CHANNELS[self._channel.get()],
            "reset_policy": self._reset_policy.get(),
            "cases": [case.to_dict() for case in self._cases],
            "results": [result.to_dict() for result in self._results],
            "summary": summarize_fuzz_results(self._results),
        }
        Path(path).write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        self._set_status(f"Exported fuzz campaign to {path}")

    def _case_summary(self) -> str:
        families: dict[str, int] = {}
        for case in self._cases:
            families[case.family] = families.get(case.family, 0) + 1
        lines = [f"Generated {len(self._cases)} cases from {self._seed_label.get().strip() or 'seed APDU'}.", ""]
        lines.extend(f"{family}: {count}" for family, count in families.items())
        return "\n".join(lines)

    @staticmethod
    def _format_summary(summary: dict[str, Any]) -> str:
        timing = summary.get("timing_ms", {})
        lines = [
            f"Executions: {summary.get('total', 0)}",
            f"Interesting: {summary.get('interesting_count', 0)}",
            f"Transport errors: {summary.get('error_count', 0)}",
            "",
            "Status clusters",
        ]
        for status, count in summary.get("status_counts", {}).items():
            lines.append(f"  {status}: {count}")
        lines.extend(("", "Response classes"))
        for name, count in summary.get("classification_counts", {}).items():
            lines.append(f"  {name}: {count}")
        if timing:
            lines.extend(
                (
                    "",
                    "Timing (ms)",
                    f"  min {timing.get('min')}  median {timing.get('median')}  max {timing.get('max')}",
                )
            )
        slowest = summary.get("slowest", [])
        if slowest:
            lines.extend(("", "Slowest"))
            for item in slowest:
                lines.append(
                    f"  #{item['case_id']} {item['elapsed_ms']} ms {item['status_word']} {item['mutation']}"
                )
        return "\n".join(lines)

    @staticmethod
    def _describe_seed(raw_hex: str) -> str:
        try:
            fields = parse_apdu(raw_hex)
        except ValueError:
            try:
                fields = parse_apdu_lenient(raw_hex)
            except ValueError:
                return "Raw APDU"
        return str(describe_apdu_fields(**fields))

    def _set_status(self, text: str):
        self._campaign_status.set(text)
        self.owner._set_run_status(text)

    @staticmethod
    def _set_text(widget: tk.Text, text: str):
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("end", text)
        widget.configure(state="disabled")

    def _post(self, fn: Callable[[], None]):
        self._queue.put(fn)

    def _drain(self):
        try:
            while True:
                fn = self._queue.get_nowait()
                try:
                    fn()
                except Exception:
                    logging.exception("Fuzzing: UI update failed")
        except queue.Empty:
            pass
        self.root.after(100, self._drain)
