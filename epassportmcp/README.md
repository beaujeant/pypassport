# ePassportViewer MCP

This package gives an external AI stateful access to the same `pypassport`
reader, ICAO 9303, authentication, analysis, attack, traffic, and fuzzing
engines used by ePassportViewer. It is headless: the MCP owns the physical
reader connection while it runs, so close the GUI before starting it.

Only three MCP tools are advertised during connection:

- `epassport_list_tools` returns a compact group/action catalog and fetches a
  detailed JSON Schema only when `detail=true`.
- `epassport_recommend_tools` selects a state-aware workflow for a goal and
  returns only the relevant action schemas.
- `epassport_call` executes any discovered action.

The detailed catalog currently includes reader/session lifecycle, automatic or
explicit PACE/BAC, exact raw-wire and Secure-Messaging APDUs, LDS capture and
chunked evidence access, live authenticity checks, security findings, complete
clear/wire traffic history, deterministic fuzzing, traceability/signing-oracle
research, bounded BAC searches, snapshot import/export, application-qualified
filesystem reads, Chip/Terminal Authentication, and redacted conformance
profiles.

## Install and configure

For live PC/SC reader access, from the repository root:

```bash
uv sync --package epassportviewer-mcp --extra reader
```

Omit `--extra reader` for offline snapshot analysis without `pyscard` or PC/SC
native libraries.

A generic stdio MCP configuration is:

```json
{
  "mcpServers": {
    "epassportviewer": {
      "command": "uv",
      "args": [
        "--directory",
        "/absolute/path/to/pypassport",
        "run",
        "--package",
        "epassportviewer-mcp",
        "--extra",
        "reader",
        "epassportviewer-mcp"
      ]
    }
  }
}
```

With a normal pip environment, install both local projects and use
`"command": "epassportviewer-mcp"`:

```bash
python -m pip install -e ./pypassport -e './epassportmcp[reader]'
```

For offline-only use, omit the extra (`-e ./epassportmcp`). The PC/SC service,
`pyscard`, and a contactless reader are required only for live actions.
Snapshot import, report generation, AA-bound comparison, and offline BAC
search can operate without a card.

## Recommended interaction

Call `epassport_recommend_tools` with the concrete objective, such as
`"complete passport security audit"`, `"inspect PACE downgrade behavior"`, or
`"fuzz READ BINARY and recover after errors"`. The response contains ordered
`epassport_call` payloads and lazy action schemas.

The normal complete workflow is:

1. `reader.list`
2. `session.connect`
3. `session.authenticate`
4. `passport.capture`
5. `passport.verify`
6. `security.audit`

For protocol work, `apdu.transmit` has three channels:

- `current`: submit a valid clear APDU; live AES/3DES Secure Messaging is
  applied and both clear and protected exchanges are returned.
- `plaintext`: bypass the active host SM for one clear APDU while retaining its
  SSC.
- `wire`: send exact bytes with no parser/interceptor/SM processing. This
  supports malformed and pre-protected frames and defaults to invalidating the
  local SM state. Follow it with `session.reset` using `kind="reauth"` to recover.

Do not start the MCP and GUI against the same reader simultaneously. PC/SC and
the ePassport Secure-Messaging SSC are sequential state, so one process must
own them for a reliable capture.
