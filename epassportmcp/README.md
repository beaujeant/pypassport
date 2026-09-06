# ePassportViewer MCP

This package is the local bridge between an external AI and a running
ePassportViewer. The GUI hosts the stateful controller and remains the sole
owner of the physical reader, MRZ/CAN, file cache, PACE/BAC session and APDU
history. The Codex/Claude-launched process only forwards MCP calls over an
ephemeral per-user local socket; it does not open PC/SC or store passport
traffic.

Only three MCP tools are advertised during connection:

- `epassport_list_tools` returns a compact group/action catalog and fetches a
  detailed JSON Schema only when `detail=true`.
- `epassport_recommend_tools` selects a state-aware workflow for a goal and
  returns only the relevant action schemas.
- `epassport_call` executes any discovered action.

The detailed catalog includes reader/session lifecycle, automatic or explicit
PACE/BAC, exact raw-wire and Secure-Messaging APDUs, LDS capture and chunked
evidence access, live authenticity checks, access-control matrices, hidden
FID/SFI discovery, chosen-challenge Active Authentication analysis, complete
clear/wire traffic history, deterministic fuzzing, known-attack workflows,
snapshot import/export, Chip/Terminal Authentication, and conformance profiles.
Responses distinguish a demonstrated failure from denied or inconclusive
evidence and retain the APDU status word behind the result.

## Install and configure

From the repository root, install the GUI and bridge together:

```bash
uv sync
uv run epassportviewer
```

Leave ePassportViewer running while using the MCP, and explicitly tick **Enable
MCP** in **Configure > Settings**. Select the reader and enter the MRZ/CAN in the
GUI: MCP calls reuse that visible session. The viewer shows bridge
connection/card-operation status and asks in-window approval before raw APDUs,
fuzzing, EAC, authentication changes, resets, and live attacks. Offline
snapshots also go through the running GUI.

### Codex

Codex can register the local stdio server with its MCP CLI. Replace the path
below with the absolute path to this repository:

```bash
codex mcp add epassportviewer -- \
  uv --directory /absolute/path/to/pypassport run \
  --package epassportviewer-mcp epassportviewer-mcp

codex mcp list
```

Restart Codex after changing MCP configuration. The equivalent persistent
configuration can be placed in `~/.codex/config.toml` (or a trusted project's
`.codex/config.toml`):

```toml
[mcp_servers.epassportviewer]
command = "uv"
args = ["--directory", "/absolute/path/to/pypassport", "run", "--package", "epassportviewer-mcp", "epassportviewer-mcp"]
```

See the current [Codex MCP documentation](https://developers.openai.com/codex/mcp/)
for configuration scopes and management commands.

### Claude Code

Claude Code supports the same local stdio launch command. Local scope keeps the
entry private to the current project; use `--scope user` instead if it should be
available everywhere:

```bash
claude mcp add --scope local --transport stdio epassportviewer -- \
  uv --directory /absolute/path/to/pypassport run \
  --package epassportviewer-mcp epassportviewer-mcp

claude mcp get epassportviewer
```

Project-shared installation can instead use `--scope project`, which writes
`.mcp.json` and asks each user to approve the server when they first trust the
workspace. See the current [Claude Code MCP documentation](https://code.claude.com/docs/en/mcp).

### Other MCP clients

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
        "epassportviewer-mcp"
      ]
    }
  }
}
```

With a normal pip environment, install all local projects and use
`"command": "epassportviewer-mcp"`:

```bash
python -m pip install -e './pypassport[reader]' -e ./epassportmcp -e ./epassportviewer
```

The PC/SC service and a contactless reader are required only for live actions.
Snapshot import, report generation, AA-bound comparison, and offline BAC
search can operate through the GUI without a card.

## Recommended interaction

Call `epassport_recommend_tools` with the concrete objective, such as
`"complete passport security audit"`, `"inspect PACE downgrade behavior"`, or
`"fuzz READ BINARY and recover after errors"`. The response contains ordered
`epassport_call` payloads and lazy action schemas.

The preferred interactive workflow is: the user selects a reader, enters the
credentials and reads/authenticates in ePassportViewer; the assistant then
starts with `session.status` and operates on that same session. If asked, it can
also assist the user with this approval-backed sequence:

1. `reader.list`
2. `session.connect`
3. `session.authenticate`
4. `passport.capture`
5. `passport.verify`
6. `security.audit`

For protected-data research, `security.access_matrix` compares DG access by
FID, SFI and enhanced READ BINARY across no-access-control, authenticated,
CA and CA+TA states. `security.discover_files` performs bounded FID/SFI scans,
including the non-advertised-but-SOD-hashed case, and `security.aa_analysis`
checks BSI plain ECDSA AA signatures and repeated nonce components. Supply
authenticated ICAO Master Lists with `csca_directory` plus explicit
`master_list_signer_paths`; an untrusted `.ml` is not silently accepted.

For protocol work, `apdu.transmit` has three channels:

- `current`: submit a valid clear APDU; live AES/3DES Secure Messaging is
  applied and both clear and protected exchanges are returned.
- `plaintext`: bypass the active host SM for one clear APDU while retaining its
  SSC.
- `wire`: send exact bytes with no parser/interceptor/SM processing. This
  supports malformed and pre-protected frames and defaults to invalidating the
  local SM state. Follow it with `session.reset` using `kind="reauth"` to recover.

MCP APDUs are normal in-process ePassportViewer operations, so they appear
immediately in the same in-memory Traffic pane as GUI reads and Forge/Security
workflows. If the GUI is stopped, MCP actions return `viewer_unavailable`
instead of silently opening the passport headlessly. A process-local operation
coordinator rejects overlapping GUI/MCP card workflows so their stateful Secure
Messaging counters cannot interleave. The confirmation layer also covers
history replacement/clearing and snapshot export because those affect the
user's visible research evidence.
