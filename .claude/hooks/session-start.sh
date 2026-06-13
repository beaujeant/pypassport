#!/bin/bash
# SessionStart hook: provision the workspace so `uv run pytest`, `uv run ruff`
# and `uv run mypy` work in Claude Code on the web.
#
# Two things are not satisfiable by uv alone:
#   * pyscard is a C extension that links libpcsclite and is built with swig, so
#     the build-time system packages must be present before `uv sync`.
#   * the GUI imports tkinter; the managed CPython pinned in .python-version
#     bundles tk, which is why we let uv manage the interpreter.
set -euo pipefail

# Only provision the remote (web) environment; local machines are set up by hand.
if [ "${CLAUDE_CODE_REMOTE:-}" != "true" ]; then
  exit 0
fi

cd "${CLAUDE_PROJECT_DIR:-.}"

# Build-time deps for pyscard. Idempotent: apt-get install is a no-op when present.
if command -v apt-get >/dev/null 2>&1; then
  sudo apt-get update -y || apt-get update -y || true
  sudo apt-get install -y libpcsclite-dev swig \
    || apt-get install -y libpcsclite-dev swig
fi

# Create the workspace .venv and install all members + the dev tool group
# (pytest/ruff/mypy). --managed-python pulls the bundled-tk CPython if missing.
uv sync --managed-python
