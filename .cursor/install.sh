#!/usr/bin/env bash

set -euxo pipefail

CURSOR_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$CURSOR_DIR/.." && pwd)"

path_export_line='export PATH="$HOME/.local/bin:$PATH"'
touch "$HOME/.bashrc"
if [[ "$(<"$HOME/.bashrc")" != *"$path_export_line"* ]]; then
  printf '\n%s\n' "$path_export_line" >> "$HOME/.bashrc"
fi

if ! command -v uv >/dev/null 2>&1; then
  # astral.sh/uv/install.sh is blocked in Cloud Agent egress; use pip instead.
  pip install --user uv
fi

case ":$PATH:" in
  *":$HOME/.local/bin:"*) ;;
  *) export PATH="$HOME/.local/bin:$PATH" ;;
esac

uv sync --locked --extra test --extra dev --directory "$ROOT"
