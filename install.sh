#!/usr/bin/env bash
# One-shot bootstrap for the DCISO Governance Gateway.
#
#   git clone https://github.com/<you>/dciso-governance-gateway
#   cd dciso-governance-gateway
#   ./install.sh
#
# It checks Docker, creates .env with generated secrets, starts the stack, and
# tells you how to plug the AI CISO in front of your Hermes agent.
set -euo pipefail
cd "$(dirname "$0")"

grn=$'\e[32m'; yel=$'\e[33m'; dim=$'\e[2m'; off=$'\e[0m'
ok() { printf '%s✓%s %s\n' "$grn" "$off" "$*"; }
die() { printf '\e[31m✗ %s\e[0m\n' "$*" >&2; exit 1; }

command -v docker >/dev/null 2>&1 || die "Docker is required. Install Docker Desktop / Docker Engine, then re-run."
docker compose version >/dev/null 2>&1 || die "Docker Compose v2 is required ('docker compose')."
ok "Docker + Compose found"

./bin/dciso setup
ok "configuration ready (.env)"

printf '\nStart the governance stack now? [Y/n] '
read -r ans || ans=y
case "${ans:-y}" in n|N) echo "skipped — run '${dim}./bin/dciso up${off}' when ready"; exit 0;; esac

./bin/dciso up

# optional: put `dciso` on PATH for this user
BIN_DIR="$HOME/.local/bin"
case ":$PATH:" in
  *":$BIN_DIR:"*)
    if [ -d "$BIN_DIR" ] && [ ! -e "$BIN_DIR/dciso" ]; then
      ln -s "$PWD/bin/dciso" "$BIN_DIR/dciso" && ok "linked 'dciso' onto your PATH (just run: dciso ...)"
    fi ;;
esac

cat <<EOF

${grn}Done.${off} The AI CISO governance layer is running.

  Dashboard : http://127.0.0.1:8900
  Next      : ${dim}./bin/dciso plug${off}     (route your Hermes through the CISO)
  Later     : ${dim}./bin/dciso unplug${off}   (remove it — Hermes back to normal)
              ${dim}./bin/dciso down${off}     (stop the stack)

Full guide: docs/USER-GUIDE.md
EOF
