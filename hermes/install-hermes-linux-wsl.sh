#!/usr/bin/env bash
# Obtain Hermes Agent for governed testing (ticket §9B/§9C).
#
# This script does NOT `curl | bash`. It downloads the installer, records its
# SHA-256, and stops so a human can review it before running. It can also do a
# pinned git checkout instead (recommended for R&D).
set -euo pipefail

MODE="${1:-review}"      # review | run-installer | git
DEST="${DEST:-$PWD/hermes/_download}"
INSTALLER_URL="https://hermes-agent.nousresearch.com/install.sh"
REPO_URL="https://github.com/NousResearch/hermes-agent.git"
mkdir -p "$DEST"

record_env() {
  {
    echo "date_utc=$(date -u +%FT%TZ)"
    echo "os=$(uname -a)"
    echo "git=$(git --version 2>/dev/null || echo none)"
    echo "docker=$(docker --version 2>/dev/null || echo none)"
    echo "python=$(python3 --version 2>/dev/null || echo none)"
    echo "uv=$(uv --version 2>/dev/null || echo none)"
  } | tee "$DEST/environment.txt"
}

case "$MODE" in
  review)
    record_env
    echo "[*] downloading installer (NOT executing)..."
    curl -fsSL "$INSTALLER_URL" -o "$DEST/install.sh"
    sha256sum "$DEST/install.sh" | tee "$DEST/install.sh.sha256"
    echo
    echo "Review $DEST/install.sh by hand, record the sha256 above in docs/,"
    echo "then re-run:  $0 run-installer      (or use:  $0 git  for a pinned checkout)"
    ;;
  run-installer)
    [ -f "$DEST/install.sh" ] || { echo "run '$0 review' first"; exit 1; }
    echo "[*] recorded sha256:"; cat "$DEST/install.sh.sha256"
    read -r -p "Proceed to execute this reviewed installer? [y/N] " a
    [ "$a" = "y" ] || { echo "aborted"; exit 1; }
    sh "$DEST/install.sh"
    exec "$SHELL" -l -c 'hermes --version && hermes --help | head -n 40'
    ;;
  git)
    record_env
    if [ ! -d "$PWD/hermes/hermes-agent/.git" ]; then
      git clone "$REPO_URL" "$PWD/hermes/hermes-agent"
    fi
    cd "$PWD/hermes/hermes-agent"
    git fetch --tags
    echo "[*] HEAD is $(git rev-parse HEAD)"
    echo "[*] Choose and record an APPROVED commit/tag in docs/, then:"
    echo "      git checkout <APPROVED_COMMIT_OR_TAG>"
    echo "      uv venv venv --python 3.11 && . venv/bin/activate && uv pip install -e '.[all]'"
    echo "      hermes --version && hermes --help"
    ;;
  *)
    echo "usage: $0 [review|run-installer|git]"; exit 2 ;;
esac
