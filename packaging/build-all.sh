#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
bash "$ROOT/packaging/build-deb.sh"
bash "$ROOT/packaging/build-rpm.sh"
