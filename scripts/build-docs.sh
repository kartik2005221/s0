#!/bin/bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../docs-portal"
exec bash build.sh "$@"
