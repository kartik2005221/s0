#!/bin/bash
# s0 Live ISO Build Entrypoint Wrapper
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec "$DIR/auto/build.sh" "$@"
