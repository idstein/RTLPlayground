#!/usr/bin/env bash
# Open the RTL837x Ghidra project in the GUI. Run setup.sh first.

set -euo pipefail

GHIDRA_HOME="${GHIDRA_HOME:-/Users/pstrawder/Downloads/ghidra_12.1_PUBLIC}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
PROJ_DIR="${REPO_ROOT}/ghidra_proj"
PROJ_NAME="${PROJ_NAME:-RTLPlayground}"

# Use pyghidraRun (not ghidraRun) so PyGhidra is initialised; that's required
# for the `.py` scripts under tools/ghidra/ to load from Script Manager.
exec "${GHIDRA_HOME}/support/pyghidraRun" "${PROJ_DIR}/${PROJ_NAME}.gpr"
