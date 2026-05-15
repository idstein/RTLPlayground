#!/usr/bin/env bash
# Headlessly create (or update) a Ghidra project containing the OEM image,
# with the RTL837x memory layout already wired up by LoadRTL837xOEM.py.
#
# Configure GHIDRA_HOME and OEM_BIN below or via environment variables.

set -euo pipefail

GHIDRA_HOME="${GHIDRA_HOME:-/Users/pstrawder/Downloads/ghidra_12.1_PUBLIC}"
OEM_BIN="${OEM_BIN:-/Users/pstrawder/Downloads/SL-SWTGW0108P-1.9.1.bin}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
PROJ_DIR="${REPO_ROOT}/ghidra_proj"
PROJ_NAME="${PROJ_NAME:-RTLPlayground}"
PROG_NAME="$(basename "${OEM_BIN}")"

if [[ ! -x "${GHIDRA_HOME}/support/pyghidraRun" ]]; then
    echo "Ghidra not found at ${GHIDRA_HOME}" >&2
    exit 1
fi
if [[ ! -f "${OEM_BIN}" ]]; then
    echo "OEM image not found at ${OEM_BIN}" >&2
    exit 1
fi

# Bootstrap the PyGhidra venv via uv (Ghidra 12 dropped bundled Jython, and the
# bundled jpype1 wheels for cp39 don't ship an arm64 macOS build, so we want a
# Python >= 3.10 universal2-compatible interpreter).
GHIDRA_VENV="${HOME}/Library/ghidra/ghidra_12.1_PUBLIC/venv"
PYGHIDRA_DIST="${GHIDRA_HOME}/Ghidra/Features/PyGhidra/pypkg/dist"
if [[ ! -x "${GHIDRA_VENV}/bin/python3" ]]; then
    if ! command -v uv >/dev/null; then
        echo "uv not found; install it (brew install uv) or create the venv manually at ${GHIDRA_VENV}" >&2
        exit 1
    fi
    echo "Bootstrapping PyGhidra venv with uv at ${GHIDRA_VENV}"
    mkdir -p "$(dirname "${GHIDRA_VENV}")"
    uv venv --python 3.13 "${GHIDRA_VENV}"
    VIRTUAL_ENV="${GHIDRA_VENV}" uv pip install --offline --find-links="${PYGHIDRA_DIST}" pyghidra
fi

mkdir -p "${PROJ_DIR}"

# PyGhidra is required because Ghidra 12 dropped the bundled Jython interpreter.
# First run will create a venv under ~/Library/ghidra/.../venv and install
# pyghidra + jpype from the wheels in $GHIDRA_HOME/Ghidra/Features/PyGhidra/pypkg/dist/.
"${GHIDRA_HOME}/support/pyghidraRun" -H --console \
    "${PROJ_DIR}" "${PROJ_NAME}" \
    -import "${OEM_BIN}" \
    -overwrite \
    -loader BinaryLoader \
    -loader-blockName tmp \
    -loader-baseAddr 0x0 \
    -loader-fileOffset 0 \
    -loader-length 0x1 \
    -processor 8051:BE:16:default \
    -scriptPath "${SCRIPT_DIR}" \
    -postScript LoadRTL837xOEM.py "${OEM_BIN}" \
    -postScript AnalyzeRTL837x.py \
    -analysisTimeoutPerFile 1200

echo
echo "Project ready: ${PROJ_DIR}/${PROJ_NAME}.gpr"
echo "Open with:    ${SCRIPT_DIR}/run.sh"
