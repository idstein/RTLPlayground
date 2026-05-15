#!/usr/bin/env bash
# Upload a `_direct_` RTLPlayground firmware to a running RTLPlayground
# switch over HTTP, using exactly one serial TCP connection per request.
#
# The 8051's uIP stack only has a handful of TCP slots. Web browsers open
# many parallel connections for assets and that exhausts the pool ("tcp:
# found no unused connections" spam on the serial). curl uses one
# connection at a time and stays well under the limit.
#
# IMPORTANT: before running, *close every browser tab pointing at the
# switch* and ideally type "reset" on the serial console to reboot the
# switch — that empties uIP's connection table. Otherwise you'll see
# "Send failure: Broken pipe" from curl because the switch RSTs the
# new connection before the handshake completes.
#
# Usage:
#   tools/upload-direct.sh <ip> <password> <path-to-direct-bin>
# Example:
#   tools/upload-direct.sh 10.0.0.231 admin out/rtlplayground_direct_SWTGW218AS.bin

set -euo pipefail

if [[ $# -lt 3 ]]; then
    echo "usage: $0 <ip> <password> <path-to-direct-bin>" >&2
    exit 1
fi

IP="$1"
PASSWORD="$2"
FILE="$3"

if [[ ! -f "${FILE}" ]]; then
    echo "error: ${FILE} not found" >&2
    exit 1
fi

SIZE=$(stat -f %z "${FILE}" 2>/dev/null || stat -c %s "${FILE}")
if [[ "${SIZE}" != "524288" ]]; then
    echo "warning: ${FILE} is ${SIZE} bytes; a _direct_ image is normally 524288" >&2
fi

JAR=$(mktemp -t rtl_cookies.XXXXXX)
trap 'rm -f "${JAR}"' EXIT

# Wait for the switch to actually accept a TCP connection on port 80. If
# uIP is exhausted, sockets get connection-refused / RST immediately.
echo "Waiting for http://${IP}/ to accept a connection (up to 30s)..."
for try in $(seq 1 30); do
    if curl --silent --max-time 2 --http1.1 --no-keepalive \
            -o /dev/null -w '' "http://${IP}/login.html" 2>/dev/null; then
        echo "  ok (try ${try})"
        break
    fi
    if [[ ${try} -eq 30 ]]; then
        echo "error: still cannot reach ${IP}:80 — type 'reset' on the serial console" >&2
        echo "       to reboot the switch (or close all browser tabs first) and rerun." >&2
        exit 3
    fi
    sleep 1
done

echo "[1/2] login to http://${IP}/ as ${PASSWORD}..."
# uIP-compatible: single connection, no Keep-Alive abuse.
# httpd.c parses the body as raw "pwd=<password>"; no URL-encoding.
HTTP_CODE=$(curl --silent --show-error --max-time 15 \
     --http1.1 --no-keepalive \
     --output /dev/null --write-out '%{http_code}' \
     -c "${JAR}" \
     -H 'Content-Type: application/x-www-form-urlencoded' \
     -X POST --data-raw "pwd=${PASSWORD}" \
     "http://${IP}/login")
echo "  login HTTP ${HTTP_CODE}"

if ! grep -qE '^[^#].*session' "${JAR}"; then
    echo "error: no session cookie set — wrong password? (got HTTP ${HTTP_CODE})" >&2
    echo "  cookie jar:" >&2
    cat "${JAR}" >&2 || true
    exit 2
fi

echo "[2/2] uploading ${FILE} (${SIZE} bytes) to http://${IP}/upload..."
# Switch reboots as soon as the upload finishes; curl will see the
# connection drop. Suppress the resulting non-zero exit so the script
# still returns 0 on a successful upload.
set +e
HTTP_CODE=$(curl --silent --show-error --max-time 180 \
     --http1.1 --no-keepalive \
     --output /dev/null --write-out '%{http_code}' \
     -b "${JAR}" \
     -F "uploadedfile=@${FILE}" \
     "http://${IP}/upload")
rc=$?
set -e
echo "  upload HTTP ${HTTP_CODE} (curl exit ${rc})"

if [[ ${rc} -ne 0 && ${rc} -ne 52 && ${rc} -ne 56 ]]; then
    # 52 = empty reply from server, 56 = recv failure; both are expected
    # because the device reboots immediately after writing the image.
    echo "warning: unexpected curl exit ${rc} during upload" >&2
fi

echo
echo "done. The switch should be rebooting now. Watch the serial console for"
echo "the new boot banner with '=== chip defaults: leds_dump BEFORE leds_setup ==='."
