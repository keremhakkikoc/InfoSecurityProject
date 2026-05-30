#!/usr/bin/env bash
# End-to-end demo orchestrator for the 11-step PDF scenario.
#
# Bootstraps the CA, issues alice + bob + server identities, registers
# pubkeys, starts the server in the background, runs Alice's upload and
# Bob's download, and asserts the recovered plaintext matches the input.
#
# Usage (from repo root):
#     make install
#     bash demo/run_demo.sh
#
# Exits 0 on success. The trap ensures the background server is killed
# even when the script aborts midway.

set -euo pipefail

# ---- Resolve repo root regardless of where this is invoked from. ----------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${REPO_ROOT}"

PORT="${ZEROTRUST_DEMO_PORT:-5050}"
SAMPLE_FILE="demo/sample_files/report.pdf"

# Canonical demo password — documented in AI.md §3.10 and README.
export ZEROTRUST_CA_PASSWORD="${ZEROTRUST_CA_PASSWORD:-demo-password}"
export ZEROTRUST_USER_PASSWORD="${ZEROTRUST_USER_PASSWORD:-demo-password}"

SERVER_PID=""
cleanup() {
    if [[ -n "${SERVER_PID}" ]] && kill -0 "${SERVER_PID}" 2>/dev/null; then
        kill "${SERVER_PID}" 2>/dev/null || true
        wait "${SERVER_PID}" 2>/dev/null || true
    fi
}
trap cleanup EXIT INT TERM

# ---- Sanity: the sample input must exist before we do anything. -----------
if [[ ! -f "${SAMPLE_FILE}" ]]; then
    echo "Missing sample input: ${SAMPLE_FILE}" >&2
    echo "See demo/README.md for how to (re)generate it." >&2
    exit 1
fi

echo "=== 1. Clean slate ==="
make clean >/dev/null

echo "=== 2. CA + identities (server, alice, bob) ==="
make ca-init
make ca-issue USER=server
make ca-issue USER=alice
make ca-issue USER=bob

echo "=== 3. Client bundles + server pubkey registration ==="
make client-setup USER=alice
make client-setup USER=bob
make server-register USER=alice
make server-register USER=bob

echo "=== 4. Start server in background on port ${PORT} ==="
python -m zerotrust.server.main --port "${PORT}" >/tmp/zerotrust-demo-server.log 2>&1 &
SERVER_PID=$!

# Wait up to ~5s for the port to come up.
for _ in $(seq 1 25); do
    if python -c "import socket,sys; s=socket.socket(); \
        sys.exit(0) if s.connect_ex(('127.0.0.1', ${PORT})) == 0 else sys.exit(1)" \
        2>/dev/null; then
        break
    fi
    sleep 0.2
done

if ! kill -0 "${SERVER_PID}" 2>/dev/null; then
    echo "Server failed to start — see /tmp/zerotrust-demo-server.log" >&2
    exit 1
fi
echo "Server running (pid=${SERVER_PID})."

echo "=== 5. Alice uploads ${SAMPLE_FILE} to bob ==="
UPLOAD_OUT="$(python -m zerotrust.client.cli --user alice upload bob "${SAMPLE_FILE}")"
echo "${UPLOAD_OUT}"
FILE_ID="$(printf '%s\n' "${UPLOAD_OUT}" | sed -n 's/^Uploaded file_id=\([^ ]*\).*/\1/p')"
if [[ -z "${FILE_ID}" ]]; then
    echo "Could not parse file_id from upload output." >&2
    exit 1
fi
echo "Upload successful (file_id=${FILE_ID})"

echo "=== 6. Bob lists his pending files ==="
python -m zerotrust.client.cli --user bob list

echo "=== 7. Bob downloads file_id=${FILE_ID} ==="
python -m zerotrust.client.cli --user bob download "${FILE_ID}"
echo "Download successful"

echo "=== 8. Verify plaintext match ==="
DOWNLOADED="client_bob/downloads/${FILE_ID}"
if [[ ! -f "${DOWNLOADED}" ]]; then
    echo "Downloaded file not found at ${DOWNLOADED}" >&2
    exit 1
fi
if ! diff -q "${SAMPLE_FILE}" "${DOWNLOADED}" >/dev/null; then
    echo "Plaintext MISMATCH between ${SAMPLE_FILE} and ${DOWNLOADED}" >&2
    exit 1
fi
echo "Plaintext match — demo OK"
