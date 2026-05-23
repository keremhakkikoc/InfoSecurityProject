#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

OUTPUT_FILE="$(mktemp)"
SERVER_LOG="demo/server.log"
SETUP_LOG="demo/setup.log"
CLIENT_LOG="demo/client.log"
SERVER_PID=""

cleanup() {
    if [[ -n "${SERVER_PID}" ]] && kill -0 "${SERVER_PID}" 2>/dev/null; then
        kill "${SERVER_PID}" 2>/dev/null || true
        wait "${SERVER_PID}" 2>/dev/null || true
    fi
    rm -f "${OUTPUT_FILE}"
}
trap cleanup EXIT INT TERM

log_step() {
    printf '%s\n' "$1" | tee -a "${OUTPUT_FILE}"
}

wait_for_server() {
    python - <<'PY'
import socket
import sys
import time

deadline = time.time() + 10
while time.time() < deadline:
    try:
        with socket.create_connection(("127.0.0.1", 5050), timeout=0.25):
            sys.exit(0)
    except OSError:
        time.sleep(0.25)
sys.exit("server did not become ready on 127.0.0.1:5050")
PY
}

run_make() {
    # Canonical Makefile targets used by the demo:
    # make clean
    # make install
    # make ca-init
    # make ca-issue USER=<name>
    # make client-setup USER=<name>
    # make server-register USER=<name>
    if command -v make >/dev/null 2>&1; then
        make "$@"
        return
    fi

    target="$1"
    shift || true
    user=""
    for arg in "$@"; do
        case "${arg}" in
            USER=*) user="${arg#USER=}" ;;
        esac
    done

    case "${target}" in
        clean)
            rm -rf .pytest_cache .ruff_cache .coverage htmlcov
            rm -rf ca_data users client_*
            rm -rf zerotrust/server/storage server/storage
            ;;
        install)
            python -m pip install -r requirements.txt
            ;;
        ca-init)
            python -m zerotrust.ca.ca init
            ;;
        ca-issue)
            if [[ -z "${user}" ]]; then
                printf 'Usage: make ca-issue USER=<name>\n' >&2
                exit 2
            fi
            python -m zerotrust.ca.ca issue "${user}"
            ;;
        client-setup)
            if [[ -z "${user}" ]]; then
                printf 'Usage: make client-setup USER=<name>\n' >&2
                exit 2
            fi
            mkdir -p "client_${user}"
            cp "users/${user}/cert.json" "client_${user}/cert.json"
            cp "users/${user}/private.pem" "client_${user}/private.pem"
            cp "ca_data/ca_cert.json" "client_${user}/ca_cert.json"
            printf '{\n  "username": "%s",\n  "server_host": "127.0.0.1",\n  "server_port": 5050,\n  "server_subject": "server"\n}\n' "${user}" > "client_${user}/config.json"
            ;;
        server-register)
            if [[ -z "${user}" ]]; then
                printf 'Usage: make server-register USER=<name>\n' >&2
                exit 2
            fi
            mkdir -p zerotrust/server/storage/pubkeys
            cp "users/${user}/cert.json" "zerotrust/server/storage/pubkeys/${user}.json"
            ;;
        *)
            printf 'Unknown fallback make target: %s\n' "${target}" >&2
            exit 2
            ;;
    esac
}

export ZEROTRUST_CA_PASSWORD="${ZEROTRUST_CA_PASSWORD:-demo-password}"
export ZEROTRUST_USER_PASSWORD="${ZEROTRUST_USER_PASSWORD:-demo-password}"
export ZEROTRUST_SERVER_PASSWORD="${ZEROTRUST_SERVER_PASSWORD:-demo-password}"

run_make clean >"${SETUP_LOG}" 2>&1
run_make install >>"${SETUP_LOG}" 2>&1
run_make ca-init >>"${SETUP_LOG}" 2>&1
run_make ca-issue USER=server >>"${SETUP_LOG}" 2>&1
run_make ca-issue USER=alice >>"${SETUP_LOG}" 2>&1
run_make ca-issue USER=bob >>"${SETUP_LOG}" 2>&1
run_make client-setup USER=alice >>"${SETUP_LOG}" 2>&1
run_make client-setup USER=bob >>"${SETUP_LOG}" 2>&1
run_make server-register USER=alice >>"${SETUP_LOG}" 2>&1
run_make server-register USER=bob >>"${SETUP_LOG}" 2>&1
log_step "Demo environment ready"

python -m zerotrust.server.main --port 5050 >"${SERVER_LOG}" 2>&1 &
SERVER_PID=$!
wait_for_server
log_step "Server started"

python -m zerotrust.client.cli --user alice login >/dev/null 2>"${CLIENT_LOG}"

UPLOAD_OUTPUT="$(
    python -m zerotrust.client.cli --user alice upload bob demo/sample_files/report.txt 2>>"${CLIENT_LOG}"
)"
FILE_ID="${UPLOAD_OUTPUT#Uploaded file_id=}"
FILE_ID="${FILE_ID%% to bob;*}"
if [[ -z "${FILE_ID}" || "${FILE_ID}" == "${UPLOAD_OUTPUT}" ]]; then
    printf 'Could not parse upload output: %s\n' "${UPLOAD_OUTPUT}" >&2
    exit 1
fi
log_step "Upload successful"

LIST_OUTPUT="$(python -m zerotrust.client.cli --user bob list 2>>"${CLIENT_LOG}")"
if [[ "${LIST_OUTPUT}" != *"${FILE_ID}"* ]]; then
    printf 'Bob list did not include uploaded file_id %s\n%s\n' "${FILE_ID}" "${LIST_OUTPUT}" >&2
    exit 1
fi
log_step "List successful"

DOWNLOAD_OUTPUT="$(python -m zerotrust.client.cli --user bob download "${FILE_ID}" 2>>"${CLIENT_LOG}")"
if [[ "${DOWNLOAD_OUTPUT}" != "Downloaded file_id=${FILE_ID}" ]]; then
    printf 'Unexpected download output: %s\n' "${DOWNLOAD_OUTPUT}" >&2
    exit 1
fi
log_step "Download successful"

diff -q "demo/sample_files/report.txt" "client_bob/downloads/${FILE_ID}" >/dev/null
log_step "Plaintext match"
log_step "Demo OK"

diff --strip-trailing-cr -u "demo/expected_output.txt" "${OUTPUT_FILE}"
