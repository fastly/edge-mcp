#!/usr/bin/env bash
#
# Local end-to-end smoke test for the example MCP server under Viceroy.
#
# Builds the Compute wasm, starts Viceroy (Fastly's local Compute runtime), and
# drives the server over real HTTP with JSON-RPC: tools/list, tools/call (echo),
# server/discover, an MRTR (input_required) round-trip, and a task create+poll.
#
# Requirements:
#   - viceroy >= 0.20 on PATH  (the fastly CLI's bundled 0.17 is too old for the
#     fastly 0.13 crate ABI — install with `cargo install --locked viceroy`)
#   - cargo with the wasm32-wasip1 target, plus curl and jq
#
# Usage:
#   scripts/smoke-test.sh              # build + run
#   SKIP_BUILD=1 scripts/smoke-test.sh # reuse bin/main.wasm
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

ADDR="127.0.0.1:7686"
URL="http://${ADDR}/"
# 32-byte AEAD test key for the Secret Store (MRTR/Task token signer). Local
# test material only — never a real key.
export SECRET_MRTR_AEAD_KEY_1="0123456789abcdef0123456789abcdef"

PASS=0
FAIL=0
VICEROY_PID=""

cleanup() { [ -n "$VICEROY_PID" ] && kill "$VICEROY_PID" 2>/dev/null; }
trap cleanup EXIT

note()  { printf '\n\033[1m%s\033[0m\n' "$*"; }
pass()  { printf '  \033[32mPASS\033[0m %s\n' "$*"; PASS=$((PASS+1)); }
fail()  { printf '  \033[31mFAIL\033[0m %s\n' "$*"; FAIL=$((FAIL+1)); }

# assert_eq <desc> <actual> <expected>
assert_eq() {
  if [ "$2" = "$3" ]; then pass "$1"; else fail "$1 (got '$2', want '$3')"; fi
}

# rpc <json> -> response body on stdout
rpc() { curl -s -X POST "$URL" -H 'Content-Type: application/json' -d "$1"; }

# _meta block carrying the required protocol version + the tasks capability.
META='"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{"extensions":{"io.modelcontextprotocol/tasks":{}}}}'

# --- Build -----------------------------------------------------------------
if [ "${SKIP_BUILD:-0}" != "1" ]; then
  note "Building example-server (wasm32-wasip1)…"
  cargo build --release --target wasm32-wasip1 --package example-server || exit 1
  mkdir -p bin
  cp target/wasm32-wasip1/release/example-server.wasm bin/main.wasm
fi
[ -f bin/main.wasm ] || { echo "bin/main.wasm missing (run without SKIP_BUILD)"; exit 1; }

# Empty local KV stores (JSON object format for Viceroy).
mkdir -p data
printf '{}\n' > data/kv_tasks.json
printf '{}\n' > data/kv_jwks.json
printf '{}\n' > data/kv_idem.json

# --- Start Viceroy ---------------------------------------------------------
# Uses fastly.demo.toml — the explicit unauthenticated demo config. The
# production manifest (fastly.toml) is secure-by-default (auth required).
note "Starting Viceroy on ${ADDR} (demo config, auth disabled)…"
viceroy --addr "$ADDR" -C fastly.demo.toml bin/main.wasm >/tmp/mcp-smoke-viceroy.log 2>&1 &
VICEROY_PID=$!

# Wait for readiness.
ready=0
for _ in $(seq 1 40); do
  if curl -s -o /dev/null "$URL" -X POST -H 'Content-Type: application/json' -d '{}' 2>/dev/null; then
    ready=1; break
  fi
  kill -0 "$VICEROY_PID" 2>/dev/null || { echo "Viceroy exited early:"; tail -20 /tmp/mcp-smoke-viceroy.log; exit 1; }
  sleep 0.25
done
[ "$ready" = 1 ] || { echo "Viceroy did not become ready"; tail -20 /tmp/mcp-smoke-viceroy.log; exit 1; }

# --- 1. tools/list ---------------------------------------------------------
note "tools/list"
RES=$(rpc "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\",\"params\":{$META}}")
TOOLS=$(echo "$RES" | jq -r '[.result.tools[].name]|sort|join(",")')
assert_eq "lists echo, book_table, long_job" "$TOOLS" "book_table,echo,long_job"
assert_eq "list is public-cacheable" "$(echo "$RES" | jq -r '.result.cacheScope')" "public"

# --- 2. tools/call echo ----------------------------------------------------
note "tools/call echo"
RES=$(rpc "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"echo\",\"arguments\":{\"message\":\"hello edge\"},$META}}")
assert_eq "echo resultType complete" "$(echo "$RES" | jq -r '.result.resultType')" "complete"
assert_eq "echo returns the message" "$(echo "$RES" | jq -r '.result.content[0].text')" "hello edge"

# --- 2b. idempotent replay (same idempotencyKey -> cached result) ----------
note "idempotency (replay returns cached result)"
IDEM="{\"jsonrpc\":\"2.0\",\"id\":21,\"method\":\"tools/call\",\"params\":{\"name\":\"echo\",\"arguments\":{\"message\":\"once\"},\"idempotencyKey\":\"smoke-key-1\",$META}}"
R1=$(rpc "$IDEM")
R2=$(rpc "$IDEM")
assert_eq "first idempotent call completes" "$(echo "$R1" | jq -r '.result.resultType')" "complete"
assert_eq "replay returns identical result" "$(echo "$R2" | jq -r '.result.content[0].text')" "$(echo "$R1" | jq -r '.result.content[0].text')"

# --- 3. server/discover ----------------------------------------------------
note "server/discover"
RES=$(rpc "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"server/discover\",\"params\":{$META}}")
assert_eq "advertises tasks extension" \
  "$(echo "$RES" | jq -r '.result.capabilities.extensions["io.modelcontextprotocol/tasks"]|type')" "object"
assert_eq "reports serverInfo.name (in _meta)" \
  "$(echo "$RES" | jq -r '.result._meta["io.modelcontextprotocol/serverInfo"].name')" "compute-mcp-example"

# --- 4. MRTR round-trip (book_table) --------------------------------------
note "MRTR (input_required -> retry)"
RES=$(rpc "{\"jsonrpc\":\"2.0\",\"id\":4,\"method\":\"tools/call\",\"params\":{\"name\":\"book_table\",$META}}")
assert_eq "first call asks for input" "$(echo "$RES" | jq -r '.result.resultType')" "input_required"
REQ_STATE=$(echo "$RES" | jq -r '.result.requestState')
if [ -n "$REQ_STATE" ] && [ "$REQ_STATE" != "null" ]; then pass "returns a requestState token"; else fail "requestState missing"; fi
RES=$(rpc "{\"jsonrpc\":\"2.0\",\"id\":5,\"method\":\"tools/call\",\"params\":{\"name\":\"book_table\",\"requestState\":\"$REQ_STATE\",\"inputResponses\":{\"date\":{\"action\":\"accept\",\"content\":\"2026-08-01\"}},$META}}")
assert_eq "retry completes" "$(echo "$RES" | jq -r '.result.resultType')" "complete"
assert_eq "retry booked the date" "$(echo "$RES" | jq -r '.result.content[0].text')" "Booked a table for 2026-08-01."

# --- 5. Tasks: create + poll to completion --------------------------------
note "Tasks (create -> poll -> complete)"
RES=$(rpc "{\"jsonrpc\":\"2.0\",\"id\":6,\"method\":\"tools/call\",\"params\":{\"name\":\"long_job\",$META}}")
# CreateTaskResult (resultType "task") flattens the task fields at the top level.
assert_eq "task created" "$(echo "$RES" | jq -r '.result.resultType')" "task"
assert_eq "task starts working" "$(echo "$RES" | jq -r '.result.status')" "working"
TASK_ID=$(echo "$RES" | jq -r '.result.taskId')
if [ -n "$TASK_ID" ] && [ "$TASK_ID" != "null" ]; then pass "returns an opaque taskId"; else fail "taskId missing"; fi

# The demo task auto-completes ~1s after creation; poll after a short wait.
# tasks/get is a "complete" result with the DetailedTask fields flattened.
sleep 2
RES=$(rpc "{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"tasks/get\",\"params\":{\"taskId\":\"$TASK_ID\",$META}}")
assert_eq "task completed on poll" "$(echo "$RES" | jq -r '.result.status')" "completed"
assert_eq "task result delivered" "$(echo "$RES" | jq -r '.result.result.content[0].text')" "job finished"

# --- 6. Protocol-version middleware ---------------------------------------
note "unsupported protocol version -> -32022"
RES=$(rpc '{"jsonrpc":"2.0","id":8,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"1999-01-01","io.modelcontextprotocol/clientCapabilities":{}}}}')
assert_eq "rejects old protocol version" "$(echo "$RES" | jq -r '.error.code')" "-32022"

# --- Summary ---------------------------------------------------------------
note "Smoke test: ${PASS} passed, ${FAIL} failed"
[ "$FAIL" -eq 0 ]
