# Sourced by the suites. start_server <port-var> <log-file> [ENV=VALUE ...]
# Starts eyesonly-server on an OS-assigned port (no collisions between parallel or
# back-to-back runs), waits until it answers /healthz, and stores the port in <port-var>.
# The server's pid is left in LAST_SRV.
start_server() {
  local var="$1" log="$2" p=""; shift 2
  env "$@" node "$ROOT/bin/eyesonly-server.mjs" serve --port 0 2>"$log" &
  LAST_SRV=$!
  for _ in $(seq 200); do
    p=$(grep -o 'listening on http://127\.0\.0\.1:[0-9]*' "$log" 2>/dev/null | grep -o '[0-9]*$')
    [[ -n "$p" ]] && curl -sf "http://127.0.0.1:$p/healthz" >/dev/null && break
    p=""; sleep 0.05
  done
  if [[ -z "$p" ]]; then echo "eyesonly-server did not start; log:" >&2; cat "$log" >&2; exit 1; fi
  printf -v "$var" '%s' "$p"
}
