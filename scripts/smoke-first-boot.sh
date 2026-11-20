#!/bin/sh
# First-boot smoke test. Proves the zero-secret contract against a real image:
# a bare `docker run` with no env generates a master key and a bootstrap root
# token, serves /health, accepts the token, verifies, and stays quiet on restart.
#
# Usage: scripts/smoke-first-boot.sh [image]
# With no argument, builds gatehouse:smoke from the working tree.
set -eu

cd "$(dirname "$0")/.."

IMAGE="${1:-}"
if [ -z "$IMAGE" ]; then
  IMAGE="gatehouse:smoke"
  echo "building $IMAGE"
  docker build -t "$IMAGE" .
fi

SUFFIX="$$"
NAME="gatehouse-first-boot-$SUFFIX"
VOLUME="gatehouse-first-boot-$SUFFIX"
STARTED=0

cleanup() {
  status=$?
  if [ "$status" -ne 0 ] && [ "$STARTED" -eq 1 ]; then
    echo "--- docker logs $NAME ---" >&2
    docker logs "$NAME" >&2 2>&1 || true
    echo "--- end logs ---" >&2
  fi
  docker rm -f "$NAME" >/dev/null 2>&1 || true
  docker volume rm -f "$VOLUME" >/dev/null 2>&1 || true
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

# Print the host port mapped to 3100 for the container.
host_port() {
  docker port "$NAME" 3100/tcp | head -n 1 | sed 's/.*://'
}

# Wait up to 30 seconds for /health to return 200.
wait_healthy() {
  port="$(host_port)"
  [ -n "$port" ] || fail "no host port mapped for $NAME"
  i=0
  while [ "$i" -lt 30 ]; do
    code="$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$port/health" || true)"
    if [ "$code" = "200" ]; then
      return 0
    fi
    i=$((i + 1))
    sleep 1
  done
  fail "/health did not return 200 within 30 seconds (last status: ${code:-none})"
}

fingerprint_of() {
  # stdin: verify output. Prints the fingerprint value.
  sed -n 's/^key fingerprint: //p' | head -n 1
}

echo "1. bare run reaches /health"
docker volume create "$VOLUME" >/dev/null
docker run -d --name "$NAME" -p 127.0.0.1:0:3100 -v "$VOLUME:/data" "$IMAGE" >/dev/null
STARTED=1
wait_healthy
PORT="$(host_port)"

echo "2. both banners are in the logs"
LOGS="$(docker logs "$NAME" 2>&1)"
printf '%s\n' "$LOGS" | grep -q 'GATEHOUSE GENERATED A NEW MASTER KEY' \
  || fail "master key banner missing"
printf '%s\n' "$LOGS" | grep -q 'GATEHOUSE BOOTSTRAP ROOT TOKEN' \
  || fail "bootstrap token banner missing"

echo "3. the logged token authenticates"
TOKEN="$(printf '%s\n' "$LOGS" | grep -E '^ +[0-9a-f]{32}[[:space:]]*$' | head -n 1 | tr -d '[:space:]')"
[ -n "$TOKEN" ] || fail "no 32-hex token line found in the banner"
code="$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $TOKEN" "http://127.0.0.1:$PORT/v1/config" || true)"
[ "$code" = "200" ] || fail "GET /v1/config with the logged token returned ${code:-none}, want 200"

echo "4. verify exits 0"
VERIFY1="$(docker run --rm -v "$VOLUME:/data" "$IMAGE" verify 2>&1)" \
  || { printf '%s\n' "$VERIFY1" >&2; fail "verify exited non-zero"; }
FP1="$(printf '%s\n' "$VERIFY1" | fingerprint_of)"
[ -n "$FP1" ] || { printf '%s\n' "$VERIFY1" >&2; fail "verify printed no key fingerprint"; }
echo "   fingerprint $FP1"

echo "5. restart is quiet and keeps the key"
BEFORE="$(docker logs "$NAME" 2>&1 | wc -l | tr -d ' ')"
docker restart "$NAME" >/dev/null
wait_healthy
AFTER_LOGS="$(docker logs "$NAME" 2>&1 | tail -n +"$((BEFORE + 1))")"
[ -n "$AFTER_LOGS" ] || fail "no log output after restart, cannot judge quietness"
if printf '%s\n' "$AFTER_LOGS" | grep -q 'GATEHOUSE GENERATED A NEW MASTER KEY'; then
  fail "master key banner printed again after restart"
fi
if printf '%s\n' "$AFTER_LOGS" | grep -q 'GATEHOUSE BOOTSTRAP ROOT TOKEN'; then
  fail "bootstrap token banner printed again after restart"
fi
VERIFY2="$(docker run --rm -v "$VOLUME:/data" "$IMAGE" verify 2>&1)" \
  || { printf '%s\n' "$VERIFY2" >&2; fail "verify exited non-zero after restart"; }
FP2="$(printf '%s\n' "$VERIFY2" | fingerprint_of)"
[ "$FP1" = "$FP2" ] || fail "fingerprint changed across restart ($FP1 -> $FP2)"

echo "OK: first-boot contract holds for $IMAGE"
