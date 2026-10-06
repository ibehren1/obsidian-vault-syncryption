#!/usr/bin/env bash
# Container checks from docs/PLAN.md (Verification). Builds the image and needs only Docker:
# everything runs through `docker run` and `docker exec`, so it also works on CI runners that
# reach Docker through a mounted socket.
#
#   ./container-checks.sh [image-tag]
set -euo pipefail
cd "$(dirname "$0")"

IMAGE=${1:-syncryption:check}
NAME=syncryption-check-$$
docker build -t "$IMAGE" .

cleanup() { docker rm -f "$NAME" >/dev/null 2>&1 || true; }
trap cleanup EXIT

fail() { echo "FAIL: $*" >&2; exit 1; }

expect_error() {
	local message=$1
	shift
	local out
	if out=$(docker run --rm "$@" "$IMAGE" 2>&1); then
		fail "started with $* (expected: $message)"
	fi
	grep -qF "$message" <<<"$out" || fail "expected '$message', got: $out"
	echo "ok refuses to start: $message"
}

ADMIN=ci-admin-token-0123456789abcdef0
expect_error "URL is required when BEHIND_PROXY=FALSE" -e SHARED_SECRET=x
expect_error "SHARED_SECRET is required" -e BEHIND_PROXY=TRUE
expect_error "ADMIN_TOKEN is required" -e BEHIND_PROXY=TRUE -e SHARED_SECRET=x
expect_error "ADMIN_TOKEN must be at least 32" -e BEHIND_PROXY=TRUE -e SHARED_SECRET=x -e ADMIN_TOKEN=short
expect_error "set all of S3_BUCKET, S3_ACCESS_KEY, S3_SECRET_KEY or none" \
	-e BEHIND_PROXY=TRUE -e SHARED_SECRET=x -e ADMIN_TOKEN=$ADMIN -e S3_BUCKET=b
expect_error "MIGRATE_TO_S3=TRUE needs" -e BEHIND_PROXY=TRUE -e SHARED_SECRET=x -e ADMIN_TOKEN=$ADMIN \
	-e MIGRATE_TO_S3=TRUE
expect_error "ADMIN_CONTACT must be a single line" -e BEHIND_PROXY=TRUE -e SHARED_SECRET=x \
	-e ADMIN_TOKEN=$ADMIN -e "ADMIN_CONTACT=$(printf 'a\tb')"

docker run -d --name "$NAME" -e BEHIND_PROXY=TRUE -e SHARED_SECRET=ci-secret -e ADMIN_TOKEN=$ADMIN \
	-e "ADMIN_CONTACT=ops@example.com" "$IMAGE" >/dev/null
for _ in $(seq 30); do
	if docker exec "$NAME" python -m syncryption_server health; then
		break
	fi
	sleep 1
done
docker exec "$NAME" python -m syncryption_server health || {
	docker logs "$NAME"
	fail "/health did not answer on :8080"
}
echo "ok BEHIND_PROXY=TRUE serves /health over HTTP on 8080"

docker cp tests "$NAME":/tmp/tests
docker cp ../testvectors "$NAME":/testvectors
docker exec -w /tmp -e SYNCRYPTION_URL=http://127.0.0.1:8080 -e SYNCRYPTION_SECRET=ci-secret \
	-e SYNCRYPTION_ADMIN_TOKEN=$ADMIN "$NAME" python -m tests.test_container

docker stop "$NAME" >/dev/null
[ "$(docker inspect -f '{{.State.ExitCode}}' "$NAME")" = 0 ] || fail "docker stop didn't exit cleanly"
echo "ok stops cleanly"
