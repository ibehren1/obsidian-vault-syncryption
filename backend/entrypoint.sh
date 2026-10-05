#!/usr/bin/env bash
# Container entrypoint (docs/architecture.md section 3).
#
#   1. Validate the environment and stop with a clear message if it is wrong.
#   2. With S3: restore meta.db from the bucket if this host has none yet.
#   3. With MIGRATE_TO_S3=TRUE: copy local blobs to S3, and stop if that fails.
#   4. Serve: uvicorn alone behind your proxy, or uvicorn plus Caddy. With S3 everything
#      runs under `litestream replicate -exec`, so the database is replicated while the
#      app runs.
#   5. If any process exits, stop the others, so the container stops and restarts.
set -euo pipefail

RUN_DIR=/run/syncryption
APP=syncryption_server.app:create_app

serve() {
	local settings pids=()
	settings=$(python -m syncryption_server render "$RUN_DIR")
	eval "$settings"
	if [ "$behind_proxy" = TRUE ]; then
		# The app reads X-Forwarded-* itself (BEHIND_PROXY=TRUE), so uvicorn must not.
		uvicorn --factory "$APP" --host 0.0.0.0 --port 8080 --no-proxy-headers \
			--no-server-header --timeout-graceful-shutdown 5 &
		pids+=($!)
	else
		# Only Caddy can reach 127.0.0.1:8000, so trust its X-Forwarded-For for client IPs.
		uvicorn --factory "$APP" --host 127.0.0.1 --port 8000 --proxy-headers \
			--forwarded-allow-ips 127.0.0.1 --no-server-header --timeout-graceful-shutdown 5 &
		pids+=($!)
		caddy run --config "$RUN_DIR/Caddyfile" --adapter caddyfile &
		pids+=($!)
	fi
	local stopping=0
	trap 'stopping=1; kill -TERM "${pids[@]}" 2>/dev/null || true' TERM INT
	set +e
	wait -n "${pids[@]}"
	local status=$?
	kill -TERM "${pids[@]}" 2>/dev/null
	wait "${pids[@]}"
	# A requested stop is a clean exit. Anything else keeps the failing status.
	if [ "$stopping" = 1 ]; then
		exit 0
	fi
	exit "$status"
}

if [ "${1:-}" = serve ]; then
	serve
fi

python -m syncryption_server check
settings=$(python -m syncryption_server render "$RUN_DIR")
eval "$settings"

if [ "$s3_enabled" = TRUE ]; then
	litestream restore -config "$RUN_DIR/litestream.yml" -if-db-not-exists -if-replica-exists "$db_path"
fi

if [ "$migrate" = TRUE ]; then
	python -m syncryption_server migrate
fi

if [ "$s3_enabled" = TRUE ]; then
	exec litestream replicate -config "$RUN_DIR/litestream.yml" -exec "$0 serve"
fi
exec "$0" serve
