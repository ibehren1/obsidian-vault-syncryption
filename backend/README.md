# vault-syncryption-server

The Vault Syncryption sync server. See [../docs/architecture.md](../docs/architecture.md),
[../docs/protocol.md](../docs/protocol.md) and the endpoint reference
[../docs/api.md](../docs/api.md).

```
uv sync
uv run pytest
uv run ruff check .
uv run ruff format --check .
```

`../docs/api.md` is generated from the app's OpenAPI schema. Regenerate it after any change
to a route or a model, or `tests/test_apidocs.py` fails:
```
uv run python -m syncryption_server apidocs > ../docs/api.md
```

Run a development server. The app is built by a factory that reads its settings from the
environment, so set at least the shared secret and the admin token, and keep the data
outside `/data`:
```
SHARED_SECRET=dev-shared-secret ADMIN_TOKEN=dev-admin-token-0123456789abcdef BEHIND_PROXY=TRUE SYNCRYPTION_DATA_DIR=./dev-data \
  uv run uvicorn --factory syncryption_server.app:create_app --reload
```
`SYNCRYPTION_DATA_DIR` is for development only and isn't part of the container
configuration. S3 is optional: without the `S3_*` variables, blobs are stored under
`<data dir>/blobs`. `ADMIN_CONTACT` (optional) sets the contact shown on `/`, in `/health`
and in maintenance and disabled-account errors, and `DISABLE_METRICS=TRUE` turns off
`/metrics`. `METRICS_ALLOWED_IPS` (optional) lists the client addresses or CIDRs that may
read `/metrics`; it defaults to loopback and private ranges. `TRUSTED_PROXIES` (optional, with `BEHIND_PROXY=TRUE`) lists the proxy
addresses or CIDRs whose `X-Forwarded-*` headers count; it defaults to loopback and
private ranges, which includes a development proxy on `127.0.0.1`. The container variables are described in
[../docs/self-hosting.md](../docs/self-hosting.md), section 2.

Tests run against a temporary directory and, for `S3BlobStore`, an in-process moto
server. Set `MINIO_ENDPOINT` (with `docker compose -f docker-compose.dev.yml up`) to also
run the store tests against MinIO (`MINIO_ENDPOINT=http://127.0.0.1:9000`).

## Container
`Dockerfile` and `entrypoint.sh` build the single container (see
[../docs/architecture.md](../docs/architecture.md), section 3). From the repository root:
```
docker compose -f docker-compose.dev.yml up --build   # app on :8080 behind a "proxy", MinIO, Litestream
backend/container-checks.sh                            # build the image and run the container checks
```
With the dev stack running, `tests/test_container.py` also runs against it:
```
SYNCRYPTION_URL=http://127.0.0.1:8080 SYNCRYPTION_SECRET=dev-secret uv run pytest tests/test_container.py
```
