"""Commands used by the container entrypoint (`python -m syncryption_server <command>`).

- `check`: validate the environment and print what will run. Exits 1 with the reason.
- `render DIR`: write `Caddyfile` (unless `BEHIND_PROXY=TRUE`) and `litestream.yml` (when S3
  is enabled) into DIR, and print the shell assignments the entrypoint needs.
- `check-data`: exit 1 if `meta.db` was written by a server before 0.1.4 (delete it).
- `migrate`: the `MIGRATE_TO_S3` copy.
- `health`: the container healthcheck, a GET of `/health` on the local app port.
- `openapi`: print the OpenAPI schema, from which the plugin's API types are generated.
"""

import argparse
import asyncio
import json
import logging
import os
import shlex
import sys
import urllib.request
from pathlib import Path
from urllib.parse import urlsplit

from syncryption_server.config import ConfigError, Settings, load_settings
from syncryption_server.db import OldDataError, check_file
from syncryption_server.migrate import MigrationError, migrate_to_s3
from syncryption_server.storage import S3BlobStore

UPSTREAM = "127.0.0.1:8000"
PROXY_PORT = 8080


def caddyfile(settings: Settings) -> str:
    if settings.url is None:
        raise ValueError("Caddy needs URL")
    return f"""{{
	admin off
	storage file_system {settings.data_dir / "caddy"}
}}

{settings.url} {{
	encode zstd gzip
	reverse_proxy {UPSTREAM}
}}
"""


def litestream_config(settings: Settings) -> str:
    """Secrets stay in the environment: Litestream expands `${...}` when it loads the file."""
    if settings.s3 is None:
        raise ValueError("S3 is not configured")
    lines = [
        "dbs:",
        f"  - path: {settings.db_path}",
        "    replica:",
        "      type: s3",
        f"      bucket: {settings.s3.bucket}",
        "      path: litestream",
        "      access-key-id: ${S3_ACCESS_KEY}",
        "      secret-access-key: ${S3_SECRET_KEY}",
    ]
    if settings.s3.endpoint_url:
        lines += [
            "      endpoint: ${S3_ENDPOINT}",
            "      region: us-east-1",
            "      force-path-style: true",
        ]
    return "\n".join(lines) + "\n"


def describe(settings: Settings) -> str:
    """One line for the log. Never includes secrets."""
    if settings.behind_proxy:
        serving = "HTTP on :8080 behind your proxy"
    else:
        serving = f"HTTPS for {urlsplit(settings.url or '').hostname} through Caddy"
    if settings.s3 is None:
        storage = f"local blobs in {settings.data_dir / 'blobs'}"
    else:
        where = settings.s3.endpoint_url or "AWS"
        storage = f"S3 bucket {settings.s3.bucket} ({where}), database replicated by Litestream"
    migrate = ", migrating local blobs to S3 first" if settings.migrate_to_s3 else ""
    return f"Vault Syncryption: {serving}; {storage}{migrate}"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="syncryption_server")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("check")
    commands.add_parser("check-data")
    render = commands.add_parser("render")
    render.add_argument("directory", type=Path)
    commands.add_parser("migrate")
    commands.add_parser("health")
    commands.add_parser("openapi")
    args = parser.parse_args(argv)
    if args.command == "health":
        return _health()
    if args.command == "openapi":
        print(json.dumps(_openapi(), indent=2, sort_keys=True))
        return 0
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    try:
        settings = load_settings()
    except ConfigError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    if args.command == "check":
        print(describe(settings))
    elif args.command == "check-data":
        try:
            check_file(settings.db_path)
        except OldDataError as e:
            print(f"error: {e}", file=sys.stderr)
            return 1
    elif args.command == "render":
        args.directory.mkdir(parents=True, exist_ok=True)
        if not settings.behind_proxy:
            (args.directory / "Caddyfile").write_text(caddyfile(settings))
        if settings.s3 is not None:
            (args.directory / "litestream.yml").write_text(litestream_config(settings))
        print(f"behind_proxy={shlex.quote(str(settings.behind_proxy).upper())}")
        print(f"s3_enabled={shlex.quote(str(settings.s3 is not None).upper())}")
        print(f"migrate={shlex.quote(str(settings.migrate_to_s3).upper())}")
        print(f"db_path={shlex.quote(str(settings.db_path))}")
    elif args.command == "migrate":
        if settings.s3 is None:
            print("error: MIGRATE_TO_S3 needs the S3 variables", file=sys.stderr)
            return 1
        try:
            asyncio.run(_migrate(settings))
        except MigrationError as e:
            print(f"error: migration to S3 failed: {e}", file=sys.stderr)
            return 1
        except Exception as e:
            print(f"error: migration to S3 failed: {type(e).__name__}: {e}", file=sys.stderr)
            return 1
    return 0


def _health() -> int:
    behind_proxy = os.environ.get("BEHIND_PROXY", "").strip().upper() == "TRUE"
    address = f"127.0.0.1:{PROXY_PORT}" if behind_proxy else UPSTREAM
    try:
        with urllib.request.urlopen(f"http://{address}/health", timeout=4) as response:  # noqa: S310
            return 0 if response.status == 200 else 1
    except OSError:
        return 1


def _openapi() -> dict:
    from syncryption_server.app import create_app

    # The schema doesn't depend on the settings, and building the app opens nothing.
    return create_app(Settings(shared_secret="unused")).openapi()  # noqa: S106


async def _migrate(settings: Settings) -> None:
    if settings.s3 is None:
        raise ValueError("S3 is not configured")
    store = S3BlobStore(settings.s3)
    await store.start()
    try:
        await migrate_to_s3(settings.data_dir, store)
    finally:
        await store.close()


if __name__ == "__main__":
    sys.exit(main())
