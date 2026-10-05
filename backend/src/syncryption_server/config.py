"""Settings from environment variables (docs/PLAN.md, Hosting).

The container is configured only through the variables in `backend/docker/docker-compose.yml`.
`SYNCRYPTION_DATA_DIR` is a development override for `/data` and is not part of the
hosting configuration.
"""

import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit


class ConfigError(Exception):
    """The environment is invalid. The message says which variable and why."""


@dataclass(frozen=True)
class S3Settings:
    bucket: str
    access_key: str
    secret_key: str
    # `S3_ENDPOINT`, for S3-compatible providers (MinIO, B2, R2, ...). None means AWS.
    endpoint_url: str | None = None


@dataclass(frozen=True)
class Settings:
    shared_secret: str
    behind_proxy: bool = False
    # Public origin (`scheme://host[:port]`), or None to use the request's origin.
    url: str | None = None
    s3: S3Settings | None = None
    migrate_to_s3: bool = False
    data_dir: Path = Path("/data")

    @property
    def db_path(self) -> Path:
        return self.data_dir / "meta.db"


def _bool(env: Mapping[str, str], name: str) -> bool:
    value = env.get(name, "").strip().upper()
    if value in ("", "FALSE"):
        return False
    if value == "TRUE":
        return True
    raise ConfigError(f"{name} must be TRUE or FALSE")


def parse_origin(url: str) -> str:
    """`https://Notes.Example.com/` -> `https://notes.example.com`."""
    parts = urlsplit(url.strip())
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ConfigError("URL must look like https://notes.example.com")
    if parts.path not in ("", "/") or parts.query or parts.fragment or parts.username:
        raise ConfigError("URL must be an origin only, without a path, query or user")
    host = parts.hostname.lower()
    if ":" in host:
        host = f"[{host}]"
    default_port = {"http": 80, "https": 443}[parts.scheme]
    port = f":{parts.port}" if parts.port and parts.port != default_port else ""
    return f"{parts.scheme}://{host}{port}"


def load_settings(env: Mapping[str, str] | None = None) -> Settings:
    env = os.environ if env is None else env
    behind_proxy = _bool(env, "BEHIND_PROXY")

    url_value = env.get("URL", "").strip()
    url = parse_origin(url_value) if url_value else None
    if not behind_proxy and url is None:
        raise ConfigError("URL is required when BEHIND_PROXY=FALSE")

    shared_secret = env.get("SHARED_SECRET", "")
    if not shared_secret.strip():
        raise ConfigError("SHARED_SECRET is required")

    names = ("S3_BUCKET", "S3_ACCESS_KEY", "S3_SECRET_KEY")
    values = [env.get(n, "").strip() for n in names]
    if any(values) and not all(values):
        missing = ", ".join(n for n, v in zip(names, values, strict=True) if not v)
        raise ConfigError(
            f"set all of S3_BUCKET, S3_ACCESS_KEY, S3_SECRET_KEY or none ({missing} empty)"
        )
    endpoint = env.get("S3_ENDPOINT", "").strip()
    if endpoint:
        if not all(values):
            raise ConfigError("S3_ENDPOINT needs S3_BUCKET, S3_ACCESS_KEY and S3_SECRET_KEY")
        parts = urlsplit(endpoint)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise ConfigError("S3_ENDPOINT must look like https://s3.example.com")
    s3 = S3Settings(*values, endpoint_url=endpoint or None) if all(values) else None

    migrate = _bool(env, "MIGRATE_TO_S3")
    if migrate and s3 is None:
        raise ConfigError("MIGRATE_TO_S3=TRUE needs S3_BUCKET, S3_ACCESS_KEY and S3_SECRET_KEY")

    data_dir = Path(env.get("SYNCRYPTION_DATA_DIR", "") or "/data")
    return Settings(
        shared_secret=shared_secret,
        behind_proxy=behind_proxy,
        url=url,
        s3=s3,
        migrate_to_s3=migrate,
        data_dir=data_dir,
    )
