"""Settings from environment variables (docs/self-hosting.md 2).

The container is configured only through the variables in `backend/docker/docker-compose.yml`.
`SYNCRYPTION_DATA_DIR` is a development override for `/data` and is not part of the
hosting configuration. Neither is `SYNCRYPTION_LITESTREAM_METRICS`, which the entrypoint
sets while Litestream replicates.
"""

import ipaddress
import os
import unicodedata
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

MIN_ADMIN_TOKEN = 32
MIN_SHARED_SECRET = 16
# `ADMIN_CONTACT` and the maintenance message: one line of free text.
MAX_NOTE = 500
# `TRUSTED_PROXIES` and `METRICS_ALLOWED_IPS` when unset: loopback and private ranges, where
# a reverse proxy or a Prometheus in front of the container (on the same host, a Docker
# network or the LAN) connects from.
PRIVATE_NETWORKS = DEFAULT_TRUSTED_PROXIES = (
    "127.0.0.0/8",
    "::1/128",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "fc00::/7",
)

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network


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
    # `ADMIN_TOKEN`, for the /admin page. Empty only when built in code (tests, `openapi`):
    # the admin page then refuses every token.
    admin_token: str = ""
    behind_proxy: bool = False
    # `TRUSTED_PROXIES`: with BEHIND_PROXY=TRUE, the peers whose X-Forwarded-* headers count.
    trusted_proxies: tuple[IPNetwork, ...] = tuple(
        ipaddress.ip_network(n) for n in DEFAULT_TRUSTED_PROXIES
    )
    # Public origin (`scheme://host[:port]`), or None to use the request's origin.
    url: str | None = None
    s3: S3Settings | None = None
    migrate_to_s3: bool = False
    # `MIGRATE_FROM_S3=TRUE`: S3 is only the source of the copy, blobs are served locally.
    migrate_from_s3: bool = False
    data_dir: Path = Path("/data")
    # `ADMIN_CONTACT`: how users reach the administrator (email, Slack, phone, ...). Public:
    # shown on `/`, in `/health` and in some errors. Empty when unset.
    admin_contact: str = ""
    # `DISABLE_METRICS=TRUE`: no `/metrics` endpoint.
    disable_metrics: bool = False
    # `METRICS_ALLOWED_IPS`: the client addresses `/metrics` answers.
    metrics_allowed: tuple[IPNetwork, ...] = tuple(
        ipaddress.ip_network(n) for n in PRIVATE_NETWORKS
    )
    # `SYNCRYPTION_LITESTREAM_METRICS`: Litestream's metrics address (`host:port`), set by
    # the entrypoint only while Litestream replicates meta.db. None otherwise.
    litestream_metrics: str | None = None

    @property
    def db_path(self) -> Path:
        return self.data_dir / "meta.db"

    @property
    def blob_s3(self) -> S3Settings | None:
        """The S3 the server stores blobs in (and Litestream replicates to), if any."""
        return None if self.migrate_from_s3 else self.s3


def _bool(env: Mapping[str, str], name: str) -> bool:
    value = env.get(name, "").strip().upper()
    if value in ("", "FALSE"):
        return False
    if value == "TRUE":
        return True
    raise ConfigError(f"{name} must be TRUE or FALSE")


def note_problem(value: str) -> str | None:
    """Why `value` isn't one line of at most MAX_NOTE characters, or None if it is."""
    if len(value) > MAX_NOTE:
        return f"must be at most {MAX_NOTE} characters"
    if any(unicodedata.category(c) == "Cc" for c in value):
        return "must be a single line without control characters"
    return None


def parse_networks(value: str, name: str = "TRUSTED_PROXIES") -> tuple[IPNetwork, ...]:
    """`"10.0.0.5, 172.16.0.0/12"` -> networks. Empty means PRIVATE_NETWORKS. `name` is the
    variable, for the error."""
    entries = [e.strip() for e in value.split(",") if e.strip()]
    networks = []
    for entry in entries or PRIVATE_NETWORKS:
        try:
            networks.append(ipaddress.ip_network(entry, strict=False))
        except ValueError:
            raise ConfigError(
                f"{name} must be IP addresses or CIDRs separated by commas ({entry!r} is neither)"
            ) from None
    return tuple(networks)


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
        raise ConfigError("SHARED_SECRET is required (generate one with: openssl rand -base64 24)")
    if len(shared_secret.strip()) < MIN_SHARED_SECRET:
        raise ConfigError(f"SHARED_SECRET must be at least {MIN_SHARED_SECRET} characters")

    admin_token = env.get("ADMIN_TOKEN", "").strip()
    if not admin_token:
        raise ConfigError("ADMIN_TOKEN is required (generate one with: openssl rand -hex 32)")
    if len(admin_token) < MIN_ADMIN_TOKEN:
        raise ConfigError(f"ADMIN_TOKEN must be at least {MIN_ADMIN_TOKEN} characters")

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
    migrate_from = _bool(env, "MIGRATE_FROM_S3")
    if migrate_from and s3 is None:
        raise ConfigError("MIGRATE_FROM_S3=TRUE needs S3_BUCKET, S3_ACCESS_KEY and S3_SECRET_KEY")
    if migrate and migrate_from:
        raise ConfigError("set only one of MIGRATE_TO_S3 and MIGRATE_FROM_S3 to TRUE")

    admin_contact = env.get("ADMIN_CONTACT", "").strip()
    problem = note_problem(admin_contact)
    if problem:
        raise ConfigError(f"ADMIN_CONTACT {problem}")

    disable_metrics = _bool(env, "DISABLE_METRICS")
    trusted_proxies = parse_networks(env.get("TRUSTED_PROXIES", ""))
    metrics_allowed = parse_networks(env.get("METRICS_ALLOWED_IPS", ""), "METRICS_ALLOWED_IPS")

    data_dir = Path(env.get("SYNCRYPTION_DATA_DIR", "") or "/data")
    litestream_metrics = env.get("SYNCRYPTION_LITESTREAM_METRICS", "").strip() or None
    return Settings(
        shared_secret=shared_secret,
        admin_token=admin_token,
        behind_proxy=behind_proxy,
        trusted_proxies=trusted_proxies,
        url=url,
        s3=s3,
        migrate_to_s3=migrate,
        migrate_from_s3=migrate_from,
        data_dir=data_dir,
        admin_contact=admin_contact,
        disable_metrics=disable_metrics,
        metrics_allowed=metrics_allowed,
        litestream_metrics=litestream_metrics,
    )
