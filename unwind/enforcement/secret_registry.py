"""SecretRegistry — known-secret exact-matching for Ghost Egress Guard.

High-precision, near-zero-false-positive detection of actual user secrets
in outbound traffic.  Deterministic exact matching of user-derived secret
material — no heuristic "looks-like-a-secret" classifiers.

Design document: docs/SECRET_REGISTRY_DESIGN.md

Key constraints:
  - In-memory only — never persisted to disk, cache, or logs.
  - Raw secret values never appear in telemetry or error messages.
  - Only fingerprintId (first 8 hex chars of SHA-256) is safe to emit.
  - Fail-safe: degraded/unavailable registry → conservative egress policy.
  - Feature-flagged: disabled by default (UNWIND_SECRET_REGISTRY=1 to enable).
"""

import base64
import configparser
import hashlib
import io
import os
import time as _time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Callable, Dict, FrozenSet, List, Optional, Set, Tuple
from urllib.parse import quote as url_quote


# ──────────────────────────────────────────────
# Enums
# ──────────────────────────────────────────────

class SourceKind(str, Enum):
    WORKSPACE_ENV = "workspace_env"
    AWS_CREDENTIALS = "aws_credentials"
    SSH_PUB_FINGERPRINT = "ssh_pub_fingerprint"
    PROCESS_ENV = "process_env"


class TransformKind(str, Enum):
    RAW = "raw"
    URL_ENCODED = "url_encoded"
    BASE64 = "base64"
    BASE64URL = "base64url"
    HEX = "hex"


class RegistryState(str, Enum):
    READY = "ready"
    LOADING = "loading"
    DEGRADED = "degraded"
    UNAVAILABLE = "unavailable"


# ──────────────────────────────────────────────
# Data classes
# ──────────────────────────────────────────────

@dataclass(frozen=True)
class SecretRecord:
    """Metadata about a loaded secret — no raw value."""
    fingerprint_id: str        # first 8 hex chars of SHA-256(value)
    source: SourceKind
    name: str                  # env var key, file key label, etc.
    token_count: int
    created_at_ms: float


@dataclass(frozen=True)
class MatchToken:
    """A single searchable token derived from a secret.  Sensitive — in-memory only."""
    token: str                 # the actual token string (NEVER log this)
    fingerprint_id: str
    source: SourceKind
    transform: TransformKind


class MatchLocation(str, Enum):
    URL_HOST = "url.host"
    URL_PATH = "url.path"
    URL_QUERY = "url.query"
    URL_USERINFO = "url.userinfo"
    SEARCH_QUERY_TEXT = "search.queryText"


@dataclass(frozen=True)
class MatchHit:
    """A single match hit — safe to log (no raw secret)."""
    fingerprint_id: str
    source: SourceKind
    transform: TransformKind
    location: MatchLocation


@dataclass
class MatchResult:
    """Result of matching a request against the registry."""
    matched: bool
    hits: List[MatchHit]
    decision: str   # "allow" | "ask" | "block"
    reason_code: str  # "secret_match" | "registry_unavailable" | "registry_degraded" | "no_match"


@dataclass
class RegistrySnapshot:
    """Point-in-time snapshot of registry state — no raw values."""
    registry_version: int
    loaded_at_ms: float
    record_count: int
    token_count: int
    records: List[SecretRecord]


@dataclass
class SecretRegistryConfig:
    """Tuneable parameters for SecretRegistry."""
    # Source paths
    workspace_root: Path = field(default_factory=lambda: Path("."))
    env_file_names: List[str] = field(default_factory=lambda: [
        ".env", ".env.local", ".env.production", ".env.development",
        ".env.staging", ".env.test",
    ])
    aws_credentials_path: Path = field(
        default_factory=lambda: Path.home() / ".aws" / "credentials"
    )
    ssh_dir: Path = field(
        default_factory=lambda: Path.home() / ".ssh"
    )

    # Env var name patterns (case-insensitive substring match)
    env_secret_name_patterns: List[str] = field(default_factory=lambda: [
        "API_KEY", "SECRET", "TOKEN", "PASSWORD", "PRIVATE_KEY", "CREDENTIAL",
        "ACCESS_KEY", "AUTH",
    ])

    # Memory limits
    max_records: int = 10_000
    max_tokens: int = 50_000
    max_token_length: int = 8192
    max_total_token_bytes: int = 16 * 1024 * 1024  # 16 MiB

    # Minimum secret length (skip very short values)
    min_secret_length: int = 8


# ──────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────

def _fingerprint(value: str) -> str:
    """SHA-256 of the value → first 8 hex chars."""
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()[:8]


def _generate_transforms(value: str) -> List[Tuple[TransformKind, str]]:
    """Generate all transform variants for a secret value.

    Returns list of (transform_kind, token_string).
    Skips empty/duplicate results.
    """
    results: List[Tuple[TransformKind, str]] = []
    seen: Set[str] = set()
    value_bytes = value.encode("utf-8", errors="replace")

    candidates = [
        (TransformKind.RAW, value),
        (TransformKind.URL_ENCODED, url_quote(value, safe="")),
        (TransformKind.BASE64, base64.b64encode(value_bytes).decode("ascii")),
        (TransformKind.BASE64URL, base64.urlsafe_b64encode(value_bytes).decode("ascii")),
        (TransformKind.HEX, value_bytes.hex()),
    ]

    for kind, token in candidates:
        if token and token not in seen:
            seen.add(token)
            results.append((kind, token))

    return results


def _is_secret_env_name(name: str, patterns: List[str]) -> bool:
    """Check if an env var name matches common secret patterns (case-insensitive)."""
    upper = name.upper()
    return any(p in upper for p in patterns)


# ──────────────────────────────────────────────
# Source parsers
# ──────────────────────────────────────────────

def _parse_env_file(path: Path) -> List[Tuple[str, str]]:
    """Parse a .env file into (key, value) pairs.

    Handles KEY=VALUE, KEY="VALUE", KEY='VALUE' forms.
    Ignores comments (#) and blank lines.
    """
    results: List[Tuple[str, str]] = []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except (OSError, PermissionError):
        return results

    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip()
        # Strip surrounding quotes
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ('"', "'"):
            value = value[1:-1]
        if key and value:
            results.append((key, value))

    return results


def _parse_aws_credentials(path: Path) -> List[Tuple[str, str]]:
    """Parse ~/.aws/credentials for secret values.

    Returns (label, value) pairs for access keys, secret keys, session tokens.
    """
    results: List[Tuple[str, str]] = []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except (OSError, PermissionError):
        return results

    parser = configparser.ConfigParser()
    try:
        parser.read_string(text)
    except configparser.Error:
        return results

    secret_keys = {"aws_access_key_id", "aws_secret_access_key", "aws_session_token"}
    for section in parser.sections():
        for key in secret_keys:
            value = parser.get(section, key, fallback=None)
            if value and value.strip():
                results.append((f"aws:{section}:{key}", value.strip()))

    return results


def _ssh_pub_fingerprints(ssh_dir: Path) -> List[Tuple[str, str]]:
    """Compute SHA-256 fingerprints of SSH public keys.

    Does NOT treat public key material as secret payload.
    Only the fingerprint is kept — no raw .pub content.
    """
    results: List[Tuple[str, str]] = []
    try:
        pub_files = list(ssh_dir.glob("*.pub"))
    except (OSError, PermissionError):
        return results

    for pub_file in pub_files:
        try:
            text = pub_file.read_text(encoding="utf-8", errors="replace").strip()
            # SSH pub key format: type base64data comment
            parts = text.split()
            if len(parts) >= 2:
                key_data = parts[1]
                try:
                    decoded = base64.b64decode(key_data)
                    fp = hashlib.sha256(decoded).hexdigest()
                    results.append((f"ssh:{pub_file.name}", fp))
                except Exception:
                    pass
        except (OSError, PermissionError):
            continue

    return results


def _collect_process_env(patterns: List[str]) -> List[Tuple[str, str]]:
    """Collect environment variables matching common secret name patterns."""
    results: List[Tuple[str, str]] = []
    for key, value in os.environ.items():
        if _is_secret_env_name(key, patterns) and value.strip():
            results.append((key, value.strip()))
    return results


# ──────────────────────────────────────────────
# SecretRegistry
# ──────────────────────────────────────────────

class SecretRegistry:
    """In-memory registry of known secret tokens for exact-match scanning.

    Lifecycle:
      1. load()       — collect sources, derive transforms, compile matcher
      2. match(...)   — check outbound text for known secrets
      3. refresh()    — atomic rebuild from sources
      4. invalidate() — clear tokens, set degraded/unavailable

    Thread safety: NOT thread-safe.  Designed for single-session use.
    """

    def __init__(self, config: SecretRegistryConfig):
        self._config = config
        self._state = RegistryState.UNAVAILABLE
        self._version = 0
        self._loaded_at_ms: float = 0
        self._records: List[SecretRecord] = []
        self._tokens: List[MatchToken] = []
        self._token_set: Set[str] = set()  # For fast "is this token in registry" checks
        self._total_token_bytes: int = 0
        self._load_errors: List[str] = []

    @property
    def state(self) -> RegistryState:
        return self._state

    def load(self) -> RegistrySnapshot:
        """Collect secrets from all sources and build the matcher.

        Population order per design doc section 4:
          1. Environment variables
          2. Workspace .env files
          3. ~/.aws/credentials
          4. ~/.ssh/*.pub fingerprints
        """
        self._state = RegistryState.LOADING
        self._load_errors = []

        raw_secrets: List[Tuple[SourceKind, str, str]] = []  # (source, name, value)

        # 1. Process environment
        try:
            for name, value in _collect_process_env(self._config.env_secret_name_patterns):
                raw_secrets.append((SourceKind.PROCESS_ENV, name, value))
        except Exception as e:
            self._load_errors.append(f"process_env: {type(e).__name__}")

        # 2. Workspace .env files
        for env_name in self._config.env_file_names:
            env_path = self._config.workspace_root / env_name
            if env_path.is_file():
                try:
                    for name, value in _parse_env_file(env_path):
                        raw_secrets.append((SourceKind.WORKSPACE_ENV, name, value))
                except Exception as e:
                    self._load_errors.append(f"env_file({env_name}): {type(e).__name__}")

        # 3. AWS credentials
        aws_path = self._config.aws_credentials_path
        if aws_path.is_file():
            try:
                for name, value in _parse_aws_credentials(aws_path):
                    raw_secrets.append((SourceKind.AWS_CREDENTIALS, name, value))
            except Exception as e:
                self._load_errors.append(f"aws_credentials: {type(e).__name__}")

        # 4. SSH pub fingerprints
        ssh_dir = self._config.ssh_dir
        if ssh_dir.is_dir():
            try:
                for name, value in _ssh_pub_fingerprints(ssh_dir):
                    raw_secrets.append((SourceKind.SSH_PUB_FINGERPRINT, name, value))
            except Exception as e:
                self._load_errors.append(f"ssh_fingerprints: {type(e).__name__}")

        # Build records and tokens
        records: List[SecretRecord] = []
        tokens: List[MatchToken] = []
        token_set: Set[str] = set()
        total_bytes = 0
        now_ms = _time.time() * 1000

        for source, name, value in raw_secrets:
            # Enforce limits
            if len(records) >= self._config.max_records:
                self._load_errors.append("max_records limit reached")
                break

            # Skip short values
            if len(value) < self._config.min_secret_length:
                continue

            fp = _fingerprint(value)
            transforms = _generate_transforms(value)
            added_count = 0

            for kind, token in transforms:
                if len(tokens) >= self._config.max_tokens:
                    self._load_errors.append("max_tokens limit reached")
                    break
                if len(token) > self._config.max_token_length:
                    continue
                token_bytes = len(token.encode("utf-8", errors="replace"))
                if total_bytes + token_bytes > self._config.max_total_token_bytes:
                    self._load_errors.append("max_total_token_bytes limit reached")
                    break

                if token not in token_set:
                    tokens.append(MatchToken(
                        token=token,
                        fingerprint_id=fp,
                        source=source,
                        transform=kind,
                    ))
                    token_set.add(token)
                    total_bytes += token_bytes
                    added_count += 1

            if added_count > 0:
                records.append(SecretRecord(
                    fingerprint_id=fp,
                    source=source,
                    name=name,
                    token_count=added_count,
                    created_at_ms=now_ms,
                ))

        # Atomic swap
        self._records = records
        self._tokens = tokens
        self._token_set = token_set
        self._total_token_bytes = total_bytes
        self._version += 1
        self._loaded_at_ms = now_ms

        if self._load_errors and not records:
            self._state = RegistryState.UNAVAILABLE
        elif self._load_errors:
            self._state = RegistryState.DEGRADED
        else:
            self._state = RegistryState.READY

        return self.snapshot()

    def refresh(self) -> RegistrySnapshot:
        """Atomic rebuild — old registry remains until new build succeeds."""
        old_records = self._records
        old_tokens = self._tokens
        old_token_set = self._token_set
        old_total = self._total_token_bytes
        old_state = self._state

        try:
            return self.load()
        except Exception:
            # Restore old state on failure
            self._records = old_records
            self._tokens = old_tokens
            self._token_set = old_token_set
            self._total_token_bytes = old_total
            self._state = old_state
            raise

    def invalidate(self, reason: str) -> None:
        """Clear all in-memory tokens and set degraded/unavailable."""
        self._tokens = []
        self._token_set = set()
        self._total_token_bytes = 0
        self._load_errors.append(f"invalidated: {reason}")
        self._state = RegistryState.UNAVAILABLE

    def match(
        self,
        url: Optional[str] = None,
        search_query_text: Optional[str] = None,
    ) -> MatchResult:
        """Match outbound request against the registry.

        Checks URL components (host, path, query, userinfo) and search text
        for exact substrings of known secret tokens.

        Returns MatchResult with hits (safe to log — fingerprint IDs only).
        """
        # Unavailable/degraded path — fail-safe
        if self._state == RegistryState.UNAVAILABLE:
            return MatchResult(
                matched=False, hits=[], decision="block",
                reason_code="registry_unavailable",
            )
        if self._state == RegistryState.DEGRADED:
            # Still try matching, but note degraded state
            pass

        if not self._token_set:
            return MatchResult(
                matched=False, hits=[], decision="allow",
                reason_code="no_match",
            )

        hits: List[MatchHit] = []

        # Parse URL into components
        if url:
            try:
                from urllib.parse import urlparse
                parsed = urlparse(url)
                url_parts: List[Tuple[MatchLocation, str]] = []
                if parsed.hostname:
                    url_parts.append((MatchLocation.URL_HOST, parsed.hostname))
                if parsed.path:
                    url_parts.append((MatchLocation.URL_PATH, parsed.path))
                if parsed.query:
                    from urllib.parse import unquote
                    url_parts.append((MatchLocation.URL_QUERY, unquote(parsed.query)))
                    # Also check raw query (tokens might be URL-encoded in the secret)
                    if parsed.query != unquote(parsed.query):
                        url_parts.append((MatchLocation.URL_QUERY, parsed.query))
                userinfo = ""
                if parsed.username:
                    userinfo += parsed.username
                if parsed.password:
                    userinfo += ":" + parsed.password
                if userinfo:
                    url_parts.append((MatchLocation.URL_USERINFO, userinfo))

                for location, text in url_parts:
                    for mt in self._tokens:
                        if mt.token in text:
                            hits.append(MatchHit(
                                fingerprint_id=mt.fingerprint_id,
                                source=mt.source,
                                transform=mt.transform,
                                location=location,
                            ))
            except Exception:
                pass

        # Search query text
        if search_query_text:
            for mt in self._tokens:
                if mt.token in search_query_text:
                    hits.append(MatchHit(
                        fingerprint_id=mt.fingerprint_id,
                        source=mt.source,
                        transform=mt.transform,
                        location=MatchLocation.SEARCH_QUERY_TEXT,
                    ))

        if hits:
            return MatchResult(
                matched=True, hits=hits, decision="block",
                reason_code="secret_match",
            )

        decision = "allow"
        reason = "no_match"
        if self._state == RegistryState.DEGRADED:
            reason = "registry_degraded"

        return MatchResult(
            matched=False, hits=[], decision=decision,
            reason_code=reason,
        )

    def snapshot(self) -> RegistrySnapshot:
        """Return a point-in-time snapshot (no raw values)."""
        return RegistrySnapshot(
            registry_version=self._version,
            loaded_at_ms=self._loaded_at_ms,
            record_count=len(self._records),
            token_count=len(self._tokens),
            records=list(self._records),
        )

    def status(self) -> dict:
        """Return registry status info."""
        return {
            "state": self._state.value,
            "registry_version": self._version,
            "loaded_at_ms": self._loaded_at_ms,
            "record_count": len(self._records),
            "token_count": len(self._tokens),
            "total_token_bytes": self._total_token_bytes,
            "load_errors": len(self._load_errors),
        }
