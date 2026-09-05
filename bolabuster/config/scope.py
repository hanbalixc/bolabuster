"""Scope-Config: Autorisierungs-Gate, Ziel, Limits, Enumerationsoptionen.

Enthaelt die Dataclasses `ScopeConfig`, `TargetConfig`, `LimitsConfig`,
`EnumerationConfig` sowie `RunConfig`, das die Laufparameter fuer die Engine
buendelt (spaetere Schritte).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urlsplit

from bolabuster.errors import ConfigError

_DEFAULT_RATE_PER_SEC = 3.0
_DEFAULT_MAX_REQUESTS = 5000
_DEFAULT_TIMEOUT_SEC = 15.0
_DEFAULT_ENUM_ENABLED = False
_DEFAULT_NEIGHBOR_RANGE = 5


@dataclass
class TargetConfig:
    base_url: str
    allow_paths: list[str]
    deny_paths: list[str] = field(default_factory=list)


@dataclass
class LimitsConfig:
    rate_per_sec: float = _DEFAULT_RATE_PER_SEC
    max_requests: int = _DEFAULT_MAX_REQUESTS
    timeout_sec: float = _DEFAULT_TIMEOUT_SEC


@dataclass
class EnumerationConfig:
    enabled: bool = _DEFAULT_ENUM_ENABLED
    neighbor_range: int = _DEFAULT_NEIGHBOR_RANGE


@dataclass
class ScopeConfig:
    engagement_ref: str
    target: TargetConfig
    limits: LimitsConfig
    enumeration: EnumerationConfig


@dataclass
class RunConfig:
    """Buendelt Laufparameter fuer die Engine (spaetere Schritte)."""

    dry_run: bool
    allow_writes: bool
    enumerate: bool
    limits: LimitsConfig
    neighbor_range: int = 5


def _validate_authorization(cfg: dict) -> str:
    authorization = cfg.get("authorization")
    if not isinstance(authorization, dict) or authorization.get("confirmed") is not True:
        raise ConfigError(
            "authorization.confirmed muss explizit 'true' sein; ohne bestaetigte "
            "Autorisierung wird der Scan abgebrochen"
        )
    return str(authorization.get("engagement_ref") or "")


def _validate_target(cfg: dict) -> TargetConfig:
    target = cfg.get("target")
    if not isinstance(target, dict):
        raise ConfigError("target ist Pflicht")

    base_url = target.get("base_url")
    if not base_url or not isinstance(base_url, str):
        raise ConfigError("target.base_url ist Pflicht")
    parsed = urlsplit(base_url)
    if not parsed.scheme or not parsed.netloc:
        raise ConfigError(f"target.base_url {base_url!r} ist keine gueltige absolute URL (Schema+Host noetig)")

    allow_paths = target.get("allow_paths")
    if not allow_paths or not isinstance(allow_paths, list) or len(allow_paths) < 1:
        raise ConfigError("target.allow_paths ist Pflicht und braucht mindestens einen Eintrag")

    deny_paths = target.get("deny_paths") or []
    if not isinstance(deny_paths, list):
        raise ConfigError("target.deny_paths muss eine Liste sein")

    return TargetConfig(base_url=base_url, allow_paths=list(allow_paths), deny_paths=list(deny_paths))


def _validate_limits(cfg: dict) -> LimitsConfig:
    limits = cfg.get("limits") or {}
    if not isinstance(limits, dict):
        raise ConfigError("limits muss ein Mapping sein")
    return LimitsConfig(
        rate_per_sec=float(limits.get("rate_per_sec", _DEFAULT_RATE_PER_SEC)),
        max_requests=int(limits.get("max_requests", _DEFAULT_MAX_REQUESTS)),
        timeout_sec=float(limits.get("timeout_sec", _DEFAULT_TIMEOUT_SEC)),
    )


def _validate_enumeration(cfg: dict) -> EnumerationConfig:
    enumeration = cfg.get("enumeration") or {}
    if not isinstance(enumeration, dict):
        raise ConfigError("enumeration muss ein Mapping sein")
    return EnumerationConfig(
        enabled=bool(enumeration.get("enabled", _DEFAULT_ENUM_ENABLED)),
        neighbor_range=int(enumeration.get("neighbor_range", _DEFAULT_NEIGHBOR_RANGE)),
    )


def load_scope(source: str | dict) -> ScopeConfig:
    """Laedt und validiert die Scope-Config aus einem YAML-Pfad oder Dict."""
    cfg = _load_yaml_or_dict(source)

    engagement_ref = _validate_authorization(cfg)
    target = _validate_target(cfg)
    limits = _validate_limits(cfg)
    enumeration = _validate_enumeration(cfg)

    return ScopeConfig(
        engagement_ref=engagement_ref,
        target=target,
        limits=limits,
        enumeration=enumeration,
    )


def _load_yaml_or_dict(source: str | dict) -> dict:
    if isinstance(source, dict):
        return source
    import yaml

    try:
        with open(source, encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
    except OSError as exc:
        raise ConfigError(f"Scope-Config {source!r} konnte nicht gelesen werden: {exc}") from exc
    if not isinstance(data, dict):
        raise ConfigError(f"Scope-Config {source!r} ist kein gueltiges YAML-Mapping")
    return data
