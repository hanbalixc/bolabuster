"""Identitaets-Loader und Top-Level-Einstieg fuer die Config-Schicht."""

from __future__ import annotations

import yaml

from bolabuster.config.auth import build_auth
from bolabuster.config.scope import ScopeConfig, load_scope
from bolabuster.errors import ConfigError
from bolabuster.models import Identity


def _load_yaml_or_dict(source: str | dict) -> dict:
    if isinstance(source, dict):
        return source
    try:
        with open(source, encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
    except OSError as exc:
        raise ConfigError(f"Identitaets-Config {source!r} konnte nicht gelesen werden: {exc}") from exc
    if not isinstance(data, dict):
        raise ConfigError(f"Identitaets-Config {source!r} ist kein gueltiges YAML-Mapping")
    return data


def load_identities(source: str | dict) -> list[Identity]:
    """Laedt und validiert die Identitaets-Config aus einem YAML-Pfad oder Dict.

    Erfordert mindestens zwei Identitaeten mit eindeutigen Namen und
    bekanntem `auth.type`.
    """
    cfg = _load_yaml_or_dict(source)

    raw_identities = cfg.get("identities")
    if not isinstance(raw_identities, list) or len(raw_identities) < 2:
        raise ConfigError("identities benoetigt mindestens 2 Eintraege")

    identities: list[Identity] = []
    seen_names: set[str] = set()
    for entry in raw_identities:
        if not isinstance(entry, dict):
            raise ConfigError("jeder identities-Eintrag muss ein Mapping sein")

        name = entry.get("name")
        if not name or not isinstance(name, str):
            raise ConfigError("identities[].name ist Pflicht")
        if name in seen_names:
            raise ConfigError(f"identities[].name {name!r} ist nicht eindeutig")
        seen_names.add(name)

        auth_cfg = entry.get("auth")
        if not isinstance(auth_cfg, dict):
            raise ConfigError(f"identity {name!r}: auth ist Pflicht")
        auth = build_auth(auth_cfg)

        headers = entry.get("headers") or {}
        if not isinstance(headers, dict):
            raise ConfigError(f"identity {name!r}: headers muss ein Mapping sein")

        known_object_ids = entry.get("known_object_ids") or []
        if not isinstance(known_object_ids, list):
            raise ConfigError(f"identity {name!r}: known_object_ids muss eine Liste sein")

        identities.append(
            Identity(
                name=name,
                auth=auth,
                headers=dict(headers),
                known_object_ids=[str(i) for i in known_object_ids],
            )
        )

    return identities


def load_config(identities_source: str | dict, scope_source: str | dict) -> tuple[list[Identity], ScopeConfig]:
    """Top-Level-Einstieg: laedt Identitaets- und Scope-Config zusammen.

    Wirft `ConfigError`, falls `authorization.confirmed` nicht `true` ist oder
    eine der beiden Configs sonst invalide ist. Kein `sys.exit` hier - das
    Mapping auf Exit-Codes obliegt der CLI.
    """
    identities = load_identities(identities_source)
    scope = load_scope(scope_source)
    return identities, scope
