"""Konkrete `AuthMaterial`-Handler und Registry.

Neue Auth-Arten werden hinzugefuegt, indem ein Handler mit `type`-Attribut
und `apply(prepared)` implementiert und in `AUTH_HANDLERS` unter seinem
`type`-Schluessel mit einer Factory registriert wird.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from bolabuster.errors import ConfigError
from bolabuster.models import AuthMaterial, PreparedRequest


@dataclass
class BearerAuth:
    """`Authorization: Bearer <token>` Header."""

    token: str
    type: str = "bearer"

    def apply(self, prepared: PreparedRequest) -> PreparedRequest:
        prepared.headers["Authorization"] = f"Bearer {self.token}"
        return prepared


@dataclass
class HeaderAuth:
    """Statische Header, z.B. API-Keys.

    YAML-Form: `auth: {type: header, headers: {X-Api-Key: "..."}}`.
    """

    headers: dict[str, str] = field(default_factory=dict)
    type: str = "header"

    def apply(self, prepared: PreparedRequest) -> PreparedRequest:
        prepared.headers.update(self.headers)
        return prepared


@dataclass
class CookieAuth:
    """`Cookie`-Header aus key=value-Paaren."""

    cookies: dict[str, str] = field(default_factory=dict)
    type: str = "cookie"

    def apply(self, prepared: PreparedRequest) -> PreparedRequest:
        cookie_value = "; ".join(f"{k}={v}" for k, v in self.cookies.items())
        prepared.headers["Cookie"] = cookie_value
        return prepared


def _build_bearer(cfg: dict) -> AuthMaterial:
    token = cfg.get("token")
    if not token:
        raise ConfigError("auth.type=bearer erfordert das Feld 'token'")
    return BearerAuth(token=token)


def _build_header(cfg: dict) -> AuthMaterial:
    headers = cfg.get("headers")
    if not headers or not isinstance(headers, dict):
        raise ConfigError("auth.type=header erfordert ein nicht-leeres Feld 'headers' (dict)")
    return HeaderAuth(headers=dict(headers))


def _build_cookie(cfg: dict) -> AuthMaterial:
    cookies = cfg.get("cookies")
    if not cookies or not isinstance(cookies, dict):
        raise ConfigError("auth.type=cookie erfordert ein nicht-leeres Feld 'cookies' (dict)")
    return CookieAuth(cookies=dict(cookies))


AUTH_HANDLERS: dict[str, Callable[[dict], AuthMaterial]] = {
    "bearer": _build_bearer,
    "header": _build_header,
    "cookie": _build_cookie,
}


def build_auth(cfg: dict) -> AuthMaterial:
    """Baut aus einem `auth`-Config-Dict das passende `AuthMaterial`."""
    if not isinstance(cfg, dict):
        raise ConfigError("auth muss ein Mapping sein")
    auth_type = cfg.get("type")
    if not auth_type:
        raise ConfigError("auth.type ist Pflicht")
    factory = AUTH_HANDLERS.get(auth_type)
    if factory is None:
        known = ", ".join(sorted(AUTH_HANDLERS))
        raise ConfigError(f"unbekannter auth.type {auth_type!r}; bekannt: {known}")
    return factory(cfg)
