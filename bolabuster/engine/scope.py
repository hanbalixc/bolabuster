"""Scope-Enforcer: verpflichtendes Autorisierungs-Gate fuer jede Anfrage.

Jede `CanonicalRequest`, die die Engine senden will, muss vorher durch
`ScopeEnforcer.check` laufen. Die Pruefung ist fail-closed: im Zweifel wird
verworfen (`allowed=False`), nie stillschweigend erlaubt. `check` wirft
nie - der Aufrufer bekommt eine `ScopeDecision` und entscheidet selbst,
ob er skippt und protokolliert.

Design-Entscheidungen (siehe Report):
- Host-Matching ist strikt: Schema, Hostname (case-insensitiv) und Port
  (nach Aufloesung der Schema-Defaults 80/443) muessen exakt mit
  `target.base_url` uebereinstimmen. Ein Schema-Mismatch (z.B. http statt
  https) gilt als out-of-scope, nicht nur ein Host-Mismatch - das
  Zielsystem koennte auf http eine andere/ungeschuetzte Instanz sein.
- Pfad-Matching nutzt `fnmatch.fnmatchcase` (case-sensitiv, plattform-
  unabhaengig - `fnmatch.fnmatch` normalisiert auf manchen Systemen
  Gross-/Kleinschreibung, was auf Windows zu einem zu grosszuegigen Match
  fuehren wuerde). `*` matcht dabei auch ueber `/` hinweg (fnmatch
  uebersetzt `*` nach `.*` in der Regex) - `/api/v1/*` matcht also auch
  `/api/v1/a/b/c`, nicht nur direkte Kinder von `/api/v1/`. Das ist so
  gewollt (einfache, vorhersehbare Allowlist-Syntax) und wird hier
  dokumentiert, damit Scope-Configs entsprechend eng geschrieben werden.
- Vor dem Matching wird der Pfad zuerst URL-dekodiert (`urllib.parse.unquote`)
  und dann ueber `posixpath.normpath` normalisiert, damit sowohl literale
  Traversal-Tricks (`/api/v1/../admin`) als auch URL-kodierte Varianten
  (`/api/v1/%2e%2e/admin`, `%2f`-kodierte Slashes) `deny_paths` nicht
  umgehen koennen - das Matching arbeitet immer auf dem aufgeloesten,
  dekodierten Pfad. Zusaetzlich wird sowohl der kodierte als auch der
  dekodierte Pfad gegen `deny_paths` geprueft (fail-closed: ein Treffer auf
  irgendeiner der beiden Formen verwirft die Anfrage).
- `deny_paths` hat Vorrang vor `allow_paths`: ein Deny-Treffer verwirft
  die Anfrage, selbst wenn ein Allow-Glob ebenfalls matcht.
- Schreibende Methoden (alles ausser GET/HEAD/OPTIONS, inkl. unbekannter
  Methoden - fail-closed) sind nur mit `allow_writes=True` erlaubt.
"""

from __future__ import annotations

import posixpath
from dataclasses import dataclass
from fnmatch import fnmatchcase
from urllib.parse import unquote, urlsplit

from bolabuster.config.scope import ScopeConfig
from bolabuster.models import CanonicalRequest

_SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
_DEFAULT_PORTS = {"http": 80, "https": 443}


@dataclass
class ScopeDecision:
    allowed: bool
    reason: str


class ScopeEnforcer:
    """Prueft jede Anfrage gegen die verpflichtende Scope-Config."""

    def __init__(self, scope: ScopeConfig, allow_writes: bool = False) -> None:
        self._scope = scope
        self._allow_writes = allow_writes
        self._target_scheme, self._target_host, self._target_port = _split_host(scope.target.base_url)

    def check(self, req: CanonicalRequest) -> ScopeDecision:
        host_decision = self._check_host(req.url)
        if not host_decision.allowed:
            return host_decision

        path_decision = self._check_path(req.url)
        if not path_decision.allowed:
            return path_decision

        return self._check_method(req.method)

    def _check_host(self, url: str) -> ScopeDecision:
        scheme, host, port = _split_host(url)
        if host is None:
            return ScopeDecision(allowed=False, reason=f"URL {url!r} hat keinen gueltigen Host")
        if scheme != self._target_scheme:
            return ScopeDecision(
                allowed=False,
                reason=f"Schema-Mismatch: {scheme!r} != erlaubtes Schema {self._target_scheme!r}",
            )
        if host != self._target_host or port != self._target_port:
            return ScopeDecision(
                allowed=False,
                reason=f"Host out-of-scope: {host}:{port} != erlaubter Host {self._target_host}:{self._target_port}",
            )
        return ScopeDecision(allowed=True, reason="host in scope")

    def _check_path(self, url: str) -> ScopeDecision:
        raw_path = urlsplit(url).path
        # Fail-closed gegen URL-kodierte Traversal (%2e%2e, %2f): sowohl der
        # roh-normalisierte als auch der (einmal) dekodiert-normalisierte
        # Pfad werden gegen deny_paths geprueft - ein Treffer auf irgendeiner
        # der beiden Formen verwirft die Anfrage. Matching/Allow-Entscheidung
        # arbeitet auf dem dekodierten Pfad, da der Zielserver den Pfad
        # ebenfalls dekodiert interpretiert.
        raw_normalized = _normalize_path(raw_path)
        decoded_path = _normalize_path(unquote(raw_path))

        for deny_glob in self._scope.target.deny_paths:
            if fnmatchcase(decoded_path, deny_glob):
                return ScopeDecision(
                    allowed=False,
                    reason=f"Pfad {decoded_path!r} durch deny_paths-Glob {deny_glob!r} gesperrt (raw={raw_path!r})",
                )
            if fnmatchcase(raw_normalized, deny_glob):
                return ScopeDecision(
                    allowed=False,
                    reason=f"Pfad {raw_normalized!r} durch deny_paths-Glob {deny_glob!r} gesperrt (raw={raw_path!r})",
                )

        for allow_glob in self._scope.target.allow_paths:
            if fnmatchcase(decoded_path, allow_glob):
                return ScopeDecision(allowed=True, reason="path in scope")

        return ScopeDecision(allowed=False, reason=f"Pfad {decoded_path!r} matcht keinen allow_paths-Eintrag")

    def _check_method(self, method: str) -> ScopeDecision:
        normalized = method.upper()
        if normalized in _SAFE_METHODS:
            return ScopeDecision(allowed=True, reason="safe method")
        if self._allow_writes:
            return ScopeDecision(allowed=True, reason="write method explicitly allowed")
        return ScopeDecision(
            allowed=False,
            reason=f"schreibende Methode {normalized!r} ohne allow_writes gesperrt",
        )


def _split_host(url: str) -> tuple[str, str | None, int | None]:
    parsed = urlsplit(url)
    scheme = (parsed.scheme or "").lower()
    hostname = parsed.hostname
    host = hostname.lower() if hostname else None
    port = parsed.port if parsed.port is not None else _DEFAULT_PORTS.get(scheme)
    return scheme, host, port


def _normalize_path(path: str) -> str:
    if not path:
        return "/"
    normalized = posixpath.normpath(path)
    if not normalized.startswith("/"):
        normalized = "/" + normalized
    return normalized
