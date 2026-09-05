"""HTTP-Wrapper fuer bolabuster.

Kapselt den tatsaechlichen Netzwerktransport hinter dem `HttpClient`-Protocol,
damit die spaetere Replay-Matrix Requests versenden kann, ohne bei
Transport-/Timeout-Fehlern abzubrechen. Solche Fehler werden in ein
`RawResponse(status=-1, error=...)` uebersetzt statt geworfen zu werden.
"""

from __future__ import annotations

import time
from typing import Protocol

import httpx

from bolabuster.models import PreparedRequest, RawResponse


class HttpClient(Protocol):
    def send(self, req: PreparedRequest, timeout: float) -> RawResponse: ...


class HttpxClient:
    """Real-Implementierung von `HttpClient`, basierend auf `httpx`.

    HTTP/2 wird nur aktiviert, wenn das optionale Paket `h2` installiert ist.
    Ohne `h2` faellt httpx sonst mit einem ImportError zur Laufzeit auf den
    ersten Request. `h2` ist bewusst keine zusaetzliche Dependency (siehe
    Vorgabe Schritt 3) -- HTTP/2 bleibt dadurch ggf. deaktiviert.
    """

    def __init__(self, http2: bool = True) -> None:
        try:
            self._client = httpx.Client(http2=http2)
        except ImportError:
            # h2 fehlt -> ohne HTTP/2 initialisieren.
            self._client = httpx.Client(http2=False)

    def send(self, req: PreparedRequest, timeout: float) -> RawResponse:
        start = time.perf_counter()
        try:
            response = self._client.request(
                req.method,
                req.url,
                headers=req.headers,
                content=req.body,
                timeout=timeout,
            )
        except httpx.HTTPError as exc:
            elapsed_ms = (time.perf_counter() - start) * 1000
            return RawResponse(
                status=-1,
                headers={},
                body=b"",
                elapsed_ms=elapsed_ms,
                error=f"{type(exc).__name__}: {exc}",
            )

        elapsed_ms = (time.perf_counter() - start) * 1000
        # httpx-Header sind case-insensitive; wir normalisieren auf lower-case
        # Keys, damit nachgelagerter Code sich nicht auf Original-Case
        # verlassen muss (und respektiert damit mehrfach vorkommende Header
        # nicht separat -- letzter Wert gewinnt, wie bei dict-Konstruktion
        # ueblich).
        headers = {k.lower(): v for k, v in response.headers.items()}
        return RawResponse(
            status=response.status_code,
            headers=headers,
            body=response.content,
            elapsed_ms=elapsed_ms,
            error=None,
        )

    def close(self) -> None:
        self._client.close()


class MockHttpClient:
    """Test-Implementierung von `HttpClient` mit vorkonfigurierten Antworten.

    Key-Schema: `f"{req.method} {req.url}"` (Methode in Original-Case wie im
    `PreparedRequest`, gefolgt von einem Leerzeichen und der vollen URL).

    Verhalten bei unbekanntem Key: es wird KEIN `KeyError` geworfen, sondern
    eine `RawResponse(status=-1, error="no mock for key <key>")` geliefert.
    Grund: konsistent mit der Vorgabe, dass ein Fehl-Request die Matrix nicht
    abbrechen darf -- ein fehlender Mock verhaelt sich wie ein Transportfehler.
    """

    def __init__(self, responses_by_key: dict[str, RawResponse]) -> None:
        self._responses_by_key = responses_by_key

    @staticmethod
    def key_for(req: PreparedRequest) -> str:
        return f"{req.method} {req.url}"

    def send(self, req: PreparedRequest, timeout: float) -> RawResponse:
        key = self.key_for(req)
        if key not in self._responses_by_key:
            return RawResponse(
                status=-1,
                headers={},
                body=b"",
                elapsed_ms=0.0,
                error=f"no mock for key {key!r}",
            )
        return self._responses_by_key[key]
