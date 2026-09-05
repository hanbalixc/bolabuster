"""Argparse-Einstieg, Orchestrierung der gesamten Pipeline (Schritt 11).

`run_scan` ist der testbare Kern (nimmt ein bereits geparstes `argparse.Namespace`
und einen optional injizierbaren `HttpClient` entgegen, liefert einen Exit-Code
zurueck) - `main` ist der duenne argv-Wrapper, der `SystemExit` wirft.

Exit-Code-Schema:
    0  Erfolgreicher Lauf (auch mit Findings - Findings sind kein Prozessfehler,
       sondern das erwartete Ergebnis eines Scans).
    1  Unerwarteter Fehler (Bug, unbehandelte Exception).
    2  Config-/Corpus-/Report-Fehler (ConfigError, CorpusParseError,
       UnsupportedCorpusError, AmbiguousCorpusError, ReportWriteError).
    3  Autorisierungs-Gate nicht bestanden (authorization.confirmed != true).
       Nicht umgehbar - wird VOR jedem sonstigen Laden/Senden geprueft.
"""

from __future__ import annotations

import argparse
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import yaml

from bolabuster.classify import CellContext, ClassifyConfig, build_finding, classify_cell
from bolabuster.config import RunConfig, load_identities, load_scope
from bolabuster.corpus import ParserOptions, get_parser
from bolabuster.detect import DEFAULT_DETECTORS, DetectionHints, extract_object_refs
from bolabuster.engine import NullLimiter, ReplayEngine, ScopeEnforcer, TokenBucketLimiter, assemble_triads
from bolabuster.engine.replay import ReplayResult
from bolabuster.errors import (
    AmbiguousCorpusError,
    ConfigError,
    CorpusParseError,
    ReportWriteError,
    UnsupportedCorpusError,
)
from bolabuster.http import HttpClient, HttpxClient
from bolabuster.models import Finding
from bolabuster.report import RunMeta, render_text, to_curl, write_json

EXIT_OK = 0
EXIT_UNEXPECTED_ERROR = 1
EXIT_CONFIG_ERROR = 2
EXIT_NOT_AUTHORIZED = 3

_DEFAULT_VERSION = "0.1.0"


def build_arg_parser() -> argparse.ArgumentParser:
    """Baut den `argparse`-Parser fuer die bolabuster-CLI."""
    parser = argparse.ArgumentParser(
        prog="bolabuster",
        description="Autorisierter IDOR/BOLA-Scanner: Scope+Identitaeten+Korpus -> Replay-Matrix -> Findings.",
    )
    parser.add_argument("--config", required=True, help="Pfad zur Identitaeten-YAML")
    parser.add_argument("--scope", required=True, help="Pfad zur Scope-YAML (inkl. Autorisierungs-Gate)")
    parser.add_argument("--corpus", required=True, help="Pfad zur Korpus-Datei (HAR, Raw-HTTP, OpenAPI, GraphQL)")
    parser.add_argument(
        "--corpus-format",
        default=None,
        help="explizites Corpus-Format (har|raw_http|openapi|graphql); ohne Angabe Auto-Detect",
    )
    parser.add_argument("--format", choices=["text", "json"], default="text", help="Ausgabeformat (Default: text)")
    parser.add_argument("--dry-run", action="store_true", help="nur die Replay-Matrix planen, nichts senden")
    parser.add_argument("--allow-writes", action="store_true", help="schreibende Methoden (nicht GET/HEAD/OPTIONS) zulassen")
    parser.add_argument("--enumerate", action="store_true", help="Nachbar-ID-Enumeration aktivieren")
    parser.add_argument("-o", "--output", default=None, help="Pfad fuer den Report (ohne -> stdout)")
    return parser


def _is_authorized(scope_source: str) -> bool:
    """Robuste Vorab-Pruefung von `authorization.confirmed`, unabhaengig von
    `load_scope`-Fehlertexten. Jede Unsicherheit (Datei fehlt/kein YAML-Mapping/
    Feld fehlt) gilt fail-closed als nicht autorisiert."""
    try:
        with open(scope_source, encoding="utf-8") as fh:
            raw = yaml.safe_load(fh)
    except OSError:
        return False
    if not isinstance(raw, dict):
        return False
    authorization = raw.get("authorization")
    if not isinstance(authorization, dict):
        return False
    return authorization.get("confirmed") is True


def _emit_dry_run_summary(results: list[ReplayResult], args: argparse.Namespace) -> int:
    """Fasst die geplante Matrix zusammen (Anzahl geplant/geskippt, je Endpoint).

    Bewusst KEINE Klassifikation/Findings im Dry-Run - es wurde nichts gesendet,
    also gibt es keine Antworten zu vergleichen.
    """
    planned = [r for r in results if r.planned_only]
    skipped = [r for r in results if r.skipped]

    by_endpoint: dict[str, int] = {}
    for r in planned:
        by_endpoint[r.endpoint] = by_endpoint.get(r.endpoint, 0) + 1

    lines = [
        "bolabuster dry-run summary",
        "===========================",
        f"geplante Requests: {len(planned)}",
        f"geskippte Requests: {len(skipped)}",
        "",
        "geplant je Endpoint:",
    ]
    for endpoint, count in sorted(by_endpoint.items()):
        lines.append(f"  {endpoint}: {count}")
    text = "\n".join(lines) + "\n"

    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)
    return EXIT_OK


def _write_output(findings: list[Finding], meta: RunMeta, args: argparse.Namespace) -> None:
    """Schreibt den Report je `--format` nach `args.output` bzw. stdout.

    `write_json` schreibt nur nach einem `Path`; fuer stdout-JSON wird ueber
    eine temporaere Datei umgeleitet, statt die Report-Schicht (out of scope
    dieses Schritts) um einen Streaming-Pfad zu erweitern.
    """
    if args.format == "json":
        if args.output:
            write_json(findings, meta, Path(args.output))
        else:
            with tempfile.TemporaryDirectory() as tmpdir:
                tmp_path = Path(tmpdir) / "report.json"
                write_json(findings, meta, tmp_path)
                sys.stdout.write(tmp_path.read_text(encoding="utf-8"))
    else:
        text = render_text(findings, meta)
        if args.output:
            Path(args.output).write_text(text, encoding="utf-8")
        else:
            sys.stdout.write(text)


def run_scan(args: argparse.Namespace, client: HttpClient | None = None) -> int:
    """Fuehrt den kompletten Scan-Lauf aus und liefert den Exit-Code.

    `client` ist injizierbar (Tests spritzen `MockHttpClient`); ohne Angabe
    wird `HttpxClient` mit dem Timeout aus den Scope-Limits verwendet.
    """
    # 1. Autorisierungs-Gate ZUERST, deterministisch, unabhaengig von
    # load_scope-Validierungsdetails - nicht umgehbar.
    if not _is_authorized(args.scope):
        print(
            f"bolabuster: authorization.confirmed ist nicht 'true' in {args.scope!r} - "
            "Scan abgebrochen (kein autorisierter Scope)",
            file=sys.stderr,
        )
        return EXIT_NOT_AUTHORIZED

    try:
        # 2. Config laden.
        identities = load_identities(args.config)
        scope = load_scope(args.scope)

        # 3. Korpus laden.
        corpus_path = Path(args.corpus)
        try:
            parser = get_parser(args.corpus_format, corpus_path)
        except (UnsupportedCorpusError, AmbiguousCorpusError) as exc:
            print(f"bolabuster: Corpus-Fehler: {exc}", file=sys.stderr)
            return EXIT_CONFIG_ERROR

        opts = ParserOptions()
        try:
            requests = parser.parse(corpus_path, opts)
        except CorpusParseError as exc:
            print(f"bolabuster: Corpus-Fehler: {exc}", file=sys.stderr)
            return EXIT_CONFIG_ERROR
        for warning in opts.warnings:
            print(f"bolabuster: warning: {warning}", file=sys.stderr)

        # 4. Detection.
        detection_hints = DetectionHints()
        for req in requests:
            req.object_refs = extract_object_refs(req, DEFAULT_DETECTORS, detection_hints)
        for warning in detection_hints.warnings:
            print(f"bolabuster: warning: {warning}", file=sys.stderr)

        # 5. RunConfig aus Scope-Limits + Flags.
        run_cfg = RunConfig(
            dry_run=args.dry_run,
            allow_writes=args.allow_writes,
            enumerate=args.enumerate,
            limits=scope.limits,
            neighbor_range=scope.enumeration.neighbor_range,
        )

        # 6. Enforcer/Limiter/Client.
        enforcer = ScopeEnforcer(scope, allow_writes=args.allow_writes)
        limiter = NullLimiter() if args.dry_run else TokenBucketLimiter(scope.limits.rate_per_sec)
        http_client = client if client is not None else HttpxClient()

        started_at = datetime.now(timezone.utc).isoformat()

        # 7. Replay.
        engine = ReplayEngine(http_client, enforcer, limiter, run_cfg)
        results = engine.run(requests, identities)

        finished_at = datetime.now(timezone.utc).isoformat()

        # 8. Dry-Run-Sonderfall: nur Planungs-Summary, keine Klassifikation.
        if args.dry_run:
            return _emit_dry_run_summary(results, args)

        # 9. Triaden -> Klassifikation -> Findings.
        triads = assemble_triads(results)
        classify_cfg = ClassifyConfig()
        findings: list[Finding] = []
        for triad in triads:
            cls = classify_cell(
                triad.owner_baseline,
                triad.attacker_resp,
                triad.attacker_own_baseline,
                triad.object_ref,
                classify_cfg,
            )
            repro_curl = to_curl(triad.attacker_prepared)
            ctx = CellContext(
                endpoint=triad.endpoint,
                parameter=triad.object_ref.selector,
                id_type=triad.object_ref.id_type,
                attacker_identity=triad.attacker_identity,
                owner_identity=triad.owner_identity,
                write_operation=triad.write_operation,
                source_ref=triad.source_ref,
                strategy=triad.strategy,
                repro_curl=repro_curl,
            )
            finding = build_finding(ctx, cls)
            if finding is not None:
                findings.append(finding)

        # 10. RunMeta + Ausgabe.
        counts: dict[str, int] = {}
        for finding in findings:
            counts[finding.severity] = counts.get(finding.severity, 0) + 1

        import bolabuster

        version = getattr(bolabuster, "__version__", _DEFAULT_VERSION)
        meta = RunMeta(
            version=version,
            target=scope.target.base_url,
            started_at=started_at,
            engagement_ref=scope.engagement_ref or None,
            finished_at=finished_at,
            counts=counts,
        )

        try:
            _write_output(findings, meta, args)
        except ReportWriteError as exc:
            print(f"bolabuster: Fehler beim Schreiben des Reports: {exc}", file=sys.stderr)
            return EXIT_CONFIG_ERROR

        # 11. Erfolgreicher Lauf, unabhaengig von der Anzahl der Findings.
        return EXIT_OK

    except ConfigError as exc:
        print(f"bolabuster: Konfigurationsfehler: {exc}", file=sys.stderr)
        return EXIT_CONFIG_ERROR
    except Exception as exc:  # noqa: BLE001 - letztes Sicherheitsnetz, siehe Vorgabe Abschnitt 3.11
        print(f"bolabuster: unerwarteter Fehler: {type(exc).__name__}: {exc}", file=sys.stderr)
        return EXIT_UNEXPECTED_ERROR


def main(argv: list[str] | None = None) -> None:
    """Duenner argv-Wrapper: parst Flags, ruft `run_scan`, wirft `SystemExit`."""
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    code = run_scan(args)
    raise SystemExit(code)
