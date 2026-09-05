# bolabuster

**Authorized IDOR/BOLA scanner** — finds broken object-level authorization vulnerabilities (OWASP API #1) by replaying API requests across multiple identities.

## What is BOLA/IDOR?

Broken Object-Level Authorization (BOLA, also called IDOR — Insecure Direct Object Reference) occurs when an API endpoint exposes a resource (object) without properly verifying that the requesting user owns or has permission to access it. 

For example:
- `GET /api/users/123/profile` returns full user data when called as any authenticated user, regardless of who user 123 is.
- `DELETE /api/invoices/456` succeeds if the current user is authenticated, even if they don't own invoice 456.

**Why multiple identities matter:** A single identity cannot prove the vulnerability — you need at least two identities with different object ownerships. bolabuster requires exactly this: you provide multiple API credentials, then systematically replays each API request from your corpus under each identity, looking for *owner-specific data* (ownership markers) leaking across identity boundaries.

---

## ⚠️ Authorization & Ethical Use

**This tool tests API authorization controls on systems you have explicit written permission to test.** Unauthorized testing is illegal.

### Requirements

- **Written Authorization:** You must have a signed penetration test agreement, bug-bounty scope document, or equivalent before running bolabuster against any target.
- **`authorization.confirmed: true`:** Every scan requires an explicit `authorization.confirmed: true` field in the scope configuration. This is a hard gate — scans fail immediately (exit code 3) without it.
- **Single Target per Scan:** Each invocation targets exactly one API host (`base_url`). No mass-targeting or horizontal scanning across domains.
- **Safe Defaults:** 
  - Read-only by default (GET, HEAD, OPTIONS only). Mutating methods (POST, PUT, DELETE, PATCH) require `--allow-writes`.
  - Automatic rate limiting (3 req/sec default).
  - No object ID enumeration unless `--enumerate` is passed.
  - `--dry-run` mode sends no requests.

### Reports Contain Live Attacker Credentials

Each Finding includes a `repro_curl` field — a ready-to-run curl command that reproduces the vulnerability using the **attacker identity's live session credentials.** Treat reports like secrets:
- Do not commit to version control.
- Restrict file access to authorized personnel only.
- Ensure secure deletion after remediation.

**Misuse is the user's responsibility.** bolabuster is designed for authorized security testing; the tool enforces the authorization gate but cannot know whether your permission is genuine.

---

## Installation

**Requirements:** Python 3.11 or later.

```bash
# Clone or extract bolabuster
cd bolabuster

# Install for use
pip install -e .

# Install with dev dependencies (for testing)
pip install -e ".[dev]"
```

This installs:
- Dependencies: `httpx`, `PyYAML`
- Console script: `bolabuster` (or `python -m bolabuster`)
- Dev tools: `pytest`, `respx` (if `[dev]` extra included)

---

## Usage

### Basic Command

```bash
bolabuster \
  --config <identities.yaml> \
  --scope <scope.yaml> \
  --corpus <corpus_file> \
  [--corpus-format har|raw_http|openapi|graphql] \
  [--format text|json] \
  [--dry-run] \
  [--allow-writes] \
  [--enumerate] \
  [-o <output_file>]
```

### Flags

| Flag | Required | Type | Description |
|------|----------|------|-------------|
| `--config` | Yes | path | Path to identities YAML. |
| `--scope` | Yes | path | Path to scope YAML (must include `authorization.confirmed: true`). |
| `--corpus` | Yes | path | Path to request corpus (HAR, raw HTTP, OpenAPI, or GraphQL). |
| `--corpus-format` | No | string | Explicit format: `har`, `raw_http`, `openapi`, `graphql`. Auto-detected if omitted. |
| `--format` | No | string | Output format: `text` (default) or `json`. |
| `--dry-run` | No | flag | Plan the replay matrix without sending requests. |
| `--allow-writes` | No | flag | Allow mutating methods (POST, PUT, DELETE, PATCH). Read-only by default. |
| `--enumerate` | No | flag | Enable neighbor-ID enumeration. Disabled by default. |
| `-o`, `--output` | No | path | Write report to file. Omit for stdout. |

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Scan completed successfully (may include findings). |
| 1 | Unexpected error (e.g., bug, unhandled exception). |
| 2 | Configuration, corpus, or report error. |
| 3 | Authorization gate failed (`authorization.confirmed != true`). |

### Example

```bash
bolabuster \
  --config examples/identities.yaml \
  --scope examples/scope.yaml \
  --corpus examples/traffic.http \
  --dry-run \
  -o report.txt
```

---

## Configuration

### Identities YAML

Defines at least 2 authenticated users, each with a name, authentication material, and optional known object IDs.

```yaml
identities:
  - name: alice
    auth:
      type: bearer
      token: alice_session_token_here
    headers:
      X-Custom-Header: alice-value
    known_object_ids:
      - "1001"
      - "2001"

  - name: bob
    auth:
      type: bearer
      token: bob_session_token_here
    known_object_ids:
      - "1002"
```

**Fields:**

- `identities` (list, required): At least 2 identity objects.
  - `name` (string, required): Unique identifier for this identity.
  - `auth` (object, required): Authentication material.
    - `type` (string, required): `bearer`, `header`, or `cookie`.
    - If `bearer`: `token` (string): Bearer token value.
    - If `header`: `headers` (dict): Header names and values (e.g., `X-Api-Key: secret`).
    - If `cookie`: `cookies` (dict): Cookie names and values.
  - `headers` (dict, optional): Additional static headers applied to all requests under this identity.
  - `known_object_ids` (list, optional): Object IDs that belong to this identity. Helps classifier identify ownership markers.

### Scope YAML

Defines authorization, target, limits, and enumeration settings.

```yaml
authorization:
  confirmed: true
  engagement_ref: "pentest-2025-02-acme"

target:
  base_url: https://api.example.com
  allow_paths:
    - "/api/v1/users/*"
    - "/api/v1/posts/*"
  deny_paths:
    - "/api/v1/admin/*"

limits:
  rate_per_sec: 3.0
  max_requests: 5000
  timeout_sec: 15.0

enumeration:
  enabled: false
  neighbor_range: 5
```

**Fields:**

- `authorization` (object, required):
  - `confirmed` (boolean, required): Must be `true`. No exceptions — scanner exits with code 3 otherwise.
  - `engagement_ref` (string, optional): Reference ID for this engagement (e.g., ticket, engagement name).

- `target` (object, required):
  - `base_url` (string, required): Absolute URL of the API (scheme + host, e.g., `https://api.example.com`). Exactly one host per run; all requests must match this host.
  - `allow_paths` (list, required): Glob patterns for paths to include (e.g., `/api/v1/users/*`, `/api/v1/posts/{id}`). At least 1 entry.
  - `deny_paths` (list, optional): Glob patterns for paths to exclude (e.g., `/api/v1/admin/*`). Deny takes precedence.

- `limits` (object, optional):
  - `rate_per_sec` (float, default 3.0): Requests per second rate limit.
  - `max_requests` (int, default 5000): Maximum requests to send in one scan.
  - `timeout_sec` (float, default 15.0): HTTP request timeout in seconds.

- `enumeration` (object, optional):
  - `enabled` (boolean, default false): Enable ID enumeration strategy (requires `--enumerate` flag).
  - `neighbor_range` (int, default 5): How many IDs to test around discovered IDs (e.g., if ID 1001 found, test 996–1006).

---

## Corpus Formats

bolabuster ingests API traffic from standard formats and auto-detects the format if `--corpus-format` is omitted.

### HAR (HTTP Archive)

Format: `.har` (JSON with extension `.har` or `.json`).

Exported from browser DevTools, Burp Suite, or Postman. bolabuster extracts requests and bodies.

**Auto-detect:** Checks for top-level `log.entries` array.

### Raw HTTP

Format: `.http` or `.txt` with HTTP/1.1-style requests (Burp-exported format).

```
GET /api/v1/users/123 HTTP/1.1
Host: api.example.com
Authorization: Bearer dummy
Content-Type: application/json

```

Requests are separated by blank lines or a dashed separator.

**Auto-detect:** Looks for `GET`, `POST`, etc. at line start followed by a path.

### OpenAPI / Swagger

Format: `.json` or `.yaml` (OpenAPI 3.0 or Swagger 2.0).

bolabuster extracts request paths, methods, and example bodies. **Note:** Swagger examples may not match real object IDs; prefer explicit object IDs in `known_object_ids`.

**Auto-detect:** Checks for `openapi`, `swagger`, `paths`, or `components` keywords.

### GraphQL

Format: `.json` (GraphQL introspection result or query collection).

Introspection JSON: standard GraphQL introspection response.
Query collection: `{"queries": [{"query": "...", "variables": {...}}, ...]}`.

**Auto-detect:** Looks for GraphQL schema keywords or `queries` array.

---

## Classification & Findings

bolabuster compares API responses across identities to detect authorization violations. A **Finding** is generated only if both conditions hold:

1. **Verdict:** One of `confirmed` or `empty_200`.
2. **Ownership Marker:** The attacker's response contains identity-specific data from the owner's baseline (e.g., owner's email, phone, or other user-generated fields).

### Verdict Types

| Verdict | Meaning | Finding? |
|---------|---------|----------|
| `confirmed` | Attacker accessed owner's data; ownership marker detected. | Yes |
| `empty_200` | HTTP 200, but response is empty or object-less. | Yes (low severity) |
| `denied` | HTTP 401/403 or login redirect. | No |
| `error` | Transport error or HTTP 5xx. | No |
| `irrelevant` | HTTP 2xx but no conclusive signal. | No |

### Severity Levels

| Severity | Conditions |
|----------|-----------|
| **critical** | `confirmed` verdict + write operation (POST, PUT, DELETE, PATCH). |
| **high** | `confirmed` verdict + read operation (GET, HEAD, OPTIONS). |
| **medium** | `confirmed` verdict + `structural_only=true`. Identical baselines; ownership unproven but structure matches owner baseline. **Manual verification recommended.** |
| **low** | `empty_200` verdict. |

### Ownership Markers

Markers are owner-specific values extracted by comparing:
- Owner's baseline response (how the owner sees their own object).
- Attacker's own baseline (how the attacker sees their own object).

Differences are candidate markers (e.g., owner's email, owner's ID). If the attacker's response to the owner's object contains any marker, the verdict is `confirmed`.

### Structural Similarity

If two responses have identical structure (JSON keys or text shape) but no markers detected, they're flagged as `structural_only=true` (medium severity, requires manual verification).

---

## Known Limitations

### CSRF & State-Token Binding

If the API requires CSRF tokens or state parameters that are bound per session/request:
- Token swaps across identities may fail (HTTP 403/401).
- Result: false negatives (authorization check passes when it shouldn't be tested).
- **Workaround:** Use `known_object_ids` to focus on endpoints that don't require state tokens.

### OpenAPI Example Values

OpenAPI specs often include placeholder example values (e.g., `123` for ID). These may not correspond to real objects in your test environment.
- Result: false negatives if no real object IDs match.
- **Workaround:** Provide explicit `known_object_ids` in identities config.

### GraphQL Global ID Decoding

GraphQL Relay global IDs are base64-encoded (`Type:id`). Decoding is best-effort:
- Non-standard encodings or type formats may not decode correctly.
- **Confidence:** 0.6 (not 1.0), used only if no higher-confidence ID type matches.

### Structural Heuristics

The structural similarity check (Jaccard index on JSON keys, size delta tolerance) is heuristic-based and may produce:
- False positives: structurally different but both sparse responses flagged as similar.
- False negatives: responses with minor formatting differences may not match.
- **Mitigation:** Review medium-severity findings manually.

### Identical Baselines (Structural-Only)

If the owner's baseline and attacker's own baseline are identical (after secret masking):
- No ownership markers can be derived.
- If attacker's response to owner's object matches the baseline structure, verdict = `confirmed`, severity = `medium`.
- **This requires manual verification** — the tool cannot prove ownership without distinct markers.

---

## Development & Testing

### Running Tests

```bash
pip install -e ".[dev]"
python -m pytest -q
```

**Test coverage:** 121 tests (network-isolated, deterministic).

### Project Layout

```
bolabuster/
├── __init__.py              # Package metadata
├── cli.py                   # CLI entry point, orchestration
├── models.py                # Core dataclasses
├── errors.py                # Custom exceptions
│
├── config/
│   ├── auth.py              # Auth material handlers (bearer, header, cookie)
│   ├── scope.py             # Scope validation
│   └── loader.py            # YAML loading
│
├── corpus/
│   ├── base.py              # CorpusParser protocol
│   ├── registry.py          # Parser registry (auto-detect, lookup)
│   ├── har.py               # HAR parser
│   ├── raw_http.py          # Raw HTTP parser
│   ├── openapi.py           # OpenAPI/Swagger parser
│   └── graphql.py           # GraphQL parser
│
├── detect/
│   ├── detectors.py         # ID detectors (numeric, uuid, graphql_global)
│   └── extract.py           # ObjectRef extraction from requests
│
├── engine/
│   ├── scope.py             # Scope enforcement
│   ├── prepare.py           # Request preparation
│   ├── replay.py            # Replay matrix execution
│   ├── ratelimit.py         # Rate limiting
│   └── __init__.py          # Engine exports
│
├── classify/
│   ├── classify.py          # Verdict logic (confirmed, denied, etc.)
│   ├── findings.py          # Finding generation
│   └── diff.py              # Response diffing, ownership markers
│
└── report/
    ├── curl.py              # repro_curl generation
    ├── json_out.py          # JSON report schema
    └── text_out.py          # Human-readable report
```

### Adding a Custom Corpus Parser

1. **Implement the `CorpusParser` protocol** in a new file (e.g., `corpus/custom.py`):

```python
from bolabuster.corpus.base import CorpusParser, ParserOptions
from bolabuster.models import CanonicalRequest

class CustomParser:
    name = "custom"
    
    def can_parse(self, source):
        # Return True if source looks like your format
        return source.suffix == ".custom"
    
    def parse(self, source, opts):
        # Parse and return list[CanonicalRequest]
        # Append warnings to opts.warnings
        return [...]
```

2. **Register in `corpus/registry.py`**:

```python
from bolabuster.corpus.custom import CustomParser

BUILTIN_PARSERS.append(CustomParser())
# or call register() at import time:
# register(CustomParser())
```

3. **Write tests** (network-isolated):

```python
def test_custom_parser_happy_path():
    parser = CustomParser()
    assert parser.name == "custom"
    requests = parser.parse(Path("test_data/sample.custom"), ParserOptions())
    assert len(requests) == 1
    assert requests[0].method == "GET"

def test_custom_parser_error_case():
    parser = CustomParser()
    with pytest.raises(CorpusParseError):
        parser.parse(Path("nonexistent.custom"), ParserOptions())
```

### Adding a Custom ID Detector

1. **Implement `IdDetector` protocol** in `detect/detectors.py`:

```python
class CustomIdDetector:
    id_type = "custom_format"
    
    def detect(self, value, ctx):
        if value.startswith("custom-"):
            return IdMatch(id_type=self.id_type, confidence=0.95)
        return None
```

2. **Add to `DEFAULT_DETECTORS`** in `detect/detectors.py`:

```python
DEFAULT_DETECTORS.append(CustomIdDetector())
```

3. **Write tests**:

```python
def test_custom_detector_match():
    detector = CustomIdDetector()
    ctx = LocationContext(location="path", selector="id")
    match = detector.detect("custom-12345", ctx)
    assert match is not None
    assert match.id_type == "custom_format"
    assert match.confidence == 0.95
```

---

## License

MIT License. See `LICENSE` for details.

---

## Contributing

We welcome contributions: bug reports, feature suggestions, new parsers, detectors, and improvements to classification logic.

See `CONTRIBUTING.md` for guidelines on testing, project layout, and contribution workflow.
