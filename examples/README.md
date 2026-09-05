# bolabuster Example Scan

This directory contains a minimal, reproducible example for testing bolabuster in `--dry-run` mode.

## Files

- **`identities.yaml`** — Two example identities (alice, bob) with fake bearer tokens and known object IDs.
- **`scope.yaml`** — Scope configuration targeting a fake `api.example.com` with `authorization.confirmed: true`.
- **`traffic.http`** — Raw HTTP requests for user, post, and comment endpoints.

## Dry-Run Example

A dry-run plans the replay matrix without sending any requests. This is safe to run against any fake/example domain:

```bash
cd bolabuster
python -m bolabuster \
  --config examples/identities.yaml \
  --scope examples/scope.yaml \
  --corpus examples/traffic.http \
  --dry-run \
  -o examples/report_dryrun.txt
```

**Expected output (to `examples/report_dryrun.txt` or stdout):**

```
bolabuster dry-run summary
===========================
geplante Requests: <N>
geskippte Requests: <M>

geplant je Endpoint:
  GET /api/v1/comments/3001: <count>
  GET /api/v1/posts/2001: <count>
  GET /api/v1/posts/2001/comments: <count>
  GET /api/v1/users/1001: <count>
  GET /api/v1/users/1001/profile: <count>
```

- **No network requests are sent** (dry-run = plan only).
- **Exit code is 0** (success).
- The summary shows how many variants (self, swap, enumerate) are planned for each endpoint.

## Real Scan

To run a real scan against an authorized target, replace:
1. **Identities:** Real session credentials (bearer tokens, cookies, headers) from your test environment.
2. **Scope:** Real `base_url` of your API and authorized paths.
3. **Corpus:** Actual API traffic (HAR export from Burp, browser DevTools, Postman export, or raw HTTP).
4. **Remove `--dry-run`** to actually send requests.
5. **Optional:** Add `--allow-writes` if you're testing write operations, `--enumerate` for ID enumeration.

Example:

```bash
python -m bolabuster \
  --config my_identities.yaml \
  --scope my_scope.yaml \
  --corpus traffic.har \
  --allow-writes \
  --format json \
  -o findings.json
```

## Notes

- The `examples/identities.yaml` and `examples/scope.yaml` target `api.example.com`, which is a reserved domain for documentation/examples and won't resolve to a real host.
- The fake bearer tokens (`EXAMPLE-alice-...`) are obviously fake and safe for version control.
- For a real test, use real (but temporary) credentials and real engagement scope.
- Always verify `authorization.confirmed: true` in your scope before running.
- Treat the output report (especially the `repro_curl` field) as sensitive — it contains live attacker credentials.
