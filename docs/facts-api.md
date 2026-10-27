# Shared-facts API

`facts.HTTPStore` (`--facts-url`) reads what a service already knows about modules and advisories, instead of looking it up in
every scan. unisupply only reads. The service is gorisk's; this page is the contract both sides build to, so the client
(`pkg/facts/http.go`) and a server cannot drift apart.

## Requests

All requests are `GET`, with `Authorization: Bearer <key>` (the key is never in a URL), `Accept: application/json` and
`User-Agent: unisupply/<version>`. HTTPS is required unless the host is loopback. Redirects are not followed.

| Request | Answers with |
|---|---|
| `GET /api/v1/facts/modules?path=<module>&version=<version>` | a [Module](#module) |
| `GET /api/v1/facts/advisories/<id>` (a Go advisory ID, `GO-2026-0001`) | an [Advisory](#advisory) |
| `GET /api/v1/facts/fixes?module=<module>&version=<version>` | a [Fix](#fix) |

`version` is the version of the module in the scan's build list; for a fix it is the first fixed version of the advisory.

## Status codes

| Status | Meaning for unisupply |
|---|---|
| `200` | the fact, as JSON, at most 1 MiB |
| `404` | the service does not have it: a miss, and not an error |
| `401`, `403` | the key is refused or lacks the scope: a miss with an error, and **no further request is made** in this run |
| `429` | rate limited: `Retry-After` in seconds is honoured once, up to 5 s; otherwise a miss with an error |
| `5xx`, a network error, a timeout (10 s) | a miss with an error; after **two in a row** with no answer between them, no further request is made in this run |
| anything else, or a body that is not the JSON of the fact | a miss with an error |

A miss with an error is not a failure of the scan: unisupply looks the fact up itself, as it does without a store. A fact is
asked for once per run (the answer, a miss included, is kept in memory).

## Freshness

The service sends what it has; the reader decides whether it is fresh enough, by `fetched_at` and by the date of the grade
(`facts.DefaultPolicy`: modules and advisories one day, fixes thirty). A fact from after the date of the grade counts as fresh.

## Shapes

Times are RFC 3339. A field marked optional is left out when empty.

### Module

```json
{
  "path": "golang.org/x/text",
  "version": "v0.3.5",
  "info": { "...": "scanner.MaintenanceInfo: archived, deprecated, retracted, last release, last activity, and the flags that say what could not be read" },
  "fetched_at": "2026-10-27T06:00:00Z",
  "source": "module_proxy+github"
}
```

`info` is the maintenance scanner's own record (`pkg/scanner/maintenance.go`). Its month counts are those of the day it was read;
the reader recomputes them for its own date. A server stores only a whole answer: not one that could not read the archived flag
because of a rate limit.

### Advisory

```json
{
  "id": "GO-2026-0001",
  "aliases": ["CVE-2026-0001", "GHSA-xxxx-xxxx-xxxx"],
  "severity": "HIGH",
  "severity_source": "osv",
  "published_at": "2026-01-02T00:00:00Z",
  "kev_checked": true,
  "in_kev": false,
  "kev_date_added": "",
  "fetched_at": "2026-10-27T06:00:00Z"
}
```

`severity` is `CRITICAL`, `HIGH`, `MEDIUM` or `LOW`, and empty when nobody has published one: that is an unknown severity, not a low
one. `severity_source` is `osv`, `nvd`, `ghsa`, or `unscored` when every source answered and none had one. `in_kev` means nothing
unless `kev_checked` is true.

Severity and known-exploited status change without the vulnerability database changing, so an advisory is re-read daily. See
"A later grade" in `docs/grading.md`: unisupply grades a stored analysis again with these facts, and asks for a new analysis when a
newer fact means the called pass could change the letter.

### Fix

```json
{
  "module": "golang.org/x/text",
  "version": "v0.3.8",
  "released_at": "2022-09-28T00:00:00Z",
  "source": "module_proxy",
  "requires_go": "1.17",
  "fetched_at": "2026-10-27T06:00:00Z"
}
```

`released_at` is the later of the advisory's publication and the time the module proxy gives the version; `source` is
`module_proxy` or `advisory`. A released version never changes, so a known fix is kept for a long time; an unknown one is not stored.

## Private modules

A module that matches the scan's private patterns is in no request: not by path and not by version.
