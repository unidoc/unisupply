# Contributing to unisupply

By participating in this project, you agree to abide by our
[Code of Conduct](CODE_OF_CONDUCT.md).

Thanks for your interest in `unisupply`. This document covers everything you
need to land a change — local setup, day-to-day workflow, code style, and the
PR process.

For security issues, **do not** open a public issue or PR — see
[SECURITY.md](SECURITY.md) for the private reporting channels.

## Development setup

You need:

- **Go 1.25** or newer (the toolchain is pinned in `go.mod`).
- **`just`** — the task runner used by every recipe in the [Justfile](Justfile).
  If you don't want to install it, run the underlying `go` commands directly;
  `just <recipe> --explain` (or just reading the Justfile) shows what they
  expand to.
- **`golangci-lint v1.64.8`** — the exact version CI runs. Match it locally to
  avoid surprises:

  ```bash
  go install github.com/golangci/golangci-lint/cmd/golangci-lint@v1.64.8
  ```

Optional but useful:

- `goimports` (`go install golang.org/x/tools/cmd/goimports@latest`) — used
  by `just fmt` to enforce import grouping with the local prefix
  `github.com/unidoc/unisupply`.
- `GITHUB_TOKEN` exported in your shell — required for the maintainer scanner
  to hit the GitHub API at useful rate limits.

Build and verify the binary works:

```bash
just build
./bin/unisupply --version
```

## Local workflow

The recipes in the Justfile are the canonical way to run the project locally.
The ones you will use day to day:

```bash
just check          # fmt + vet + test  — run before every commit
just test           # go test ./...
just test-race      # go test -race ./...
just test-cover     # with coverage report
just lint           # golangci-lint run ./...
just fmt            # gofmt + goimports
just self-scan      # run unisupply against unisupply (dogfooding)
just self-scan-full # self-scan with --scan-ci enabled
```

`just check` is the minimum bar: a PR that fails `just check` will fail CI.

## PR process

### Branch model

- **`master`** is the release branch. Direct merges to `master` are not
  accepted from contributors — releases land via release-candidate branches
  (`rc-vX.Y.Z`) cut by maintainers.
- **`development`** is the integration branch. **All** changes target
  `development`, including documentation-only changes. There is no
  fast-path for docs.
- Feature branches should be cut from `development` and named descriptively
  (e.g. `feat/scanner-foo`, `fix/policy-edge-case`, `docs/readme-tweaks`).

### Opening a PR

1. Run `just check` and `just self-scan` locally — both should be clean.
2. Push your branch and open a PR against `development`.
3. Fill in the PR description: what changed, why, and how to verify. Link the
   issue if there is one.
4. CI must be green before review. If a check is flaking and not related to
   your change, say so in the PR thread rather than re-running silently.
5. At least one maintainer review is required before merge.

### Commit messages

Use imperative-mood subject lines, optionally with a Conventional-Commits
prefix (`feat:`, `fix:`, `docs:`, `chore:`, `refactor:`, `test:`). Keep the
subject under 70 characters; put the *why* in the body.

## Code style

- **Formatting** — `gofmt` is mandatory. `goimports` groups imports as:
  stdlib, third-party, then `github.com/unidoc/unisupply/...`. `just fmt`
  applies both.
- **Linting** — `golangci-lint` config is in [`.golangci.yml`](.golangci.yml).
  Do not disable lints inline without a comment justifying it.
- **No naked `interface{}`** — use `any`. Reach for a typed interface or a
  concrete type before reaching for either.
- **Errors** — wrap with `fmt.Errorf("context: %w", err)`. Do not log and
  return; pick one. Sentinel errors live next to the package they belong to.
- **Tests** — prefer table-driven tests with named cases. Use
  `t.Run(tc.name, ...)` so failures point at the offending case. Avoid
  network or filesystem dependencies in unit tests; if a scanner needs them,
  put it in an integration test gated by a build tag.
- **Concurrency** — keep goroutine ownership obvious. Bound parallelism with
  a semaphore or `errgroup` rather than spawning unbounded workers.
- **Logging** — `unisupply` writes user-facing output via `pkg/report`; do
  not log to stdout/stderr from library code unless `--verbose` is set.

## Adding a new scanner

The cleanest reference is
[`pkg/scanner/typosquat.go`](pkg/scanner/typosquat.go) — small, deterministic,
no external dependencies, table-driven tests. Use it as a template.

A scanner typically:

1. Lives in its own file under `pkg/scanner/<name>.go`.
2. Exposes a single entry point that takes the resolved dependency graph (or
   the relevant subset) and returns a typed result struct.
3. Records its findings on the per-dependency result so `pkg/scorer` can
   incorporate them into the composite risk score.
4. Has a sibling `<name>_test.go` with table-driven coverage of the
   detection rules — including negative cases.
5. Gets wired into the orchestration in `cmd/unisupply/main.go` and
   surfaced in every output format (`pkg/report/{text,json,pdf,sbom}.go`).

If your scanner needs a network call, add a `--<name>-timeout` flag and
respect the existing global `--timeout`. If it needs a token or API key,
follow the `GITHUB_TOKEN` pattern: env var first, flag second.

## Apache NOTICE compliance

Some dependencies ship their own `NOTICE` file (required by Apache 2.0 §4(d)).
When they do, their attribution must appear in the repo-root `NOTICE` file with
both the module path **and** the resolved version string (e.g.
`gopkg.in/yaml.v3 v3.0.1`). CI enforces this automatically via the
`license-check` job.

**If CI fails with `UNCOVERED NOTICE`:** open the `NOTICE` file of the flagged
module in your module cache (`$(go env GOMODCACHE)`), copy its contents into the
repo-root `NOTICE` under a `---` separator, and add a header line with the
module path and version. Re-check locally with:

```bash
bash .github/scripts/check-licenses.sh
```

> **Note:** the script requires bash 4+ (`mapfile`). macOS ships bash 3.2 — install a newer version via Homebrew (`brew install bash`) or run the check in CI.

**If you upgrade a dep** that already appears in the repo-root `NOTICE`, update
the version string there too — the check matches path *and* version, so a stale
version fails the same way as a missing entry.

## Questions

Open a GitHub Discussion for design questions or "is this a good idea"
threads. Open an issue for concrete bugs or feature requests. For anything
security-sensitive, see [SECURITY.md](SECURITY.md).
