# Releasing unisupply

This document describes the end-to-end procedure for cutting a stable
`vX.Y.Z` release of unisupply. It is aimed at repository maintainers with
write access to `unidoc/unisupply`.

---

## Prerequisites

Before starting a release, confirm you have:

- **Write access** to `unidoc/unisupply` on GitHub.
- **SSH signing key** registered on your GitHub account under
  *Settings → SSH and GPG keys → New SSH key → Key type: Signing Key*,
  with the same email as your `git config user.email`.
- **Entry in `.github/allowed_signers`** for that key. If your key is not
  listed, open a PR to add it before proceeding.
- **`gh` CLI** logged in (`gh auth status`).
- **Go toolchain** matching the version in `go.mod`.

Verify your signing setup end-to-end before the first release:

```bash
git config gpg.format ssh
git config gpg.ssh.allowedSignersFile .github/allowed_signers
git tag -s v0.0.0-smoke -m "smoke test"
git verify-tag v0.0.0-smoke && echo "signing OK"
git tag -d v0.0.0-smoke
```

---

## 1. Cut a release branch

```bash
git fetch origin
git switch -c rc-vX.Y.Z origin/development
```

Branch naming must match `rc-v*` — the `version-check` CI job is gated to
that pattern targeting `master`. The `coverage` floor check runs on any PR
targeting `master`.

---

## 2. Bump version and changelog

**a. Version constant** — edit `internal/version/version.go`:

```go
const Version = "X.Y.Z"   // drop the -dev suffix
```

**b. CHANGELOG** — replace the `[Unreleased]` heading with the release
heading (ISO 8601 date):

```markdown
## [X.Y.Z] - YYYY-MM-DD
```

Commit both changes together:

```bash
git add internal/version/version.go CHANGELOG.md
git commit -m "release: bump version to vX.Y.Z"
```

---

## 3. Open a release PR

```bash
gh pr create \
  --base master \
  --title "release: vX.Y.Z" \
  --body "Release vX.Y.Z. See CHANGELOG.md for details."
```

Wait for all CI checks to go green:

- `ci.yml` — build, vet, lint, tests, race detector
- `version-check` — confirms `internal/version.Version` matches the tag
- `coverage` — enforces minimum test coverage

Obtain at least one approval from a maintainer listed in `CODEOWNERS`.

---

## 4. Merge and tag

Merge the PR (fast-forward or merge commit per repo policy). Then tag the
merged commit on `master`:

```bash
git fetch origin
git switch master
git pull --ff-only origin master

git config gpg.format ssh
git config gpg.ssh.allowedSignersFile .github/allowed_signers
git tag -s vX.Y.Z -m "vX.Y.Z"
```

`-s` creates a signed tag; `gpg.format ssh` directs git to use your SSH
signing key rather than GPG.

Verify the tag before pushing:

```bash
git verify-tag vX.Y.Z && echo "tag OK"
```

---

## 5. Push and publish

```bash
git push origin vX.Y.Z
```

This triggers `release.yml`, which:

1. Builds cross-platform binaries (`linux`, `darwin`, `windows` × `amd64`, `arm64`).
2. Generates a CycloneDX SBOM.
3. Computes `SHA256SUMS`.
4. Creates a **draft** GitHub Release and uploads all assets.

Monitor progress:

```bash
gh run watch
```

When the workflow completes, edit the release notes in the GitHub UI (paste
the relevant `CHANGELOG.md` section), then click **Publish release**.

---

## 6. Verify the release

```bash
# Module proxy picks up the tag within a few minutes
go install github.com/unidoc/unisupply/cmd/unisupply@vX.Y.Z
unisupply --version
```

Check that `pkg.go.dev/github.com/unidoc/unisupply` indexes the new tag
(may take ~10 minutes after the push).

---

## 7. Post-release housekeeping

**a. Sync `development` from `master` via PR** — open a branch from `master`
that bumps the version to the next pre-release and reopens the changelog, then
PR it into `development`:

```bash
git fetch origin
git switch -c chore/open-vX.Y.(Z+1)-dev origin/master
```

Edit `internal/version/version.go`:

```go
const Version = "X.Y.(Z+1)-dev"   // or X.(Y+1).0-dev for a planned minor
```

Add the next `[Unreleased]` heading to `CHANGELOG.md` above the just-released
entry:

```markdown
## [Unreleased]

<!-- Add new entries here as they land on `development`. -->

## [X.Y.Z] - YYYY-MM-DD
```

Commit and open the PR targeting `development`:

```bash
git add internal/version/version.go CHANGELOG.md
git commit -m "chore: open X.Y.(Z+1)-dev development cycle"
git push -u origin chore/open-vX.Y.(Z+1)-dev
gh pr create \
  --base development \
  --title "chore: open vX.Y.(Z+1)-dev development cycle" \
  --body "Post-release: bumps version to X.Y.(Z+1)-dev and reopens CHANGELOG after vX.Y.Z."
```

Merge once CI is green.

---

## Adding or removing a release maintainer

The `.github/allowed_signers` file controls who may sign release tags.
Any change to it is a security-critical event and is gated to individual
maintainer approval via `CODEOWNERS`.

**To add a maintainer:**

1. They generate (or designate) an SSH-Ed25519 key:
   ```bash
   ssh-keygen -t ed25519 -C "their-email@example.com" -f ~/.ssh/unisupply_signing
   ```
2. They register it on GitHub under *Settings → SSH and GPG keys → Signing Key*.
3. Open a PR appending a line to `.github/allowed_signers`:
   ```
   their-email@example.com ssh-ed25519 AAAA...key-body... comment
   ```
4. The existing maintainers approve and merge.

**To remove a maintainer:** delete their line and open a PR.
