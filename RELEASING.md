# Releasing `@nemoir/web-runtime`

The canonical release version is `package.json`'s `version` field. A release is
an explicit, reviewed version bump merged to `main`; tags and GitHub Releases
are outputs of the release workflow, not manual triggers.

## One-time setup

1. In GitHub, create an environment named **`npm`** for this repository. It can
   require an approver if you want a final human gate; no secrets are needed.
2. In npm package settings, configure a GitHub Actions **Trusted Publisher**:
   - owner: `hkalexling`
   - repository: `nemoir-web-runtime`
   - workflow filename: `release.yml`
   - environment: `npm`
   - allowed action: `npm publish`

The repository URL in `package.json` is intentionally part of this trust
relationship and must remain exact.

## Automatic release flow

A push to `main` that changes `package.json` runs `Release`.

- The workflow compares the version at `github.event.before` with the exact
  pushed commit. Only an increasing canonical SemVer version (`X.Y.Z`) is
  eligible; normal metadata changes do not publish.
- An unprivileged job runs `npm ci`, type checks, tests, builds, runs the
  runtime release-gate test, packs the final `.tgz`, and saves it with
  `SHA256SUMS`.
- The only privileged job downloads and verifies that artifact, creates a
  draft `vX.Y.Z` GitHub Release at the exact commit, publishes the prebuilt
  tarball through npm OIDC, attaches a GitHub provenance attestation when the
  repository is public, then finalizes the release.

The privileged job never checks out or executes source code. It uses no
`NPM_TOKEN` and never reads local npm configuration.

## Dry runs and recovery

Use **Actions → Release → Run workflow** for a dry run; `dry_run` defaults to
`true`. Supply `ref` with an exact commit SHA when validating or recovering an
older candidate.

Registry versions are immutable. A retry is accepted only when an existing npm
version, tag, and **draft** GitHub Release all refer to the same commit. A final
release or a tag at another commit is refused rather than overwritten.

## Visibility and provenance

npm Trusted Publishing works from a private source repository. npm provenance
is generated automatically by trusted publishing only once the source repo is
public; the workflow intentionally does not force a provenance flag while the
repository remains private.
