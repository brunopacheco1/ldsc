<!--
SPDX-FileCopyrightText: LDSC contributors

SPDX-License-Identifier: Apache-2.0
-->

# Releasing

All components share one version (mono repo). Pushing a signed tag `vX.Y.Z`
runs [`.github/workflows/release.yml`](../.github/workflows/release.yml), which:
1. checks the tag is annotated, signed by the maintainer (keys from
   `github.com/<owner>.gpg`), equal to `version` in `Cargo.toml`, and
   listed in `CHANGELOG.md`;
2. tests the workspace and builds static musl binaries on native amd64 and
   arm64 runners;
3. builds one multi-arch image per component (`ldsc-connector` today;
   `ldsc-identity` and `ldsc-issuer` join later,
   [ADR 0003](adr/0003-component-split.md)) and pushes it to
   `ghcr.io/brunopacheco1/<component>:X.Y.Z`;
4. signs each image with cosign (keyless, the workflow's identity);
5. attaches build provenance (SLSA v1) and a CycloneDX SBOM to each image
   as GitHub attestations;
6. creates a GitHub release with the changelog section, the binaries, the
   SBOMs, the provenance bundle (`ldsc-X.Y.Z.intoto.jsonl`) and
   `THIRD-PARTY-NOTICES.txt`.

A pull request that changes the release workflow, the `Dockerfile` or the
notices script runs the same build as a dry run: nothing is pushed or signed.

## One-time setup (owner)

1. **Settings → Environments → New environment** `release`. Restrict it to
   tags matching `v*`. Optionally require yourself as a reviewer, so every
   release waits for a click.
2. No signing secrets are needed: cosign keyless signing and attestations
   use the workflow's OIDC token. Images are pushed with the workflow's
   `GITHUB_TOKEN`.
3. After the first release, make the package public: **Packages →
   ldsc-connector → Package settings → Change visibility → Public**, and
   link it to this repository if GitHub did not.

## Releasing a version

1. In a pull request, set `version` in `Cargo.toml` (`[workspace.package]`)
   to `X.Y.Z`, rename `## [Unreleased]` in `CHANGELOG.md` to
   `## [X.Y.Z] - YYYY-MM-DD`, add a fresh empty `## [Unreleased]` above it,
   and merge.
2. Tag the merge commit with your personal key and push the tag:
   ```sh
   git switch main && git pull
   git tag -s vX.Y.Z -m "LDSC X.Y.Z"
   git push origin vX.Y.Z
   ```
3. Watch **Actions → Release**. When it is green, the images and the GitHub
   release are published.

## Checking a release

- Signature:
  ```sh
  cosign verify ghcr.io/brunopacheco1/ldsc-connector:X.Y.Z \
    --certificate-identity-regexp '^https://github.com/brunopacheco1/ldsc/\.github/workflows/release\.yml@refs/tags/v' \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com
  ```
- Provenance:
  `gh attestation verify oci://ghcr.io/brunopacheco1/ldsc-connector:X.Y.Z --repo brunopacheco1/ldsc`
- SBOM: attached to the GitHub release and to the image as an attestation.

If the release fails after the tag is pushed, fix the cause, delete the tag
(locally and with `git push origin :refs/tags/vX.Y.Z`), and tag again,
unless an image was already pushed; then use a new patch number.
