<!--
SPDX-FileCopyrightText: Portitor contributors

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
3. builds one multi-arch image per component and pushes it to
   `ghcr.io/brunopacheco1/<component>:X.Y.Z`. From 0.6 there are three:

   | Image | Ports | State |
   |---|---|---|
   | `ghcr.io/brunopacheco1/portitor-connector` | 8080 DSP, 8081 management | `/data/portitor.db` |
   | `ghcr.io/brunopacheco1/portitor-identity` | 8090 DID document, STS, credential service; 8091 management | `/data/portitor-identity.db` |
   | `ghcr.io/brunopacheco1/portitor-issuer` | 8070 DID document, DCP issuer service, status lists; 8071 management | `/data/portitor-issuer.db` |

   ([ADR 0003](adr/0003-component-split.md), [ADR 0018](adr/0018-issuer-component.md));
4. signs each image with cosign (keyless, the workflow's identity);
5. attaches build provenance (SLSA v1) and a CycloneDX SBOM to each image
   as GitHub attestations;
6. creates a GitHub release with the changelog section, the image
   digests, the binaries, one SBOM and one provenance bundle per component
   (`<component>-X.Y.Z.cdx.json`, `<component>-X.Y.Z.intoto.jsonl`) and
   `THIRD-PARTY-NOTICES.txt` (all components).

The components are listed once, in `COMPONENTS` at the top of the
workflow; each one is a build target of the same name in the single
`Dockerfile` (`docker build --target portitor-identity .`). The image
steps (build, push, sign, attest) run as a matrix over that list, one job
per image, and the GitHub release is created only when every image job
succeeded. Adding a component means: a binary crate, a target in the
`Dockerfile`, a line in `.dockerignore`, and its name in `COMPONENTS`.

A pull request that changes the release workflow, the `Dockerfile` or the
notices script runs the same build as a dry run: nothing is pushed or signed.

## One-time setup (owner)

1. **Settings → Environments → New environment** `release`. Restrict it to
   tags matching `v*`. Optionally require yourself as a reviewer, so every
   release waits for a click. Each image job uses the environment; one
   **Review deployments** approval covers all images of a run.
2. No signing secrets are needed: cosign keyless signing and attestations
   use the workflow's OIDC token. Images are pushed with the workflow's
   `GITHUB_TOKEN`.
3. After the first release of each image, make its package public:
   **Packages → portitor-connector** (and, from 0.5, **portitor-identity**;
   from 0.6, **portitor-issuer**)
   **→ Package settings → Change visibility → Public**, and link it to this
   repository if GitHub did not. A new package starts private, so pulling
   it fails until this is done.

## Documentation review

Every release checks its documentation against the code before the
version is set, as part of the release's quality review (on the release
branch, next to the readability review). Fix what is wrong in the release
pull request, or record why it stays.

- `python3 scripts/check_docs.py` passes (CI runs it too): the C4
  diagrams in `docs/diagrams/` show every crate and image, and name only
  files and types that exist; every OpenAPI file has the new version.
- The C4 diagrams ([ARCHITECTURE.md](ARCHITECTURE.md), "Diagrams") still
  tell the truth: new components, ports, adapters, containers or outside
  systems are drawn, removed ones are gone. Edit them in draw.io.
- [ARCHITECTURE.md](ARCHITECTURE.md), [DEPLOYING.md](DEPLOYING.md),
  [TESTING.md](TESTING.md) and the README match what the release does
  (settings, ports, images, flows).
- The OpenAPI files in `docs/api/`: the generated management descriptions
  are current (their tests fail otherwise); the hand-written
  `openapi.json` (DSP), `identity-openapi.json` (DID document, STS,
  DCP credential service) and `issuer-openapi.json` (DID document, DCP
  issuer service, status lists) list every route (their tests check that each
  listed route is served) and describe what changed.
- The website (`site/index.html`, published with the API pages by
  `pages.yml`) shows the release's features and the roadmap state.
- [ROADMAP.md](ROADMAP.md) and the [CHANGELOG](../CHANGELOG.md) say what
  shipped.

## Releasing a version

1. In a pull request, set `version` in `Cargo.toml` (`[workspace.package]`)
   to `X.Y.Z`, rename `## [Unreleased]` in `CHANGELOG.md` to
   `## [X.Y.Z] - YYYY-MM-DD`, add a fresh empty `## [Unreleased]` above it,
   set `info.version` in `docs/api/openapi.json`,
   `docs/api/identity-openapi.json` and `docs/api/issuer-openapi.json`, regenerate
   `docs/api/management-openapi.json`,
   `docs/api/identity-management-openapi.json`
   (`PORTITOR_UPDATE_OPENAPI=1 cargo test -p portitor-connector --test management_api`
   and the same with `-p portitor-identity`) and
   `docs/api/issuer-management-openapi.json`
   (`cargo test -p portitor-issuer --test issuer -- --ignored write_management_description`),
   and merge.
2. Tag the merge commit with your personal key and push the tag:
   ```sh
   git switch main && git pull
   git tag -s vX.Y.Z -m "Portitor X.Y.Z"
   git push origin vX.Y.Z
   ```
3. Watch **Actions → Release**. When it is green, the images and the GitHub
   release are published.

## Checking a release

Check every image of the release the same way:

```sh
for image in portitor-connector portitor-identity portitor-issuer; do
  # signature: signed by this repository's release workflow, from a tag
  cosign verify "ghcr.io/brunopacheco1/$image:X.Y.Z" \
    --certificate-identity-regexp '^https://github.com/brunopacheco1/portitor/\.github/workflows/release\.yml@refs/tags/v' \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com
  # build provenance (SLSA v1)
  gh attestation verify "oci://ghcr.io/brunopacheco1/$image:X.Y.Z" --repo brunopacheco1/portitor
  # SBOM attestation (CycloneDX)
  gh attestation verify "oci://ghcr.io/brunopacheco1/$image:X.Y.Z" --repo brunopacheco1/portitor \
    --predicate-type https://cyclonedx.org/bom
done
```

- The digests printed by `cosign verify` must match the ones in the
  release notes.
- SBOMs: attached to the GitHub release (one per component) and to each
  image as an attestation.

If the release fails after the tag is pushed, fix the cause, delete the tag
(locally and with `git push origin :refs/tags/vX.Y.Z`), and tag again,
unless an image was already pushed; then use a new patch number.
