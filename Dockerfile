# SPDX-FileCopyrightText: LDSC contributors
#
# SPDX-License-Identifier: Apache-2.0
#
# The binary is built beforehand as a static musl executable and copied to
# dist/<arch>/ (amd64 or arm64), for example:
#   cargo build --release --target x86_64-unknown-linux-musl -p ldsc-connector
#   mkdir -p dist/amd64 && cp target/x86_64-unknown-linux-musl/release/ldsc-connector dist/amd64/
# The image holds only that file and the CA certificate bundle: no shell, no
# package manager, no libc. With nothing to run inside the image, buildx
# builds every platform without emulation.

# CA certificates (Mozilla's bundle as packaged by Debian, MPL-2.0) so the
# connector can verify https callback addresses. Taken from distroless
# static, pinned by digest and updated by Dependabot; nothing runs in it.
FROM gcr.io/distroless/static-debian12:latest@sha256:d75cdd72874d4790092fcb1b058493ecf6bb5bf2b2b897045b00ff01d91843f2 AS certs

FROM scratch
ARG TARGETARCH
# Set by the release workflow; "dev" and empty values mark a local build.
ARG VERSION=dev
ARG REVISION=""
ARG CREATED=""
# OCI image annotations (pre-defined keys):
# https://github.com/opencontainers/image-spec/blob/main/annotations.md
LABEL org.opencontainers.image.title="ldsc-connector" \
      org.opencontainers.image.description="LDSC connector for the Dataspace Protocol (DSP 2025-1)" \
      org.opencontainers.image.authors="LDSC contributors" \
      org.opencontainers.image.vendor="LDSC contributors" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.url="https://github.com/brunopacheco1/ldsc" \
      org.opencontainers.image.source="https://github.com/brunopacheco1/ldsc" \
      org.opencontainers.image.documentation="https://github.com/brunopacheco1/ldsc/tree/main/docs" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.created="${CREATED}"
COPY --from=certs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY dist/${TARGETARCH}/ldsc-connector /ldsc-connector
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/ldsc-connector"]
