# SPDX-FileCopyrightText: LDSC contributors
#
# SPDX-License-Identifier: Apache-2.0
#
# The binary is built beforehand as a static musl executable and copied to
# dist/<arch>/ (amd64 or arm64), for example:
#   cargo build --release --target x86_64-unknown-linux-musl -p ldsc-connector
#   mkdir -p dist/amd64 && cp target/x86_64-unknown-linux-musl/release/ldsc-connector dist/amd64/
# The image holds only that file: no shell, no package manager, no libc.
# With nothing to run inside the image, buildx builds every platform without emulation.
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
COPY dist/${TARGETARCH}/ldsc-connector /ldsc-connector
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/ldsc-connector"]
