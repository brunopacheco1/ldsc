# SPDX-FileCopyrightText: Portitor contributors
#
# SPDX-License-Identifier: Apache-2.0
#
# The binary is built beforehand as a static musl executable and copied to
# dist/<arch>/ (amd64 or arm64), for example:
#   cargo build --release --target x86_64-unknown-linux-musl -p portitor-connector
#   mkdir -p dist/amd64 && cp target/x86_64-unknown-linux-musl/release/portitor-connector dist/amd64/
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
LABEL org.opencontainers.image.title="portitor-connector" \
      org.opencontainers.image.description="Portitor connector for the Dataspace Protocol (DSP 2025-1)" \
      org.opencontainers.image.authors="Portitor contributors" \
      org.opencontainers.image.vendor="Portitor contributors" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.url="https://github.com/brunopacheco1/portitor" \
      org.opencontainers.image.source="https://github.com/brunopacheco1/portitor" \
      org.opencontainers.image.documentation="https://github.com/brunopacheco1/portitor/tree/main/docs" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.created="${CREATED}"
COPY --from=certs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY dist/${TARGETARCH}/portitor-connector /portitor-connector
# Negotiations are kept in a SQLite file. /data is owned by the runtime user;
# mount a volume there so the file survives a new container.
COPY --from=certs --chown=65532:65532 /home/nonroot /data
ENV PORTITOR_DB_FILE=/data/portitor.db
VOLUME /data
USER 65532:65532
# 8080: DSP. 8081: management API, only when PORTITOR_MANAGEMENT_API_KEY_FILE is
# set; it listens on 127.0.0.1 unless PORTITOR_MANAGEMENT_BIND says otherwise.
EXPOSE 8080 8081
ENTRYPOINT ["/portitor-connector"]
