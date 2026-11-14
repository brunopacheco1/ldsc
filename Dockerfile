# SPDX-FileCopyrightText: Portitor contributors
#
# SPDX-License-Identifier: Apache-2.0
#
# One Dockerfile for every Portitor image (ADR 0003). Each image is a build
# target named after its component:
#   docker build --target portitor-connector -t portitor-connector .
#   docker build --target portitor-identity -t portitor-identity .
#   docker build --target portitor-issuer -t portitor-issuer .
# Without --target, Docker builds the last one, portitor-connector.
#
# The binaries are built beforehand as static musl executables and copied to
# dist/<arch>/ (amd64 or arm64), for example:
#   cargo build --release --target x86_64-unknown-linux-musl -p portitor-connector -p portitor-identity -p portitor-issuer
#   mkdir -p dist/amd64 && cp target/x86_64-unknown-linux-musl/release/portitor-{connector,identity,issuer} dist/amd64/
# An image holds only its binary and the CA certificate bundle: no shell, no
# package manager, no libc. With nothing to run inside the image, buildx
# builds every platform without emulation.

# CA certificates (Mozilla's bundle as packaged by Debian, MPL-2.0) so the
# components can verify https addresses. Taken from distroless static,
# pinned by digest and updated by Dependabot; nothing runs in it.
FROM gcr.io/distroless/static-debian12:latest@sha256:d75cdd72874d4790092fcb1b058493ecf6bb5bf2b2b897045b00ff01d91843f2 AS certs

# What every image shares: labels, CA bundle, a writable /data, the user.
FROM scratch AS base
# Set by the release workflow; "dev" and empty values mark a local build.
ARG VERSION=dev
ARG REVISION=""
ARG CREATED=""
# OCI image annotations (pre-defined keys):
# https://github.com/opencontainers/image-spec/blob/main/annotations.md
# Each component sets its own title and description below.
LABEL org.opencontainers.image.authors="Portitor contributors" \
      org.opencontainers.image.vendor="Portitor contributors" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.url="https://github.com/brunopacheco1/portitor" \
      org.opencontainers.image.source="https://github.com/brunopacheco1/portitor" \
      org.opencontainers.image.documentation="https://github.com/brunopacheco1/portitor/tree/main/docs" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.created="${CREATED}"
COPY --from=certs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
# State is kept in a SQLite file. /data is owned by the runtime user;
# mount a volume there so the file survives a new container.
COPY --from=certs --chown=65532:65532 /home/nonroot /data
VOLUME /data
USER 65532:65532

# Identity: DID document, Secure Token Service and credential service (DCP, ADR 0015).
FROM base AS portitor-identity
ARG TARGETARCH
LABEL org.opencontainers.image.title="portitor-identity" \
      org.opencontainers.image.description="Portitor identity: DID document, STS and credential service (DCP 1.0)"
COPY dist/${TARGETARCH}/portitor-identity /portitor-identity
ENV PORTITOR_DB_FILE=/data/portitor-identity.db
# 8090: DID document, STS and credential service. 8091: management API, only
# when PORTITOR_MANAGEMENT_API_KEY_FILE is set; it listens on 127.0.0.1
# unless PORTITOR_MANAGEMENT_BIND says otherwise.
EXPOSE 8090 8091
ENTRYPOINT ["/portitor-identity"]

# Issuer: issues and revokes credentials for a dataspace authority (DCP, ADR 0018).
# One per dataspace, run by the authority; never on a participant's host.
FROM base AS portitor-issuer
ARG TARGETARCH
LABEL org.opencontainers.image.title="portitor-issuer" \
      org.opencontainers.image.description="Portitor issuer: issues and revokes credentials for a dataspace authority (DCP 1.0)"
COPY dist/${TARGETARCH}/portitor-issuer /portitor-issuer
ENV PORTITOR_DB_FILE=/data/portitor-issuer.db
# 8070: DID document, issuer metadata, credential requests and status, status
# lists. 8071: management API, only when PORTITOR_MANAGEMENT_API_KEY_FILE is
# set; it listens on 127.0.0.1 unless PORTITOR_MANAGEMENT_BIND says otherwise.
EXPOSE 8070 8071
ENTRYPOINT ["/portitor-issuer"]

# Connector: DSP control plane and the built-in data plane.
FROM base AS portitor-connector
ARG TARGETARCH
LABEL org.opencontainers.image.title="portitor-connector" \
      org.opencontainers.image.description="Portitor connector for the Dataspace Protocol (DSP 2025-1)"
COPY dist/${TARGETARCH}/portitor-connector /portitor-connector
ENV PORTITOR_DB_FILE=/data/portitor.db
# 8080: DSP. 8081: management API, only when PORTITOR_MANAGEMENT_API_KEY_FILE is
# set; it listens on 127.0.0.1 unless PORTITOR_MANAGEMENT_BIND says otherwise.
EXPOSE 8080 8081
ENTRYPOINT ["/portitor-connector"]
