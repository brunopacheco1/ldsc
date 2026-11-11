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
COPY dist/${TARGETARCH}/ldsc-connector /ldsc-connector
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/ldsc-connector"]
