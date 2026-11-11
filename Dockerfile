# SPDX-FileCopyrightText: LDSC contributors
#
# SPDX-License-Identifier: Apache-2.0
#
# The binary is built beforehand as a static musl executable
# (cargo build --release --target x86_64-unknown-linux-musl -p ldsc).
# The image holds only that file: no shell, no package manager, no libc.
FROM scratch
COPY target/x86_64-unknown-linux-musl/release/ldsc /ldsc
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/ldsc"]
