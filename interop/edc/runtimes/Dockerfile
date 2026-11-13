# SPDX-FileCopyrightText: Portitor contributors
#
# SPDX-License-Identifier: Apache-2.0
#
# The EDC runtimes of the EDC interop test, built from the released EDC
# modules on Maven Central (see gradle.properties). Test-only images.
# One build stage makes the three jars; pick a runtime with --target:
#   docker build --target controlplane -t portitor-interop/edc-controlplane .
# The Compose file (../compose.yaml) does this for each service.

# Gradle 9 with JDK 21 (the shadow plugin 9 needs Gradle 9)
FROM gradle:9.8.2-jdk21@sha256:85f8f572045bfb31874d66d7d8a2bd0c17d8cb9ad34b6a4d02f5d552b4b92c04 AS build
WORKDIR /src
COPY . .
RUN gradle --no-daemon --quiet shadowJar

FROM eclipse-temurin:21.0.13_9-jre-noble@sha256:0d57a8e90c2bb844c5a8e1b2b71e11eff06dad7edcfd803cd21ed4ae203b2515 AS runtime
WORKDIR /app
# EDC reads its settings from this file (configuration-filesystem); the
# Compose file mounts it
ENV EDC_FS_CONFIG=/config/runtime.properties
ENTRYPOINT ["java", "-jar", "/app/runtime.jar"]

FROM runtime AS controlplane
COPY --from=build /src/controlplane/build/libs/controlplane.jar /app/runtime.jar

FROM runtime AS dataplane
COPY --from=build /src/dataplane/build/libs/dataplane.jar /app/runtime.jar

FROM runtime AS identityhub
COPY --from=build /src/identityhub/build/libs/identityhub.jar /app/runtime.jar
