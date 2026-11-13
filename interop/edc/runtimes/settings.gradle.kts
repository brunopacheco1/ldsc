// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

// The EDC runtimes of the EDC interop test (docs/TESTING.md): an EDC
// control plane, a data plane and an IdentityHub, assembled from the
// released EDC modules on Maven Central. Test-only; never shipped.

pluginManagement {
    repositories {
        gradlePluginPortal()
        mavenCentral()
    }
}

dependencyResolutionManagement {
    repositories {
        mavenCentral()
    }
}

rootProject.name = "portitor-edc-interop"
include("controlplane", "dataplane", "identityhub")
