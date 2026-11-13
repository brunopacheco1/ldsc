// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

// A minimal EDC data plane for HTTP pull transfers, built with the Data
// Plane Signaling SDK, as EDC's own tests (system-tests/e2e-transfer-test/
// signaling-data-plane) and the Minimum Viable Dataspace do: EDC 1.0 has
// no data plane of its own.

val edcVersion: String by project
val dataplaneSdkVersion: String by project

dependencies {
    implementation("org.eclipse.edc:boot:$edcVersion")
    implementation("org.eclipse.edc:runtime-core:$edcVersion")
    implementation("org.eclipse.edc:http:$edcVersion")
    implementation("org.eclipse.edc:configuration-filesystem:$edcVersion")
    implementation("org.eclipse.dataplane-core:dataplane-sdk-core:$dataplaneSdkVersion")
    implementation("org.eclipse.dataplane-core:dataplane-sdk-jakarta-ee:$dataplaneSdkVersion")
    // the annotations of the two small web APIs below (version as in EDC)
    implementation("jakarta.ws.rs:jakarta.ws.rs-api:4.0.0")
    runtimeOnly("org.eclipse.edc:api-observability:$edcVersion")
}
