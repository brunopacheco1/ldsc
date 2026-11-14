// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

// EDC IdentityHub: DID document, STS, credential service. The "oauth2"
// variant protects its Identity API with tokens; scripts/edc-interop.sh
// signs them with a test-only key and serves its JWKS (identity-api-jwks
// in compose.yaml).

val edcVersion: String by project

dependencies {
    runtimeOnly("org.eclipse.edc:identityhub-oauth2-bom:$edcVersion")
    runtimeOnly("org.eclipse.edc:vault-hashicorp:$edcVersion")
}
