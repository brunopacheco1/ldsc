// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

// EDC IdentityHub: DID document, STS, credential service. The "oauth2"
// variant protects its Identity API with tokens; the test signs them with
// the demo authority's key (test-issuer admin-token) and serves the JWKS.

val edcVersion: String by project

dependencies {
    runtimeOnly("org.eclipse.edc:identityhub-oauth2-bom:$edcVersion")
    runtimeOnly("org.eclipse.edc:vault-hashicorp:$edcVersion")
}
