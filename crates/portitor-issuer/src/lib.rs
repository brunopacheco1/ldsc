// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! The Portitor issuer component (ADR 0018): run once per dataspace by
//! its authority, it issues and revokes credentials with the Decentralized
//! Claims Protocol v1.0.1, section 6 (Credential Issuance Protocol).
//!
//! Built in release 0.6:
//! - its DID document (`did:web`) with an `IssuerService` entry;
//! - issuer metadata, credential requests and their status (public port);
//! - delivery of issued credentials to the holder's Storage API, through
//!   an outbox;
//! - one signed BitstringStatusList credential per profile, for revocation;
//! - a management API (API key): participants, offers, revocation.
