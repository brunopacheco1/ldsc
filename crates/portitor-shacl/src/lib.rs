// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! A SHACL Core subset (ADR 0005), enough for the HealthDCAT-AP release 8
//! and DCAT-AP 3.0.0 shapes. Pure: no I/O, no network. Shapes that use a
//! part of SHACL this crate does not implement are refused when they are
//! loaded, so nothing is passed silently.
//!
//! Built in release 0.7 (empty in the foundation commit).
