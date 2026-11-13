// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Helpers for the unit tests.

use std::cell::Cell;

use crate::transfer::provider::Environment;

/// A test environment: ids `urn:uuid:c1`, `urn:uuid:c2`, and so on, and a
/// fixed time.
#[derive(Default)]
pub(crate) struct CountingEnv(Cell<u32>);

impl Environment for CountingEnv {
    fn new_id(&self) -> String {
        self.0.set(self.0.get() + 1);
        format!("urn:uuid:c{}", self.0.get())
    }
    fn now(&self) -> String {
        "2026-11-13T12:00:00Z".to_owned()
    }
}
