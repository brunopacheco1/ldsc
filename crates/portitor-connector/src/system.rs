// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! What the connector takes from the operating system: random ids and the
//! current time (shared helpers in `portitor_runtime::system`).

use portitor_dsp::negotiation::provider::Environment;
pub use portitor_runtime::system::{hex, new_uuid, now_secs, xsd_date_time};

/// Adapter: identifiers from the OS random generator, time from the clock.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemEnvironment;

impl Environment for SystemEnvironment {
    fn new_id(&self) -> String {
        new_uuid()
    }

    fn now(&self) -> String {
        xsd_date_time(now_secs())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn environment_gives_utc_times_and_uuids() {
        assert!(SystemEnvironment.now().ends_with('Z'));
        assert!(SystemEnvironment.new_id().starts_with("urn:uuid:"));
    }
}
