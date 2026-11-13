// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Helpers for reading settings from environment variables, shared by
//! the connector and the identity component.

/// The items of a comma-separated setting, trimmed, without empty ones:
/// `"a, b,,c "` is `["a", "b", "c"]`.
#[must_use]
pub fn comma_list(text: &str) -> Vec<String> {
    let mut items = Vec::new();
    for item in text.split(',') {
        let item = item.trim();
        if !item.is_empty() {
            items.push(item.to_owned());
        }
    }
    items
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn items_are_trimmed_and_empty_ones_dropped() {
        assert_eq!(comma_list("a, b,,c "), ["a", "b", "c"]);
        assert!(comma_list("").is_empty());
        assert!(comma_list(" , ").is_empty());
    }
}
