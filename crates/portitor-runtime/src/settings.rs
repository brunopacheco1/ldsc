// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Helpers for reading settings from environment variables, shared by
//! the connector, the identity component and the issuer.

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

/// The path part of an `http(s)` URL, without a trailing `/`: `""` for
/// `https://id.example/`, `"/cs"` for `https://id.example/cs/`. `None`
/// if it is not an `http(s)` URL with a host, or has a query or fragment.
/// A component serves its DCP routes under the path of its public service
/// URL.
#[must_use]
pub fn base_path(url: &str) -> Option<String> {
    let rest = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))?;
    let (host, path) = rest.split_once('/').unwrap_or((rest, ""));
    if host.is_empty() || path.contains(['?', '#']) {
        return None;
    }
    Some(format!("/{path}").trim_end_matches('/').to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_paths() {
        assert_eq!(base_path("https://id.example").as_deref(), Some(""));
        assert_eq!(base_path("https://id.example/").as_deref(), Some(""));
        assert_eq!(
            base_path("http://id.example:8090/cs/").as_deref(),
            Some("/cs")
        );
        assert_eq!(base_path("ftp://id.example"), None);
        assert_eq!(base_path("https:///cs"), None);
        assert_eq!(base_path("https://id.example/cs?x=1"), None);
    }

    #[test]
    fn items_are_trimmed_and_empty_ones_dropped() {
        assert_eq!(comma_list("a, b,,c "), ["a", "b", "c"]);
        assert!(comma_list("").is_empty());
        assert!(comma_list(" , ").is_empty());
    }
}
