//! Character entropy of domain labels (design spec §6.2, "random-looking domain").
//!
//! Malware often contacts machine-generated domains such as `x7fk2qpz.com`.
//! Their characters are spread evenly, so they have higher entropy than
//! ordinary words such as `google`.

use std::collections::BTreeMap;

/// Returns the Shannon entropy of `label`, in bits per character.
///
/// Returns `0.0` for an empty string. A `BTreeMap` is used so the result is
/// identical on every run.
pub fn shannon_entropy(label: &str) -> f64 {
    let mut counts: BTreeMap<char, usize> = BTreeMap::new();
    for c in label.chars() {
        *counts.entry(c).or_insert(0) += 1;
    }
    let total: usize = counts.values().sum();
    if total == 0 {
        return 0.0;
    }
    let total = total as f64;
    counts
        .values()
        .map(|&n| {
            let p = n as f64 / total;
            -p * p.log2()
        })
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_and_single_character_labels_have_zero_entropy() {
        assert_eq!(shannon_entropy(""), 0.0);
        assert_eq!(shannon_entropy("aaaa"), 0.0);
    }

    #[test]
    fn two_equally_common_characters_give_one_bit() {
        assert_eq!(shannon_entropy("ab"), 1.0);
        assert_eq!(shannon_entropy("abab"), 1.0);
    }

    #[test]
    fn random_looking_label_scores_higher_than_a_word() {
        let random = shannon_entropy("x7fk2qpz");
        let word = shannon_entropy("google");
        assert!(random > word, "random = {random}, word = {word}");
        assert!((random - 3.0).abs() < 1e-12, "8 distinct chars = 3 bits");
    }
}
