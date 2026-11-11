//! Robust statistics used by per-app behaviour profiles (design spec §6.2).
//!
//! The median and the median absolute deviation (MAD) are used instead of
//! the mean and standard deviation because a few extreme values, such as one
//! huge download, barely move them.

/// Scale factor that makes the MAD comparable to a standard deviation for
/// normally distributed data.
pub const MAD_SCALE: f64 = 1.4826;

/// Returns the median of `values`.
///
/// Returns `None` if `values` is empty or contains NaN.
pub fn median(values: &[f64]) -> Option<f64> {
    if values.is_empty() || values.iter().any(|v| v.is_nan()) {
        return None;
    }
    let mut sorted = values.to_vec();
    sorted.sort_by(f64::total_cmp);
    let n = sorted.len();
    let mid = n / 2;
    if n % 2 == 1 {
        Some(sorted[mid])
    } else {
        Some((sorted[mid - 1] + sorted[mid]) / 2.0)
    }
}

/// Returns the median absolute deviation: the median of `|x - median|`.
///
/// Returns `None` under the same conditions as [`median`].
pub fn mad(values: &[f64]) -> Option<f64> {
    let m = median(values)?;
    let deviations: Vec<f64> = values.iter().map(|v| (v - m).abs()).collect();
    median(&deviations)
}

/// Returns the robust z-score of `x` against a `history` of values.
///
/// The score is `(x - median) / (MAD_SCALE * MAD)`. A score above about 6
/// means `x` is far outside the app's normal range.
///
/// Returns `None` if `x` is NaN, if `history` is empty or contains NaN, or if
/// `history` has no spread (MAD of zero). In the last case a score would be
/// meaningless, and callers should compare `x` to the median directly.
pub fn robust_z(x: f64, history: &[f64]) -> Option<f64> {
    if x.is_nan() {
        return None;
    }
    let m = median(history)?;
    let spread = MAD_SCALE * mad(history)?;
    if spread == 0.0 {
        return None;
    }
    Some((x - m) / spread)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn median_of_odd_and_even_lengths() {
        assert_eq!(median(&[3.0, 1.0, 2.0]), Some(2.0));
        assert_eq!(median(&[4.0, 1.0, 3.0, 2.0]), Some(2.5));
    }

    #[test]
    fn median_rejects_empty_and_nan() {
        assert_eq!(median(&[]), None);
        assert_eq!(median(&[1.0, f64::NAN]), None);
    }

    #[test]
    fn mad_ignores_a_single_outlier() {
        // median = 3, deviations = [2, 1, 0, 1, 997], so MAD = 1.
        assert_eq!(mad(&[1.0, 2.0, 3.0, 4.0, 1000.0]), Some(1.0));
    }

    #[test]
    fn robust_z_flags_a_large_upload_spike() {
        // An app that normally uploads about 2 MB per hour suddenly uploads 150 MB.
        let history = [2.0, 2.1, 1.9, 2.0, 2.2, 1.8, 2.0];
        let z = robust_z(150.0, &history).expect("history has spread");
        assert!(z > 6.0, "z = {z}");
    }

    #[test]
    fn robust_z_is_small_for_normal_values() {
        let history = [2.0, 2.1, 1.9, 2.0, 2.2, 1.8, 2.0];
        let z = robust_z(2.1, &history).expect("history has spread");
        assert!(z.abs() < 1.0, "z = {z}");
    }

    #[test]
    fn robust_z_is_none_without_spread_or_for_nan() {
        assert_eq!(robust_z(5.0, &[2.0, 2.0, 2.0]), None);
        assert_eq!(robust_z(f64::NAN, &[1.0, 2.0, 3.0]), None);
    }
}
