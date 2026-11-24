//! The local time zone, for what is counted in local days and hours
//! (behaviour profiles' active days and usual hours).

use std::time::{SystemTime, UNIX_EPOCH};

use windows::Win32::Foundation::{FILETIME, SYSTEMTIME};
use windows::Win32::System::Time::{
    DYNAMIC_TIME_ZONE_INFORMATION, FileTimeToSystemTime, GetDynamicTimeZoneInformation,
    SystemTimeToFileTime, SystemTimeToTzSpecificLocalTimeEx,
};

/// Seconds between 1601-01-01 (the start of Windows file times) and the
/// Unix epoch.
const FILETIME_UNIX_OFFSET: u64 = 11_644_473_600;
/// Windows file times count 100-nanosecond intervals.
const TICKS_PER_SEC: u64 = 10_000_000;
/// `GetDynamicTimeZoneInformation`'s failure value.
const TIME_ZONE_ID_INVALID: u32 = u32::MAX;

/// The local time zone's offset from UTC at `at`, in seconds (positive east
/// of Greenwich), with daylight saving time as it applies at `at`. 0 if
/// Windows cannot say.
pub fn local_offset_secs(at: SystemTime) -> i32 {
    offset(at).unwrap_or(0)
}

fn offset(at: SystemTime) -> Option<i32> {
    // Whole seconds, so the comparison below is not thrown off by the
    // milliseconds a SYSTEMTIME cannot hold.
    let secs = at.duration_since(UNIX_EPOCH).ok()?.as_secs();
    let utc_ticks = secs
        .checked_add(FILETIME_UNIX_OFFSET)?
        .checked_mul(TICKS_PER_SEC)?;
    let utc_file = to_filetime(utc_ticks);

    let mut zone = DYNAMIC_TIME_ZONE_INFORMATION::default();
    // SAFETY: `zone` is a valid, writable structure of the expected type.
    if unsafe { GetDynamicTimeZoneInformation(&mut zone) } == TIME_ZONE_ID_INVALID {
        return None;
    }
    let mut utc = SYSTEMTIME::default();
    let mut local = SYSTEMTIME::default();
    let mut local_file = FILETIME::default();
    // SAFETY: every pointer is to a live local of the type the function
    // expects; `zone` was filled in by Windows above.
    unsafe {
        FileTimeToSystemTime(&utc_file, &mut utc).ok()?;
        SystemTimeToTzSpecificLocalTimeEx(Some(&zone), &utc, &mut local).ok()?;
        SystemTimeToFileTime(&local, &mut local_file).ok()?;
    }
    let local_ticks = from_filetime(local_file);
    let difference = i128::from(local_ticks) - i128::from(utc_ticks);
    i32::try_from(difference / i128::from(TICKS_PER_SEC)).ok()
}

fn to_filetime(ticks: u64) -> FILETIME {
    FILETIME {
        dwLowDateTime: (ticks & 0xFFFF_FFFF) as u32,
        dwHighDateTime: (ticks >> 32) as u32,
    }
}

fn from_filetime(time: FILETIME) -> u64 {
    (u64::from(time.dwHighDateTime) << 32) | u64::from(time.dwLowDateTime)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn offset_is_a_real_time_zone_offset() {
        let now = SystemTime::now();
        let offset = local_offset_secs(now);
        // Time zones run from UTC-12 to UTC+14, in steps of 15 minutes.
        assert!((-12 * 3_600..=14 * 3_600).contains(&offset), "{offset}");
        assert_eq!(offset % 900, 0, "{offset}");
        // Before 1970 there is nothing to ask Windows.
        assert_eq!(local_offset_secs(UNIX_EPOCH - Duration::from_secs(1)), 0);
    }

    #[test]
    fn file_times_round_trip() {
        let ticks = 133_000_000_000_000_000;
        assert_eq!(from_filetime(to_filetime(ticks)), ticks);
    }
}
