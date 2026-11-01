//! Timezone handling for schedule evaluation.
//!
//! Cron schedules configured in `clients.groups.*` (and their
//! `blocked_services[].schedule` entries) are evaluated against the wall clock
//! of the zone configured in `clients.timezone`, defaulting to the host's
//! system-local zone. Without this, a documented parental window such as
//! `0 0 15-21 * * MON-FRI` would silently shift by the host's UTC offset.
//!
//! # Supported zones
//!
//! The workspace's locked dependency set does not link a timezone database
//! (`chrono-tz` is not available), so only the system-local zone, UTC and
//! fixed numeric UTC offsets can be resolved. IANA names such as
//! `Europe/Warsaw` are rejected at config-parse time with an explicit error
//! instead of being silently treated as UTC. Fixed offsets do not follow DST
//! transitions — use `local` on hosts whose zone observes DST.

use chrono::{DateTime, FixedOffset, Local, Utc};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::str::FromStr;
use thiserror::Error;

/// Timezone used to evaluate client-group cron schedules.
///
/// Defaults to [`ClientTimeZone::Local`] (the host's system zone).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum ClientTimeZone {
    /// Host system-local zone, resolved for each evaluated timestamp.
    #[default]
    Local,
    /// Fixed numeric UTC offset; no DST transitions.
    Fixed(FixedOffset),
}

impl ClientTimeZone {
    /// Whether this is the default system-local zone.
    #[must_use]
    pub fn is_local(&self) -> bool {
        matches!(self, Self::Local)
    }

    /// Converts a UTC instant into this zone.
    ///
    /// For the local zone the offset is resolved for `utc` itself, so DST
    /// transitions are honored.
    #[must_use]
    pub fn at_utc(&self, utc: DateTime<Utc>) -> DateTime<FixedOffset> {
        match *self {
            Self::Local => utc.with_timezone(&Local).fixed_offset(),
            Self::Fixed(offset) => utc.with_timezone(&offset),
        }
    }

    /// The current instant in this zone.
    #[must_use]
    pub fn now(&self) -> DateTime<FixedOffset> {
        self.at_utc(Utc::now())
    }
}

impl fmt::Display for ClientTimeZone {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::Local => f.write_str("local"),
            Self::Fixed(offset) => write!(f, "{offset}"),
        }
    }
}

/// Error returned when `clients.timezone` cannot be resolved.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum TimeZoneError {
    #[error(
        "clients.timezone cannot be empty; use \"local\", \"UTC\" or a numeric offset such as \"+02:00\""
    )]
    Empty,

    #[error(
        "clients.timezone '{value}' is not supported: IANA zone names require a timezone \
         database that is not linked into this build; use \"local\", \"UTC\" or a fixed \
         numeric UTC offset such as \"+02:00\""
    )]
    UnsupportedZone { value: String },

    #[error(
        "clients.timezone '{value}' is not a valid UTC offset; expected ±HH, ±HH:MM or ±HH:MM:SS"
    )]
    InvalidOffset { value: String },
}

impl FromStr for ClientTimeZone {
    type Err = TimeZoneError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            return Err(TimeZoneError::Empty);
        }

        let lower = trimmed.to_ascii_lowercase();
        if matches!(lower.as_str(), "local" | "system") {
            return Ok(Self::Local);
        }
        if matches!(lower.as_str(), "utc" | "z" | "gmt" | "etc/utc" | "etc/gmt") {
            return Ok(Self::Fixed(zero_offset()));
        }

        // `UTC+2` / `GMT-05:00` are accepted spellings of a numeric offset.
        let offset_part = lower
            .strip_prefix("utc")
            .or_else(|| lower.strip_prefix("gmt"))
            .unwrap_or(lower.as_str());

        let (sign, digits) = match offset_part.as_bytes().first() {
            Some(b'+') => (1_i64, &offset_part[1..]),
            Some(b'-') => (-1_i64, &offset_part[1..]),
            _ => {
                return Err(TimeZoneError::UnsupportedZone {
                    value: trimmed.to_string(),
                });
            }
        };

        let seconds = parse_offset_seconds(digits).ok_or_else(|| TimeZoneError::InvalidOffset {
            value: trimmed.to_string(),
        })?;
        let total = sign * seconds;
        let offset = if total >= 0 {
            FixedOffset::east_opt(total as i32)
        } else {
            FixedOffset::west_opt((-total) as i32)
        };
        offset
            .map(Self::Fixed)
            .ok_or_else(|| TimeZoneError::InvalidOffset {
                value: trimmed.to_string(),
            })
    }
}

fn zero_offset() -> FixedOffset {
    FixedOffset::east_opt(0).expect("zero offset is always valid")
}

/// Parses `HH`, `HHMM`, `HH:MM` or `HH:MM:SS` into seconds.
fn parse_offset_seconds(digits: &str) -> Option<i64> {
    let (hours, minutes, seconds) = if let Some((hours, rest)) = digits.split_once(':') {
        match rest.split_once(':') {
            Some((minutes, seconds)) => (hours, minutes, seconds),
            None => (hours, rest, "0"),
        }
    } else {
        if !digits.is_ascii() {
            return None;
        }
        match digits.len() {
            1 | 2 => (digits, "0", "0"),
            4 => (&digits[0..2], &digits[2..4], "0"),
            6 => (&digits[0..2], &digits[2..4], &digits[4..6]),
            _ => return None,
        }
    };

    let hours: i64 = hours.parse().ok()?;
    let minutes: i64 = minutes.parse().ok()?;
    let seconds: i64 = seconds.parse().ok()?;
    if !(0..=24).contains(&hours) || minutes > 59 || seconds > 59 {
        return None;
    }
    Some(hours * 3600 + minutes * 60 + seconds)
}

impl Serialize for ClientTimeZone {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for ClientTimeZone {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        value.parse().map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Timelike};

    fn utc(y: i32, m: u32, d: u32, h: u32, min: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(y, m, d, h, min, 0).unwrap()
    }

    #[test]
    fn test_parse_supported_zones() {
        assert_eq!(
            "local".parse::<ClientTimeZone>().unwrap(),
            ClientTimeZone::Local
        );
        assert_eq!(
            "SYSTEM".parse::<ClientTimeZone>().unwrap(),
            ClientTimeZone::Local
        );
        assert_eq!(
            " UTC ".parse::<ClientTimeZone>().unwrap(),
            ClientTimeZone::Fixed(zero_offset())
        );
        assert_eq!(
            "GMT".parse::<ClientTimeZone>().unwrap(),
            ClientTimeZone::Fixed(zero_offset())
        );
        assert_eq!(
            "+02:00".parse::<ClientTimeZone>().unwrap(),
            ClientTimeZone::Fixed(FixedOffset::east_opt(2 * 3600).unwrap())
        );
        assert_eq!(
            "-0530".parse::<ClientTimeZone>().unwrap(),
            ClientTimeZone::Fixed(FixedOffset::west_opt(5 * 3600 + 30 * 60).unwrap())
        );
        assert_eq!(
            "UTC+2".parse::<ClientTimeZone>().unwrap(),
            ClientTimeZone::Fixed(FixedOffset::east_opt(2 * 3600).unwrap())
        );
        assert_eq!(
            "+05:30:30".parse::<ClientTimeZone>().unwrap(),
            ClientTimeZone::Fixed(FixedOffset::east_opt(5 * 3600 + 30 * 60 + 30).unwrap())
        );
    }

    #[test]
    fn test_iana_names_are_rejected_explicitly() {
        let err = "Europe/Warsaw".parse::<ClientTimeZone>().unwrap_err();
        assert!(matches!(err, TimeZoneError::UnsupportedZone { .. }));
        assert!(
            err.to_string().contains("IANA"),
            "error must explain the limitation: {err}"
        );

        assert!(matches!(
            "".parse::<ClientTimeZone>().unwrap_err(),
            TimeZoneError::Empty
        ));
        assert!(matches!(
            "+25:00".parse::<ClientTimeZone>().unwrap_err(),
            TimeZoneError::InvalidOffset { .. }
        ));
        assert!(matches!(
            "+02:60".parse::<ClientTimeZone>().unwrap_err(),
            TimeZoneError::InvalidOffset { .. }
        ));
        assert!(matches!(
            "2".parse::<ClientTimeZone>().unwrap_err(),
            TimeZoneError::UnsupportedZone { .. }
        ));
    }

    #[test]
    fn test_at_utc_converts_to_configured_zone() {
        let zone: ClientTimeZone = "+05:00".parse().unwrap();
        let local = zone.at_utc(utc(2026, 9, 7, 10, 0));
        assert_eq!(local.hour(), 15);
        assert_eq!(local.offset().local_minus_utc(), 5 * 3600);

        let zone: ClientTimeZone = "-05:30".parse().unwrap();
        let local = zone.at_utc(utc(2026, 9, 7, 10, 0));
        assert_eq!(local.hour(), 4);
        assert_eq!(local.minute(), 30);
    }

    #[test]
    fn test_display_round_trips() {
        for raw in ["local", "+02:00", "-05:30", "UTC"] {
            let zone: ClientTimeZone = raw.parse().unwrap();
            let printed = zone.to_string();
            assert_eq!(
                printed.parse::<ClientTimeZone>().unwrap(),
                zone,
                "serialized value must parse back"
            );
        }
    }

    #[test]
    fn test_serde_round_trip() {
        use crate::config::ClientsConfig;

        let parsed: ClientsConfig = toml::from_str("timezone = \"+05:00\"").unwrap();
        assert_eq!(parsed.timezone.to_string(), "+05:00");

        let default: ClientsConfig = toml::from_str("").unwrap();
        assert!(default.timezone.is_local());
        let serialized = toml::to_string(&default).unwrap();
        assert!(
            !serialized.contains("timezone"),
            "the default zone is omitted from serialized config: {serialized:?}"
        );
        let reparsed: ClientsConfig = toml::from_str(&serialized).unwrap();
        assert!(reparsed.timezone.is_local());
    }
}
