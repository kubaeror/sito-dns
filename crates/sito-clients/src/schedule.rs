//! Schedule parsing and lazy query-time evaluation using `croner`.
//!
//! Supports 6-field (seconds-level) and 5-field (standard) cron expressions,
//! with descriptive error messages pinpointing invalid field numbers, and
//! deterministic window boundary evaluation.

use chrono::{DateTime, Utc};
use croner::Cron;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::str::FromStr;
use thiserror::Error;

/// Error encountered while parsing or validating a cron schedule.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ScheduleError {
    #[error("cron expression '{expression}' is invalid: {message}")]
    InvalidSyntax {
        expression: String,
        message: String,
        field_number: Option<usize>,
        field_name: Option<String>,
    },
}

impl ScheduleError {
    pub fn field_error(
        expression: impl Into<String>,
        field_number: usize,
        field_name: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        let name = field_name.into();
        let msg = message.into();
        Self::InvalidSyntax {
            expression: expression.into(),
            message: format!("field {field_number} ({name}): {msg}"),
            field_number: Some(field_number),
            field_name: Some(name),
        }
    }

    pub fn general_error(expression: impl Into<String>, message: impl Into<String>) -> Self {
        Self::InvalidSyntax {
            expression: expression.into(),
            message: message.into(),
            field_number: None,
            field_name: None,
        }
    }
}

/// A parsed schedule evaluated at query time against timestamps.
#[derive(Debug, Clone)]
pub struct Schedule {
    raw: String,
    cron: Cron,
    window_cron: Option<Cron>,
}

impl PartialEq for Schedule {
    fn eq(&self, other: &Self) -> bool {
        self.raw == other.raw
    }
}

impl Eq for Schedule {}

impl Schedule {
    /// Parse a cron schedule expression.
    ///
    /// Accepts 5-field (`min hour dom mon dow`) or 6-field (`sec min hour dom mon dow`)
    /// cron expressions. Validates ranges and syntax, returning an error specifying
    /// the field number if validation fails.
    pub fn parse(expression: &str) -> Result<Self, ScheduleError> {
        let trimmed = expression.trim();
        if trimmed.is_empty() {
            return Err(ScheduleError::general_error(
                expression,
                "schedule expression cannot be empty",
            ));
        }

        validate_cron_fields(trimmed)?;

        let cron = Cron::from_str(trimmed).map_err(|e| {
            // Attempt to attribute to a specific field if possible
            classify_croner_error(trimmed, &e)
        })?;

        // Construct window cron for range-style expressions where sec/min might be 0
        let window_cron = build_window_cron(trimmed);

        Ok(Self {
            raw: trimmed.to_string(),
            cron,
            window_cron,
        })
    }

    /// Check if the schedule is active at the specified timestamp.
    pub fn is_active(&self, timestamp: &DateTime<Utc>) -> bool {
        if let Some(ref window) = self.window_cron {
            if let Ok(matching) = window.is_time_matching(timestamp) {
                if matching {
                    return true;
                }
            }
        }

        self.cron.is_time_matching(timestamp).unwrap_or(false)
    }

    /// Get the original raw cron string.
    pub fn as_str(&self) -> &str {
        &self.raw
    }
}

impl FromStr for Schedule {
    type Err = ScheduleError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl fmt::Display for Schedule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.raw)
    }
}

impl Serialize for Schedule {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.raw)
    }
}

impl<'de> Deserialize<'de> for Schedule {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Self::parse(&s).map_err(serde::de::Error::custom)
    }
}

/// Validates individual fields of a cron expression and reports descriptive
/// errors with field numbers if values exceed legal boundaries.
fn validate_cron_fields(expr: &str) -> Result<(), ScheduleError> {
    if expr.starts_with('@') {
        // Special macros like @daily, @hourly
        return Ok(());
    }

    let fields: Vec<&str> = expr.split_whitespace().collect();
    let num_fields = fields.len();

    if !(5..=7).contains(&num_fields) {
        return Err(ScheduleError::general_error(
            expr,
            format!("cron expression must have 5, 6, or 7 fields, got {num_fields}"),
        ));
    }

    // Determine field semantics
    let (sec_idx, min_idx, hour_idx, dom_idx, mon_idx, _dow_idx) = if num_fields == 5 {
        (None, 0, 1, 2, 3, 4)
    } else {
        (Some(0), 1, 2, 3, 4, 5)
    };

    if let Some(s_idx) = sec_idx {
        validate_numeric_field(expr, fields[s_idx], s_idx + 1, "seconds", 0, 59)?;
    }
    validate_numeric_field(expr, fields[min_idx], min_idx + 1, "minutes", 0, 59)?;
    validate_numeric_field(expr, fields[hour_idx], hour_idx + 1, "hours", 0, 23)?;
    validate_numeric_field(expr, fields[dom_idx], dom_idx + 1, "day of month", 1, 31)?;
    validate_numeric_field(expr, fields[mon_idx], mon_idx + 1, "month", 1, 12)?;

    Ok(())
}

fn validate_numeric_field(
    full_expr: &str,
    field_text: &str,
    field_num: usize,
    field_name: &str,
    min: u32,
    max: u32,
) -> Result<(), ScheduleError> {
    for part in field_text.split(',') {
        let clean = part.trim();
        if clean.is_empty() || clean == "*" || clean == "?" {
            continue;
        }

        // Handle step: e.g. */10 or 5-20/2
        let (range_part, _step) = match clean.split_once('/') {
            Some((l, r)) => {
                if let Ok(step_val) = r.parse::<u32>() {
                    if step_val == 0 {
                        return Err(ScheduleError::field_error(
                            full_expr,
                            field_num,
                            field_name,
                            "step value cannot be zero",
                        ));
                    }
                }
                (l, Some(r))
            }
            None => (clean, None),
        };

        if range_part == "*" {
            continue;
        }

        // Handle range: e.g. 15-21
        if let Some((start_str, end_str)) = range_part.split_once('-') {
            if let Ok(start) = start_str.parse::<u32>() {
                if start < min || start > max {
                    return Err(ScheduleError::field_error(
                        full_expr,
                        field_num,
                        field_name,
                        format!("value {start} is out of bounds ({min}-{max})"),
                    ));
                }
            }
            if let Ok(end) = end_str.parse::<u32>() {
                if end < min || end > max {
                    return Err(ScheduleError::field_error(
                        full_expr,
                        field_num,
                        field_name,
                        format!("value {end} is out of bounds ({min}-{max})"),
                    ));
                }
            }
            continue;
        }

        // Single number
        if let Ok(val) = range_part.parse::<u32>() {
            if val < min || val > max {
                return Err(ScheduleError::field_error(
                    full_expr,
                    field_num,
                    field_name,
                    format!("value {val} is out of bounds ({min}-{max})"),
                ));
            }
        }
    }

    Ok(())
}

fn classify_croner_error(expr: &str, err: &croner::errors::CronError) -> ScheduleError {
    ScheduleError::general_error(expr, format!("{err}"))
}

/// Builds a window-matching Cron expression if the user wrote an interval
/// with `0 0 ...` representing active hours.
fn build_window_cron(expr: &str) -> Option<Cron> {
    if expr.starts_with('@') {
        return None;
    }

    let parts: Vec<&str> = expr.split_whitespace().collect();
    if parts.len() == 6 {
        // [sec, min, hour, dom, mon, dow]
        if parts[0] == "0" && parts[1] == "0" {
            let mut window_parts = parts.clone();
            window_parts[0] = "*";
            window_parts[1] = "*";
            let window_expr = window_parts.join(" ");
            return Cron::from_str(&window_expr).ok();
        } else if parts[0] == "0" && parts[1].contains('-') {
            // e.g. 0 15-30 10 * * *
            let mut window_parts = parts.clone();
            window_parts[0] = "*";
            let window_expr = window_parts.join(" ");
            return Cron::from_str(&window_expr).ok();
        }
    } else if parts.len() == 5 {
        // [min, hour, dom, mon, dow]
        if parts[0] == "0" {
            let mut window_parts = vec!["*", "*"];
            window_parts.extend_from_slice(&parts[1..]);
            let window_expr = window_parts.join(" ");
            return Cron::from_str(&window_expr).ok();
        }

        let mut window_parts = vec!["*"];
        window_parts.extend_from_slice(&parts);
        let window_expr = window_parts.join(" ");
        return Cron::from_str(&window_expr).ok();
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn test_valid_6_field_cron() {
        let schedule = Schedule::parse("0 0 15-21 * * MON-FRI").unwrap();
        assert_eq!(schedule.as_str(), "0 0 15-21 * * MON-FRI");
    }

    #[test]
    fn test_valid_5_field_cron() {
        let schedule = Schedule::parse("*/15 9-17 * * 1-5").unwrap();
        assert_eq!(schedule.as_str(), "*/15 9-17 * * 1-5");
    }

    #[test]
    fn test_bad_cron_rejected_with_field_number() {
        // Bad hour in 6-field cron -> field 3
        let err1 = Schedule::parse("0 0 99 * * *").unwrap_err();
        match err1 {
            ScheduleError::InvalidSyntax {
                field_number,
                message,
                ..
            } => {
                assert_eq!(field_number, Some(3));
                assert!(message.contains("field 3 (hours)"));
                assert!(message.contains("99 is out of bounds"));
            }
        }

        // Bad minute in 5-field cron -> field 1
        let err2 = Schedule::parse("75 * * * *").unwrap_err();
        match err2 {
            ScheduleError::InvalidSyntax {
                field_number,
                message,
                ..
            } => {
                assert_eq!(field_number, Some(1));
                assert!(message.contains("field 1 (minutes)"));
                assert!(message.contains("75 is out of bounds"));
            }
        }

        // Bad day of month in 6-field cron -> field 4
        let err3 = Schedule::parse("0 0 12 35 * *").unwrap_err();
        match err3 {
            ScheduleError::InvalidSyntax {
                field_number,
                message,
                ..
            } => {
                assert_eq!(field_number, Some(4));
                assert!(message.contains("field 4 (day of month)"));
                assert!(message.contains("35 is out of bounds"));
            }
        }

        // Bad month in 6-field cron -> field 5
        let err4 = Schedule::parse("0 0 12 1 15 *").unwrap_err();
        match err4 {
            ScheduleError::InvalidSyntax {
                field_number,
                message,
                ..
            } => {
                assert_eq!(field_number, Some(5));
                assert!(message.contains("field 5 (month)"));
                assert!(message.contains("15 is out of bounds"));
            }
        }

        // Invalid field count
        let err5 = Schedule::parse("too few fields").unwrap_err();
        match err5 {
            ScheduleError::InvalidSyntax {
                field_number,
                message,
                ..
            } => {
                assert_eq!(field_number, None);
                assert!(message.contains("must have 5, 6, or 7 fields"));
            }
        }
    }

    #[test]
    fn test_boundary_toggle_deterministic() {
        // Monday 2026-09-07, schedule active 15:00 to 21:59 UTC on MON-FRI
        let schedule = Schedule::parse("0 0 15-21 * * MON-FRI").unwrap();

        // 1. One second before window opens: 14:59:59 Monday -> inactive
        let t_before = Utc.with_ymd_and_hms(2026, 9, 7, 14, 59, 59).unwrap();
        assert!(!schedule.is_active(&t_before), "14:59:59 must be inactive");

        // 2. Exactly at window opening: 15:00:00 Monday -> active
        let t_start = Utc.with_ymd_and_hms(2026, 9, 7, 15, 0, 0).unwrap();
        assert!(schedule.is_active(&t_start), "15:00:00 must be active");

        // 3. Middle of the window: 17:34:12 Monday -> active
        let t_mid = Utc.with_ymd_and_hms(2026, 9, 7, 17, 34, 12).unwrap();
        assert!(schedule.is_active(&t_mid), "17:34:12 must be active");

        // 4. Last second of the window: 21:59:59 Monday -> active
        let t_end = Utc.with_ymd_and_hms(2026, 9, 7, 21, 59, 59).unwrap();
        assert!(schedule.is_active(&t_end), "21:59:59 must be active");

        // 5. One second after window closes: 22:00:00 Monday -> inactive
        let t_after = Utc.with_ymd_and_hms(2026, 9, 7, 22, 0, 0).unwrap();
        assert!(!schedule.is_active(&t_after), "22:00:00 must be inactive");

        // 6. Weekend check: 16:00:00 Saturday 2026-09-12 -> inactive
        let t_weekend = Utc.with_ymd_and_hms(2026, 9, 12, 16, 0, 0).unwrap();
        assert!(!schedule.is_active(&t_weekend), "Saturday must be inactive");
    }

    #[test]
    fn test_minute_level_boundary_toggle() {
        // Active between 10:15 and 10:30 (inclusive) every day
        let schedule = Schedule::parse("0 15-30 10 * * *").unwrap();

        let t1 = Utc.with_ymd_and_hms(2026, 9, 7, 10, 14, 59).unwrap();
        assert!(!schedule.is_active(&t1));

        let t2 = Utc.with_ymd_and_hms(2026, 9, 7, 10, 15, 0).unwrap();
        assert!(schedule.is_active(&t2));

        let t3 = Utc.with_ymd_and_hms(2026, 9, 7, 10, 30, 59).unwrap();
        assert!(schedule.is_active(&t3));

        let t4 = Utc.with_ymd_and_hms(2026, 9, 7, 10, 31, 0).unwrap();
        assert!(!schedule.is_active(&t4));
    }
}
