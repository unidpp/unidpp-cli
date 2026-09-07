//! Verifier output rendering: grades, findings, readings, and the
//! fixed-width tables the flagship `verify` command prints.

use std::fmt::Write as _;

/// The grade of one check or of the overall verdict — the CLI-side
/// mirror of the core's degradation ladder (pass / degraded-with-reason
/// / fail, never a bare boolean).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
pub enum Grade {
    /// Check (or verdict) passed.
    Pass,
    /// Explicitly degraded — the reason is always carried.
    Degraded,
    /// Failed outright (integrity).
    Fail,
}

impl Grade {
    /// Uppercase table label.
    pub fn label(self) -> &'static str {
        match self {
            Grade::Pass => "PASS",
            Grade::Degraded => "DEGRADED",
            Grade::Fail => "FAIL",
        }
    }

    /// Process exit code for this grade.
    pub fn exit_code(self) -> u8 {
        match self {
            Grade::Pass => crate::exit::PASS,
            Grade::Degraded => crate::exit::DEGRADED,
            Grade::Fail => crate::exit::FAIL,
        }
    }

    /// The worse of two grades.
    pub fn worst(self, other: Grade) -> Grade {
        if self >= other {
            self
        } else {
            other
        }
    }

    /// Lowercase token for `--json` output.
    pub fn token(self) -> &'static str {
        match self {
            Grade::Pass => "pass",
            Grade::Degraded => "degraded",
            Grade::Fail => "fail",
        }
    }
}

/// One verification finding: a named check, its grade, and the
/// officer-facing detail.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Finding {
    /// Check name (`schema/decode`, `signature/ecdsa-p256`, …).
    pub check: String,
    /// Outcome of this check.
    pub grade: Grade,
    /// Why (always populated, especially for degradations).
    pub detail: String,
}

impl Finding {
    /// Construct a finding.
    pub fn new(check: impl Into<String>, grade: Grade, detail: impl Into<String>) -> Finding {
        Finding {
            check: check.into(),
            grade,
            detail: detail.into(),
        }
    }
}

/// Render a fixed-width table: header row, then one row per entry,
/// columns aligned on their widest cell. The `grade` column (if any)
/// is the only one whose width varies with content — alignment is
/// computed, not hardcoded, so tables stay formal at any detail length.
pub fn render_table(headers: &[&str], rows: &[Vec<String>]) -> String {
    let column_count = headers.len();
    let mut widths: Vec<usize> = headers.iter().map(|h| h.len()).collect();
    for row in rows {
        for (i, cell) in row.iter().take(column_count).enumerate() {
            widths[i] = widths[i].max(cell.len());
        }
    }
    let mut out = String::new();
    let mut line = |cells: &[String]| {
        for (i, cell) in cells.iter().take(column_count).enumerate() {
            let _ = write!(out, "  {:<width$}", cell, width = widths[i]);
        }
        out.push('\n');
    };
    line(&headers.iter().map(|h| h.to_string()).collect::<Vec<_>>());
    let ruler: Vec<String> = widths.iter().map(|w| "-".repeat(*w)).collect();
    line(&ruler);
    for row in rows {
        line(row);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grade_ordering_and_codes() {
        assert!(Grade::Fail > Grade::Degraded);
        assert!(Grade::Degraded > Grade::Pass);
        assert_eq!(Grade::Pass.worst(Grade::Degraded), Grade::Degraded);
        assert_eq!(Grade::Fail.worst(Grade::Pass), Grade::Fail);
        assert_eq!(Grade::Degraded.exit_code(), 1);
        assert_eq!(Grade::Degraded.token(), "degraded");
        assert_eq!(Grade::Degraded.label(), "DEGRADED");
    }

    #[test]
    fn table_aligns_on_widest_cell() {
        let table = render_table(
            &["CHECK", "GRADE", "DETAIL"],
            &[
                vec!["sig".into(), "PASS".into(), "ok".into()],
                vec![
                    "freshness".into(),
                    "DEGRADED".into(),
                    "stale since yesterday".into(),
                ],
            ],
        );
        let lines: Vec<&str> = table.lines().collect();
        assert_eq!(lines.len(), 4);
        // Column starts (byte offsets where a run of non-space begins),
        // first three columns only: identical across header, ruler, and
        // every data row — that is what "formal table" means here.
        let col_starts = |line: &str| -> Vec<usize> {
            let mut out = Vec::new();
            let mut in_run = false;
            for (i, c) in line.char_indices() {
                if c != ' ' && !in_run {
                    out.push(i);
                    in_run = true;
                } else if c == ' ' {
                    in_run = false;
                }
            }
            out
        };
        let header = col_starts(lines[0]);
        assert_eq!(header.len(), 3);
        assert_eq!(&col_starts(lines[1])[..3], &header[..]);
        assert_eq!(&col_starts(lines[2])[..3], &header[..]);
        assert_eq!(&col_starts(lines[3])[..3], &header[..]);
        assert!(lines[2].contains("sig"));
        assert!(lines[3].contains("freshness"));
        assert!(lines[3].contains("DEGRADED"));
    }
}
