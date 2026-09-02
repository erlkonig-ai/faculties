//! Collection-native Habit ontology.
//!
//! A habit is one immutable standing intention. Completions are independent
//! intrinsic occurrences, while pause/resume assertions form an intrinsic
//! predecessor DAG. Set union therefore preserves concurrent assertions and
//! never asks a timestamp or collection-record order to choose current state.

use triblespace::macros::id_hex;
use triblespace::prelude::*;

/// Stable extrinsic scope of the authored Habit collection.
///
/// Minted with `trible genid` on 2026-08-11:
/// `1BAEE6DB7A2AE4343E611774E04DEE50`.
pub const DEFAULT_SCOPE_ID: Id = id_hex!("1BAEE6DB7A2AE4343E611774E04DEE50");

/// Immutable standing-intention definition.
///
/// Retained from CC's unmerged Habit lineage; its meaning is unchanged.
pub const KIND_HABIT_ID: Id = id_hex!("FBCAA4D17D2BD375FA50188254689B06");

/// Completion occurrence. A habit's cooldown is measured from these facts.
///
/// Retained from CC's unmerged Habit lineage; its meaning is unchanged.
pub const KIND_DONE_ID: Id = id_hex!("406D754E3673FEAAEBF39365DB28383A");

/// One active/paused assertion in a habit-local predecessor DAG.
///
/// Retained from CC's unmerged Habit lineage. V4 adds
/// `metadata::supersedes` predecessors instead of timestamp arbitration.
pub const KIND_STATE_ID: Id = id_hex!("A55E1014B229CB8A8B2F92FD03236F91");

pub const STATE_PAUSED: &str = "paused";
pub const STATE_ACTIVE: &str = "active";

pub mod attrs {
    use super::*;

    attributes! {
        /// Short command-facing label for a standing intention.
        "4AB58053472C4163C39C9A4047F8111E" unsafe as label: inlineencodings::ShortString;

        /// Text shown when the intention is due.
        "1E82BD7E8EFEA00FD3FAB3ECEFD0BA33" unsafe as nudge:
            inlineencodings::Handle<blobencodings::UTF8String>;

        /// Author-written condition source, parsed when the catalog is read.
        "134ECC925E8547B46AF67D6DC29B5F5C" unsafe as condition:
            inlineencodings::Handle<blobencodings::UTF8String>;

        /// Habit definition governed by a completion or state assertion.
        "F00FAA4B44DB1E79E36055410B476C42" unsafe as of: inlineencodings::GenId;

        /// `active` or `paused` on a state assertion.
        "5C1E4BD13E8FA4633F286CD5B33BCAC7" unsafe as state: inlineencodings::ShortString;

        /// Executable the standing intention carries with it, addressed by
        /// content hash. A habit whose predicate lives in the pile is the same
        /// habit in every window; one whose predicate is an absolute path is a
        /// habit only the authoring machine can ever evaluate.
        ///
        /// Anchor minted with `trible genid` on 2026-08-13:
        /// `96EC24A8226E9D848A4905D982485678`. Declared in the anchored form
        /// (no `unsafe`) because this attribute has no published byte identity
        /// to preserve — the encoding therefore participates in its id.
        "96EC24A8226E9D848A4905D982485678" as script:
            inlineencodings::Handle<blobencodings::RawBytes>;
    }
}

/// Placeholder inside a `when` command standing for the habit's own carried
/// script.
///
/// Evaluation expands it to the local path of the materialized blob, so one
/// condition text stays meaningful on every machine holding the collection.
/// It is recognized only as the leading command word; occurrences in later
/// arguments, comments, quotes, or longer words stay literal. A real command
/// named `script` (BSD's terminal recorder) keeps working because it carries
/// no `@`.
pub const SCRIPT_TOKEN: &str = "@script";

/// Labels are inline values and command addresses. Refuse overflow explicitly
/// instead of allowing the encoder to panic.
pub const MAX_LABEL_BYTES: usize = 30;

/// Default cooldown for an open shell predicate.
pub const DEFAULT_COOLDOWN_SECS: i64 = 60 * 60;

/// A time-of-day habit stays satisfied for almost one day. The one-hour
/// tolerance prevents a slightly later observation from skipping a day.
pub const DAILY_COOLDOWN_SECS: i64 = 23 * 60 * 60;

/// One parsed condition: a predicate command and a completion cooldown.
///
/// The command is deliberately not optional. An interval is the always-true
/// predicate plus a cooldown, so every surface form follows the same path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Condition {
    pub cooldown_secs: i64,
    pub command: String,
}

impl Condition {
    /// Parse `every <duration>`, `daily at <HH:MM>`, or `when <command>`.
    /// `every` and `daily` also accept a trailing cooldown override.
    pub fn parse(source: &str) -> Result<Self, String> {
        let source = source.trim();
        let (head, cooldown_override) = match source.rfind("cooldown ") {
            // Inside `when`, `cooldown` belongs to the shell source. Treating
            // it as syntax would silently truncate an arbitrary command.
            Some(at) if !source.starts_with("when ") => {
                let secs = parse_duration(source[at + "cooldown ".len()..].trim())?;
                (source[..at].trim(), Some(secs))
            }
            _ => (source, None),
        };

        let (command, default_cooldown) = if let Some(rest) = head.strip_prefix("every ") {
            ("true".to_owned(), parse_duration(rest.trim())?)
        } else if let Some(rest) = head.strip_prefix("daily at ") {
            let (hour, minute) = parse_hhmm(rest.trim())?;
            (
                format!("[ \"$(date +%H%M)\" -ge {hour:02}{minute:02} ]"),
                DAILY_COOLDOWN_SECS,
            )
        } else if let Some(rest) = head.strip_prefix("when ") {
            let command = rest.trim();
            if command.is_empty() {
                return Err("`when` needs a command".into());
            }
            (command.to_owned(), DEFAULT_COOLDOWN_SECS)
        } else {
            return Err(format!(
                "unrecognized condition {source:?} — expected `every <duration>`, \
                 `daily at <HH:MM>`, or `when <command>`"
            ));
        };

        Ok(Self {
            cooldown_secs: cooldown_override.unwrap_or(default_cooldown),
            command,
        })
    }

    /// Suffix after a leading `@script` command word, when present.
    ///
    /// The token is deliberately grammar, not substring replacement: only the
    /// first shell word may name the carried executable. Text in arguments,
    /// comments, quotes, or longer words such as `@scripture` stays literal.
    pub fn script_suffix(&self) -> Option<&str> {
        let suffix = self.command.strip_prefix(SCRIPT_TOKEN)?;
        match suffix.chars().next() {
            None => Some(suffix),
            Some(character) if character.is_whitespace() => Some(suffix),
            Some(_) => None,
        }
    }

    /// Whether the predicate delegates to the habit's own carried script.
    /// `every` and `daily at` synthesize other leading command words, so only
    /// an authored `when @script …` can answer yes.
    pub fn uses_script(&self) -> bool {
        self.script_suffix().is_some()
    }

    /// Whether no completion lies inside this condition's cooldown window.
    /// A never-completed habit is immediately eligible.
    pub fn cooled_down(&self, now_secs: i64, completed_at: impl IntoIterator<Item = i64>) -> bool {
        completed_at
            .into_iter()
            .all(|done| now_secs.saturating_sub(done) >= self.cooldown_secs)
    }
}

/// Parse `90s`, `30m`, `24h`, or `7d` into seconds.
pub fn parse_duration(text: &str) -> Result<i64, String> {
    let text = text.trim();
    let split = text
        .find(|character: char| !character.is_ascii_digit())
        .ok_or_else(|| format!("duration {text:?} needs a unit (s/m/h/d)"))?;
    let (digits, unit) = text.split_at(split);
    let value: i64 = digits
        .parse()
        .map_err(|_| format!("bad duration {text:?}"))?;
    if value <= 0 {
        return Err(format!("duration {text:?} must be positive"));
    }
    let scale = match unit.trim() {
        "s" => 1,
        "m" => 60,
        "h" => 60 * 60,
        "d" => 24 * 60 * 60,
        other => return Err(format!("unknown duration unit {other:?} (use s/m/h/d)")),
    };
    value
        .checked_mul(scale)
        .ok_or_else(|| format!("duration {text:?} is too large"))
}

fn parse_hhmm(text: &str) -> Result<(u32, u32), String> {
    let (hours, minutes) = text
        .split_once(':')
        .ok_or_else(|| format!("expected HH:MM, got {text:?}"))?;
    let hour: u32 = hours
        .trim()
        .parse()
        .map_err(|_| format!("bad hour in {text:?}"))?;
    let minute: u32 = minutes
        .trim()
        .parse()
        .map_err(|_| format!("bad minute in {text:?}"))?;
    if hour > 23 || minute > 59 {
        return Err(format!("{text:?} is not a valid time of day"));
    }
    Ok((hour, minute))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_is_an_always_true_condition_not_an_optional_command() {
        let condition = Condition::parse("every 24h").unwrap();
        assert_eq!(condition.command, "true");
        assert_eq!(condition.cooldown_secs, 24 * 60 * 60);
    }

    #[test]
    fn daily_and_shell_forms_share_the_same_shape() {
        let daily = Condition::parse("daily at 09:30").unwrap();
        assert_eq!(daily.command, "[ \"$(date +%H%M)\" -ge 0930 ]");
        assert_eq!(daily.cooldown_secs, DAILY_COOLDOWN_SECS);

        let shell = Condition::parse("when git status --porcelain | grep -q .").unwrap();
        assert_eq!(shell.command, "git status --porcelain | grep -q .");
        assert_eq!(shell.cooldown_secs, DEFAULT_COOLDOWN_SECS);
    }

    #[test]
    fn cooldown_is_completion_relative_and_checks_the_whole_set() {
        let condition = Condition::parse("every 1h").unwrap();
        assert!(condition.cooled_down(10_000, []));
        assert!(condition.cooled_down(10_000, [1_000, 6_400]));
        assert!(!condition.cooled_down(10_000, [1_000, 9_000]));
    }

    #[test]
    fn only_an_authored_when_can_reach_the_carried_script() {
        assert!(Condition::parse("when @script --due")
            .unwrap()
            .uses_script());
        assert!(Condition::parse("when @script | grep -q .")
            .unwrap()
            .uses_script());
        for literal in [
            "when echo @script",
            "when true # @script",
            "when @scripture --chapter 1",
            "when \"@script\" --due",
        ] {
            assert!(
                !Condition::parse(literal).unwrap().uses_script(),
                "{literal}"
            );
        }
        // A real `script(1)` invocation carries no `@` and stays untouched.
        assert!(!Condition::parse("when script -q /dev/null true")
            .unwrap()
            .uses_script());
        assert!(!Condition::parse("every 1h").unwrap().uses_script());
        assert!(!Condition::parse("daily at 09:30").unwrap().uses_script());
    }

    #[test]
    fn malformed_conditions_fail_loud() {
        for source in [
            "",
            "hourly",
            "every",
            "every 0h",
            "every 5x",
            "daily at 25:00",
            "when ",
        ] {
            assert!(Condition::parse(source).is_err(), "{source:?}");
        }
    }
}
