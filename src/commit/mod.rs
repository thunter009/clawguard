use regex::Regex;
use std::fmt;

/// Conventional commit types recognized by the normalizer.
const VALID_TYPES: &[&str] = &[
    "feat", "fix", "docs", "style", "refactor", "test", "chore", "perf", "ci", "build",
];

/// Result of normalizing a commit message.
#[derive(Debug, Clone)]
pub struct NormalizeResult {
    #[allow(dead_code)]
    pub original: String,
    pub normalized: String,
    pub changes: Vec<String>,
}

impl fmt::Display for NormalizeResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.changes.is_empty() {
            write!(f, "Already normalized")?;
        } else {
            for c in &self.changes {
                writeln!(f, "  - {}", c)?;
            }
        }
        Ok(())
    }
}

/// Validation error for commit messages that cannot be normalized.
#[derive(Debug, Clone)]
pub struct CommitError {
    pub message: String,
    pub hints: Vec<String>,
}

impl fmt::Display for CommitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)?;
        for h in &self.hints {
            write!(f, "\n  hint: {}", h)?;
        }
        Ok(())
    }
}

/// Normalizes commit messages to conventional commit format.
///
/// Format: `type(scope): description`
///
/// Handles:
/// - Lowercasing the type prefix
/// - Adding missing type (defaults to `chore`)
/// - Ensuring colon+space after type/scope
/// - Lowercasing first character of description
/// - Stripping trailing periods from subject line
/// - Preserving body and trailers
pub fn normalize(raw: &str) -> Result<NormalizeResult, CommitError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(CommitError {
            message: "empty commit message".to_string(),
            hints: vec!["provide a subject line".to_string()],
        });
    }

    // Split into subject + rest (body/trailers)
    let (subject, rest) = split_subject_body(trimmed);

    if subject.is_empty() {
        return Err(CommitError {
            message: "empty subject line".to_string(),
            hints: vec!["first line must contain a description".to_string()],
        });
    }

    let mut changes: Vec<String> = Vec::new();

    // Try to parse existing conventional commit prefix
    let conv_re = Regex::new(r"^(?i)([a-z]+)(\([^)]*\))?\s*:\s*(.*)$").unwrap();

    let (commit_type, scope, description) = if let Some(caps) = conv_re.captures(&subject) {
        let raw_type = caps.get(1).unwrap().as_str();
        let scope = caps.get(2).map(|m| m.as_str().to_string());
        let desc = caps.get(3).unwrap().as_str().to_string();

        let lower_type = raw_type.to_lowercase();
        if raw_type != lower_type {
            changes.push(format!(
                "lowercased type '{}' -> '{}'",
                raw_type, lower_type
            ));
        }

        if !VALID_TYPES.contains(&lower_type.as_str()) {
            return Err(CommitError {
                message: format!("unknown commit type '{}'", lower_type),
                hints: vec![format!("valid types: {}", VALID_TYPES.join(", "))],
            });
        }

        (lower_type, scope, desc)
    } else {
        // No conventional prefix -- infer type from keywords
        let inferred = infer_type(&subject);
        changes.push(format!("added type '{}'", inferred));
        (inferred, None, subject.clone())
    };

    // Normalize description
    let mut desc = description.trim().to_string();

    // Strip trailing period from subject
    if desc.ends_with('.') {
        desc = desc.trim_end_matches('.').to_string();
        changes.push("removed trailing period".to_string());
    }

    // Lowercase first char of description
    if let Some(first) = desc.chars().next() {
        if first.is_uppercase() {
            let lowered = format!("{}{}", first.to_lowercase(), &desc[first.len_utf8()..]);
            if lowered != desc {
                changes.push("lowercased description start".to_string());
                desc = lowered;
            }
        }
    }

    // Enforce max subject length (72 chars)
    let scope_str = scope.as_deref().unwrap_or("");
    let prefix = format!("{}{}: ", commit_type, scope_str);
    let max_desc_len = 72_usize.saturating_sub(prefix.len());
    if desc.len() > max_desc_len {
        desc = desc[..max_desc_len].to_string();
        changes.push("truncated subject to 72 chars".to_string());
    }

    let normalized_subject = format!("{}{}: {}", commit_type, scope_str, desc);

    // Rebuild full message
    let normalized = if rest.is_empty() {
        normalized_subject
    } else {
        format!("{}\n\n{}", normalized_subject, rest)
    };

    Ok(NormalizeResult {
        original: raw.to_string(),
        normalized,
        changes,
    })
}

/// Validate that a commit message has required trailers.
pub fn validate_trailers(message: &str, required: &[&str]) -> Vec<String> {
    let mut missing = Vec::new();
    for trailer in required {
        let pattern = format!("{}:", trailer);
        if !message.lines().any(|line| line.starts_with(&pattern)) {
            missing.push(trailer.to_string());
        }
    }
    missing
}

/// Split message into subject line and body (everything after first blank line).
fn split_subject_body(message: &str) -> (String, String) {
    if let Some(pos) = message.find("\n\n") {
        let subject = message[..pos]
            .lines()
            .next()
            .unwrap_or("")
            .trim()
            .to_string();
        let rest = message[pos + 2..].trim().to_string();
        (subject, rest)
    } else {
        let subject = message.lines().next().unwrap_or("").trim().to_string();
        (subject, String::new())
    }
}

/// Infer commit type from description keywords.
fn infer_type(description: &str) -> String {
    let lower = description.to_lowercase();

    if lower.starts_with("add ") || lower.starts_with("implement ") || lower.contains("new ") {
        return "feat".to_string();
    }
    if lower.starts_with("fix ") || lower.contains("bug") || lower.contains("patch") {
        return "fix".to_string();
    }
    if lower.starts_with("doc") || lower.starts_with("readme") || lower.contains("changelog") {
        return "docs".to_string();
    }
    if lower.starts_with("refactor") || lower.contains("rename") || lower.contains("move ") {
        return "refactor".to_string();
    }
    if lower.starts_with("test") || lower.contains("spec") || lower.contains("coverage") {
        return "test".to_string();
    }
    if lower.starts_with("ci") || lower.contains("pipeline") || lower.contains("github action") {
        return "ci".to_string();
    }
    if lower.starts_with("perf") || lower.contains("optimi") || lower.contains("speed") {
        return "perf".to_string();
    }
    if lower.starts_with("build") || lower.contains("cargo") || lower.contains("dependenc") {
        return "build".to_string();
    }
    if lower.starts_with("style") || lower.contains("format") || lower.contains("lint") {
        return "style".to_string();
    }

    "chore".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn already_normalized() {
        let r = normalize("feat: add login endpoint").unwrap();
        assert_eq!(r.normalized, "feat: add login endpoint");
        assert!(r.changes.is_empty());
    }

    #[test]
    fn with_scope() {
        let r = normalize("fix(auth): handle expired tokens").unwrap();
        assert_eq!(r.normalized, "fix(auth): handle expired tokens");
        assert!(r.changes.is_empty());
    }

    #[test]
    fn uppercase_type() {
        let r = normalize("FEAT: new widget").unwrap();
        assert_eq!(r.normalized, "feat: new widget");
        assert!(r.changes.iter().any(|c| c.contains("lowercased type")));
    }

    #[test]
    fn no_prefix_infer_feat() {
        let r = normalize("add user authentication").unwrap();
        assert_eq!(r.normalized, "feat: add user authentication");
    }

    #[test]
    fn no_prefix_infer_fix() {
        let r = normalize("fix crash on empty input").unwrap();
        assert_eq!(r.normalized, "fix: fix crash on empty input");
    }

    #[test]
    fn trailing_period_removed() {
        let r = normalize("chore: update deps.").unwrap();
        assert_eq!(r.normalized, "chore: update deps");
        assert!(r.changes.iter().any(|c| c.contains("trailing period")));
    }

    #[test]
    fn uppercase_description() {
        let r = normalize("feat: Add new feature").unwrap();
        assert_eq!(r.normalized, "feat: add new feature");
        assert!(r
            .changes
            .iter()
            .any(|c| c.contains("lowercased description")));
    }

    #[test]
    fn preserves_body_and_trailers() {
        let msg = "feat: add auth\n\nDetailed body here.\n\nSigned-off-by: dev@example.com";
        let r = normalize(msg).unwrap();
        assert!(r.normalized.contains("Detailed body here."));
        assert!(r.normalized.contains("Signed-off-by:"));
    }

    #[test]
    fn empty_message_errors() {
        assert!(normalize("").is_err());
        assert!(normalize("   ").is_err());
    }

    #[test]
    fn unknown_type_errors() {
        let r = normalize("yolo: something");
        assert!(r.is_err());
    }

    #[test]
    fn missing_colon_spacing() {
        let r = normalize("feat:no space").unwrap();
        assert_eq!(r.normalized, "feat: no space");
    }

    #[test]
    fn infer_docs() {
        let r = normalize("document the API endpoints").unwrap();
        assert_eq!(r.normalized, "docs: document the API endpoints");
    }

    #[test]
    fn infer_refactor() {
        let r = normalize("refactor database layer").unwrap();
        assert_eq!(r.normalized, "refactor: refactor database layer");
    }

    #[test]
    fn infer_chore_fallback() {
        let r = normalize("bump version to 2.0").unwrap();
        assert_eq!(r.normalized, "chore: bump version to 2.0");
    }

    #[test]
    fn validate_trailers_missing() {
        let msg = "feat: something\n\nSigned-off-by: dev";
        let missing = validate_trailers(msg, &["Signed-off-by", "Reviewed-by"]);
        assert_eq!(missing, vec!["Reviewed-by"]);
    }

    #[test]
    fn validate_trailers_all_present() {
        let msg = "feat: x\n\nFoo: a\nBar: b";
        let missing = validate_trailers(msg, &["Foo", "Bar"]);
        assert!(missing.is_empty());
    }

    #[test]
    fn long_subject_truncated() {
        let long_desc = "a".repeat(100);
        let msg = format!("feat: {}", long_desc);
        let r = normalize(&msg).unwrap();
        assert!(r.normalized.len() <= 72);
        assert!(r.changes.iter().any(|c| c.contains("truncated")));
    }
}
