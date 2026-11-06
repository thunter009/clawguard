use regex::Regex;
use std::fmt;

const ALLOWED_TYPES: &[&str] = &[
    "feat", "fix", "docs", "style", "refactor", "perf", "test", "build", "ci", "chore", "revert",
];

#[derive(Debug, Clone, PartialEq)]
pub struct ConventionalCommit {
    pub typ: String,
    pub scope: Option<String>,
    pub breaking: bool,
    pub description: String,
    pub body: Option<String>,
}

impl fmt::Display for ConventionalCommit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.typ)?;
        if let Some(scope) = &self.scope {
            write!(f, "({})", scope)?;
        }
        if self.breaking {
            write!(f, "!")?;
        }
        write!(f, ": {}", self.description)?;
        if let Some(body) = &self.body {
            write!(f, "\n\n{}", body)?;
        }
        Ok(())
    }
}

#[derive(Debug, PartialEq)]
pub enum ParseError {
    Empty,
    MissingSeparator,
    MissingDescription,
    InvalidType(String),
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::Empty => write!(f, "empty commit message"),
            ParseError::MissingSeparator => write!(f, "missing ': ' separator after type"),
            ParseError::MissingDescription => write!(f, "missing description after type"),
            ParseError::InvalidType(t) => write!(
                f,
                "invalid type '{}'; allowed: {}",
                t,
                ALLOWED_TYPES.join(", ")
            ),
        }
    }
}

/// Parse a conventional commit message string into structured form.
pub fn parse(msg: &str) -> Result<ConventionalCommit, ParseError> {
    let msg = msg.trim();
    if msg.is_empty() {
        return Err(ParseError::Empty);
    }

    // Split first line from body
    let (first_line, body) = match msg.find("\n\n") {
        Some(pos) => {
            let body = msg[pos + 2..].trim();
            let body = if body.is_empty() {
                None
            } else {
                Some(body.to_string())
            };
            (&msg[..pos], body)
        }
        None => (msg.split('\n').next().unwrap_or(msg), None),
    };
    let first_line = first_line.trim();

    // Match: type[(scope)][!]: description
    let re = Regex::new(r"^([a-zA-Z]+)(?:\(([^)]*)\))?(!)?\s*:\s*(.*)$").unwrap();
    let caps = re
        .captures(first_line)
        .ok_or(ParseError::MissingSeparator)?;

    let typ = caps.get(1).unwrap().as_str().to_lowercase();
    let scope = caps
        .get(2)
        .map(|m| m.as_str().trim().to_string())
        .filter(|s| !s.is_empty());
    let breaking = caps.get(3).is_some();
    let description = caps.get(4).unwrap().as_str().trim().to_string();

    if description.is_empty() {
        return Err(ParseError::MissingDescription);
    }

    if !ALLOWED_TYPES.contains(&typ.as_str()) {
        return Err(ParseError::InvalidType(typ));
    }

    Ok(ConventionalCommit {
        typ,
        scope,
        breaking,
        description,
        body,
    })
}

/// Validate a commit message, returning list of issues. Empty = valid.
pub fn validate(msg: &str) -> Vec<String> {
    let mut issues = Vec::new();
    match parse(msg) {
        Ok(commit) => {
            if commit.description.len() > 72 {
                issues.push(format!(
                    "description exceeds 72 chars ({})",
                    commit.description.len()
                ));
            }
            if commit.description.ends_with('.') {
                issues.push("description should not end with a period".to_string());
            }
        }
        Err(e) => {
            issues.push(e.to_string());
        }
    }
    issues
}

/// Normalize a commit message: lowercase type, trim whitespace, ensure proper separator.
/// Returns Err if the message is unfixable (no recognizable structure).
pub fn normalize(msg: &str) -> Result<String, ParseError> {
    let commit = parse(msg)?;
    Ok(commit.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_simple() {
        let c = parse("feat: add login").unwrap();
        assert_eq!(c.typ, "feat");
        assert_eq!(c.scope, None);
        assert!(!c.breaking);
        assert_eq!(c.description, "add login");
        assert_eq!(c.body, None);
    }

    #[test]
    fn parse_with_scope() {
        let c = parse("fix(auth): token expiry").unwrap();
        assert_eq!(c.typ, "fix");
        assert_eq!(c.scope, Some("auth".to_string()));
        assert_eq!(c.description, "token expiry");
    }

    #[test]
    fn parse_breaking() {
        let c = parse("feat(api)!: remove v1 endpoints").unwrap();
        assert!(c.breaking);
    }

    #[test]
    fn parse_with_body() {
        let c = parse("fix: bug\n\ndetailed explanation here").unwrap();
        assert_eq!(c.body, Some("detailed explanation here".to_string()));
    }

    #[test]
    fn parse_empty() {
        assert_eq!(parse(""), Err(ParseError::Empty));
        assert_eq!(parse("  "), Err(ParseError::Empty));
    }

    #[test]
    fn parse_missing_separator() {
        assert_eq!(parse("feat add thing"), Err(ParseError::MissingSeparator));
    }

    #[test]
    fn parse_missing_description() {
        assert_eq!(parse("feat: "), Err(ParseError::MissingDescription));
    }

    #[test]
    fn parse_invalid_type() {
        assert!(matches!(
            parse("yolo: whatever"),
            Err(ParseError::InvalidType(_))
        ));
    }

    #[test]
    fn normalize_fixes_case() {
        assert_eq!(normalize("FEAT: add thing").unwrap(), "feat: add thing");
    }

    #[test]
    fn normalize_fixes_whitespace() {
        assert_eq!(
            normalize("fix :  extra spaces  ").unwrap(),
            "fix: extra spaces"
        );
    }

    #[test]
    fn normalize_preserves_scope() {
        assert_eq!(
            normalize("Fix(Auth): token issue").unwrap(),
            "fix(Auth): token issue"
        );
    }

    #[test]
    fn normalize_preserves_body() {
        let input = "FIX: thing\n\nbody text";
        let result = normalize(input).unwrap();
        assert_eq!(result, "fix: thing\n\nbody text");
    }

    #[test]
    fn validate_ok() {
        assert!(validate("feat: short msg").is_empty());
    }

    #[test]
    fn validate_long_description() {
        let long = format!("feat: {}", "a".repeat(80));
        let issues = validate(&long);
        assert!(issues.iter().any(|i| i.contains("72 chars")));
    }

    #[test]
    fn validate_trailing_period() {
        let issues = validate("feat: add thing.");
        assert!(issues.iter().any(|i| i.contains("period")));
    }

    #[test]
    fn validate_bad_format() {
        let issues = validate("not a commit");
        assert!(!issues.is_empty());
    }
}
