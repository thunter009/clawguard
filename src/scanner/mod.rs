//! Static analysis scanner for skill files.
//!
//! Detects dangerous commands, data exfiltration patterns, obfuscated
//! payloads, and credential harvesting via regex-based heuristics.

pub mod content;

use crate::config::ScannerConfig;
use regex::Regex;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use tracing::{warn};

/// Result of scanning a single skill file or directory.
#[derive(Debug, Clone)]
pub struct ScanResult {
    /// Absolute path to the scanned skill.
    pub skill_path: String,
    /// Human-readable skill name (file or directory basename).
    pub skill_name: String,
    /// SHA-256 digest of the skill content.
    pub sha256: String,
    /// Total size in bytes.
    pub size_bytes: u64,
    /// Overall security verdict.
    pub verdict: ScanVerdict,
    /// Individual security findings.
    pub findings: Vec<Finding>,
}

/// Aggregate security verdict for a scanned skill.
#[derive(Debug, Clone, PartialEq)]
pub enum ScanVerdict {
    /// No security issues found.
    Clean,
    /// Non-critical findings that warrant review.
    Suspicious,
    /// Critical findings — skill should be blocked.
    Malicious,
    /// File exceeds the configured size limit.
    Oversized,
    /// An I/O or processing error occurred.
    Error(String),
}

impl std::fmt::Display for ScanVerdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScanVerdict::Clean => write!(f, "CLEAN"),
            ScanVerdict::Suspicious => write!(f, "SUSPICIOUS"),
            ScanVerdict::Malicious => write!(f, "MALICIOUS"),
            ScanVerdict::Oversized => write!(f, "OVERSIZED"),
            ScanVerdict::Error(e) => write!(f, "ERROR: {}", e),
        }
    }
}

/// A single security finding within a scanned file.
#[derive(Debug, Clone)]
pub struct Finding {
    /// How severe this finding is.
    pub severity: Severity,
    /// Classification of the finding.
    pub category: FindingCategory,
    /// Human-readable explanation.
    pub description: String,
    /// Source line where the match was found, if applicable.
    pub line_number: Option<usize>,
    /// The text that triggered the match.
    pub matched_text: String,
}

/// Finding severity level, ordered from lowest to highest.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
#[allow(dead_code)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Info => write!(f, "INFO"),
            Severity::Low => write!(f, "LOW"),
            Severity::Medium => write!(f, "MEDIUM"),
            Severity::High => write!(f, "HIGH"),
            Severity::Critical => write!(f, "CRITICAL"),
        }
    }
}

/// Classification of a security finding.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum FindingCategory {
    DangerousCommand,
    DataExfiltration,
    ObfuscatedCode,
    SensitiveFileAccess,
    NetworkCallback,
    PrivilegeEscalation,
    CryptoMining,
    CredentialHarvesting,
}

impl std::fmt::Display for FindingCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FindingCategory::DangerousCommand => write!(f, "Dangerous Command"),
            FindingCategory::DataExfiltration => write!(f, "Data Exfiltration"),
            FindingCategory::ObfuscatedCode => write!(f, "Obfuscated Code"),
            FindingCategory::SensitiveFileAccess => write!(f, "Sensitive File Access"),
            FindingCategory::NetworkCallback => write!(f, "Network Callback"),
            FindingCategory::PrivilegeEscalation => write!(f, "Privilege Escalation"),
            FindingCategory::CryptoMining => write!(f, "Crypto Mining"),
            FindingCategory::CredentialHarvesting => write!(f, "Credential Harvesting"),
        }
    }
}

/// Regex-based static analyzer for skill files and directories.
pub struct SkillScanner {
    config: ScannerConfig,
    dangerous_regexes: Vec<(Regex, String)>,
    exfiltration_regexes: Vec<(Regex, String)>,
    builtin_regexes: Vec<(Regex, FindingCategory, Severity, String)>,
}

impl SkillScanner {
    /// Create a new scanner from config, compiling all regex patterns.
    pub fn new(config: ScannerConfig) -> Self {
        let dangerous_regexes = config
            .dangerous_patterns
            .iter()
            .filter_map(|p| {
                Regex::new(p)
                    .ok()
                    .map(|r| (r, format!("Dangerous pattern: {}", p)))
            })
            .collect();

        let exfiltration_regexes = config
            .exfiltration_patterns
            .iter()
            .filter_map(|p| {
                Regex::new(p)
                    .ok()
                    .map(|r| (r, format!("Exfiltration pattern: {}", p)))
            })
            .collect();

        let builtin_regexes = vec![
            (
                Regex::new(r#"(?i)(password|passwd|secret|api.?key|token)\s*[:=]\s*['\"]"#).unwrap(),
                FindingCategory::CredentialHarvesting,
                Severity::High,
                "Hardcoded credential or secret".to_string(),
            ),
            (
                Regex::new(r#"(?i)(stratum\+tcp|xmrig|coinhive|cryptonight|monero.*pool)"#).unwrap(),
                FindingCategory::CryptoMining,
                Severity::Critical,
                "Cryptocurrency mining reference".to_string(),
            ),
            (
                Regex::new(r#"(?i)(reverse.?shell|bind.?shell|meterpreter|payload)"#).unwrap(),
                FindingCategory::DangerousCommand,
                Severity::Critical,
                "Reverse shell or exploit payload reference".to_string(),
            ),
            (
                Regex::new(r#"(?i)(sudo\s+chmod|setuid|setgid|chown\s+root|SUID)"#).unwrap(),
                FindingCategory::PrivilegeEscalation,
                Severity::High,
                "Privilege escalation attempt".to_string(),
            ),
            (
                Regex::new(r#"(?i)(npm\s+install|pip\s+install)\s+[a-z0-9_-]{1,5}\b"#).unwrap(),
                FindingCategory::DangerousCommand,
                Severity::Medium,
                "Short package name install (typosquatting risk)".to_string(),
            ),
            (
                Regex::new(r#"(?i)(AWS_SECRET|AWS_ACCESS_KEY|AZURE_|GCP_|\.aws/credentials)"#).unwrap(),
                FindingCategory::CredentialHarvesting,
                Severity::Critical,
                "Cloud credential access".to_string(),
            ),
            (
                Regex::new(r#"(?i)(keychain|keyring|security\s+find-generic-password)"#).unwrap(),
                FindingCategory::CredentialHarvesting,
                Severity::High,
                "System keychain/keyring access".to_string(),
            ),
            (
                Regex::new(r#"(?i)(Login\s*Data|Cookies|Web\s*Data|\.mozilla|\.chrome)"#).unwrap(),
                FindingCategory::CredentialHarvesting,
                Severity::High,
                "Browser credential/cookie access".to_string(),
            ),
            (
                Regex::new(r#"(?i)(osascript\s+-e|AppleScript|System\s*Events)"#).unwrap(),
                FindingCategory::CredentialHarvesting,
                Severity::High,
                "macOS AppleScript execution (AMOS stealer pattern)".to_string(),
            ),
        ];

        Self {
            config,
            dangerous_regexes,
            exfiltration_regexes,
            builtin_regexes,
        }
    }

    /// Scan a single skill file or directory, returning findings and a verdict.
    pub fn scan_skill<P: AsRef<Path>>(&self, path: P) -> ScanResult {
        let path = path.as_ref();
        let skill_name = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "unknown".to_string());

        if path.is_dir() {
            return self.scan_directory(path, &skill_name);
        }
        self.scan_file(path, &skill_name)
    }

    fn scan_file(&self, path: &Path, skill_name: &str) -> ScanResult {
        let content = match fs::read_to_string(path) {
            Ok(c) => c,
            Err(e) => {
                return ScanResult {
                    skill_path: path.display().to_string(),
                    skill_name: skill_name.to_string(),
                    sha256: String::new(),
                    size_bytes: 0,
                    verdict: ScanVerdict::Error(format!("Read error: {}", e)),
                    findings: vec![],
                };
            }
        };

        let size = content.len() as u64;
        let sha256 = Self::compute_sha256(&content);

        if size > self.config.max_skill_size_bytes {
            return ScanResult {
                skill_path: path.display().to_string(),
                skill_name: skill_name.to_string(),
                sha256,
                size_bytes: size,
                verdict: ScanVerdict::Oversized,
                findings: vec![Finding {
                    severity: Severity::Medium,
                    category: FindingCategory::DangerousCommand,
                    description: format!("File exceeds size limit: {} > {}", size, self.config.max_skill_size_bytes),
                    line_number: None,
                    matched_text: String::new(),
                }],
            };
        }

        let mut findings = Vec::new();

        for (line_num, line) in content.lines().enumerate() {
            let ln = line_num + 1;

            for (regex, desc) in &self.dangerous_regexes {
                if let Some(m) = regex.find(line) {
                    findings.push(Finding {
                        severity: Severity::High,
                        category: FindingCategory::DangerousCommand,
                        description: desc.clone(),
                        line_number: Some(ln),
                        matched_text: m.as_str().to_string(),
                    });
                }
            }

            for (regex, desc) in &self.exfiltration_regexes {
                if let Some(m) = regex.find(line) {
                    findings.push(Finding {
                        severity: Severity::Critical,
                        category: FindingCategory::DataExfiltration,
                        description: desc.clone(),
                        line_number: Some(ln),
                        matched_text: m.as_str().to_string(),
                    });
                }
            }

            for (regex, category, severity, desc) in &self.builtin_regexes {
                if let Some(m) = regex.find(line) {
                    findings.push(Finding {
                        severity: severity.clone(),
                        category: category.clone(),
                        description: desc.clone(),
                        line_number: Some(ln),
                        matched_text: m.as_str().to_string(),
                    });
                }
            }
        }

        if self.config.block_obfuscated {
            findings.extend(self.detect_obfuscation(&content));
        }

        let verdict = Self::determine_verdict(&findings);

        ScanResult {
            skill_path: path.display().to_string(),
            skill_name: skill_name.to_string(),
            sha256,
            size_bytes: size,
            verdict,
            findings,
        }
    }

    fn scan_directory(&self, dir: &Path, skill_name: &str) -> ScanResult {
        let mut all_findings = Vec::new();
        let mut total_size: u64 = 0;

        for file_path in Self::collect_files(dir) {
            let result = self.scan_file(&file_path, skill_name);
            total_size += result.size_bytes;
            all_findings.extend(result.findings);
        }

        let sha256 = Self::compute_sha256(&format!("dir:{}", dir.display()));
        let verdict = Self::determine_verdict(&all_findings);

        ScanResult {
            skill_path: dir.display().to_string(),
            skill_name: skill_name.to_string(),
            sha256,
            size_bytes: total_size,
            verdict,
            findings: all_findings,
        }
    }

    fn detect_obfuscation(&self, content: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        let b64_re = Regex::new(r#"[A-Za-z0-9+/]{100,}={0,2}"#).unwrap();
        let hex_re = Regex::new(r#"\\x[0-9a-fA-F]{2}(\\x[0-9a-fA-F]{2}){10,}"#).unwrap();
        let uni_re = Regex::new(r#"\\u[0-9a-fA-F]{4}(\\u[0-9a-fA-F]{4}){5,}"#).unwrap();

        for (line_num, line) in content.lines().enumerate() {
            let ln = line_num + 1;

            if let Some(m) = b64_re.find(line) {
                let preview_end = 50.min(m.as_str().len());
                findings.push(Finding {
                    severity: Severity::High,
                    category: FindingCategory::ObfuscatedCode,
                    description: "Long Base64 string (possible obfuscated payload)".to_string(),
                    line_number: Some(ln),
                    matched_text: format!("{}...", &m.as_str()[..preview_end]),
                });
            }

            if let Some(m) = hex_re.find(line) {
                let preview_end = 40.min(m.as_str().len());
                findings.push(Finding {
                    severity: Severity::High,
                    category: FindingCategory::ObfuscatedCode,
                    description: "Hex-encoded byte sequence".to_string(),
                    line_number: Some(ln),
                    matched_text: format!("{}...", &m.as_str()[..preview_end]),
                });
            }

            if let Some(m) = uni_re.find(line) {
                let preview_end = 40.min(m.as_str().len());
                findings.push(Finding {
                    severity: Severity::Medium,
                    category: FindingCategory::ObfuscatedCode,
                    description: "Unicode escape obfuscation".to_string(),
                    line_number: Some(ln),
                    matched_text: format!("{}...", &m.as_str()[..preview_end]),
                });
            }

            if line.len() > 5000 {
                findings.push(Finding {
                    severity: Severity::Low,
                    category: FindingCategory::ObfuscatedCode,
                    description: format!("Very long line ({} chars) - possible minified code", line.len()),
                    line_number: Some(ln),
                    matched_text: format!("{}...", &line[..80]),
                });
            }
        }

        findings
    }

    fn determine_verdict(findings: &[Finding]) -> ScanVerdict {
        if findings.is_empty() {
            return ScanVerdict::Clean;
        }
        let has_critical = findings.iter().any(|f| f.severity == Severity::Critical);
        let high_count = findings.iter().filter(|f| f.severity == Severity::High).count();

        if has_critical || high_count >= 3 {
            ScanVerdict::Malicious
        } else if high_count >= 1 {
            ScanVerdict::Suspicious
        } else {
            ScanVerdict::Suspicious
        }
    }

    fn compute_sha256(content: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(content.as_bytes());
        hex::encode(hasher.finalize())
    }

    fn collect_files(dir: &Path) -> Vec<PathBuf> {
        let mut files = Vec::new();
        if let Ok(entries) = fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() {
                    files.push(path);
                } else if path.is_dir() {
                    files.extend(Self::collect_files(&path));
                }
            }
        }
        files
    }

    /// Scan every skill in the configured skills directory.
    pub fn scan_all_skills(&self) -> Vec<ScanResult> {
        let dir = Path::new(&self.config.skills_directory);
        if !dir.exists() {
            warn!("Skills directory not found: {}", self.config.skills_directory);
            return vec![];
        }
        let mut results = Vec::new();
        if let Ok(entries) = fs::read_dir(dir) {
            for entry in entries.flatten() {
                results.push(self.scan_skill(entry.path()));
            }
        }
        results
    }

    /// Format a scan result as a human-readable ASCII report.
    pub fn format_report(result: &ScanResult) -> String {
        let mut r = String::new();
        let sep = "+--------------------------------------------------+";
        r.push_str(&format!("{}\n", sep));
        r.push_str(&format!("| Skill Scan: {:<37}|\n", result.skill_name));
        r.push_str(&format!("{}\n", sep));
        let path_display = if result.skill_path.len() > 37 {
            format!("...{}", &result.skill_path[result.skill_path.len()-34..])
        } else {
            result.skill_path.clone()
        };
        r.push_str(&format!("| Path:    {:<40}|\n", path_display));
        let hash_display = if result.sha256.len() > 38 {
            format!("{}...", &result.sha256[..35])
        } else {
            result.sha256.clone()
        };
        r.push_str(&format!("| SHA-256: {:<40}|\n", hash_display));
        r.push_str(&format!("| Size:    {:<40}|\n", format!("{} bytes", result.size_bytes)));
        r.push_str(&format!("| Verdict: {:<40}|\n", format!("{}", result.verdict)));
        r.push_str(&format!("| Issues:  {:<40}|\n", result.findings.len()));
        r.push_str(&format!("{}\n", sep));

        if result.findings.is_empty() {
            r.push_str("| No security issues found.                        |\n");
        } else {
            for (i, f) in result.findings.iter().enumerate() {
                r.push_str(&format!(
                    "| [{}] {} - {}\n",
                    f.severity, f.category, f.description
                ));
                if let Some(ln) = f.line_number {
                    let text_preview = if f.matched_text.len() > 50 {
                        format!("{}...", &f.matched_text[..47])
                    } else {
                        f.matched_text.clone()
                    };
                    r.push_str(&format!("| Line {}: {}\n", ln, text_preview));
                }
                if i < result.findings.len() - 1 {
                    r.push_str("|--------------------------------------------------\n");
                }
            }
        }
        r.push_str(&format!("{}\n", sep));
        r
    }
}
