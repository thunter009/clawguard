use crate::config::LoggerConfig;
use tracing_subscriber::{fmt, EnvFilter};

/// Initialize the logging system
pub fn init_logging(config: &LoggerConfig) {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(&config.level));

    let subscriber = fmt()
        .with_env_filter(filter)
        .with_target(true)
        .with_thread_ids(true)
        .with_file(true)
        .with_line_number(true)
        .with_ansi(true);

    subscriber.init();
}

/// Security event types for structured audit logging
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum SecurityEvent {
    WebSocketBlocked {
        ip: String,
        reason: String,
    },
    WebSocketAllowed {
        ip: String,
        origin: String,
    },
    SkillBlocked {
        skill_name: String,
        verdict: String,
        findings_count: usize,
    },
    SkillAllowed {
        skill_name: String,
        sha256: String,
    },
    CostLimitHit {
        reason: String,
        current_spend: f64,
        budget: f64,
    },
    CostWarning {
        reason: String,
        current_spend: f64,
        budget: f64,
    },
    WastefulJobDetected {
        job_id: String,
        avg_tokens: u64,
        total_cost: f64,
    },
}

impl std::fmt::Display for SecurityEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SecurityEvent::WebSocketBlocked { ip, reason } => {
                write!(f, "[WS-BLOCK] IP={} Reason={}", ip, reason)
            }
            SecurityEvent::WebSocketAllowed { ip, origin } => {
                write!(f, "[WS-ALLOW] IP={} Origin={}", ip, origin)
            }
            SecurityEvent::SkillBlocked {
                skill_name,
                verdict,
                findings_count,
            } => {
                write!(
                    f,
                    "[SKILL-BLOCK] Skill={} Verdict={} Findings={}",
                    skill_name, verdict, findings_count
                )
            }
            SecurityEvent::SkillAllowed { skill_name, sha256 } => {
                write!(f, "[SKILL-ALLOW] Skill={} SHA256={}", skill_name, sha256)
            }
            SecurityEvent::CostLimitHit {
                reason,
                current_spend,
                budget,
            } => {
                write!(
                    f,
                    "[COST-BLOCK] Reason={} Spent=${:.4} Budget=${:.2}",
                    reason, current_spend, budget
                )
            }
            SecurityEvent::CostWarning {
                reason,
                current_spend,
                budget,
            } => {
                write!(
                    f,
                    "[COST-WARN] Reason={} Spent=${:.4} Budget=${:.2}",
                    reason, current_spend, budget
                )
            }
            SecurityEvent::WastefulJobDetected {
                job_id,
                avg_tokens,
                total_cost,
            } => {
                write!(
                    f,
                    "[WASTEFUL-JOB] Job={} AvgTokens={} TotalCost=${:.4}",
                    job_id, avg_tokens, total_cost
                )
            }
        }
    }
}
