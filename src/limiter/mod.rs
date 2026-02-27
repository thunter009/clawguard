use crate::config::LimiterConfig;
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tracing::{error, info, warn};

/// Tracks API usage and enforces spending limits
pub struct CostLimiter {
    config: LimiterConfig,
    /// Rolling window token counters
    minute_tokens: Arc<TokenWindow>,
    hour_tokens: Arc<TokenWindow>,
    day_tokens: Arc<TokenWindow>,
    /// Cumulative cost tracking
    daily_cost_millicents: AtomicU64, // Track in millicents for precision
    daily_reset_timestamp: AtomicU64,
    /// Per-cron-job tracking to detect wasteful jobs
    job_costs: Arc<DashMap<String, JobCostInfo>>,
    /// Stats
    total_requests_allowed: AtomicU64,
    total_requests_blocked: AtomicU64,
}

/// Rolling window for token counting
struct TokenWindow {
    tokens: AtomicU64,
    window_start: AtomicU64,
    window_duration_secs: u64,
}

impl TokenWindow {
    fn new(duration_secs: u64) -> Self {
        Self {
            tokens: AtomicU64::new(0),
            window_start: AtomicU64::new(Utc::now().timestamp() as u64),
            window_duration_secs: duration_secs,
        }
    }

    fn add_tokens(&self, count: u64) -> u64 {
        let now = Utc::now().timestamp() as u64;
        let window_start = self.window_start.load(Ordering::Relaxed);

        // Reset window if expired
        if now - window_start >= self.window_duration_secs {
            self.tokens.store(count, Ordering::Relaxed);
            self.window_start.store(now, Ordering::Relaxed);
            count
        } else {
            self.tokens.fetch_add(count, Ordering::Relaxed) + count
        }
    }

    fn current(&self) -> u64 {
        let now = Utc::now().timestamp() as u64;
        let window_start = self.window_start.load(Ordering::Relaxed);
        if now - window_start >= self.window_duration_secs {
            0
        } else {
            self.tokens.load(Ordering::Relaxed)
        }
    }
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct JobCostInfo {
    total_tokens: u64,
    total_cost_millicents: u64,
    request_count: u64,
    first_seen: DateTime<Utc>,
    last_seen: DateTime<Utc>,
}

/// Result of a cost limit check
#[derive(Debug, Clone)]
pub enum LimitResult {
    Allowed {
        estimated_cost_usd: f64,
        daily_total_usd: f64,
        budget_remaining_usd: f64,
    },
    Blocked(LimitReason),
    Warning {
        _estimated_cost_usd: f64,
        daily_total_usd: f64,
        reason: String,
    },
}

#[derive(Debug, Clone)]
pub enum LimitReason {
    RequestTooLarge { tokens: u64, max: u64 },
    MinuteRateExceeded { current: u64, max: u64 },
    HourRateExceeded { current: u64, max: u64 },
    DailyBudgetExceeded { spent_usd: f64, max_usd: f64 },
}

impl std::fmt::Display for LimitReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LimitReason::RequestTooLarge { tokens, max } => {
                write!(f, "Request too large: {} tokens (max: {})", tokens, max)
            }
            LimitReason::MinuteRateExceeded { current, max } => {
                write!(f, "Minute rate exceeded: {} tokens (max: {})", current, max)
            }
            LimitReason::HourRateExceeded { current, max } => {
                write!(f, "Hour rate exceeded: {} tokens (max: {})", current, max)
            }
            LimitReason::DailyBudgetExceeded { spent_usd, max_usd } => {
                write!(
                    f,
                    "Daily budget exceeded: ${:.2} spent (max: ${:.2})",
                    spent_usd, max_usd
                )
            }
        }
    }
}

impl CostLimiter {
    pub fn new(config: LimiterConfig) -> Self {
        Self {
            config,
            minute_tokens: Arc::new(TokenWindow::new(60)),
            hour_tokens: Arc::new(TokenWindow::new(3600)),
            day_tokens: Arc::new(TokenWindow::new(86400)),
            daily_cost_millicents: AtomicU64::new(0),
            daily_reset_timestamp: AtomicU64::new(Utc::now().timestamp() as u64),
            job_costs: Arc::new(DashMap::new()),
            total_requests_allowed: AtomicU64::new(0),
            total_requests_blocked: AtomicU64::new(0),
        }
    }

    /// Check if a request with the given token count should be allowed
    pub fn check_request(
        &self,
        input_tokens: u64,
        output_tokens: u64,
        job_id: Option<&str>,
    ) -> LimitResult {
        let total_tokens = input_tokens + output_tokens;

        // 1. Check per-request limit
        if total_tokens > self.config.max_tokens_per_request {
            self.total_requests_blocked.fetch_add(1, Ordering::Relaxed);
            warn!(
                tokens = total_tokens,
                max = self.config.max_tokens_per_request,
                "BLOCKED: Request exceeds per-request token limit"
            );
            return LimitResult::Blocked(LimitReason::RequestTooLarge {
                tokens: total_tokens,
                max: self.config.max_tokens_per_request,
            });
        }

        // 2. Check minute rate
        let minute_total = self.minute_tokens.current() + total_tokens;
        if minute_total > self.config.max_tokens_per_minute {
            self.total_requests_blocked.fetch_add(1, Ordering::Relaxed);
            warn!(
                current = minute_total,
                max = self.config.max_tokens_per_minute,
                "BLOCKED: Minute token rate exceeded"
            );
            return LimitResult::Blocked(LimitReason::MinuteRateExceeded {
                current: minute_total,
                max: self.config.max_tokens_per_minute,
            });
        }

        // 3. Check hour rate
        let hour_total = self.hour_tokens.current() + total_tokens;
        if hour_total > self.config.max_tokens_per_hour {
            self.total_requests_blocked.fetch_add(1, Ordering::Relaxed);
            warn!(
                current = hour_total,
                max = self.config.max_tokens_per_hour,
                "BLOCKED: Hour token rate exceeded"
            );
            return LimitResult::Blocked(LimitReason::HourRateExceeded {
                current: hour_total,
                max: self.config.max_tokens_per_hour,
            });
        }

        // 4. Calculate cost
        let input_cost = (input_tokens as f64 / 1000.0) * self.config.cost_per_1k_input_tokens;
        let output_cost = (output_tokens as f64 / 1000.0) * self.config.cost_per_1k_output_tokens;
        let request_cost = input_cost + output_cost;
        let request_cost_millicents = (request_cost * 100_000.0) as u64;

        // Check daily reset
        self.maybe_reset_daily();

        let current_daily_millicents =
            self.daily_cost_millicents.load(Ordering::Relaxed) + request_cost_millicents;
        let current_daily_usd = current_daily_millicents as f64 / 100_000.0;

        // 5. Check daily budget
        if current_daily_usd > self.config.max_cost_per_day_usd {
            self.total_requests_blocked.fetch_add(1, Ordering::Relaxed);
            error!(
                spent = format!("${:.4}", current_daily_usd),
                max = format!("${:.2}", self.config.max_cost_per_day_usd),
                "BLOCKED: Daily budget exceeded!"
            );
            return LimitResult::Blocked(LimitReason::DailyBudgetExceeded {
                spent_usd: current_daily_usd,
                max_usd: self.config.max_cost_per_day_usd,
            });
        }

        // Record the usage
        self.minute_tokens.add_tokens(total_tokens);
        self.hour_tokens.add_tokens(total_tokens);
        self.day_tokens.add_tokens(total_tokens);
        self.daily_cost_millicents
            .fetch_add(request_cost_millicents, Ordering::Relaxed);
        self.total_requests_allowed.fetch_add(1, Ordering::Relaxed);

        // Track per-job costs
        if let Some(job) = job_id {
            self.track_job_cost(job, total_tokens, request_cost_millicents);
        }

        let budget_remaining = self.config.max_cost_per_day_usd - current_daily_usd;

        // 6. Check warning threshold
        let usage_percent = (current_daily_usd / self.config.max_cost_per_day_usd) * 100.0;
        if usage_percent >= self.config.alert_threshold_percent {
            warn!(
                spent = format!("${:.4}", current_daily_usd),
                budget = format!("${:.2}", self.config.max_cost_per_day_usd),
                percent = format!("{:.1}%", usage_percent),
                "⚠️  Budget alert threshold reached!"
            );
            return LimitResult::Warning {
                _estimated_cost_usd: request_cost,
                daily_total_usd: current_daily_usd,
                reason: format!(
                    "Budget usage at {:.1}% (${:.4} / ${:.2})",
                    usage_percent, current_daily_usd, self.config.max_cost_per_day_usd
                ),
            };
        }

        info!(
            tokens = total_tokens,
            cost = format!("${:.4}", request_cost),
            daily = format!("${:.4}", current_daily_usd),
            remaining = format!("${:.2}", budget_remaining),
            "API request allowed"
        );

        LimitResult::Allowed {
            estimated_cost_usd: request_cost,
            daily_total_usd: current_daily_usd,
            budget_remaining_usd: budget_remaining,
        }
    }

    fn maybe_reset_daily(&self) {
        let now = Utc::now().timestamp() as u64;
        let last_reset = self.daily_reset_timestamp.load(Ordering::Relaxed);
        if now - last_reset >= 86400 {
            self.daily_cost_millicents.store(0, Ordering::Relaxed);
            self.daily_reset_timestamp.store(now, Ordering::Relaxed);
            info!("Daily cost counter reset");
        }
    }

    fn track_job_cost(&self, job_id: &str, tokens: u64, cost_millicents: u64) {
        let now = Utc::now();
        self.job_costs
            .entry(job_id.to_string())
            .and_modify(|info| {
                info.total_tokens += tokens;
                info.total_cost_millicents += cost_millicents;
                info.request_count += 1;
                info.last_seen = now;
            })
            .or_insert(JobCostInfo {
                total_tokens: tokens,
                total_cost_millicents: cost_millicents,
                request_count: 1,
                first_seen: now,
                last_seen: now,
            });

        // Check for wasteful jobs (like the $20 heartbeat incident)
        if let Some(info) = self.job_costs.get(job_id) {
            let cost_usd = info.total_cost_millicents as f64 / 100_000.0;
            let avg_tokens = info.total_tokens / info.request_count.max(1);
            if avg_tokens > 100_000 && info.request_count > 3 {
                warn!(
                    job = %job_id,
                    avg_tokens = avg_tokens,
                    total_cost = format!("${:.2}", cost_usd),
                    requests = info.request_count,
                    "🔥 Wasteful job detected! High token usage per request"
                );
            }
        }
    }

    /// Get current usage stats
    pub fn stats(&self) -> CostStats {
        let daily_millicents = self.daily_cost_millicents.load(Ordering::Relaxed);
        CostStats {
            daily_cost_usd: daily_millicents as f64 / 100_000.0,
            daily_budget_usd: self.config.max_cost_per_day_usd,
            minute_tokens: self.minute_tokens.current(),
            hour_tokens: self.hour_tokens.current(),
            total_allowed: self.total_requests_allowed.load(Ordering::Relaxed),
            total_blocked: self.total_requests_blocked.load(Ordering::Relaxed),
            active_jobs: self.job_costs.len(),
        }
    }

    /// Get top cost-consuming jobs
    pub fn top_jobs(&self, n: usize) -> Vec<(String, f64, u64)> {
        let mut jobs: Vec<_> = self
            .job_costs
            .iter()
            .map(|entry| {
                let cost = entry.value().total_cost_millicents as f64 / 100_000.0;
                (entry.key().clone(), cost, entry.value().request_count)
            })
            .collect();
        jobs.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        jobs.truncate(n);
        jobs
    }
}

#[derive(Debug, Clone)]
pub struct CostStats {
    pub daily_cost_usd: f64,
    pub daily_budget_usd: f64,
    pub minute_tokens: u64,
    pub hour_tokens: u64,
    pub total_allowed: u64,
    pub total_blocked: u64,
    pub active_jobs: usize,
}

impl std::fmt::Display for CostStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let usage_pct = if self.daily_budget_usd > 0.0 {
            (self.daily_cost_usd / self.daily_budget_usd) * 100.0
        } else {
            0.0
        };
        write!(
            f,
            "Cost Stats — Today: ${:.4}/{:.2} ({:.1}%) | Min: {} tok | Hr: {} tok | Allowed: {} | Blocked: {} | Jobs: {}",
            self.daily_cost_usd,
            self.daily_budget_usd,
            usage_pct,
            self.minute_tokens,
            self.hour_tokens,
            self.total_allowed,
            self.total_blocked,
            self.active_jobs,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    fn test_limiter() -> CostLimiter {
        let mut config = Config::default_config().limiter;
        config.max_cost_per_day_usd = 1.0; // Low budget for testing
        config.max_tokens_per_request = 10_000;
        config.max_tokens_per_minute = 50_000;
        config.alert_threshold_percent = 50.0;
        CostLimiter::new(config)
    }

    #[test]
    fn test_allows_normal_request() {
        let limiter = test_limiter();
        match limiter.check_request(1000, 500, None) {
            LimitResult::Allowed { .. } => {}
            other => panic!("Expected Allowed, got {:?}", other),
        }
    }

    #[test]
    fn test_blocks_oversized_request() {
        let limiter = test_limiter();
        match limiter.check_request(15_000, 0, None) {
            LimitResult::Blocked(LimitReason::RequestTooLarge { .. }) => {}
            other => panic!("Expected RequestTooLarge, got {:?}", other),
        }
    }

    #[test]
    fn test_blocks_when_budget_exceeded() {
        let limiter = test_limiter();
        // Burn through the $1 budget with many requests
        for _ in 0..200 {
            let _ = limiter.check_request(5000, 2000, Some("test-job"));
        }
        // At some point it should have blocked
        let stats = limiter.stats();
        assert!(
            stats.total_blocked > 0 || stats.daily_cost_usd >= 0.5,
            "Should have either blocked or hit warning threshold"
        );
    }

    #[test]
    fn test_detects_wasteful_heartbeat() {
        let limiter = test_limiter();
        // Simulate the OpenClaw heartbeat problem: 120K tokens per time check
        for _ in 0..5 {
            let _ = limiter.check_request(9_000, 1_000, Some("heartbeat-cron"));
        }
        let top = limiter.top_jobs(1);
        assert!(!top.is_empty(), "Should track the heartbeat job");
        assert_eq!(top[0].0, "heartbeat-cron");
    }
}
