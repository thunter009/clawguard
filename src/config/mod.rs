use serde::Deserialize;
use std::fs;
use std::path::Path;

/// Top-level configuration for ClawGuard
#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    pub general: GeneralConfig,
    pub proxy: ProxyConfig,
    pub scanner: ScannerConfig,
    pub limiter: LimiterConfig,
    pub logger: LoggerConfig,
    #[serde(default)]
    pub content_scan: Option<ContentScanConfig>,
    #[serde(default)]
    pub source_routing: Option<SourceRoutingConfig>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ContentScanConfig {
    pub enabled: bool,
    pub model: String,
    pub endpoint: String,
    pub corpus_file: String,
    #[serde(default = "default_allowlist")]
    pub allowlist_file: String,
    #[serde(default = "default_threshold")]
    pub similarity_threshold: f64,
    #[serde(default = "default_action")]
    pub action: String,
    pub log_file: Option<String>,
}

fn default_allowlist() -> String {
    String::new()
}
fn default_threshold() -> f64 {
    0.55
}
fn default_action() -> String {
    "flag".to_string()
}

#[derive(Debug, Deserialize, Clone)]
pub struct SourceRoutingConfig {
    pub enabled: bool,
    #[serde(default = "default_source_routing_model")]
    pub default_model: String,
    #[serde(default)]
    pub external: Option<SourceRuleConfig>,
    #[serde(default)]
    pub internal: Option<SourceRuleConfig>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct SourceRuleConfig {
    #[serde(default)]
    pub model: Option<String>,
    #[serde(default)]
    pub min_model: Option<String>,
    #[serde(default)]
    pub sources: Vec<String>,
}

fn default_source_routing_model() -> String {
    "anthropic/claude-haiku-4-5".to_string()
}

#[derive(Debug, Deserialize, Clone)]
pub struct GeneralConfig {
    /// Address to bind the gateway on
    pub bind_address: String,
    /// Port for the gateway
    pub bind_port: u16,
    /// Upstream OpenClaw gateway address
    pub upstream_host: String,
    /// Upstream OpenClaw gateway port
    pub upstream_port: u16,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ProxyConfig {
    /// Enable WebSocket origin validation
    pub validate_origin: bool,
    /// Allowed origins for WebSocket connections
    pub allowed_origins: Vec<String>,
    /// Block requests without Origin header
    pub block_missing_origin: bool,
    /// Enable token protection (prevent token leakage in URLs)
    pub protect_tokens: bool,
    /// Max concurrent WebSocket connections
    pub max_connections: usize,
    /// Connection timeout in seconds
    pub connection_timeout_secs: u64,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ScannerConfig {
    /// Enable skill scanning before installation
    pub enabled: bool,
    /// Directory to watch for new skills
    pub skills_directory: String,
    /// Block skills that match dangerous patterns
    pub block_dangerous: bool,
    /// Dangerous command patterns (regex)
    pub dangerous_patterns: Vec<String>,
    /// Dangerous network patterns (regex) — detect exfiltration
    pub exfiltration_patterns: Vec<String>,
    /// Max allowed file size for a skill (bytes)
    pub max_skill_size_bytes: u64,
    /// Block obfuscated code (base64 encoded payloads, hex strings)
    pub block_obfuscated: bool,
}

#[derive(Debug, Deserialize, Clone)]
pub struct LimiterConfig {
    /// Enable API cost limiting
    pub enabled: bool,
    /// Max tokens per request
    pub max_tokens_per_request: u64,
    /// Max tokens per minute
    pub max_tokens_per_minute: u64,
    /// Max tokens per hour
    pub max_tokens_per_hour: u64,
    /// Max estimated cost per day (USD)
    pub max_cost_per_day_usd: f64,
    /// Cost per 1K input tokens (USD) — Claude Opus default
    pub cost_per_1k_input_tokens: f64,
    /// Cost per 1K output tokens (USD) — Claude Opus default
    pub cost_per_1k_output_tokens: f64,
    /// Alert threshold (percentage of daily budget)
    pub alert_threshold_percent: f64,
}

#[derive(Debug, Deserialize, Clone)]
pub struct LoggerConfig {
    /// Log level: trace, debug, info, warn, error
    pub level: String,
    /// Log to file
    pub log_file: Option<String>,
    /// Log blocked requests
    pub log_blocked: bool,
    /// Log all WebSocket frames (verbose)
    pub log_frames: bool,
    /// Log API cost tracking
    pub log_costs: bool,
}

impl Config {
    /// Load configuration from a TOML file
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self, Box<dyn std::error::Error>> {
        let content = fs::read_to_string(path)?;
        let config: Config = toml::from_str(&content)?;
        Ok(config)
    }

    /// Generate a default configuration
    pub fn default_config() -> Self {
        Config {
            general: GeneralConfig {
                bind_address: "127.0.0.1".to_string(),
                bind_port: 18800,
                upstream_host: "127.0.0.1".to_string(),
                upstream_port: 18789,
            },
            proxy: ProxyConfig {
                validate_origin: true,
                allowed_origins: vec![
                    "http://localhost".to_string(),
                    "http://127.0.0.1".to_string(),
                    "https://localhost".to_string(),
                    "https://127.0.0.1".to_string(),
                ],
                block_missing_origin: true,
                protect_tokens: true,
                max_connections: 50,
                connection_timeout_secs: 30,
            },
            scanner: ScannerConfig {
                enabled: true,
                skills_directory: "~/.openclaw/skills".to_string(),
                block_dangerous: true,
                dangerous_patterns: vec![
                    r"curl\s+.*-[dX]".to_string(),
                    r"wget\s+.*\|.*sh".to_string(),
                    r"eval\s*\(".to_string(),
                    r"exec\s*\(".to_string(),
                    r"child_process".to_string(),
                    r"subprocess\.".to_string(),
                    r"os\.system\s*\(".to_string(),
                    r"Runtime\.getRuntime\(\)\.exec".to_string(),
                    r"powershell\s+-e".to_string(),
                    r"rm\s+-rf\s+/".to_string(),
                    r"chmod\s+777".to_string(),
                    r"\.ssh/".to_string(),
                    r"id_rsa".to_string(),
                    r"/etc/passwd".to_string(),
                    r"/etc/shadow".to_string(),
                ],
                exfiltration_patterns: vec![
                    r"curl\s+.*https?://[^/]*\.(ru|cn|tk|ml|ga|cf)/".to_string(),
                    r"curl\s+.*-d\s+.*\$\(.*\)".to_string(),
                    r"nc\s+-e".to_string(),
                    r"ncat\s+.*-e".to_string(),
                    r"/dev/tcp/".to_string(),
                    r"base64\s+-d\s*\|.*sh".to_string(),
                    r"php\s+-r\s+.*fsockopen".to_string(),
                    r"python.*socket\.connect".to_string(),
                    r"\.onion".to_string(),
                ],
                max_skill_size_bytes: 5_000_000,
                block_obfuscated: true,
            },
            limiter: LimiterConfig {
                enabled: true,
                max_tokens_per_request: 50_000,
                max_tokens_per_minute: 200_000,
                max_tokens_per_hour: 2_000_000,
                max_cost_per_day_usd: 10.0,
                cost_per_1k_input_tokens: 0.015,
                cost_per_1k_output_tokens: 0.075,
                alert_threshold_percent: 75.0,
            },
            logger: LoggerConfig {
                level: "info".to_string(),
                log_file: Some("/var/log/clawguard/clawguard.log".to_string()),
                log_blocked: true,
                log_frames: false,
                log_costs: true,
            },
            content_scan: None,
            source_routing: None,
        }
    }

    /// Serialize config to TOML string
    pub fn to_toml_string(&self) -> String {
        // Manual serialization since we use Deserialize only
        format!(
            r#"# ============================================
# ClawGuard Configuration
# Security gateway for OpenClaw
# ============================================

[general]
bind_address = "{bind_addr}"
bind_port = {bind_port}
upstream_host = "{up_host}"
upstream_port = {up_port}

[proxy]
# WebSocket origin validation (mitigates CVE-2026-25253)
validate_origin = {val_origin}
allowed_origins = [{origins}]
block_missing_origin = {block_missing}
protect_tokens = {protect_tokens}
max_connections = {max_conn}
connection_timeout_secs = {conn_timeout}

[scanner]
# Skill scanning before installation
enabled = {scan_enabled}
skills_directory = "{skills_dir}"
block_dangerous = {block_danger}
max_skill_size_bytes = {max_size}
block_obfuscated = {block_obf}

# Dangerous command patterns (regex)
dangerous_patterns = [
{danger_patterns}
]

# Data exfiltration patterns (regex)
exfiltration_patterns = [
{exfil_patterns}
]

[limiter]
# API cost control (prevents runaway spending)
enabled = {lim_enabled}
max_tokens_per_request = {max_req}
max_tokens_per_minute = {max_min}
max_tokens_per_hour = {max_hour}
max_cost_per_day_usd = {max_cost}
cost_per_1k_input_tokens = {cost_in}
cost_per_1k_output_tokens = {cost_out}
alert_threshold_percent = {alert_pct}

[logger]
level = "{log_level}"
log_file = "{log_file}"
log_blocked = {log_blocked}
log_frames = {log_frames}
log_costs = {log_costs}
"#,
            bind_addr = self.general.bind_address,
            bind_port = self.general.bind_port,
            up_host = self.general.upstream_host,
            up_port = self.general.upstream_port,
            val_origin = self.proxy.validate_origin,
            origins = self.proxy.allowed_origins.iter()
                .map(|o| format!("\"{}\"", o))
                .collect::<Vec<_>>()
                .join(", "),
            block_missing = self.proxy.block_missing_origin,
            protect_tokens = self.proxy.protect_tokens,
            max_conn = self.proxy.max_connections,
            conn_timeout = self.proxy.connection_timeout_secs,
            scan_enabled = self.scanner.enabled,
            skills_dir = self.scanner.skills_directory,
            block_danger = self.scanner.block_dangerous,
            max_size = self.scanner.max_skill_size_bytes,
            block_obf = self.scanner.block_obfuscated,
            danger_patterns = self.scanner.dangerous_patterns.iter()
                .map(|p| format!("    \"{}\"", p.replace('\\', "\\\\")))
                .collect::<Vec<_>>()
                .join(",\n"),
            exfil_patterns = self.scanner.exfiltration_patterns.iter()
                .map(|p| format!("    \"{}\"", p.replace('\\', "\\\\")))
                .collect::<Vec<_>>()
                .join(",\n"),
            lim_enabled = self.limiter.enabled,
            max_req = self.limiter.max_tokens_per_request,
            max_min = self.limiter.max_tokens_per_minute,
            max_hour = self.limiter.max_tokens_per_hour,
            max_cost = self.limiter.max_cost_per_day_usd,
            cost_in = self.limiter.cost_per_1k_input_tokens,
            cost_out = self.limiter.cost_per_1k_output_tokens,
            alert_pct = self.limiter.alert_threshold_percent,
            log_level = self.logger.level,
            log_file = self.logger.log_file.as_deref().unwrap_or(""),
            log_blocked = self.logger.log_blocked,
            log_frames = self.logger.log_frames,
            log_costs = self.logger.log_costs,
        )
    }
}
