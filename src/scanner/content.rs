//! Embedding-based content scanner for prompt-injection detection.
//!
//! Compares incoming text against a pre-embedded corpus of known-bad
//! patterns using cosine similarity, powered by a local Ollama model.

use crate::config::ContentScanConfig;
use serde::{Deserialize, Serialize};
use std::fs;
use tracing::{info, warn};

/// A single labeled embedding in the known-bad corpus.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorpusEntry {
    /// Descriptive label for this pattern (e.g. "prompt injection").
    pub label: String,
    /// Pre-computed embedding vector.
    pub embedding: Vec<f64>,
}

/// Incoming content scan request (POST /scan body).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanRequest {
    /// The text to scan for injection patterns.
    pub content: String,
    /// Optional source identifier for allowlist matching.
    #[serde(default)]
    pub source: String,
}

/// Result of an embedding-based content scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResponse {
    /// Highest cosine similarity score against the corpus.
    pub score: f64,
    /// Whether the score exceeded the configured threshold.
    pub flagged: bool,
    /// Action taken: `"allow"`, `"flag"`, or `"block"`.
    pub action: String,
    /// Label of the closest corpus entry, if any.
    pub matched_pattern: Option<String>,
}

/// Raw embedding response from the Ollama API.
#[derive(Debug, Deserialize)]
struct OllamaEmbedResponse {
    embedding: Vec<f64>,
}

/// Embedding-based content scanner backed by a local Ollama model.
pub struct ContentScanner {
    config: ContentScanConfig,
    corpus: Vec<CorpusEntry>,
    allowlist: Vec<String>,
    client: reqwest::Client,
}

impl ContentScanner {
    /// Create a scanner, loading corpus and allowlist from disk.
    pub fn new(config: ContentScanConfig) -> Self {
        let corpus = Self::load_corpus(&config.corpus_file);
        let allowlist = Self::load_allowlist(&config.allowlist_file);
        info!(
            corpus_size = corpus.len(),
            threshold = config.similarity_threshold,
            "Content scanner initialized"
        );
        Self {
            config,
            corpus,
            allowlist,
            client: reqwest::Client::new(),
        }
    }

    fn load_corpus(path: &str) -> Vec<CorpusEntry> {
        match fs::read_to_string(path) {
            Ok(data) => serde_json::from_str(&data).unwrap_or_else(|e| {
                warn!(error = %e, "Failed to parse corpus file");
                vec![]
            }),
            Err(e) => {
                warn!(path = %path, error = %e, "Failed to read corpus file");
                vec![]
            }
        }
    }

    fn load_allowlist(path: &str) -> Vec<String> {
        if path.is_empty() {
            return vec![];
        }
        match fs::read_to_string(path) {
            Ok(data) => data.lines().map(|l| l.trim().to_string()).filter(|l| !l.is_empty() && !l.starts_with('#')).collect(),
            Err(_) => vec![],
        }
    }

    /// Scan content by embedding it and comparing against the corpus.
    pub async fn scan(&self, req: &ScanRequest) -> ScanResponse {
        // Check allowlist
        if !req.source.is_empty() && self.allowlist.iter().any(|a| req.source.contains(a)) {
            return ScanResponse {
                score: 0.0,
                flagged: false,
                action: "allow".to_string(),
                matched_pattern: None,
            };
        }

        if self.corpus.is_empty() {
            return ScanResponse {
                score: 0.0,
                flagged: false,
                action: "allow".to_string(),
                matched_pattern: Some("no corpus loaded".to_string()),
            };
        }

        // Embed the content
        let embedding = match self.embed(&req.content).await {
            Ok(e) => e,
            Err(e) => {
                warn!(error = %e, "Embedding failed, allowing request");
                return ScanResponse {
                    score: 0.0,
                    flagged: false,
                    action: "allow".to_string(),
                    matched_pattern: Some(format!("embed error: {}", e)),
                };
            }
        };

        // Find max cosine similarity against corpus
        let mut max_score: f64 = 0.0;
        let mut best_label: Option<String> = None;

        for entry in &self.corpus {
            let sim = cosine_similarity(&embedding, &entry.embedding);
            if sim > max_score {
                max_score = sim;
                best_label = Some(entry.label.clone());
            }
        }

        let flagged = max_score >= self.config.similarity_threshold;
        let action = if flagged {
            self.config.action.clone()
        } else {
            "allow".to_string()
        };

        // Log if flagged
        if flagged {
            if let Some(ref log_path) = self.config.log_file {
                let ts = chrono::Utc::now().to_rfc3339();
                let line = format!(
                    "{} score={:.4} source={} pattern={}\n",
                    ts,
                    max_score,
                    req.source,
                    best_label.as_deref().unwrap_or("?")
                );
                let _ = fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(log_path)
                    .and_then(|mut f| {
                        use std::io::Write;
                        f.write_all(line.as_bytes())
                    });
            }
        }

        ScanResponse {
            score: max_score,
            flagged,
            action,
            matched_pattern: best_label,
        }
    }

    async fn embed(&self, text: &str) -> Result<Vec<f64>, String> {
        let body = serde_json::json!({
            "model": self.config.model,
            "prompt": text,
        });

        let resp = self
            .client
            .post(&self.config.endpoint)
            .json(&body)
            .send()
            .await
            .map_err(|e| format!("request failed: {}", e))?;

        if !resp.status().is_success() {
            return Err(format!("ollama returned {}", resp.status()));
        }

        let data: OllamaEmbedResponse = resp
            .json()
            .await
            .map_err(|e| format!("parse failed: {}", e))?;

        Ok(data.embedding)
    }
}

/// Compute cosine similarity between two vectors. Returns 0.0 on dimension mismatch.
fn cosine_similarity(a: &[f64], b: &[f64]) -> f64 {
    if a.len() != b.len() || a.is_empty() {
        return 0.0;
    }
    let dot: f64 = a.iter().zip(b.iter()).map(|(x, y)| x * y).sum();
    let mag_a: f64 = a.iter().map(|x| x * x).sum::<f64>().sqrt();
    let mag_b: f64 = b.iter().map(|x| x * x).sum::<f64>().sqrt();
    if mag_a == 0.0 || mag_b == 0.0 {
        return 0.0;
    }
    dot / (mag_a * mag_b)
}
