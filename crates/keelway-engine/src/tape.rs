use crate::core::{Decision, KeelwayError, Principal, Receipt, ToolCall, UnsealedReceipt};
use crate::policy::PolicyEngine;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use tokio::sync::{mpsc, oneshot};

pub const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Summary returned by streaming SHA-256 hash-chain verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TapeVerification {
    pub count: u64,
    pub head_hash: String,
    pub valid: bool,
}

/// Offline replay verdict for a single recorded receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "UPPERCASE")]
pub enum ReplayVerdict {
    Allow,
    Deny,
    Indeterminate { touched_fields: Vec<String> },
}

/// Result of replaying one recorded receipt against a candidate policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayEntry {
    pub seq: u64,
    pub org_id: String,
    pub agent_id: String,
    pub server: String,
    pub tool: String,
    pub original_decision: Decision,
    pub replayed_verdict: ReplayVerdict,
    pub changed: bool,
    pub reason: String,
}

struct WriteCommand {
    unsealed: UnsealedReceipt,
    ack: oneshot::Sender<Result<Receipt, KeelwayError>>,
}

/// Handle to the dedicated OS-thread group-commit SHA-256 `TapeWriter`.
#[derive(Clone)]
pub struct TapeWriter {
    tx: mpsc::Sender<WriteCommand>,
}

impl TapeWriter {
    /// Opens or creates `path`, verifies existing SHA-256 chain integrity (fail-closed),
    /// and spawns a dedicated OS thread for serialized group-commit appends.
    pub fn open(path: PathBuf) -> Result<Self, KeelwayError> {
        let (initial_seq, initial_hash) = if path.exists() {
            let v = verify_tape(&path)?;
            (v.count, v.head_hash)
        } else {
            if let Some(parent) = path.parent()
                && !parent.as_os_str().is_empty()
            {
                std::fs::create_dir_all(parent)?;
            }
            (0u64, GENESIS_HASH.to_owned())
        };

        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        let (tx, mut rx) = mpsc::channel::<WriteCommand>(1024);

        let thread_path = path.clone();
        std::thread::Builder::new()
            .name("keelway-tape-writer".to_owned())
            .spawn(move || {
                run_writer_loop(file, initial_seq, initial_hash, &mut rx);
            })
            .map_err(|e| {
                KeelwayError::Tape(format!(
                    "failed to spawn tape writer thread for '{}': {e}",
                    thread_path.display()
                ))
            })?;

        Ok(Self { tx })
    }

    /// Durably appends a receipt (waiting for `sync_data()` ack before returning).
    pub async fn append(&self, unsealed: UnsealedReceipt) -> Result<Receipt, KeelwayError> {
        let (ack_tx, ack_rx) = oneshot::channel();
        self.tx
            .send(WriteCommand {
                unsealed,
                ack: ack_tx,
            })
            .await
            .map_err(|_| KeelwayError::Tape("tape writer channel closed".to_owned()))?;
        ack_rx
            .await
            .map_err(|_| KeelwayError::Tape("tape writer dropped ack channel".to_owned()))?
    }
}

fn run_writer_loop(
    mut file: File,
    mut seq: u64,
    mut prev_hash: String,
    rx: &mut mpsc::Receiver<WriteCommand>,
) {
    while let Some(first) = rx.blocking_recv() {
        // Group-commit batching: drain all immediately queued receipts in one fsync
        let mut batch = vec![first];
        while let Ok(next) = rx.try_recv() {
            batch.push(next);
            if batch.len() >= 128 {
                break;
            }
        }

        let mut sealed_batch: Vec<(Receipt, oneshot::Sender<Result<Receipt, KeelwayError>>)> =
            Vec::with_capacity(batch.len());
        let mut serialized_buf = String::new();
        let mut batch_err: Option<String> = None;

        for cmd in batch {
            let next_seq = seq + 1;
            let receipt_res = seal_receipt(next_seq, &prev_hash, cmd.unsealed);
            match receipt_res {
                Ok(receipt) => match serde_json::to_string(&receipt) {
                    Ok(line) => {
                        seq = next_seq;
                        prev_hash = receipt.entry_hash.clone();
                        serialized_buf.push_str(&line);
                        serialized_buf.push('\n');
                        sealed_batch.push((receipt, cmd.ack));
                    }
                    Err(e) => {
                        let _ = cmd
                            .ack
                            .send(Err(KeelwayError::Tape(format!("serialize receipt: {e}"))));
                    }
                },
                Err(e) => {
                    let _ = cmd.ack.send(Err(e));
                }
            }
        }

        if !serialized_buf.is_empty() {
            if let Err(e) = file
                .write_all(serialized_buf.as_bytes())
                .and_then(|()| file.flush())
                .and_then(|()| file.sync_data())
            {
                batch_err = Some(format!("tape write/sync_data failed: {e}"));
            }
        }

        for (receipt, ack) in sealed_batch {
            if let Some(ref err_msg) = batch_err {
                let _ = ack.send(Err(KeelwayError::Tape(err_msg.clone())));
            } else {
                let _ = ack.send(Ok(receipt));
            }
        }
    }
}

/// Computes deterministic SHA-256 `entry_hash` over canonical receipt fields + `prev_hash`.
pub fn compute_entry_hash(receipt: &Receipt) -> Result<String, KeelwayError> {
    let mut clone = receipt.clone();
    clone.entry_hash.clear();
    let canonical = serde_json::to_vec(&clone)?;
    let mut hasher = Sha256::new();
    hasher.update(canonical);
    Ok(hex::encode(hasher.finalize()))
}

fn seal_receipt(seq: u64, prev_hash: &str, u: UnsealedReceipt) -> Result<Receipt, KeelwayError> {
    let mut receipt = Receipt {
        seq,
        prev_hash: prev_hash.to_owned(),
        entry_hash: String::new(),
        timestamp: u.timestamp,
        org_id: u.org_id,
        agent_id: u.agent_id,
        server: u.server,
        tool: u.tool,
        redacted_args: u.redacted_args,
        redacted_fields: u.redacted_fields,
        decision: u.decision,
        explanation: u.explanation,
        policy_digest: u.policy_digest,
        state: u.state,
        outcome: u.outcome,
        provenance: u.provenance,
    };
    receipt.entry_hash = compute_entry_hash(&receipt)?;
    Ok(receipt)
}

/// Verifies `keelway-tape.jsonl` in O(1) memory using streaming `BufReader`.
pub fn verify_tape(path: &Path) -> Result<TapeVerification, KeelwayError> {
    let file = File::open(path).map_err(|e| {
        KeelwayError::Tape(format!("failed to open tape '{}': {e}", path.display()))
    })?;
    let reader = BufReader::new(file);
    let mut expected_seq = 0u64;
    let mut expected_prev = GENESIS_HASH.to_owned();

    for (line_idx, line_res) in reader.lines().enumerate() {
        let line = line_res?;
        if line.trim().is_empty() {
            continue;
        }
        let receipt: Receipt = serde_json::from_str(&line).map_err(|e| {
            KeelwayError::Tape(format!(
                "corrupted JSON at line {} of '{}': {e}",
                line_idx + 1,
                path.display()
            ))
        })?;
        expected_seq += 1;
        if receipt.seq != expected_seq {
            return Err(KeelwayError::Tape(format!(
                "sequence gap at line {}: expected seq {}, got {}",
                line_idx + 1,
                expected_seq,
                receipt.seq
            )));
        }
        if receipt.prev_hash != expected_prev {
            return Err(KeelwayError::Tape(format!(
                "broken hash chain at seq {}: prev_hash mismatch",
                receipt.seq
            )));
        }
        let recomputed = compute_entry_hash(&receipt)?;
        if receipt.entry_hash != recomputed {
            return Err(KeelwayError::Tape(format!(
                "tampered receipt at seq {}: entry_hash mismatch",
                receipt.seq
            )));
        }
        expected_prev = receipt.entry_hash;
    }

    Ok(TapeVerification {
        count: expected_seq,
        head_hash: expected_prev,
        valid: true,
    })
}

/// Streams receipts from `path` in O(1) memory, invoking `visitor` for each verified receipt.
pub fn stream_receipts<F>(path: &Path, mut visitor: F) -> Result<TapeVerification, KeelwayError>
where
    F: FnMut(Receipt) -> Result<(), KeelwayError>,
{
    let file = File::open(path).map_err(|e| {
        KeelwayError::Tape(format!("failed to open tape '{}': {e}", path.display()))
    })?;
    let reader = BufReader::new(file);
    let mut expected_seq = 0u64;
    let mut expected_prev = GENESIS_HASH.to_owned();

    for (line_idx, line_res) in reader.lines().enumerate() {
        let line = line_res?;
        if line.trim().is_empty() {
            continue;
        }
        let receipt: Receipt = serde_json::from_str(&line).map_err(|e| {
            KeelwayError::Tape(format!("corrupted JSON at line {}: {e}", line_idx + 1))
        })?;
        expected_seq += 1;
        if receipt.seq != expected_seq || receipt.prev_hash != expected_prev {
            return Err(KeelwayError::Tape(format!(
                "hash chain broken at seq {}",
                receipt.seq
            )));
        }
        let recomputed = compute_entry_hash(&receipt)?;
        if receipt.entry_hash != recomputed {
            return Err(KeelwayError::Tape(format!(
                "tampered receipt at seq {}",
                receipt.seq
            )));
        }
        expected_prev = receipt.entry_hash.clone();
        visitor(receipt)?;
    }

    Ok(TapeVerification {
        count: expected_seq,
        head_hash: expected_prev,
        valid: true,
    })
}

/// Replays recorded receipts offline against `policy_engine` with zero upstream side effects.
/// Flags any receipt where an evaluated validator inspects a redacted argument field as `INDETERMINATE`.
pub fn replay_tape(
    path: &Path,
    policy_engine: &PolicyEngine,
    principal_roles_lookup: &dyn Fn(&str, &str) -> Vec<String>,
) -> Result<Vec<ReplayEntry>, KeelwayError> {
    let mut entries = Vec::new();
    stream_receipts(path, |receipt| {
        let inspected = policy_engine.inspected_arg_pointers(&receipt.server, &receipt.tool);
        let touched: Vec<String> = receipt
            .redacted_fields
            .iter()
            .filter(|rf| {
                inspected
                    .iter()
                    .any(|ip| *rf == ip || rf.starts_with(&format!("{ip}/")))
            })
            .cloned()
            .collect();

        if !touched.is_empty() {
            entries.push(ReplayEntry {
                seq: receipt.seq,
                org_id: receipt.org_id,
                agent_id: receipt.agent_id,
                server: receipt.server,
                tool: receipt.tool,
                original_decision: receipt.decision,
                replayed_verdict: ReplayVerdict::Indeterminate {
                    touched_fields: touched.clone(),
                },
                changed: true,
                reason: format!(
                    "INDETERMINATE (redacted_field_touched: {})",
                    touched.join(", ")
                ),
            });
            return Ok(());
        }

        let principal = Principal {
            org_id: receipt.org_id.clone(),
            agent_id: receipt.agent_id.clone(),
            roles: principal_roles_lookup(&receipt.org_id, &receipt.agent_id),
        };
        let eval = policy_engine.evaluate(
            &principal,
            &ToolCall {
                server: receipt.server.clone(),
                tool: receipt.tool.clone(),
                arguments: receipt.redacted_args.clone(),
            },
        )?;
        let replayed_verdict = match eval.decision {
            Decision::Allow => ReplayVerdict::Allow,
            Decision::Deny => ReplayVerdict::Deny,
        };
        let changed = eval.decision != receipt.decision;
        entries.push(ReplayEntry {
            seq: receipt.seq,
            org_id: receipt.org_id,
            agent_id: receipt.agent_id,
            server: receipt.server,
            tool: receipt.tool,
            original_decision: receipt.decision,
            replayed_verdict,
            changed,
            reason: eval.explanation.reason,
        });
        Ok(())
    })?;
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{Explanation, ReceiptState};
    use chrono::Utc;
    use serde_json::json;
    use tempfile::tempdir;

    fn dummy_unsealed(seq_hint: usize) -> UnsealedReceipt {
        UnsealedReceipt {
            timestamp: Utc::now(),
            org_id: "acme".to_owned(),
            agent_id: "coding-agent".to_owned(),
            server: "github".to_owned(),
            tool: format!("tool_{seq_hint}"),
            redacted_args: json!({ "n": seq_hint }),
            redacted_fields: vec![],
            decision: Decision::Allow,
            explanation: Explanation {
                decision: Decision::Allow,
                rule_ids: vec!["policy0".to_owned()],
                validator_outcomes: vec![],
                reason: "allowed".to_owned(),
                policy_digest: "abc".to_owned(),
            },
            policy_digest: "abc".to_owned(),
            state: ReceiptState::Sealed,
            outcome: None,
            provenance: None,
        }
    }

    #[tokio::test]
    async fn concurrent_appends_preserve_linear_sha256_chain() -> Result<(), KeelwayError> {
        let dir = tempdir()?;
        let tape_path = dir.path().join("keelway-tape.jsonl");
        let writer = TapeWriter::open(tape_path.clone())?;

        let mut handles = Vec::new();
        for i in 0..40 {
            let w = writer.clone();
            handles.push(tokio::spawn(
                async move { w.append(dummy_unsealed(i)).await },
            ));
        }
        for h in handles {
            let res = h
                .await
                .map_err(|e| KeelwayError::Tape(format!("join error: {e}")))?;
            res?;
        }
        drop(writer);

        let v = verify_tape(&tape_path)?;
        assert!(v.valid);
        assert_eq!(v.count, 40);
        Ok(())
    }

    #[tokio::test]
    async fn tampered_tape_fails_closed_on_startup() -> Result<(), KeelwayError> {
        let dir = tempdir()?;
        let tape_path = dir.path().join("keelway-tape.jsonl");
        let writer = TapeWriter::open(tape_path.clone())?;
        writer.append(dummy_unsealed(1)).await?;
        drop(writer);

        let raw = std::fs::read_to_string(&tape_path)?;
        let tampered = raw.replace("tool_1", "tool_999");
        std::fs::write(&tape_path, tampered)?;

        assert!(TapeWriter::open(tape_path).is_err());
        Ok(())
    }
}
