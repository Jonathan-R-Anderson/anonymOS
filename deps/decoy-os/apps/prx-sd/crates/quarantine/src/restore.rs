use anyhow::Result;
use chrono::Utc;

use crate::vault::{Quarantine, QuarantineId};

/// Restore multiple quarantined files to their original paths.
///
/// Each file is restored independently; failures for one file do not
/// prevent restoration of the others. Returns one `Result` per ID.
pub fn batch_restore(quarantine: &Quarantine, ids: &[QuarantineId]) -> Vec<Result<()>> {
    ids.iter()
        .map(|id| {
            // Load metadata to determine original path.
            let entries = quarantine.list()?;
            let meta = entries
                .iter()
                .find(|(entry_id, _)| entry_id == id)
                .map(|(_, m)| m.clone())
                .ok_or_else(|| anyhow::anyhow!("quarantine entry not found: {id}"))?;

            quarantine.restore(*id, &meta.original_path)
        })
        .collect()
}

/// Permanently delete multiple quarantined files.
///
/// Each deletion is independent; failures for one file do not prevent
/// deletion of the others. Returns one `Result` per ID.
pub fn batch_delete(quarantine: &Quarantine, ids: &[QuarantineId]) -> Vec<Result<()>> {
    ids.iter().map(|id| quarantine.delete(*id)).collect()
}

/// Delete quarantined files older than `max_age_days` days.
///
/// Returns the number of entries that were successfully deleted.
pub fn cleanup_expired(quarantine: &Quarantine, max_age_days: u32) -> Result<usize> {
    let entries = quarantine.list()?;
    let now = Utc::now();
    let max_age = chrono::Duration::days(i64::from(max_age_days));
    let mut deleted = 0;

    for (id, meta) in &entries {
        let age = now.signed_duration_since(meta.quarantine_time);
        if age > max_age {
            match quarantine.delete(*id) {
                Ok(()) => {
                    deleted += 1;
                    tracing::info!(
                        id = %id,
                        age_days = age.num_days(),
                        original_path = %meta.original_path.display(),
                        "expired quarantine entry deleted"
                    );
                }
                Err(e) => {
                    tracing::warn!(
                        id = %id,
                        error = %e,
                        "failed to delete expired quarantine entry"
                    );
                }
            }
        }
    }

    Ok(deleted)
}
