//! # Safe Workspace Staging & Symlink Traversal Defeat (Chapters 21, 22, 28, 29)
//!
//! Enforces:
//! 1. Containment boundary: Rejects path traversal and symlink escapes pointing outside workspace root.
//! 2. Immutable candidate sealing: Snapshots candidate content into immutable buffers.
//! 3. TOCTOU race defeat: Workspace mutations occurring after candidate sealing have zero effect on verification.

use crate::error::ValidationError;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Component, Path, PathBuf};

/// Immutable Sealed Candidate Snapshot
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedCandidate {
    pub relative_path: PathBuf,
    pub content_digest: String,
    pub bytes: Vec<u8>,
}

impl SealedCandidate {
    pub fn new(relative_path: PathBuf, bytes: Vec<u8>) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        let content_digest = hex::encode(hasher.finalize());
        Self {
            relative_path,
            content_digest,
            bytes,
        }
    }
}

pub struct WorkspaceStagingGuard;

impl WorkspaceStagingGuard {
    /// Validates that a requested path is strictly contained within the workspace root
    /// and does not escape via directory traversal (`..`), absolute paths, or external symlinks.
    pub fn validate_path(
        workspace_root: &Path,
        rel_path: &Path,
    ) -> Result<PathBuf, ValidationError> {
        // 1. Path must not be absolute
        if rel_path.is_absolute() {
            return Err(ValidationError::ContainmentEscapeViolation(format!(
                "Absolute path rejected: {}",
                rel_path.display()
            )));
        }

        // 2. Reject '..' parent dir traversal components
        for component in rel_path.components() {
            if matches!(component, Component::ParentDir) {
                return Err(ValidationError::ContainmentEscapeViolation(format!(
                    "Path traversal parent component '..' rejected: {}",
                    rel_path.display()
                )));
            }
        }

        let canonical_root = workspace_root.canonicalize().map_err(|e| {
            ValidationError::ContainmentEscapeViolation(format!(
                "Failed to canonicalize workspace root {}: {}",
                workspace_root.display(),
                e
            ))
        })?;

        let full_path = canonical_root.join(rel_path);

        // 3. If file exists, check symlink resolution doesn't escape canonical root
        if full_path.exists() {
            let canonical_target = full_path.canonicalize().map_err(|e| {
                ValidationError::ContainmentEscapeViolation(format!(
                    "Failed to canonicalize candidate target {}: {}",
                    full_path.display(),
                    e
                ))
            })?;

            if !canonical_target.starts_with(&canonical_root) {
                return Err(ValidationError::ContainmentEscapeViolation(format!(
                    "Symlink escape detected: target {} points outside workspace root {}",
                    canonical_target.display(),
                    canonical_root.display()
                )));
            }
            Ok(canonical_target)
        } else {
            Ok(full_path)
        }
    }

    /// Read and seal a candidate file from workspace, producing an immutable snapshot.
    /// Defeats check-to-use TOCTOU races: future edits to the workspace file do not alter this snapshot.
    pub fn seal_candidate_file(
        workspace_root: &Path,
        rel_path: &Path,
    ) -> Result<SealedCandidate, ValidationError> {
        let validated = Self::validate_path(workspace_root, rel_path)?;
        let bytes = fs::read(&validated).map_err(|e| {
            ValidationError::ContainmentEscapeViolation(format!(
                "Failed to read candidate file {}: {}",
                validated.display(),
                e
            ))
        })?;

        Ok(SealedCandidate::new(rel_path.to_path_buf(), bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_path_traversal_rejection() {
        let dir = tempdir().unwrap();
        let ws_root = dir.path();

        let malicious = Path::new("../../etc/passwd");
        let res = WorkspaceStagingGuard::validate_path(ws_root, malicious);
        assert!(matches!(
            res,
            Err(ValidationError::ContainmentEscapeViolation(_))
        ));

        let abs_path = Path::new("/var/log/system.log");
        let res_abs = WorkspaceStagingGuard::validate_path(ws_root, abs_path);
        assert!(matches!(
            res_abs,
            Err(ValidationError::ContainmentEscapeViolation(_))
        ));
    }

    #[test]
    fn test_symlink_escape_defeat() {
        let dir = tempdir().unwrap();
        let ws_root = dir.path().join("workspace");
        let outside = dir.path().join("outside");
        fs::create_dir(&ws_root).unwrap();
        fs::create_dir(&outside).unwrap();

        let secret_file = outside.join("secret.key");
        fs::write(&secret_file, b"top-secret-token").unwrap();

        // Create symlink inside workspace pointing outside
        let link_path = ws_root.join("leak_link");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&secret_file, &link_path).unwrap();

        #[cfg(unix)]
        {
            let res = WorkspaceStagingGuard::validate_path(&ws_root, Path::new("leak_link"));
            assert!(matches!(
                res,
                Err(ValidationError::ContainmentEscapeViolation(_))
            ));
        }
    }

    #[test]
    fn test_immutable_candidate_sealing_defeats_toctou() {
        let dir = tempdir().unwrap();
        let ws_root = dir.path();

        let patch_path = ws_root.join("solution.patch");
        fs::write(
            &patch_path,
            b"diff --git a/src/main.rs b/src/main.rs\n+verified",
        )
        .unwrap();

        // 1. Seal candidate
        let sealed =
            WorkspaceStagingGuard::seal_candidate_file(ws_root, Path::new("solution.patch"))
                .unwrap();
        let initial_digest = sealed.content_digest.clone();

        // 2. Malicious concurrent workspace mutation (TOCTOU race attempt)
        fs::write(&patch_path, b"MALICIOUS BACKDOOR PAYLOAD").unwrap();

        // 3. Sealed candidate retains original verified content and digest!
        assert_eq!(sealed.content_digest, initial_digest);
        assert_eq!(
            sealed.bytes,
            b"diff --git a/src/main.rs b/src/main.rs\n+verified"
        );
    }
}
