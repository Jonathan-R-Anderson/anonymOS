//! ML model inference engine.
//!
//! Loads ONNX models via `tract` and runs inference on feature vectors.
//! Falls back to a lightweight heuristic scorer when no model is available.
//!
//! The ONNX support requires the `onnx` feature flag to be enabled.
//! Without it, only the heuristic fallback model is available.

use std::path::Path;

use anyhow::Result;
use serde::{Deserialize, Serialize};
#[cfg(feature = "onnx")]
use tracing::warn;
use tracing::{debug, info};

use crate::ml_features::{ELF_FEATURE_DIM, PE_FEATURE_DIM};

/// Prediction result from the ML model.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MlPrediction {
    /// Estimated probability that the file is malicious (0.0 - 1.0).
    pub malicious_probability: f32,
    /// Confidence in the prediction (0.0 - 1.0).
    pub confidence: f32,
    /// Which model produced this prediction.
    pub model_type: &'static str,
}

// ---- ONNX model wrapper (behind feature flag) --------------------------------

#[cfg(feature = "onnx")]
mod onnx_backend {
    use super::*;
    use tract_onnx::prelude::*;

    pub(super) type OnnxModel = SimplePlan<TypedFact, Box<dyn TypedOp>, Graph<TypedFact, Box<dyn TypedOp>>>;

    pub(super) fn load_model(path: &Path, feature_dim: usize) -> Result<OnnxModel> {
        let model = tract_onnx::onnx()
            .model_for_path(path)?
            .with_input_fact(
                0,
                #[allow(clippy::cast_possible_wrap)]
                InferenceFact::dt_shape(f32::datum_type(), tvec![1, feature_dim as i64]),
            )?
            .into_optimized()?
            .into_runnable()?;
        Ok(model)
    }

    pub(super) fn run_inference(model: &OnnxModel, features: &[f32]) -> Result<f32> {
        let input = tract_ndarray::Array2::from_shape_vec((1, features.len()), features.to_vec())?;
        let result = model.run(tvec!(input.into_tensor().into()))?;
        let output = result[0].to_array_view::<f32>()?;
        // The model is expected to output a single probability value.
        // Handle both [1,1] and [1,2] output shapes.
        let prob = if output.len() >= 2 {
            // Assume softmax [benign, malicious]
            output.as_slice().and_then(|s| s.get(1).copied()).unwrap_or(0.0)
        } else {
            output.as_slice().and_then(|s| s.first().copied()).unwrap_or(0.0)
        };
        Ok(prob.clamp(0.0, 1.0))
    }
}

/// The ML inference engine.
///
/// Holds optional ONNX models for PE and ELF classification. When no model
/// files are found, it falls back to a simple weighted heuristic scorer.
pub struct MlModel {
    #[cfg(feature = "onnx")]
    pe_model: Option<onnx_backend::OnnxModel>,
    #[cfg(feature = "onnx")]
    elf_model: Option<onnx_backend::OnnxModel>,

    // Track whether we're in fallback mode (always true when onnx feature is off)
    pe_fallback: bool,
    elf_fallback: bool,
}

impl MlModel {
    /// Try to load ONNX models from `model_dir`.
    ///
    /// Expected files: `pe_model.onnx` and `elf_model.onnx`.
    /// If either is missing, that format falls back to the heuristic scorer.
    pub fn load(model_dir: &Path) -> Result<Self> {
        info!(dir = %model_dir.display(), "attempting to load ML models");

        #[cfg(feature = "onnx")]
        {
            let pe_path = model_dir.join("pe_model.onnx");
            let elf_path = model_dir.join("elf_model.onnx");

            let pe_model = if pe_path.exists() {
                match onnx_backend::load_model(&pe_path, PE_FEATURE_DIM) {
                    Ok(m) => {
                        info!("loaded PE ONNX model");
                        Some(m)
                    }
                    Err(e) => {
                        warn!(error = %e, "failed to load PE ONNX model, using fallback");
                        None
                    }
                }
            } else {
                debug!("pe_model.onnx not found, using fallback");
                None
            };

            let elf_model = if elf_path.exists() {
                match onnx_backend::load_model(&elf_path, ELF_FEATURE_DIM) {
                    Ok(m) => {
                        info!("loaded ELF ONNX model");
                        Some(m)
                    }
                    Err(e) => {
                        warn!(error = %e, "failed to load ELF ONNX model, using fallback");
                        None
                    }
                }
            } else {
                debug!("elf_model.onnx not found, using fallback");
                None
            };

            let pe_fallback = pe_model.is_none();
            let elf_fallback = elf_model.is_none();

            Ok(Self {
                pe_model,
                elf_model,
                pe_fallback,
                elf_fallback,
            })
        }

        #[cfg(not(feature = "onnx"))]
        {
            debug!("onnx feature not enabled, using fallback models for all formats");
            let _ = model_dir; // suppress unused warning
            Ok(Self::new_fallback())
        }
    }

    /// Create a fallback-only model (no ONNX inference).
    pub fn new_fallback() -> Self {
        debug!("initialising ML model in fallback mode");
        Self {
            #[cfg(feature = "onnx")]
            pe_model: None,
            #[cfg(feature = "onnx")]
            elf_model: None,
            pe_fallback: true,
            elf_fallback: true,
        }
    }

    /// Run PE malware prediction.
    pub fn predict_pe(&self, features: &[f32; PE_FEATURE_DIM]) -> MlPrediction {
        #[cfg(feature = "onnx")]
        {
            if let Some(model) = &self.pe_model {
                match onnx_backend::run_inference(model, features) {
                    Ok(prob) => {
                        return MlPrediction {
                            malicious_probability: prob,
                            confidence: 0.85,
                            model_type: "onnx",
                        };
                    }
                    Err(e) => {
                        warn!(error = %e, "ONNX PE inference failed, falling back");
                    }
                }
            }
        }

        fallback_pe_score(features)
    }

    /// Run ELF malware prediction.
    pub fn predict_elf(&self, features: &[f32; ELF_FEATURE_DIM]) -> MlPrediction {
        #[cfg(feature = "onnx")]
        {
            if let Some(model) = &self.elf_model {
                match onnx_backend::run_inference(model, features) {
                    Ok(prob) => {
                        return MlPrediction {
                            malicious_probability: prob,
                            confidence: 0.85,
                            model_type: "onnx",
                        };
                    }
                    Err(e) => {
                        warn!(error = %e, "ONNX ELF inference failed, falling back");
                    }
                }
            }
        }

        fallback_elf_score(features)
    }

    /// Whether either model is using ONNX (not fallback).
    pub const fn has_onnx_models(&self) -> bool {
        !self.pe_fallback || !self.elf_fallback
    }
}

// ---- Fallback heuristic models -----------------------------------------------

/// Simple weighted feature sum for PE files (no ML model needed).
///
/// Focuses on the most discriminating features:
/// - High entropy (packing/encryption)
/// - Suspicious API counts
/// - Writable code sections
/// - Packer indicators (UPX sections, zero-size sections)
#[allow(clippy::indexing_slicing)] // All indices are compile-time constants verified by const assert below
fn fallback_pe_score(f: &[f32; PE_FEATURE_DIM]) -> MlPrediction {
    // Compile-time guard: the highest index we access is 58, so the feature
    // dimension must be at least 59.  If PE_FEATURE_DIM is ever reduced below
    // that, this line will cause a build error instead of a runtime panic.
    const _: () = assert!(
        PE_FEATURE_DIM >= 59,
        "PE_FEATURE_DIM too small for fallback model indices"
    );

    let mut score: f32 = 0.0;

    // Overall entropy contribution (f[8] is /8.0, so >0.875 means >7.0)
    if f[8] > 0.875 {
        score += 0.25;
    } else if f[8] > 0.8 {
        score += 0.10;
    }

    // Max section entropy
    if f[9] > 0.875 {
        score += 0.15;
    }

    // Has UPX section
    score += f[12] * 0.15;

    // Has writable code
    score += f[13] * 0.12;

    // Suspicious API categories (f[14]-f[20])
    let api_sum: f32 = f[14..=20].iter().sum();
    score += (api_sum * 2.5).min(0.3);

    // Process injection specifically
    score += (f[14] * 5.0).min(0.15);

    // Zero-size sections (f[24])
    if f[24] > 1.0 {
        score += 0.08;
    }

    // High entropy sections count (f[25])
    if f[25] > 2.0 {
        score += 0.10;
    }

    // No debug info in a complex binary is mildly suspicious
    #[allow(clippy::float_cmp)]
    let no_debug_complex = f[58] == 0.0 && f[6] > 10.0;
    if no_debug_complex {
        score += 0.05;
    }

    // Zero timestamp (f[3])
    #[allow(clippy::float_cmp)]
    let zero_ts = f[3] == 0.0;
    if zero_ts {
        score += 0.05;
    }

    let prob = score.clamp(0.0, 1.0);
    let confidence = if (0.2..=0.7).contains(&prob) { 0.4 } else { 0.6 };

    MlPrediction {
        malicious_probability: prob,
        confidence,
        model_type: "heuristic_fallback",
    }
}

/// Simple weighted feature sum for ELF files.
#[allow(clippy::indexing_slicing)] // All indices are compile-time constants verified by const assert below
fn fallback_elf_score(f: &[f32; ELF_FEATURE_DIM]) -> MlPrediction {
    // Compile-time guard: the highest index we access is 43, so the feature
    // dimension must be at least 44.
    const _: () = assert!(
        ELF_FEATURE_DIM >= 44,
        "ELF_FEATURE_DIM too small for fallback model indices"
    );

    let mut score: f32 = 0.0;

    // Overall entropy (f[7])
    if f[7] > 0.875 {
        score += 0.20;
    } else if f[7] > 0.8 {
        score += 0.08;
    }

    // Max section entropy (f[8])
    if f[8] > 0.875 {
        score += 0.15;
    }

    // Suspicious Linux API counts (f[11]-f[16])
    // ptrace
    score += (f[11] * 0.08).min(0.15);
    // mprotect
    score += (f[12] * 0.04).min(0.08);
    // memfd_create (highly suspicious)
    score += (f[13] * 0.12).min(0.15);
    // execveat (highly suspicious)
    score += (f[14] * 0.10).min(0.15);
    // socket + connect
    score += ((f[15] + f[16]) * 0.03).min(0.08);

    // High entropy sections (f[17])
    if f[17] > 2.0 {
        score += 0.10;
    }

    // LD_PRELOAD reference (f[42])
    score += f[42] * 0.15;

    // ptrace reference (f[43])
    score += f[43] * 0.08;

    // No interpreter + no dynamic libs = static, possibly packed
    #[allow(clippy::float_cmp)]
    let static_packed = f[6] == 0.0 && f[5] == 0.0 && f[7] > 0.8;
    if static_packed {
        score += 0.12;
    }

    let prob = score.clamp(0.0, 1.0);
    let confidence = if (0.2..=0.7).contains(&prob) { 0.4 } else { 0.6 };

    MlPrediction {
        malicious_probability: prob,
        confidence,
        model_type: "heuristic_fallback",
    }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::float_cmp, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn fallback_model_initialises() {
        let model = MlModel::new_fallback();
        assert!(!model.has_onnx_models());
    }

    #[test]
    fn fallback_pe_clean_file_low_score() {
        // A "clean" PE: low entropy, no suspicious APIs, has debug info
        let mut f = [0.0f32; PE_FEATURE_DIM];
        f[0] = 1.0; // is_64bit
        f[4] = 4.0; // 4 sections
        f[6] = 5.0; // 5 import functions
        f[8] = 0.5; // moderate entropy
        f[9] = 0.6; // max section entropy
        f[58] = 1.0; // has debug info
        f[3] = 1.0; // valid timestamp

        let pred = fallback_pe_score(&f);
        assert!(
            pred.malicious_probability < 0.3,
            "clean PE should score low, got {}",
            pred.malicious_probability
        );
        assert_eq!(pred.model_type, "heuristic_fallback");
    }

    #[test]
    fn fallback_pe_malicious_pattern_high_score() {
        let mut f = [0.0f32; PE_FEATURE_DIM];
        f[8] = 0.95; // high overall entropy
        f[9] = 0.98; // high max section entropy
        f[12] = 1.0; // UPX section
        f[13] = 1.0; // writable code
        f[14] = 0.1; // process injection APIs
        f[15] = 0.06; // anti-debug APIs
        f[3] = 0.0; // zero timestamp
        f[24] = 2.0; // zero-size sections
        f[25] = 3.0; // high entropy sections

        let pred = fallback_pe_score(&f);
        assert!(
            pred.malicious_probability > 0.7,
            "malicious PE should score high, got {}",
            pred.malicious_probability
        );
    }

    #[test]
    fn fallback_elf_clean_file_low_score() {
        let mut f = [0.0f32; ELF_FEATURE_DIM];
        f[0] = 1.0; // is_64bit
        f[1] = 3.0; // DYN type
        f[5] = 3.0; // some dynamic libs
        f[6] = 1.0; // has interpreter
        f[7] = 0.5; // moderate entropy

        let pred = fallback_elf_score(&f);
        assert!(
            pred.malicious_probability < 0.3,
            "clean ELF should score low, got {}",
            pred.malicious_probability
        );
    }

    #[test]
    fn fallback_elf_malicious_pattern_high_score() {
        let mut f = [0.0f32; ELF_FEATURE_DIM];
        f[7] = 0.95; // high entropy
        f[8] = 0.98; // max section entropy
        f[11] = 1.0; // ptrace call
        f[13] = 1.0; // memfd_create
        f[14] = 1.0; // execveat
        f[42] = 1.0; // LD_PRELOAD
        f[43] = 1.0; // ptrace ref
        f[17] = 3.0; // many high-entropy sections

        let pred = fallback_elf_score(&f);
        assert!(
            pred.malicious_probability > 0.5,
            "malicious ELF should score high, got {}",
            pred.malicious_probability
        );
    }

    #[test]
    fn load_nonexistent_dir_falls_back() {
        let model = MlModel::load(Path::new("/nonexistent/path"));
        assert!(model.is_ok());
        let model = model.unwrap();
        assert!(!model.has_onnx_models());
    }

    #[test]
    fn predict_via_model_works() {
        let model = MlModel::new_fallback();
        let pe_features = [0.0f32; PE_FEATURE_DIM];
        let pred = model.predict_pe(&pe_features);
        assert!(pred.malicious_probability >= 0.0);
        assert!(pred.malicious_probability <= 1.0);
        assert_eq!(pred.model_type, "heuristic_fallback");

        let elf_features = [0.0f32; ELF_FEATURE_DIM];
        let pred = model.predict_elf(&elf_features);
        assert!(pred.malicious_probability >= 0.0);
        assert!(pred.malicious_probability <= 1.0);
    }
}
