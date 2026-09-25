//! Signature update client for the prx-sd antivirus engine.
//!
//! This crate provides:
//!
//! - **Delta patches** (`DeltaPatch`, `YaraRuleEntry`, `RuleAction`) for
//!   expressing incremental signature database updates.
//! - **Ed25519 signature verification** (`verify_payload`, `sign_payload`) to
//!   ensure updates are authentic.
//! - **HTTP update client** (`UpdateClient`) that fetches, verifies, and
//!   applies updates from the prx-sd update server.

pub mod client;
pub mod community;
pub mod delta;
pub mod verify;

pub use client::UpdateClient;
pub use delta::{DeltaPatch, RuleAction, YaraRuleEntry};
pub use verify::{sign_payload, verify_payload};
