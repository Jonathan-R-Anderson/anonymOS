//! `ClamAV` signature format parsers.
//!
//! This module provides parsers for common `ClamAV` signature file formats:
//!
//! - **CVD** (`.cvd`) - `ClamAV` Virus Database container files
//! - **NDB** (`.ndb`) - Hex signature (body-based) files
//! - **LDB** (`.ldb`) - Logical signature files with boolean expressions

pub mod cvd;
pub mod hdb;
pub mod ldb;
pub mod ndb;

pub use cvd::{CvdFile, CvdHeader};
pub use hdb::{HashKind, HashSignature, HashSignatureSet, decode_hex, parse_hdb, parse_hsb};
pub use ldb::{LdbSignature, parse_ldb};
pub use ndb::{NdbOffset, NdbSignature, parse_hex_pattern, parse_ndb};
