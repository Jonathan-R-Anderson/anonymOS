Build-time toolchain dependencies live here when they are safe to relocate.

The vendored `jhc-0.8.2` source tree is intentionally still at the repository root for now because its generated/autoconf files contain baked-in source paths and moving it would break those scripts without a larger normalization pass.
