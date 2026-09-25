// Minimal WASM plugin example for prx-sd.
//
// Compile with:
//   cargo build --target wasm32-wasip1 --release
//
// The resulting .wasm lives at:
//   target/wasm32-wasip1/release/example_plugin.wasm

// ── Host imports ────────────────────────────────────────────────────────────

extern "C" {
    fn report_finding(
        name_ptr: *const u8,
        name_len: u32,
        score: u32,
        detail_ptr: *const u8,
        detail_len: u32,
    );
}

// ── Plugin exports ──────────────────────────────────────────────────────────

/// Write the plugin name into the buffer provided by the host and return the
/// actual byte length of the name.
#[no_mangle]
pub extern "C" fn plugin_name(buf: *mut u8, len: u32) -> u32 {
    write_str(buf, len, "Example Scanner")
}

/// Write the plugin version into the buffer provided by the host.
#[no_mangle]
pub extern "C" fn plugin_version(buf: *mut u8, len: u32) -> u32 {
    write_str(buf, len, "0.1.0")
}

/// Called once after the module is instantiated. Return 0 on success.
#[no_mangle]
pub extern "C" fn on_load() -> i32 {
    0
}

/// Scan `data_len` bytes starting at `data_ptr`.
///
/// Returns a threat score between 0 (clean) and 100 (definitely malicious).
#[no_mangle]
pub extern "C" fn scan(data_ptr: *const u8, data_len: u32) -> i32 {
    // SAFETY: The host guarantees data_ptr points to data_len valid bytes in guest memory.
    let data = unsafe { core::slice::from_raw_parts(data_ptr, data_len as usize) };
    let marker = b"MALICIOUS_MARKER";

    if contains(data, marker) {
        // Also report via the host function so that details are captured.
        let name = b"Marker.Generic";
        let detail = b"File contains the MALICIOUS_MARKER test string";
        // SAFETY: name and detail are valid byte slices with correct lengths.
        // The host import reads exactly the specified number of bytes.
        unsafe {
            report_finding(
                name.as_ptr(),
                name.len() as u32,
                90,
                detail.as_ptr(),
                detail.len() as u32,
            );
        }
        return 90;
    }

    0
}

/// Simple memory allocator export so the host can request guest memory.
#[no_mangle]
pub extern "C" fn alloc(size: u32) -> u32 {
    // SAFETY: Alignment of 1 is always valid, and size > 0 is guaranteed by the caller.
    let layout = unsafe {
        core::alloc::Layout::from_size_align_unchecked(size as usize, 1)
    };
    // SAFETY: layout has non-zero size (enforced by caller) and valid alignment.
    let ptr = unsafe { std::alloc::alloc(layout) };
    ptr as u32
}

// ── Helpers ─────────────────────────────────────────────────────────────────

fn write_str(buf: *mut u8, buf_len: u32, s: &str) -> u32 {
    let bytes = s.as_bytes();
    let to_copy = bytes.len().min(buf_len as usize);
    // SAFETY: bytes and buf do not overlap (source is Rust str, dest is host buffer).
    // to_copy is bounded by both source length and destination capacity.
    unsafe {
        core::ptr::copy_nonoverlapping(bytes.as_ptr(), buf, to_copy);
    }
    bytes.len() as u32
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    if needle.len() > haystack.len() {
        return false;
    }
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}
