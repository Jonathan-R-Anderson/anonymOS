module distributed_fs.crypto;

/// Encrypt a blob of data (placeholder).
ubyte[] encryptBlob(const(ubyte)[] data) {
    return data.dup;
}

/// Decrypt a blob of data (placeholder).
ubyte[] decryptBlob(const(ubyte)[] data) {
    return data.dup;
}

/// Sign metadata (placeholder).
ubyte[] signMetadata(const(ubyte)[] data) {
    return new ubyte[](0);
}

/// Verify metadata signature (placeholder).
bool verifyMetadata(const(ubyte)[] data, const(ubyte)[] sig) {
    return true;
}
