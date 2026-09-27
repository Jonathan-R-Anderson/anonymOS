function canonicalStringify(value) {
    if (value === null || typeof value !== 'object') {
        return JSON.stringify(value);
    }
    if (Array.isArray(value)) {
        return '[' + value.map(canonicalStringify).join(',') + ']';
    }
    const keys = Object.keys(value).sort();
    const entries = keys.map(function (key) {
        return JSON.stringify(key) + ':' + canonicalStringify(value[key]);
    });
    return '{' + entries.join(',') + '}';
}

function utf8Encode(value) {
    return new TextEncoder().encode(value);
}

function utf8Decode(value) {
    return new TextDecoder().decode(value);
}

function hexToBytes(hexValue) {
    const normalized = String(hexValue || '').trim();
    if (normalized.length % 2 !== 0) {
        throw new Error('Invalid hex length');
    }
    const bytes = new Uint8Array(normalized.length / 2);
    for (let index = 0; index < normalized.length; index += 2) {
        bytes[index / 2] = parseInt(normalized.slice(index, index + 2), 16);
    }
    return bytes;
}

function bytesToHex(bytes) {
    return Array.from(bytes).map(function (value) {
        return value.toString(16).padStart(2, '0');
    }).join('');
}

function base64ToUtf8(base64Value) {
    const binary = atob(base64Value);
    const bytes = new Uint8Array(binary.length);
    for (let index = 0; index < binary.length; index += 1) {
        bytes[index] = binary.charCodeAt(index);
    }
    return utf8Decode(bytes);
}

function base64ToJson(base64Value) {
    return JSON.parse(base64ToUtf8(base64Value));
}

async function sha256Hex(value) {
    const digest = await crypto.subtle.digest('SHA-256', utf8Encode(value));
    return bytesToHex(new Uint8Array(digest));
}

function envelopeSigningPayload(envelope) {
    return {
        v: envelope.v,
        id: envelope.id,
        type: envelope.type,
        seq: envelope.seq,
        ts: envelope.ts,
        signer: envelope.signer,
        payload: envelope.payload,
        prev_hash: envelope.prev_hash === undefined ? null : envelope.prev_hash,
    };
}

function scopeKeyForBoard(boardName) {
    return 'board:' + boardName;
}

function scopeKeyForThread(threadId) {
    return 'thread:' + threadId;
}

export {
    base64ToJson,
    bytesToHex,
    canonicalStringify,
    envelopeSigningPayload,
    hexToBytes,
    scopeKeyForBoard,
    scopeKeyForThread,
    sha256Hex,
    utf8Encode,
};
