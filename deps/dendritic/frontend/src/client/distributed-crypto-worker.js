import 'regenerator-runtime/runtime';

import {
    base64ToJson,
    canonicalStringify,
    envelopeSigningPayload,
    hexToBytes,
    sha256Hex,
    utf8Encode,
} from '../distributed/shared';


const MAX_CONTENT_LENGTH = 20000;
const ALLOWED_TYPES = new Set(['board', 'thread', 'post', 'delete']);


function ensureEnvelopeShape(envelope) {
    if (!envelope || typeof envelope !== 'object') {
        throw new Error('invalid_envelope');
    }
    if (envelope.v !== 1) {
        throw new Error('unsupported_version');
    }
    if (!ALLOWED_TYPES.has(envelope.type)) {
        throw new Error('invalid_type');
    }
    if (typeof envelope.id !== 'string' || envelope.id.length < 3 || envelope.id.length > 255) {
        throw new Error('invalid_id');
    }
    if (typeof envelope.seq !== 'number' || !Number.isFinite(envelope.seq) || envelope.seq <= 0) {
        throw new Error('invalid_seq');
    }
    if (typeof envelope.ts !== 'number' || !Number.isFinite(envelope.ts) || envelope.ts <= 0) {
        throw new Error('invalid_ts');
    }
    if (typeof envelope.signer !== 'string' || envelope.signer.length < 32) {
        throw new Error('invalid_signer');
    }
    if (typeof envelope.sig !== 'string' || envelope.sig.length < 32) {
        throw new Error('invalid_sig');
    }
    if (typeof envelope.payload !== 'string' || !envelope.payload.length) {
        throw new Error('invalid_payload');
    }
    if (envelope.prev_hash !== null && envelope.prev_hash !== undefined) {
        if (typeof envelope.prev_hash !== 'string' || envelope.prev_hash.length !== 64) {
            throw new Error('invalid_prev_hash');
        }
    }
}


function ensurePayloadShape(envelopeType, payload) {
    if (!payload || typeof payload !== 'object') {
        throw new Error('invalid_payload_json');
    }
    if (typeof payload.id !== 'string' || payload.id !== undefined && payload.id.length > 255) {
        throw new Error('invalid_payload_id');
    }
    if (envelopeType === 'board') {
        if (typeof payload.name !== 'string' || payload.name.length < 1 || payload.name.length > 64) {
            throw new Error('invalid_board_name');
        }
        return;
    }
    if (typeof payload.board_id !== 'string' || payload.board_id.length < 1 || payload.board_id.length > 64) {
        throw new Error('invalid_board_id');
    }
    if (envelopeType === 'thread') {
        if (typeof payload.thread_numeric_id !== 'number') {
            throw new Error('invalid_thread_numeric_id');
        }
        if (typeof payload.content === 'string' && payload.content.length > MAX_CONTENT_LENGTH) {
            throw new Error('thread_content_too_large');
        }
        return;
    }
    if (envelopeType === 'post') {
        if (typeof payload.thread_numeric_id !== 'number') {
            throw new Error('invalid_post_thread_numeric_id');
        }
        if (typeof payload.author !== 'string' || payload.author.length > 256) {
            throw new Error('invalid_author');
        }
        if (typeof payload.content !== 'string' || payload.content.length > MAX_CONTENT_LENGTH) {
            throw new Error('invalid_content');
        }
    }
}


async function verifySignature(envelope) {
    if (!crypto || !crypto.subtle || typeof crypto.subtle.importKey !== 'function') {
        throw new Error('crypto_unavailable');
    }
    const verifyKey = await crypto.subtle.importKey(
        'raw',
        hexToBytes(envelope.signer),
        { name: 'Ed25519' },
        false,
        ['verify']
    );
    return crypto.subtle.verify(
        { name: 'Ed25519' },
        verifyKey,
        hexToBytes(envelope.sig),
        utf8Encode(canonicalStringify(envelopeSigningPayload(envelope)))
    );
}


async function validateEnvelope(envelope, maxClockSkewMs) {
    ensureEnvelopeShape(envelope);
    if ((envelope.ts - Date.now()) > maxClockSkewMs) {
        throw new Error('clock_skew');
    }
    const payload = base64ToJson(envelope.payload);
    ensurePayloadShape(envelope.type, payload);
    const signatureValid = await verifySignature(envelope);
    if (!signatureValid) {
        throw new Error('invalid_sig');
    }
    const envelopeHash = await sha256Hex(canonicalStringify(envelopeSigningPayload(envelope)));
    return {
        envelope: envelope,
        payload: payload,
        hash: envelopeHash,
    };
}


self.onmessage = function (event) {
    const requestId = event.data && event.data.requestId;
    const envelope = event.data && event.data.envelope;
    const maxClockSkewMs = event.data && event.data.maxClockSkewMs ? event.data.maxClockSkewMs : 300000;
    validateEnvelope(envelope, maxClockSkewMs).then(function (result) {
        self.postMessage({
            requestId: requestId,
            ok: true,
            envelope: result.envelope,
            payload: result.payload,
            hash: result.hash,
        });
    }).catch(function (error) {
        self.postMessage({
            requestId: requestId,
            ok: false,
            reason: error && error.message ? error.message : 'validation_failed',
            raw: envelope,
        });
    });
};
