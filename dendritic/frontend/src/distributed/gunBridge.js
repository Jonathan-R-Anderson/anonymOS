let gunInstance = null;


function relayPeerUrl(config) {
    if (!config || !config.gunRelayUrl) {
        return window.location.origin + '/gun';
    }
    if (config.gunRelayUrl.indexOf('http://') === 0 || config.gunRelayUrl.indexOf('https://') === 0) {
        return config.gunRelayUrl;
    }
    return window.location.origin + config.gunRelayUrl;
}


function gunAvailable() {
    return typeof window !== 'undefined' && typeof window.Gun === 'function';
}


function getGun(config) {
    if (!gunAvailable()) {
        return null;
    }
    if (gunInstance) {
        return gunInstance;
    }
    gunInstance = window.Gun({
        peers: [relayPeerUrl(config)],
        localStorage: false,
    });
    return gunInstance;
}


function scopeChannel(config, scopeId) {
    const gun = getGun(config);
    if (!gun) {
        return null;
    }
    return gun.get('maniwani').get('scopes').get(scopeId).get('records');
}


function publishEnvelope(config, scopeId, envelope) {
    const channel = scopeChannel(config, scopeId);
    if (!channel) {
        return false;
    }
    channel.get(envelope.id).put({
        v: envelope.v,
        id: envelope.id,
        type: envelope.type,
        seq: envelope.seq,
        ts: envelope.ts,
        signer: envelope.signer,
        sig: envelope.sig,
        payload: envelope.payload,
        prev_hash: envelope.prev_hash === undefined ? null : envelope.prev_hash,
    });
    return true;
}


function subscribeToScope(config, scopeId, handler) {
    const channel = scopeChannel(config, scopeId);
    if (!channel) {
        return function noop() {};
    }
    const seenKeys = new Map();
    const subscription = channel.map().on(function (data, key) {
        if (!data || typeof data !== 'object' || !data.id || !data.sig) {
            return;
        }
        const revisionKey = String(data.seq || '') + ':' + String(data.sig || '');
        if (seenKeys.get(key) === revisionKey) {
            return;
        }
        seenKeys.set(key, revisionKey);
        handler({
            v: data.v,
            id: data.id,
            type: data.type,
            seq: data.seq,
            ts: data.ts,
            signer: data.signer,
            sig: data.sig,
            payload: data.payload,
            prev_hash: data.prev_hash === undefined ? null : data.prev_hash,
        });
    });
    return function unsubscribe() {
        if (subscription && typeof subscription.off === 'function') {
            subscription.off();
        }
    };
}


export {
    gunAvailable,
    publishEnvelope,
    subscribeToScope,
};
