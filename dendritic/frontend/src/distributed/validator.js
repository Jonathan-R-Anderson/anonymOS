let workerInstance = null;
let requestCounter = 0;
const pendingRequests = new Map();


function getWorker(workerUrl) {
    if (workerInstance) {
        return workerInstance;
    }
    workerInstance = new Worker(workerUrl);
    workerInstance.onmessage = function (event) {
        const payload = event.data || {};
        const pending = pendingRequests.get(payload.requestId);
        if (!pending) {
            return;
        }
        pendingRequests.delete(payload.requestId);
        if (payload.ok) {
            pending.resolve(payload);
            return;
        }
        pending.reject(payload);
    };
    workerInstance.onerror = function (error) {
        pendingRequests.forEach(function (pending) {
            pending.reject({ reason: error && error.message ? error.message : 'worker_error' });
        });
        pendingRequests.clear();
        workerInstance = null;
    };
    return workerInstance;
}


function validatorAvailable(config) {
    return Boolean(
        config &&
        config.workerUrl &&
        typeof Worker !== 'undefined' &&
        window.crypto &&
        window.crypto.subtle
    );
}


function validateEnvelope(config, envelope) {
    if (!validatorAvailable(config)) {
        return Promise.reject({ reason: 'validator_unavailable' });
    }
    const requestId = 'req-' + String(requestCounter++);
    const worker = getWorker(config.workerUrl);
    return new Promise(function (resolve, reject) {
        pendingRequests.set(requestId, { resolve: resolve, reject: reject });
        worker.postMessage({
            requestId: requestId,
            envelope: envelope,
            maxClockSkewMs: config.maxClockSkewMs || 300000,
        });
    });
}


export {
    validateEnvelope,
    validatorAvailable,
};
