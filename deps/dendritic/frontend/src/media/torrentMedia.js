const torrentEntries = {};
const transferListeners = new Set();
let torrentClient = null;
let webTorrentCtorPromise = null;
const WEBTORRENT_READY_EVENT = 'maniwani:webtorrent-ready';


function getViewerMediaConfig() {
    if (typeof window === 'undefined') {
        return {
            preferredMode: 'torrent',
            canDirectFallback: true,
            directFallbackPeerThreshold: 5,
            iceServers: [],
            forceTurnRelay: false,
        };
    }
    const config = window._MEDIA_DELIVERY || {};
    const parsedDirectFallbackPeerThreshold = parseInt(config.directFallbackPeerThreshold, 10);
    return {
        preferredMode: config.preferredMode === 'direct' ? 'direct' : 'torrent',
        canDirectFallback: typeof config.canDirectFallback === 'boolean' ? config.canDirectFallback : true,
        directFallbackPeerThreshold: Number.isFinite(parsedDirectFallbackPeerThreshold)
            ? Math.max(0, parsedDirectFallbackPeerThreshold)
            : 5,
        iceServers: Array.isArray(config.iceServers) ? config.iceServers : [],
        forceTurnRelay: !!config.forceTurnRelay,
    };
}


function getWebTorrentCtor() {
    if (typeof window === 'undefined') {
        return null;
    }
    const candidate = window.WebTorrent || null;
    if (candidate && candidate.default) {
        return candidate.default;
    }
    return candidate;
}


function waitForWebTorrentCtor() {
    const readyCtor = getWebTorrentCtor();
    if (readyCtor || typeof window === 'undefined') {
        return Promise.resolve(readyCtor);
    }
    if (webTorrentCtorPromise) {
        return webTorrentCtorPromise;
    }
    webTorrentCtorPromise = new Promise(function (resolve) {
        let settled = false;
        let timeoutId = null;

        function finish() {
            if (settled) {
                return;
            }
            settled = true;
            if (timeoutId !== null && typeof window.clearTimeout === 'function') {
                window.clearTimeout(timeoutId);
            }
            window.removeEventListener(WEBTORRENT_READY_EVENT, finish);
            const ctor = getWebTorrentCtor();
            webTorrentCtorPromise = null;
            resolve(ctor);
        }

        window.addEventListener(WEBTORRENT_READY_EVENT, finish);
        if (typeof window.setTimeout === 'function') {
            timeoutId = window.setTimeout(finish, 5000);
        }
    });
    return webTorrentCtorPromise;
}


function createTorrentClient(WebTorrentCtor) {
    if (torrentClient) {
        return torrentClient;
    }
    if (!WebTorrentCtor || !WebTorrentCtor.WEBRTC_SUPPORT) {
        return null;
    }
    const viewerConfig = getViewerMediaConfig();
    const trackerConfig = {};
    if (viewerConfig.iceServers.length || viewerConfig.forceTurnRelay) {
        trackerConfig.rtcConfig = {
            iceServers: viewerConfig.iceServers,
            iceTransportPolicy: viewerConfig.forceTurnRelay ? 'relay' : 'all',
        };
    }
    torrentClient = new WebTorrentCtor({
        dht: false,
        lsd: false,
        tracker: trackerConfig,
    });
    torrentClient.on('error', function (error) {
        console.error('WebTorrent client error', error);
    });
    return torrentClient;
}


function getTorrentClient() {
    if (torrentClient) {
        return Promise.resolve(torrentClient);
    }
    return waitForWebTorrentCtor().then(function (WebTorrentCtor) {
        return createTorrentClient(WebTorrentCtor);
    });
}


function errorMessage(error) {
    if (!error) {
        return null;
    }
    return error.message || String(error);
}


function baseSnapshot(entry) {
    const torrent = entry.torrent;
    return {
        mediaId: entry.torrentPayload ? entry.torrentPayload.media_id : null,
        mimetype: entry.torrentPayload ? entry.torrentPayload.mimetype : null,
        displayName: torrent ? torrent.name : (entry.torrentPayload ? entry.torrentPayload.display_name : null),
        status: entry.status,
        magnetUrl: entry.torrentPayload ? entry.torrentPayload.magnet_url : null,
        magnetSource: entry.torrentPayload ? entry.torrentPayload.magnet_source : null,
        torrentUrl: entry.torrentPayload ? entry.torrentPayload.torrent_url : null,
        blobReady: !!entry.blob,
        ready: !!(torrent && torrent.ready),
        done: !!(torrent && torrent.done),
        numPeers: torrent ? (torrent.numPeers || 0) : 0,
        progress: torrent ? (torrent.progress || 0) : 0,
        downloadSpeed: torrent ? (torrent.downloadSpeed || 0) : 0,
        uploadSpeed: torrent ? (torrent.uploadSpeed || 0) : 0,
        downloaded: torrent ? (torrent.downloaded || 0) : 0,
        uploaded: torrent ? (torrent.uploaded || 0) : 0,
        length: torrent ? (torrent.length || 0) : 0,
        errorMessage: errorMessage(entry.error),
    };
}


function snapshot(entry) {
    return Object.assign({}, baseSnapshot(entry), {
        blob: entry.blob || null,
        blobUrl: entry.blobUrl || null,
        error: entry.error || null,
    });
}


function transferSnapshot(entry) {
    return Object.assign({
        infoHash: entry.infoHash,
        error: errorMessage(entry.error),
    }, baseSnapshot(entry));
}


function allTransferSnapshots() {
    return Object.keys(torrentEntries).map(function (infoHash) {
        return transferSnapshot(torrentEntries[infoHash]);
    }).sort(function (left, right) {
        return (left.mediaId || 0) - (right.mediaId || 0);
    });
}


function emitTransferSnapshots() {
    const currentSnapshots = allTransferSnapshots();
    transferListeners.forEach(function (listener) {
        listener(currentSnapshots);
    });
}


function emit(entry) {
    const currentSnapshot = snapshot(entry);
    entry.listeners.forEach(function (listener) {
        listener(currentSnapshot);
    });
    emitTransferSnapshots();
}


function replaceResolvedBlob(entry, blob) {
    if (entry.blobUrl && typeof URL !== 'undefined' && typeof URL.revokeObjectURL === 'function') {
        URL.revokeObjectURL(entry.blobUrl);
    }
    entry.blob = blob || null;
    if (!blob || typeof URL === 'undefined' || typeof URL.createObjectURL !== 'function') {
        entry.blobUrl = null;
        return;
    }
    entry.blobUrl = URL.createObjectURL(blob);
    console.info('[torrentMedia] blob ready', {
        infoHash: entry.infoHash,
        mediaId: entry.torrentPayload ? entry.torrentPayload.media_id : null,
        blobUrl: entry.blobUrl,
    });
}


function resolveBlob(file, callback) {
    if (!file) {
        callback(new Error('Torrent file is unavailable.'));
        return;
    }
    if (typeof file.getBlob === 'function') {
        file.getBlob(callback);
        return;
    }
    if (typeof file.blob === 'function') {
        Promise.resolve(file.blob()).then(function (blob) {
            callback(null, blob);
        }).catch(callback);
        return;
    }
    if (typeof file.getBlobURL === 'function') {
        file.getBlobURL(function (error, blobUrl) {
            if (error) {
                callback(error);
                return;
            }
            fetch(blobUrl).then(function (response) {
                if (!response.ok) {
                    throw new Error('Failed to read torrent blob URL.');
                }
                return response.blob();
            }).then(function (blob) {
                if (typeof URL !== 'undefined' && typeof URL.revokeObjectURL === 'function') {
                    URL.revokeObjectURL(blobUrl);
                }
                callback(null, blob);
            }).catch(callback);
        });
        return;
    }
    callback(new Error('Browser torrent blob APIs are unavailable.'));
}


function ensureStatsTimer(entry) {
    if (entry.statsTimer || typeof window === 'undefined' || typeof window.setInterval !== 'function') {
        return;
    }
    entry.statsTimer = window.setInterval(function () {
        if (entry.torrent) {
            emit(entry);
        }
    }, 1000);
}


function bindTorrent(entry, torrent) {
    if (!torrent || entry.boundTorrent === torrent) {
        return;
    }
    entry.boundTorrent = torrent;
    entry.torrent = torrent;
    ensureStatsTimer(entry);

    function refresh(nextStatus) {
        if (nextStatus) {
            entry.status = nextStatus;
        }
        emit(entry);
    }

    torrent.on('warning', function (error) {
        entry.error = error;
        refresh(entry.status);
    });
    torrent.on('error', function (error) {
        entry.error = error;
        refresh('error');
    });
    torrent.on('metadata', function () {
        refresh('loading');
    });
    torrent.on('ready', function () {
        refresh('loading');
        resolveEntryBlob(entry);
    });
    torrent.on('done', function () {
        refresh(entry.blob ? 'ready' : 'loading');
        resolveEntryBlob(entry);
    });
    torrent.on('wire', function () {
        refresh(entry.status);
    });
    torrent.on('download', function () {
        refresh(entry.status);
    });
    torrent.on('upload', function () {
        refresh(entry.status);
    });
}


function resolveEntryBlob(entry) {
    if (entry.blob || entry.resolvingBlob || !entry.torrent) {
        if (entry.blob) {
            entry.status = 'ready';
            emit(entry);
        }
        return;
    }
    const file = entry.torrent.files && entry.torrent.files.length ? entry.torrent.files[0] : null;
    if (!file) {
        entry.error = new Error('Torrent file is unavailable.');
        entry.status = 'error';
        emit(entry);
        return;
    }
    if (typeof file.select === 'function') {
        file.select();
    }
    entry.resolvingBlob = true;
    resolveBlob(file, function (error, blob) {
        entry.resolvingBlob = false;
        if (error) {
            entry.error = error;
            entry.status = 'error';
            emit(entry);
            return;
        }
        entry.error = null;
        replaceResolvedBlob(entry, blob);
        entry.status = 'ready';
        emit(entry);
    });
}


function preferredTorrentSource(torrentPayload) {
    if (!torrentPayload) {
        return null;
    }
    return torrentPayload.magnet_url || torrentPayload.torrent_url || null;
}


function startTorrentDownload(entry) {
    if (!entry.torrentPayload || !entry.torrentPayload.magnet_url) {
        entry.status = 'unavailable';
        emit(entry);
        return;
    }
    if (entry.clientLoading) {
        return;
    }

    function attachToTorrent(torrent) {
        bindTorrent(entry, torrent);
        entry.status = entry.blob ? 'ready' : 'loading';
        emit(entry);
        if (torrent.ready) {
            resolveEntryBlob(entry);
            return;
        }
        torrent.on('ready', function () {
            resolveEntryBlob(entry);
        });
    }

    entry.status = 'loading';
    emit(entry);
    entry.clientLoading = true;

    // After 10s with 0 peers and no blob, nudge the server to re-seed so the
    // swarm has at least one seeder while the browser uses the direct fallback.
    if (
        !entry.ensureSeededSent &&
        entry.torrentPayload &&
        entry.torrentPayload.media_id &&
        typeof window !== 'undefined' &&
        typeof window.fetch === 'function' &&
        typeof window.setTimeout === 'function'
    ) {
        var _mediaId = entry.torrentPayload.media_id;
        window.setTimeout(function () {
            if (entry.ensureSeededSent || entry.blob) {
                return;
            }
            var peers = entry.torrent ? (entry.torrent.numPeers || 0) : 0;
            if (peers === 0) {
                entry.ensureSeededSent = true;
                window.fetch('/upload/' + _mediaId + '/ensure-seeded', { method: 'POST' })
                    .catch(function () {});
            }
        }, 10000);
    }

    console.info('[torrentMedia] start', {
        infoHash: entry.infoHash,
        mediaId: entry.torrentPayload ? entry.torrentPayload.media_id : null,
        sourceKind: preferredTorrentSource(entry.torrentPayload) === (entry.torrentPayload ? entry.torrentPayload.magnet_url : null)
            ? 'magnet'
            : 'torrent',
        torrentUrl: entry.torrentPayload ? entry.torrentPayload.torrent_url : null,
        magnetUrl: entry.torrentPayload ? entry.torrentPayload.magnet_url : null,
    });

    getTorrentClient().then(function (client) {
        entry.clientLoading = false;
        if (!client) {
            entry.status = 'unsupported';
            emit(entry);
            return;
        }

        const existingTorrent = (client.torrents || []).find(function (torrent) {
            return torrent.infoHash === entry.infoHash;
        });
        if (existingTorrent) {
            attachToTorrent(existingTorrent);
            return;
        }

        const source = preferredTorrentSource(entry.torrentPayload);
        try {
            client.add(source, {
                announce: entry.torrentPayload.announce_urls || [],
            }, attachToTorrent);
        } catch (error) {
            if (source !== entry.torrentPayload.magnet_url && entry.torrentPayload.magnet_url) {
                try {
                    client.add(entry.torrentPayload.magnet_url, {
                        announce: entry.torrentPayload.announce_urls || [],
                    }, attachToTorrent);
                    return;
                } catch (fallbackError) {
                    entry.error = fallbackError;
                }
            } else {
                entry.error = error;
            }
            entry.status = 'error';
            console.warn('[torrentMedia] add failed', {
                infoHash: entry.infoHash,
                mediaId: entry.torrentPayload ? entry.torrentPayload.media_id : null,
                error: errorMessage(entry.error),
            });
            emit(entry);
        }
    }).catch(function (error) {
        entry.clientLoading = false;
        entry.error = error;
        entry.status = 'error';
        console.warn('[torrentMedia] client init failed', {
            infoHash: entry.infoHash,
            mediaId: entry.torrentPayload ? entry.torrentPayload.media_id : null,
            error: errorMessage(error),
        });
        emit(entry);
    });
}


export function subscribeToTorrentMedia(torrentPayload, listener) {
    if (!torrentPayload || !torrentPayload.info_hash) {
        listener({
            mediaId: null,
            mimetype: null,
            displayName: null,
            blob: null,
            blobUrl: null,
            status: 'idle',
            error: null,
            magnetUrl: null,
            magnetSource: null,
            torrentUrl: null,
            blobReady: false,
            ready: false,
            done: false,
            numPeers: 0,
            progress: 0,
            downloadSpeed: 0,
            uploadSpeed: 0,
            downloaded: 0,
            uploaded: 0,
            length: 0,
            errorMessage: null,
        });
        return function () {};
    }

    let entry = torrentEntries[torrentPayload.info_hash];
    if (!entry) {
        entry = torrentEntries[torrentPayload.info_hash] = {
            infoHash: torrentPayload.info_hash,
            torrentPayload: torrentPayload,
            blob: null,
            blobUrl: null,
            error: null,
            status: 'idle',
            listeners: new Set(),
            torrent: null,
            boundTorrent: null,
            resolvingBlob: false,
            statsTimer: null,
            clientLoading: false,
            ensureSeededSent: false,
        };
    } else {
        entry.torrentPayload = torrentPayload;
    }

    entry.listeners.add(listener);
    listener(snapshot(entry));
    emitTransferSnapshots();
    if (entry.status === 'idle') {
        startTorrentDownload(entry);
    }

    return function unsubscribe() {
        entry.listeners.delete(listener);
    };
}


export function subscribeToTorrentTransfers(listener) {
    transferListeners.add(listener);
    listener(allTransferSnapshots());
    return function unsubscribe() {
        transferListeners.delete(listener);
    };
}


export function viewerPreferredMediaMode() {
    return getViewerMediaConfig().preferredMode;
}


export function viewerCanDirectFallback() {
    return getViewerMediaConfig().canDirectFallback;
}


export function viewerDirectFallbackPeerThreshold() {
    return getViewerMediaConfig().directFallbackPeerThreshold;
}


export function shouldUseDirectFallbackNow(torrentState, options) {
    const preferredMode = options && options.preferredMode
        ? options.preferredMode
        : viewerPreferredMediaMode();
    const canDirectFallback = options && typeof options.canDirectFallback === 'boolean'
        ? options.canDirectFallback
        : viewerCanDirectFallback();
    const peerThreshold = options && typeof options.directFallbackPeerThreshold === 'number'
        ? options.directFallbackPeerThreshold
        : viewerDirectFallbackPeerThreshold();

    if (preferredMode === 'direct') {
        return true;
    }
    if (!canDirectFallback) {
        return false;
    }
    if (!torrentState) {
        return peerThreshold > 0;
    }
    if (torrentState.blobUrl) {
        return false;
    }

    const status = torrentState.status || 'idle';
    if (status === 'error' || status === 'unsupported' || status === 'unavailable') {
        return true;
    }

    if (peerThreshold <= 0) {
        return false;
    }
    return Number(torrentState.numPeers || 0) < peerThreshold;
}
