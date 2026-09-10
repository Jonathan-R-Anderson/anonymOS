import axios from 'axios';
import { publishEnvelope, subscribeToScope } from './gunBridge';
import {
    getBoard,
    getSyncState,
    listBoardThreads,
    listThreadPosts,
    mergeManifest,
    putValidatedEnvelope,
    quarantineEnvelope,
    subscribeBoard,
    subscribeThread,
} from './localDb';
import { validateEnvelope, validatorAvailable } from './validator';


const DEFAULT_REFRESH_DEBOUNCE_MS = 60;
const DEFAULT_FEED_RETRY_MS = 5000;
const SUPER_PEER_STORAGE_KEY = 'maniwani:distributed:super-peer';


function electedSuperPeer(config) {
    if (typeof window === 'undefined') {
        return false;
    }
    const params = new URLSearchParams(window.location.search || '');
    if (params.get('superpeer') === '1') {
        window.localStorage.setItem(SUPER_PEER_STORAGE_KEY, '1');
        return true;
    }
    if (params.get('superpeer') === '0') {
        window.localStorage.setItem(SUPER_PEER_STORAGE_KEY, '0');
        return false;
    }
    const stored = window.localStorage.getItem(SUPER_PEER_STORAGE_KEY);
    if (stored === '1') {
        return true;
    }
    if (stored === '0') {
        return false;
    }
    const elected = Math.random() < Number(config.superPeerRatio || 0.05);
    window.localStorage.setItem(SUPER_PEER_STORAGE_KEY, elected ? '1' : '0');
    return elected;
}


function withAfterSeq(baseUrl, afterSeq) {
    const separator = baseUrl.indexOf('?') === -1 ? '?' : '&';
    return baseUrl + separator + 'after_seq=' + encodeURIComponent(afterSeq);
}


function loadScriptOnce(url) {
    if (!url) {
        return Promise.resolve(false);
    }
    if (document.querySelector('script[data-distributed-src="' + url + '"]')) {
        return Promise.resolve(true);
    }
    return new Promise(function (resolve, reject) {
        const script = document.createElement('script');
        script.src = url;
        script.async = true;
        script.dataset.distributedSrc = url;
        script.onload = function () {
            resolve(true);
        };
        script.onerror = reject;
        document.head.appendChild(script);
    });
}


async function ingestEnvelope(config, envelope, options) {
    const ingestOptions = options || {};
    try {
        const validated = await validateEnvelope(config, envelope);
        const result = await putValidatedEnvelope(
            config.scopeId,
            validated.envelope,
            validated.payload,
            validated.hash
        );
        if (result.stored && ingestOptions.publishToGun) {
            publishEnvelope(config, config.scopeId, validated.envelope);
        }
        return result;
    } catch (error) {
        const reason = error && error.reason ? error.reason : error && error.message ? error.message : 'ingest_failed';
        await quarantineEnvelope(envelope, reason);
        throw error;
    }
}


async function refreshCatalogFromLocal(config) {
    const boardRecord = await getBoard(config.boardName);
    if (boardRecord && boardRecord.display && typeof config.onBoardMeta === 'function') {
        config.onBoardMeta(boardRecord.display);
    }
    const threads = await listBoardThreads(config.boardName, { limit: 500 });
    if (threads.length && typeof config.onThreads === 'function') {
        config.onThreads(threads);
    }
}


async function refreshThreadFromLocal(config) {
    const posts = await listThreadPosts(config.threadId);
    if (posts.length && typeof config.onPosts === 'function') {
        config.onPosts(posts);
    }
}


async function refreshFromLocal(config) {
    if (config.pageType === 'thread') {
        return refreshThreadFromLocal(config);
    }
    return refreshCatalogFromLocal(config);
}


async function reconcileScope(config, options) {
    const reconcileOptions = options || {};
    const manifestResponse = await axios.get(config.manifestUrl);
    const manifest = manifestResponse.data;
    const previousState = await getSyncState(config.scopeId);
    await mergeManifest(manifest);

    const manifestMatches =
        previousState &&
        Number(previousState.manifest_last_seq || previousState.last_seq || 0) >= Number(manifest.last_seq || 0) &&
        String(previousState.checksum || '') === String(manifest.checksum || '') &&
        Number(previousState.record_count || 0) === Number(manifest.record_count || 0);
    if (manifestMatches && !reconcileOptions.forceFetch) {
        await refreshFromLocal(config);
        return false;
    }

    const afterSeq = (
        !reconcileOptions.forceFetch &&
        previousState &&
        String(previousState.checksum || '') === String(manifest.checksum || '')
    ) ? Number(previousState.last_seq || 0) : 0;
    const deltaResponse = await axios.get(withAfterSeq(config.deltaUrl, afterSeq));
    const records = (deltaResponse.data && deltaResponse.data.records) || [];
    for (let index = 0; index < records.length; index += 1) {
        await ingestEnvelope(config, records[index], { publishToGun: reconcileOptions.publishToGun });
    }
    await refreshFromLocal(config);
    return records.length > 0;
}


async function startDistributedScope(config) {
    if (!config || !config.enabled || !validatorAvailable(config) || !window.indexedDB) {
        return false;
    }

    const cleanup = [];
    let refreshTimer = null;
    let stopped = false;
    let eventSource = null;
    let feedRetryTimer = null;
    const isSuperPeer = electedSuperPeer(config);

    const scheduleRefresh = function () {
        if (stopped || refreshTimer !== null) {
            return;
        }
        refreshTimer = window.setTimeout(async function () {
            refreshTimer = null;
            try {
                await refreshFromLocal(config);
            } catch (error) {
                console.error('distributed local refresh failed', error);
            }
        }, DEFAULT_REFRESH_DEBOUNCE_MS);
    };

    const startFeed = async function () {
        if (!isSuperPeer || stopped) {
            return;
        }
        const state = await getSyncState(config.scopeId);
        const afterSeq = Number(state && state.last_seq || 0);
        eventSource = new EventSource(withAfterSeq(config.feedUrl, afterSeq));
        eventSource.addEventListener('manifest', function (event) {
            try {
                mergeManifest(JSON.parse(event.data));
            } catch (error) {
                console.error('distributed manifest merge failed', error);
            }
        });
        eventSource.addEventListener('envelope', function (event) {
            let parsed;
            try {
                parsed = JSON.parse(event.data);
            } catch (error) {
                console.error('distributed feed payload parse failed', error);
                return;
            }
            ingestEnvelope(config, parsed, { publishToGun: true }).then(scheduleRefresh).catch(function (error) {
                console.error('distributed feed ingest failed', error);
            });
        });
        eventSource.onerror = function () {
            if (eventSource) {
                eventSource.close();
            }
            if (stopped) {
                return;
            }
            feedRetryTimer = window.setTimeout(function () {
                startFeed().catch(function (error) {
                    console.error('distributed feed restart failed', error);
                });
            }, DEFAULT_FEED_RETRY_MS);
        };
    };

    try {
        if (!window.Gun && config.gunScriptUrl) {
            try {
                await loadScriptOnce(config.gunScriptUrl);
            } catch (error) {
                console.error('distributed gun runtime load failed', error);
            }
        }
        if (config.pageType === 'thread') {
            cleanup.push(subscribeThread(config.threadId, scheduleRefresh));
        } else {
            cleanup.push(subscribeBoard(config.boardName, scheduleRefresh));
        }
        cleanup.push(subscribeToScope(config, config.scopeId, function (envelope) {
            ingestEnvelope(config, envelope, { publishToGun: false }).then(scheduleRefresh).catch(function (error) {
                console.error('distributed gun ingest failed', error);
            });
        }));
        await refreshFromLocal(config);
        await reconcileScope(config, {
            forceFetch: false,
            publishToGun: isSuperPeer,
        });
        await startFeed();
        const intervalId = window.setInterval(function () {
            reconcileScope(config, {
                forceFetch: false,
                publishToGun: isSuperPeer,
            }).catch(function (error) {
                console.error('distributed reconcile failed', error);
            });
        }, Number(config.syncIntervalMs || 600000));
        cleanup.push(function () {
            window.clearInterval(intervalId);
        });
    } catch (error) {
        cleanup.forEach(function (fn) {
            try {
                fn();
            } catch (_ignored) {}
        });
        throw error;
    }

    return {
        stop: function stop() {
            stopped = true;
            cleanup.forEach(function (fn) {
                try {
                    fn();
                } catch (_ignored) {}
            });
            if (refreshTimer !== null) {
                window.clearTimeout(refreshTimer);
            }
            if (feedRetryTimer !== null) {
                window.clearTimeout(feedRetryTimer);
            }
            if (eventSource) {
                eventSource.close();
            }
        },
        isSuperPeer: isSuperPeer,
    };
}


export {
    startDistributedScope,
};
