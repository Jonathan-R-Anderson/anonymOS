import { scopeKeyForBoard, scopeKeyForThread } from './shared';


const DB_NAME = 'maniwani-distributed-v1';
const DB_VERSION = 1;
const STORES = {
    BOARDS: 'boards',
    THREADS: 'threads',
    POSTS: 'posts',
    SYNC_STATE: 'sync_state',
    QUARANTINE: 'quarantine',
};

let dbPromise = null;
const listeners = new Map();


function requestToPromise(request) {
    return new Promise(function (resolve, reject) {
        request.onsuccess = function () {
            resolve(request.result);
        };
        request.onerror = function () {
            reject(request.error);
        };
    });
}


function rangeForBoard(boardId) {
    return IDBKeyRange.bound([boardId, 0], [boardId, Number.MAX_SAFE_INTEGER]);
}


function rangeForThread(threadId) {
    return IDBKeyRange.bound([threadId, 0], [threadId, Number.MAX_SAFE_INTEGER]);
}


function openDistributedDb() {
    if (dbPromise) {
        return dbPromise;
    }
    dbPromise = new Promise(function (resolve, reject) {
        const request = indexedDB.open(DB_NAME, DB_VERSION);
        request.onupgradeneeded = function () {
            const db = request.result;
            if (!db.objectStoreNames.contains(STORES.BOARDS)) {
                const boards = db.createObjectStore(STORES.BOARDS, { keyPath: 'id' });
                boards.createIndex('board_name', 'name', { unique: false });
            }
            if (!db.objectStoreNames.contains(STORES.THREADS)) {
                const threads = db.createObjectStore(STORES.THREADS, { keyPath: 'id' });
                threads.createIndex('board_last_activity', ['board_id', 'last_activity'], { unique: false });
                threads.createIndex('thread_numeric_id', 'thread_numeric_id', { unique: false });
            }
            if (!db.objectStoreNames.contains(STORES.POSTS)) {
                const posts = db.createObjectStore(STORES.POSTS, { keyPath: 'id' });
                posts.createIndex('thread_created_at', ['thread_numeric_id', 'created_at'], { unique: false });
                posts.createIndex('board_created_at', ['board_id', 'created_at'], { unique: false });
            }
            if (!db.objectStoreNames.contains(STORES.SYNC_STATE)) {
                db.createObjectStore(STORES.SYNC_STATE, { keyPath: 'scope_id' });
            }
            if (!db.objectStoreNames.contains(STORES.QUARANTINE)) {
                const quarantine = db.createObjectStore(STORES.QUARANTINE, { keyPath: 'rowid', autoIncrement: true });
                quarantine.createIndex('received_at', 'received_at', { unique: false });
            }
        };
        request.onsuccess = function () {
            resolve(request.result);
        };
        request.onerror = function () {
            reject(request.error);
        };
    });
    return dbPromise;
}


function notify(key) {
    const handlers = listeners.get(key);
    if (!handlers) {
        return;
    }
    handlers.forEach(function (handler) {
        try {
            handler();
        } catch (error) {
            console.error('distributed listener failed', error);
        }
    });
}


function subscribeListener(key, handler) {
    if (!listeners.has(key)) {
        listeners.set(key, new Set());
    }
    listeners.get(key).add(handler);
    return function unsubscribe() {
        const handlers = listeners.get(key);
        if (!handlers) {
            return;
        }
        handlers.delete(handler);
        if (handlers.size === 0) {
            listeners.delete(key);
        }
    };
}


async function quarantineEnvelope(rawEnvelope, reason) {
    const db = await openDistributedDb();
    const transaction = db.transaction([STORES.QUARANTINE], 'readwrite');
    transaction.objectStore(STORES.QUARANTINE).add({
        raw: JSON.stringify(rawEnvelope),
        reason: String(reason || 'invalid'),
        received_at: Date.now(),
    });
    return new Promise(function (resolve, reject) {
        transaction.oncomplete = function () {
            resolve(true);
        };
        transaction.onerror = function () {
            reject(transaction.error);
        };
    });
}


async function getSyncState(scopeId) {
    const db = await openDistributedDb();
    const transaction = db.transaction([STORES.SYNC_STATE], 'readonly');
    return requestToPromise(transaction.objectStore(STORES.SYNC_STATE).get(scopeId));
}


async function mergeManifest(manifest) {
    const db = await openDistributedDb();
    const currentState = await getSyncState(manifest.scope_id);
    const transaction = db.transaction([STORES.SYNC_STATE], 'readwrite');
    const store = transaction.objectStore(STORES.SYNC_STATE);
    const nextState = Object.assign({}, currentState || {}, {
        scope_id: manifest.scope_id,
        board_id: manifest.board_id,
        page_type: manifest.page_type,
        thread_id: manifest.thread_id,
        manifest_last_seq: manifest.last_seq,
        checksum: manifest.checksum,
        record_count: manifest.record_count,
        signer: manifest.signer,
        manifest_received_at: Date.now(),
    });
    store.put(nextState);
    return new Promise(function (resolve, reject) {
        transaction.oncomplete = function () {
            resolve(nextState);
        };
        transaction.onerror = function () {
            reject(transaction.error);
        };
    });
}


function normalizeBoardRecord(payload, envelope, hash) {
    return {
        id: payload.id,
        name: payload.name,
        display_name: payload.display_name,
        description: payload.description,
        source: payload.source,
        seq: envelope.seq,
        verified: 1,
        envelope_hash: hash,
        display: payload,
    };
}


function normalizeThreadRecord(payload, envelope, hash) {
    return {
        id: payload.id,
        source: payload.source,
        board_id: payload.board_id,
        thread_numeric_id: payload.thread_numeric_id,
        title: payload.title,
        content: payload.content,
        media_hash: payload.media_hash,
        last_activity: payload.last_activity,
        created_at: payload.created_at,
        post_count: payload.post_count,
        media_count: payload.media_count,
        seq: envelope.seq,
        verified: 1,
        envelope_hash: hash,
        display: payload.display,
    };
}


function normalizePostRecord(payload, envelope, hash) {
    return {
        id: payload.id,
        source: payload.source,
        board_id: payload.board_id,
        thread_id: payload.thread_id,
        thread_numeric_id: payload.thread_numeric_id,
        author: payload.author,
        content: payload.content,
        media_hash: payload.media_hash,
        created_at: payload.created_at,
        seq: envelope.seq,
        verified: 1,
        envelope_hash: hash,
        display: payload.display,
    };
}


async function putValidatedEnvelope(scopeId, envelope, payload, hash) {
    const db = await openDistributedDb();
    const scopeState = await getSyncState(scopeId);
    if (
        scopeState &&
        envelope.prev_hash &&
        scopeState.last_hash &&
        scopeState.last_hash !== envelope.prev_hash &&
        Number(envelope.seq) > Number(scopeState.last_seq || 0)
    ) {
        await quarantineEnvelope(envelope, 'chain_mismatch');
        return { stored: false, reason: 'chain_mismatch' };
    }
    const transaction = db.transaction(
        [STORES.BOARDS, STORES.THREADS, STORES.POSTS, STORES.SYNC_STATE],
        'readwrite'
    );
    const boardStore = transaction.objectStore(STORES.BOARDS);
    const threadStore = transaction.objectStore(STORES.THREADS);
    const postStore = transaction.objectStore(STORES.POSTS);
    const syncStore = transaction.objectStore(STORES.SYNC_STATE);
    const result = { stored: true, board_id: payload.board_id || payload.name, thread_numeric_id: payload.thread_numeric_id || null };

    if (envelope.type === 'board') {
        boardStore.put(normalizeBoardRecord(payload, envelope, hash));
        result.board_id = payload.name;
    } else if (envelope.type === 'thread') {
        threadStore.put(normalizeThreadRecord(payload, envelope, hash));
    } else if (envelope.type === 'post') {
        postStore.put(normalizePostRecord(payload, envelope, hash));
    } else {
        result.stored = false;
    }

    if (result.stored) {
        syncStore.put(Object.assign({}, scopeState || {}, {
            scope_id: scopeId,
            board_id: result.board_id,
            thread_id: result.thread_numeric_id,
            last_seq: Math.max(Number(scopeState && scopeState.last_seq || 0), Number(envelope.seq || 0)),
            last_hash: hash,
            last_sync_ts: Date.now(),
        }));
    }

    return new Promise(function (resolve, reject) {
        transaction.oncomplete = function () {
            if (result.stored) {
                if (result.board_id) {
                    notify(scopeKeyForBoard(result.board_id));
                }
                if (result.thread_numeric_id) {
                    notify(scopeKeyForThread(result.thread_numeric_id));
                }
            }
            resolve(result);
        };
        transaction.onerror = function () {
            reject(transaction.error);
        };
    });
}


async function getBoard(boardName) {
    const db = await openDistributedDb();
    const transaction = db.transaction([STORES.BOARDS], 'readonly');
    const store = transaction.objectStore(STORES.BOARDS);
    const index = store.index('board_name');
    return requestToPromise(index.get(boardName));
}


async function listBoardThreads(boardName, options) {
    const normalizedOptions = options || {};
    const limit = normalizedOptions.limit || 500;
    const db = await openDistributedDb();
    const transaction = db.transaction([STORES.THREADS], 'readonly');
    const index = transaction.objectStore(STORES.THREADS).index('board_last_activity');
    return new Promise(function (resolve, reject) {
        const rows = [];
        const request = index.openCursor(rangeForBoard(boardName), 'prev');
        request.onsuccess = function () {
            const cursor = request.result;
            if (!cursor || rows.length >= limit) {
                resolve(rows);
                return;
            }
            rows.push(cursor.value.display);
            cursor.continue();
        };
        request.onerror = function () {
            reject(request.error);
        };
    });
}


async function listThreadPosts(threadId) {
    const db = await openDistributedDb();
    const transaction = db.transaction([STORES.POSTS], 'readonly');
    const index = transaction.objectStore(STORES.POSTS).index('thread_created_at');
    return new Promise(function (resolve, reject) {
        const rows = [];
        const request = index.openCursor(rangeForThread(threadId), 'next');
        request.onsuccess = function () {
            const cursor = request.result;
            if (!cursor) {
                resolve(rows);
                return;
            }
            rows.push(cursor.value.display);
            cursor.continue();
        };
        request.onerror = function () {
            reject(request.error);
        };
    });
}


function subscribeBoard(boardName, handler) {
    return subscribeListener(scopeKeyForBoard(boardName), handler);
}


function subscribeThread(threadId, handler) {
    return subscribeListener(scopeKeyForThread(threadId), handler);
}


export {
    getBoard,
    getSyncState,
    listBoardThreads,
    listThreadPosts,
    mergeManifest,
    openDistributedDb,
    putValidatedEnvelope,
    quarantineEnvelope,
    subscribeBoard,
    subscribeThread,
};
