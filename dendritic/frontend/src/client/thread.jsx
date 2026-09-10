import axios from 'axios';
import React from 'react';
import ReactDOM from 'react-dom';
import regeneratorRuntime from 'regenerator-runtime';
import NewPostModal from '../components/NewPostModal';
import Thread, { THREAD_RENDER_VERSION } from '../components/Thread';
import { startDistributedScope } from '../distributed/syncManager';
import { reducer, newPost, setPosts, DEFAULT_STATE } from '../state';
import { createStore } from 'redux';
import { Provider } from 'react-redux';

const initialState = window._STORE;
const store = createStore(reducer, initialState);
const POLL_INTERVAL_MS = 5000;
const TERMINAL_POLL_STATUSES = new Set([404, 410]);

// Per-viewer moderation fields. These describe the VIEWER's permissions, not the
// post's content, so a live update (poll or distributed sync) must never strip
// them — otherwise the moderation controls "appear then disappear" the moment
// the first refresh lands. Preserve them from the already-loaded (authenticated)
// posts whenever a refresh arrives without the viewer context.
const VIEWER_MOD_FIELDS = [
    'viewer_can_moderate', 'viewer_is_admin',
    'delete_url', 'move_url', 'ban_url', 'shadowban_url', 'block_media_url',
    'fingerprint_ban_url',
];

function applyStableViewerContext(incoming) {
    const current = store.getState().posts || [];
    const byId = {};
    current.forEach(function (p) { if (p && p.id != null) { byId[p.id] = p; } });
    return (incoming || []).map(function (post) {
        const prev = byId[post.id];
        if (prev && prev.viewer_can_moderate && !post.viewer_can_moderate) {
            const merged = Object.assign({}, post);
            VIEWER_MOD_FIELDS.forEach(function (field) {
                if (prev[field] !== undefined) { merged[field] = prev[field]; }
            });
            return merged;
        }
        return post;
    });
}


async function fetchPost(postId) {
    let endpoint = '/api/v1/post/' + postId;
    let response = await axios.get(endpoint);
    console.log('response:');
    console.log(response);
    let postData = response.data;
    return postData;
}

async function fetchThread(threadId) {
    let endpoint = '/api/v1/thread/' + threadId;
    let response = await axios.get(endpoint);
    return response.data;
}

async function refreshThread(threadId) {
    let posts = await fetchThread(threadId);
    store.dispatch(setPosts(applyStableViewerContext(posts)));
}

function isTerminalPollingError(error) {
    const status = error && error.response ? error.response.status : null;
    return TERMINAL_POLL_STATUSES.has(status);
}

async function eventLoop() {
    if(!!window.SharedWorker) {
        let workerUrl = window._LIVE_PROXY;
        let liveProxy = new SharedWorker(workerUrl);
        
        liveProxy.port.onmessage = async function(e) {
            let data = e.data;
            switch(data.message) {
            case 'new-post':
            case 'new-reply':
                let post = await fetchPost(data.post);
                console.log('new post:');
                console.log(post);
                store.dispatch(newPost(post));
                break;
            case 'debug':
                console.log(data.content);
                break;
            }
        };

        const threadId = window._THREAD;
        liveProxy.port.postMessage({'message': 'subscribe-thread', 'thread': threadId});
        console.log('thread ID: ' + threadId);
    }
}

function startPolling(threadId) {
    let intervalId = null;

    function stopPolling() {
        if(intervalId !== null) {
            window.clearInterval(intervalId);
            intervalId = null;
        }
    }

    async function poll() {
        try {
            await refreshThread(threadId);
        } catch(error) {
            if(isTerminalPollingError(error)) {
                console.warn('Stopping thread polling after terminal response for thread ' + threadId);
                stopPolling();
                return;
            }
            console.error(error);
        }
    }

    poll();
    intervalId = window.setInterval(poll, POLL_INTERVAL_MS);
}

async function bootstrapRealtime() {
    const distributedConfig = window._DISTRIBUTED || null;
    let distributedStarted = false;
    if (distributedConfig && distributedConfig.enabled) {
        try {
            distributedStarted = await startDistributedScope(Object.assign({}, distributedConfig, {
                onPosts: function () {
                    // Same rationale as the catalog: the distributed local store
                    // is append-only and can retain deleted replies, so use the
                    // signal only as a change-notification and refetch the
                    // authoritative thread from the server (reflects deletions).
                    refreshThread(window._THREAD).catch(console.error);
                },
            }));
        } catch (error) {
            console.error('distributed thread sync unavailable, falling back to polling', error);
        }
    }
    // The SharedWorker/SSE path is an alternative realtime source; only use it
    // when the distributed layer didn't start, so we never run two push paths.
    if (!distributedStarted) {
        eventLoop();
    }
    // ALWAYS poll as a backstop. The distributed (gun.js) layer can report it
    // "started" yet never deliver a post (dead relay/peers), in which case new
    // replies never auto-populate at the bottom of the thread. Polling guarantees
    // they show up within POLL_INTERVAL_MS without a page refresh.
    startPolling(window._THREAD);
}

bootstrapRealtime();

const app = <React.Fragment>
              <Provider store={store}>
                <NewPostModal thread_id={window._THREAD}/>
                <Thread />
              </Provider>
            </React.Fragment>;
const root = document.getElementById('thread-container');
function canHydrateThread(rootNode) {
    if(!rootNode || rootNode.children.length === 0) {
        return false;
    }
    for(const node of rootNode.childNodes) {
        if(node.nodeType === Node.TEXT_NODE && node.textContent !== '') {
            return false;
        }
    }
    const marker = rootNode.querySelector('[data-thread-render-version]');
    return !!marker && marker.getAttribute('data-thread-render-version') === THREAD_RENDER_VERSION;
}
if(canHydrateThread(root)) {
    ReactDOM.hydrate(app, root);
} else {
    ReactDOM.render(app, root);
}
