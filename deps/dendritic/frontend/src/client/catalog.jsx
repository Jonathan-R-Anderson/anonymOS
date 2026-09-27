import axios from 'axios';
import React from 'react';
import ReactDOM from 'react-dom';
import regeneratorRuntime from 'regenerator-runtime';
import Catalog from '../components/Catalog';
import NewThreadModal from '../components/NewThreadModal';
import { startDistributedScope } from '../distributed/syncManager';
import { reducer, setStyles, setThreads, DEFAULT_STATE } from '../state';
import { createStore } from 'redux';
import { Provider } from 'react-redux';

const initialState = window._STORE;
const store = createStore(reducer, initialState);
const POLL_INTERVAL_MS = 10000;

async function fetchCatalog(boardId) {
    // Fetch the full catalog and replace the store so the component can
    // animate the reordering via FLIP without having to compute a diff here.
    let endpoint = '/api/v1/board/' + boardId + '/catalog';
    let response = await axios.get(endpoint);
    return response.data;
}

async function updateCatalog(boardId) {
    let catalog = await fetchCatalog(boardId);
    store.dispatch(setThreads(catalog));
}

async function eventLoop() {
    if(!!window.SharedWorker) {
        let workerUrl = window._LIVE_PROXY;
        let liveProxy = new SharedWorker(workerUrl);

        liveProxy.port.onmessage = async function(e) {
            let data = e.data;
            switch(data.message) {
            case 'new-thread':
            case 'bump-thread':
                await updateCatalog(data.board);
                break;
            case 'debug':
                console.log(data.content);
                break;
            }
        };
        const boardId = window._BOARD;
        liveProxy.port.postMessage({'message': 'subscribe-board', 'board': boardId});
        console.log('board ID: ' + boardId);
    }
}

function startPolling(boardId) {
    updateCatalog(boardId).catch(console.error);
    window.setInterval(function() {
        updateCatalog(boardId).catch(console.error);
    }, POLL_INTERVAL_MS);
}

async function bootstrapRealtime() {
    const distributedConfig = window._DISTRIBUTED || null;
    let distributedStarted = false;
    if (distributedConfig && distributedConfig.enabled) {
        try {
            distributedStarted = await startDistributedScope(Object.assign({}, distributedConfig, {
                onThreads: function () {
                    // The distributed layer's local P2P store is append-only: a
                    // thread deleted server-side never produces a delta to prune
                    // it, so its own thread list re-adds deleted threads on top of
                    // the fresh poll ("deleted threads still rendering"). Use the
                    // distributed signal only as a fast change-notification and
                    // pull the authoritative catalog from the server, which
                    // reflects deletions.
                    updateCatalog(window._BOARD).catch(console.error);
                },
                onBoardMeta: function (boardRecord) {
                    if (boardRecord && boardRecord.tag_styles) {
                        store.dispatch(setStyles(boardRecord.tag_styles));
                    }
                },
            }));
        } catch (error) {
            console.error('distributed catalog sync unavailable, falling back to polling', error);
        }
    }
    // The SharedWorker/SSE path is an alternative realtime source; only use it
    // when the distributed layer didn't start, so we never run two push paths.
    if (!distributedStarted) {
        eventLoop();
    }
    // ALWAYS poll as a backstop. The distributed (gun.js) layer can report it
    // "started" yet never deliver a single thread update (dead relay/peers), in
    // which case the board silently stops live-updating — the exact regression
    // here. thread.jsx already polls unconditionally; the catalog must too.
    startPolling(window._BOARD);
}

bootstrapRealtime();

const app = <React.Fragment>
              <Provider store={store}>
                <NewThreadModal board_id={window._BOARD}/>
                <Catalog />
              </Provider>
            </React.Fragment>;
const root = document.getElementById('catalog-root');
if(root && root.children.length > 0) {
    ReactDOM.hydrate(app, root);
} else {
    ReactDOM.render(app, root);
}
