import React from 'react';
import ReactDOM from 'react-dom';
import VideoWatch from '../components/VideoWatch';

// The template embeds the watch store as window._STORE (see the contract's
// react-video-watch.html shape) and renders the SSR shell inside #video-root.
const store = window._STORE || {};
const app = <VideoWatch store={store}/>;
const root = document.getElementById('video-root');
if (root && root.children.length > 0) {
    ReactDOM.hydrate(app, root);
} else if (root) {
    ReactDOM.render(app, root);
}
