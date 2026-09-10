import React from 'react';
import ReactDOM from 'react-dom';
import Videos from '../components/Videos';

// The template embeds the listing store as window._STORE (see the contract's
// react-videos.html shape) and renders the SSR markup inside #videos-root.
const store = window._STORE || {};
const app = <Videos store={store}/>;
const root = document.getElementById('videos-root');
if (root && root.children.length > 0) {
    ReactDOM.hydrate(app, root);
} else if (root) {
    ReactDOM.render(app, root);
}
