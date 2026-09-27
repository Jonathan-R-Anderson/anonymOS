import React from 'react';
import ReactDOM from 'react-dom';
import regeneratorRuntime from 'regenerator-runtime';
import ThreadGallery from '../components/ThreadGallery';


const app = (
    <ThreadGallery
      posts={Array.isArray(window._GALLERY_POSTS) ? window._GALLERY_POSTS : []}
      mediaDelivery={window._MEDIA_DELIVERY || {}}
    />
);
const root = document.getElementById('gallery-root');

if (root && root.children.length > 0) {
    ReactDOM.hydrate(app, root);
} else {
    ReactDOM.render(app, root);
}
