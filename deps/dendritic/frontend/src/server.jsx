import './logger'; // Tee all console output to the shared log folder (keep first).
import express from 'express';
import React from 'react';
import ReactDOMServer from 'react-dom/server';
import { ethers } from 'ethers';
import BoardIndex from './components/BoardIndex';
import Catalog from './components/Catalog';
import { NewPostForm, NewThreadForm } from './components/PostForm';
import NewPostModal from './components/NewPostModal';
import NewThreadModal from './components/NewThreadModal';
import Post from './components/Post';
import Thread from './components/Thread';
import ThreadGallery from './components/ThreadGallery';
import Videos from './components/Videos';
import VideoWatch from './components/VideoWatch';
import { getCaptchaProps } from './captcha';
import { reducer, setBoard, setStyles, setCaptcha, DEFAULT_STATE } from './state';
import { createStore } from 'redux';
import { Provider } from 'react-redux';

const Gun = require('gun');
const gunClientPath = require.resolve('gun/gun.js');

const app = express();
// need to increase the limit for the sake of potential embedded captchas
app.use(express.json({limit: '3mb', extended: true}));
app.get('/gun/gun.js', (_req, res) => {
    res.type('application/javascript');
    res.sendFile(gunClientPath);
});
const port = 3000;


app.get('/health-check', (req, res) => res.send('OK'));
app.get('/relay-status', (_req, res) => {
    res.json({ok: true, gun: true});
});
app.post('/verify/wallet', function(req, res) {
    const address = req.body.address;
    const message = req.body.message;
    const signature = req.body.signature;

    if (!address || !message || !signature) {
        return res.status(400).json({valid: false, error: 'Missing address, message, or signature'});
    }

    try {
        const recoveredAddress = ethers.utils.verifyMessage(message, signature);
        return res.json({
            valid: recoveredAddress.toLowerCase() === address.toLowerCase(),
            recovered_address: recoveredAddress
        });
    } catch (error) {
        return res.status(400).json({valid: false, error: error.message});
    }
});
// Recover the signer of a 32-byte DIGEST, as opposed to a text message.
//
// A separate endpoint rather than a flag on /verify/wallet, because the two
// have genuinely different semantics and conflating them is a silent failure
// rather than a loud one: ethers.utils.verifyMessage treats a STRING as UTF-8
// text, so passing the hex digest "0xabc..." to it would recover the signer of
// the 66 characters "0xabc...", not of the 32 bytes they spell. That verifies
// consistently, against the wrong thing, forever.
//
// arrayify() is what makes it the bytes. This matches personal_sign over a
// digest, which is what ChannelManagerV2._recover expects on chain.
app.post('/verify/digest', function(req, res) {
    const digest = req.body.digest;
    const signature = req.body.signature;

    if (!digest || !signature) {
        return res.status(400).json({valid: false, error: 'Missing digest or signature'});
    }

    try {
        const bytes = ethers.utils.arrayify(digest);
        if (bytes.length !== 32) {
            return res.status(400).json({valid: false, error: 'digest must be 32 bytes'});
        }
        const recoveredAddress = ethers.utils.verifyMessage(bytes, signature);
        return res.json({valid: true, recovered_address: recoveredAddress});
    } catch (error) {
        return res.status(400).json({valid: false, error: error.message});
    }
});
function serveCatalog(req, res) {
    const catalog = req.body.data.catalog;
    const boardId = req.body.data.board_id;
    const initialState = Object.assign({}, DEFAULT_STATE, {
        threads: catalog.threads,
        mediaDelivery: req.body.data.mediaDelivery || {},
    });
    const store = createStore(reducer, initialState);
    store.dispatch(setStyles(catalog.tag_styles));
    store.dispatch(setCaptcha(getCaptchaProps(req.body.data)));
    const template = req.body.template;
    const templateWithData = template.replace('STORE_DATA',
                                                JSON.stringify(store.getState())).
          replace('BOARD_ID', boardId);
    var serverDOM = ReactDOMServer.renderToString(<Provider store={store}>
                                                    <NewThreadModal board_id={boardId}/>
                                                    <Catalog display_board={false}/>
                                                  </Provider>);
    return res.send(templateWithData.replace('TEMPLATE_CONTENT', serverDOM));
}
app.post('/render/catalog', serveCatalog);
app.post('/render/board-index', function (req, res) {
    const items = req.body.data.items;
    const serverDOM = ReactDOMServer.renderToString(<BoardIndex items={items}/>);
    const template = req.body.template;
    return res.send(template.replace('TEMPLATE_CONTENT', serverDOM));
    
}); 
function serveThread(req, res) {
    const thread = req.body.data.thread;
    const threadId = req.body.data.thread_id;
    const initialState = Object.assign({}, DEFAULT_STATE, {
        posts: thread.posts,
        mediaDelivery: req.body.data.mediaDelivery || {},
        remoteReply: req.body.data.remoteReply || {},
    });
    const store = createStore(reducer, initialState);
    store.dispatch(setCaptcha(getCaptchaProps(req.body.data)));
    const template = req.body.template;
    const templateWithData = template.replace('STORE_DATA',
                                                JSON.stringify(store.getState())).
          replace('THREAD_ID', threadId);
    var serverDOM = ReactDOMServer.renderToString(<React.Fragment>
                                                    <Provider store={store}>
                                                      <NewPostModal thread_id={threadId}/>
                                                      <Thread />
                                                    </Provider>
                                                  </React.Fragment>);
    return res.send(templateWithData.replace('TEMPLATE_CONTENT', serverDOM));
}
app.post('/render/thread', serveThread);
app.post('/render/post', function (req, res) {
    const post = req.body.data;
    const template = req.body.template;
    return res.send(template.replace('TEMPLATE_CONTENT', ReactDOMServer.renderToString(<Post {...post}/>)));
});
app.post('/render/firehose', function (req, res) {
    const firehose = req.body.data.firehose;
    const initialState = Object.assign({}, DEFAULT_STATE, {threads: firehose.threads});
    const store = createStore(reducer, initialState);
    store.dispatch(setStyles(firehose.tag_styles));
    const template = req.body.template;
    var serverDOM = ReactDOMServer.renderToString(<Provider store={store}>
                                                    <Catalog display_board={true}/>
                                                  </Provider>);
    return res.send(template.replace('TEMPLATE_CONTENT', serverDOM));
});

app.post('/render/new-thread', function (req, res) {
    const boardId = req.body.data.board_id;
    const captchaProps = getCaptchaProps(req.body.data);
    const template = req.body.template;
    const serverDOM = ReactDOMServer.renderToString(<NewThreadForm action="/threads/new" board_id={boardId} embed_submit={true} {...captchaProps}/>);
    return res.send(template.replace('TEMPLATE_CONTENT', serverDOM));
});

app.post('/render/new-post', function (req, res) {
    const threadId = req.body.data.thread_id;
    const replyTo = req.body.data.reply_to;
    const replySourcePostId = req.body.data.replySourcePostId;
    const captchaProps = getCaptchaProps(req.body.data);
    const template = req.body.template;
    const sourceQuoteMap = replyTo && replySourcePostId
        ? JSON.stringify({[String(replyTo)]: String(replySourcePostId)})
        : '{}';
    const serverDOM = ReactDOMServer.renderToString(<NewPostForm
      action={"/threads/" + threadId + "/new"}
      thread_id={threadId}
      reply_to={replyTo}
      body_value={req.body.data.body_value}
      subject_value={req.body.data.subject_value}
      name_value={req.body.data.name_value}
      cancel_outbound_id={req.body.data.cancel_outbound_id}
      source_quote_map={sourceQuoteMap}
      embed_submit={true}
      remoteReply={req.body.data.remoteReply || {}}
      {...captchaProps}
    />);
    return res.send(template.replace('TEMPLATE_CONTENT', serverDOM));
});

app.post('/render/gallery', function (req, res) {
    const posts = req.body.data.posts;
    const mediaDelivery = req.body.data.mediaDelivery || {};
    const template = req.body.template;
    const serverDOM = ReactDOMServer.renderToString(<ThreadGallery posts={posts} mediaDelivery={mediaDelivery}/>);
    return res.send(template.replace('TEMPLATE_CONTENT', serverDOM));
});

// The backend's renderer.render_videos(store) / render_video_watch(store) post
// the full window._STORE object as `data`, so req.body.data IS the store here.
// Function-form replacements avoid String.replace interpreting `$` sequences in
// user-generated titles / descriptions / comments.
app.post('/render/videos', function (req, res) {
    const store = req.body.data || {};
    const template = req.body.template;
    const serverDOM = ReactDOMServer.renderToString(<Videos store={store}/>);
    const templateWithData = template.replace('STORE_DATA', function () { return JSON.stringify(store); });
    return res.send(templateWithData.replace('TEMPLATE_CONTENT', function () { return serverDOM; }));
});

app.post('/render/videowatch', function (req, res) {
    const store = req.body.data || {};
    const template = req.body.template;
    const serverDOM = ReactDOMServer.renderToString(<VideoWatch store={store}/>);
    const templateWithData = template.replace('STORE_DATA', function () { return JSON.stringify(store); });
    return res.send(templateWithData.replace('TEMPLATE_CONTENT', function () { return serverDOM; }));
});

const server = app.listen(port, () => console.log(`Render server started on port ${port}`));
Gun({
    web: server,
    localStorage: false,
});
