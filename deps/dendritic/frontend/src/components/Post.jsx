import React, { useState, useEffect, useRef } from 'react';
import ReactDOM from 'react-dom';
import TimeAgo from 'react-timeago';
import {
    shouldUseDirectFallbackNow,
    subscribeToTorrentMedia,
    viewerDirectFallbackPeerThreshold,
} from '../media/torrentMedia';
import {
    scoreSelectionText,
    sentimentColor,
    sentimentHighlightPalette,
    highlightableSentimentToken,
    normalizeTokenValue,
} from '../semantic/threadSemantic';
import { fetchWordScores, learnWords } from '../client/sentimentApi';

const OPEN_REPLY_BOX_EVENT = 'maniwani:open-reply-box';

// Ban / shadowban duration choices (value -> label). Mirrors BAN_DURATION_CHOICES
// in backend/model/Ban.py; "permanent" means no expiry.
const BAN_DURATION_OPTIONS = [
    ['permanent', 'Permanent'],
    ['1h', '1 hour'],
    ['6h', '6 hours'],
    ['1d', '1 day'],
    ['3d', '3 days'],
    ['1w', '1 week'],
    ['2w', '2 weeks'],
    ['30d', '30 days'],
    ['90d', '90 days'],
];

function getThumbClass(spoiler) {
    return spoiler? "thread-thumbnail thumbnail-spoiler" : "thread-thumbnail";
}

function formatBytes(value) {
    const numericValue = Number(value || 0);
    if (!numericValue) {
        return '0 B';
    }
    const units = ['B', 'KB', 'MB', 'GB'];
    let unitIndex = 0;
    let displayValue = numericValue;
    while (displayValue >= 1024 && unitIndex < units.length - 1) {
        displayValue = displayValue / 1024;
        unitIndex += 1;
    }
    const precision = displayValue >= 100 || unitIndex === 0 ? 0 : 1;
    return displayValue.toFixed(precision) + ' ' + units[unitIndex];
}

function formatRate(value) {
    return formatBytes(value) + '/s';
}

function formatPercent(value) {
    const numericValue = Number(value || 0);
    return (Math.round(numericValue * 1000) / 10).toFixed(1) + '%';
}

function emptyTorrentState(torrentPayload) {
    return {
        mediaId: torrentPayload ? torrentPayload.media_id : null,
        mimetype: torrentPayload ? torrentPayload.mimetype : null,
        displayName: torrentPayload ? torrentPayload.display_name : null,
        blob: null,
        blobUrl: null,
        status: 'idle',
        error: null,
        errorMessage: null,
        magnetUrl: torrentPayload ? torrentPayload.magnet_url : null,
        magnetSource: torrentPayload ? torrentPayload.magnet_source : null,
        torrentUrl: torrentPayload ? torrentPayload.torrent_url : null,
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
    };
}

function useTorrentMediaSource(props) {
    const isImageTorrent = !!(
        props.media &&
        props.torrent &&
        typeof props.mimetype === 'string' &&
        props.mimetype.indexOf('image/') === 0
    );
    const shouldUseTorrent = !!(props.media && props.torrent && (isImageTorrent || props.preferredMediaMode !== 'direct'));
    const [torrentState, setTorrentState] = useState(emptyTorrentState(props.torrent));

    useEffect(function () {
        if (!shouldUseTorrent) {
            setTorrentState(emptyTorrentState(props.torrent));
            return undefined;
        }
        return subscribeToTorrentMedia(props.torrent, setTorrentState);
    }, [
        shouldUseTorrent,
        props.torrent ? props.torrent.info_hash : null,
        props.torrent ? props.torrent.magnet_url : null,
    ]);

    return torrentState;
}

function ImageLightbox(props) {
    const [portalTarget, setPortalTarget] = useState(null);

    useEffect(function () {
        if (typeof document === 'undefined') {
            return undefined;
        }

        setPortalTarget(document.body);
        const previousOverflow = document.body.style.overflow;

        function keyDownHandler(event) {
            if (event.key === 'Escape') {
                props.onClose();
            }
        }

        document.body.style.overflow = 'hidden';
        document.addEventListener('keydown', keyDownHandler);

        return function () {
            document.body.style.overflow = previousOverflow;
            document.removeEventListener('keydown', keyDownHandler);
        };
    }, [props.onClose]);

    function stopPropagation(event) {
        event.stopPropagation();
    }

    const overlay = (
        <div className="post-image-viewer" role="dialog" aria-modal="true" onClick={props.onClose}>
          <button type="button" className="post-image-viewer__close" aria-label="Close expanded image" onClick={function (event) {
              stopPropagation(event);
              props.onClose();
          }}>
            ×
          </button>
          <div className="post-image-viewer__viewport">
            <div className="post-image-viewer__canvas" onClick={stopPropagation}>
              {props.isVideo
                  ? <video className="post-image-viewer__video" controls autoPlay playsInline>
                      <source src={props.src} type={props.mimetype}/>
                    </video>
                  : props.isAudio
                      ? <div style={{display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '16px'}}>
                          <div aria-hidden="true" style={{fontSize: '72px', lineHeight: 1, color: '#b07274'}}>♪</div>
                          <audio className="post-image-viewer__audio" controls autoPlay src={props.src} style={{width: 'min(560px, 86vw)'}}></audio>
                        </div>
                      : <img className="post-image-viewer__image" src={props.src} alt="Expanded post media"/>}
            </div>
          </div>
        </div>
    );

    if (!portalTarget) {
        return null;
    }

    return ReactDOM.createPortal(overlay, portalTarget);
}

function GenericThumbnail(props) {
    return (
        <img className={getThumbClass(props.spoiler)} src={props.display_url || props.thumb_url}/>
    );
}

function TorrentPendingThumbnail(props) {
    return (
        <div className={getThumbClass(props.spoiler) + " d-flex align-items-center justify-content-center bg-light text-muted"}>
          <small>Loading torrent...</small>
        </div>
    );
}

function AnimatedImageThumbnail(props) {
    const [thumbClass, setThumbClass] = useState(getThumbClass(props.spoiler));
    const [currentSource, setThumbSource] = useState(props.thumb_url);
    useEffect(function () {
        setThumbSource(props.thumb_url);
    }, [props.thumb_url]);
    function mouseEnterHandler(e) {
        if (!props.media_url) {
            return;
        }
        setThumbSource(props.media_url);
        setThumbClass(getThumbClass(false));
    }
    function mouseLeaveHandler(e) {
        setThumbSource(props.thumb_url);
        setThumbClass(getThumbClass(props.spoiler));
    }
    return (
        <img className={thumbClass} src={currentSource} onMouseEnter={mouseEnterHandler} onMouseLeave={mouseLeaveHandler}/>
    );
}

const HOVER_PREVIEW_MS = 5000;   // play the hover preview for 5s, then stop
const HOVER_FADE_STEPS = 12;     // audio fade-out resolution
const HOVER_FADE_INTERVAL_MS = 50;

function VideoThumbnail(props) {
    const [thumbClass, setThumbClass] = useState(getThumbClass(props.spoiler));
    const videoRef = useRef(null);
    const stopTimerRef = useRef(null);
    const fadeTimerRef = useRef(null);

    function clearPreviewTimers() {
        if (stopTimerRef.current) { window.clearTimeout(stopTimerRef.current); stopTimerRef.current = null; }
        if (fadeTimerRef.current) { window.clearInterval(fadeTimerRef.current); fadeTimerRef.current = null; }
    }
    // Clear any pending timers if the tile unmounts mid-preview.
    useEffect(function () { return clearPreviewTimers; }, []);

    if (!props.media_url) {
        return <img className={thumbClass} src={props.thumb_url}/>;
    }

    function mouseEnterHandler() {
        const video = videoRef.current;
        if (!video) { return; }
        clearPreviewTimers();
        setThumbClass(getThumbClass(false));
        try { video.volume = 1; } catch (error) { /* ignore */ }
        const playPromise = video.play();
        if (playPromise && playPromise.catch) { playPromise.catch(function () { /* autoplay may be blocked */ }); }
        // After 5s, fade the audio out (~600ms) and pause, so the preview does
        // not loop forever with sound.
        stopTimerRef.current = window.setTimeout(function () {
            let step = 0;
            const startVolume = video.volume || 1;
            fadeTimerRef.current = window.setInterval(function () {
                step += 1;
                const next = startVolume * (1 - step / HOVER_FADE_STEPS);
                try { video.volume = next > 0 ? next : 0; } catch (error) { /* ignore */ }
                if (step >= HOVER_FADE_STEPS) {
                    window.clearInterval(fadeTimerRef.current);
                    fadeTimerRef.current = null;
                    video.pause();
                }
            }, HOVER_FADE_INTERVAL_MS);
        }, HOVER_PREVIEW_MS);
    }
    function mouseLeaveHandler() {
        const video = videoRef.current;
        clearPreviewTimers();
        if (video) {
            video.pause();
            video.currentTime = 0;
            try { video.volume = 1; } catch (error) { /* ignore */ }
        }
        setThumbClass(getThumbClass(props.spoiler));
    }
    return (
        <div className={thumbClass}>
          <video ref={videoRef} className={thumbClass} loop={true} preload="metadata"
                 onMouseEnter={mouseEnterHandler} onMouseLeave={mouseLeaveHandler} poster={props.thumb_url}>
            <source src={props.media_url} type={props.mimetype}/>
          </video>
        </div>
    );
}

function TorrentMetricLine(props) {
    const browserSegments = [];
    const relaySegments = [];
    let browserClassName = 'text-muted';

    if (props.expect_torrent && props.torrent_stats.blobUrl) {
        browserSegments.push('rendering from blob url');
        browserClassName = 'text-success';
    } else if (props.expect_torrent && props.transport_status === 'idle') {
        browserSegments.push('starting torrent');
    } else if (props.transport_status === 'loading') {
        browserSegments.push('waiting for torrent blob');
        browserSegments.push('swarm ' + formatPercent(props.torrent_stats.progress));
    } else if (props.transport_status === 'ready') {
        browserSegments.push(props.torrent_stats.done ? 'seeding blob' : 'blob ready');
    } else if (props.transport_status === 'error') {
        browserSegments.push('torrent blob failed');
        browserClassName = 'text-warning';
    } else if (props.transport_status === 'unsupported') {
        browserSegments.push('WebTorrent unavailable');
        browserClassName = 'text-warning';
    } else if (props.transport_status === 'unavailable') {
        browserSegments.push('torrent unavailable');
        browserClassName = 'text-warning';
    }

    if (props.expect_torrent && !props.torrent_stats.blobUrl) {
        browserSegments.push(props.direct_assist_active ? 'serving from server while joining swarm' : 'waiting for torrent preview');
    }

    if (props.transport_status === 'loading' || props.transport_status === 'ready') {
        browserSegments.push((props.torrent_stats.numPeers || 0) + ' peer' + ((props.torrent_stats.numPeers || 0) === 1 ? '' : 's'));
        if (props.torrent_stats.downloadSpeed || props.transport_status === 'loading') {
            browserSegments.push('down ' + formatRate(props.torrent_stats.downloadSpeed));
        }
        if (props.torrent_stats.uploadSpeed || props.torrent_stats.done) {
            browserSegments.push('up ' + formatRate(props.torrent_stats.uploadSpeed));
        }
    }

    if (props.torrent_stats.magnetSource === 'db') {
        browserSegments.push('db magnet');
    } else if (props.torrent_stats.magnetSource) {
        browserSegments.push(props.torrent_stats.magnetSource + ' magnet');
    }

    if (props.expect_torrent && props.torrent_stats.blobUrl) {
        browserSegments.push('open target blob:');
    } else if (props.expect_torrent && props.direct_assist_active) {
        browserSegments.push('server assist active');
    } else if (props.expect_torrent && props.direct_fallback_disabled) {
        browserSegments.push('direct fallback disabled');
    }

    if (props.seedbox_torrent_status) {
        relaySegments.push('relay ' + props.seedbox_torrent_status.status);
        relaySegments.push((props.seedbox_torrent_status.numPeers || 0) + ' peer' + ((props.seedbox_torrent_status.numPeers || 0) === 1 ? '' : 's'));
        if (props.seedbox_torrent_status.uploadSpeed || props.seedbox_torrent_status.status === 'seeding') {
            relaySegments.push('up ' + formatRate(props.seedbox_torrent_status.uploadSpeed));
        }
    }

    if (!browserSegments.length && !relaySegments.length) {
        return null;
    }

    return (
        <div className="post-media-metrics">
          {browserSegments.length > 0 && <small className={browserClassName}>{browserSegments.join(' · ')}</small>}
          {relaySegments.length > 0 && <small className="text-muted">{relaySegments.join(' · ')}</small>}
        </div>
    );
}

function PostThumbnail(props) {
    let thumbnailImpl;
    if (props.torrent_preview_pending) {
        thumbnailImpl = <TorrentPendingThumbnail spoiler={props.spoiler}/>;
    } else if(props.mimetype.startsWith("video")) {
        thumbnailImpl = <VideoThumbnail spoiler={props.spoiler} thumb_url={props.thumb_url} media_url={props.media_url}/>;
    } else if(props.mimetype.startsWith("image") && props.is_animated) {
        thumbnailImpl = <AnimatedImageThumbnail spoiler={props.spoiler} thumb_url={props.thumb_url} media_url={props.media_url}/>;
    } else {
        thumbnailImpl = <GenericThumbnail spoiler={props.spoiler} thumb_url={props.thumb_url} display_url={props.display_url}/>;
    }

    const [animatedTextStatus, setAnimatedTextStatus] = useState(false);
    useEffect(() => {
        setAnimatedTextStatus(true);
    }, []);

    const [showSpoilerLabel, setShowSpoilerLabel] = useState(true);
    const [viewerOpen, setViewerOpen] = useState(false);
    const isImage = props.mimetype.startsWith("image");
    const isVideo = props.mimetype.startsWith("video");
    const isAudio = props.mimetype.startsWith("audio");
    const canExpandImage = isImage && !!props.expand_url;
    const canExpandVideo = isVideo && !!props.media_url;
    const canExpandAudio = isAudio && !!props.media_url;
    const canExpand = canExpandImage || canExpandVideo || canExpandAudio;
    // Source shown in the centered overlay: the full image, or the playable media.
    const expandSource = (canExpandVideo || canExpandAudio) ? props.media_url : props.expand_url;
    const mediaHref = props.href_url || props.media_url || (isImage ? props.expand_url : props.display_url) || null;
    const deliveryState = props.expect_torrent
        ? (props.torrent_stats.blobUrl ? 'torrent-blob' : ('torrent-' + props.transport_status))
        : 'direct-server';

    useEffect(function () {
        if (!canExpand && viewerOpen) {
            setViewerOpen(false);
        }
    }, [canExpand, viewerOpen]);

    function mouseEnterHandler(e) {
        if(props.spoiler) {
            setShowSpoilerLabel(false);
        }
    }
    function mouseLeaveHandler(e) {
        if(props.spoiler) {
            setShowSpoilerLabel(true);
        }
    }
    function mediaClickHandler(event) {
        if (!canExpand) {
            return;
        }
        if (event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) {
            return;
        }
        event.preventDefault();
        setViewerOpen(true);
    }

    const mediaContents = (
        <>
          {props.spoiler && showSpoilerLabel && <span className="spoiler-label text-danger">!</span>}
          {thumbnailImpl}
        </>
    );

    return (
        <div className="col">
          <div className="row">
            <div className="post-thumbnail" onMouseEnter={mouseEnterHandler} onMouseLeave={mouseLeaveHandler}
                 data-analytics-content-type={isVideo ? "video" : "image"}
                 data-analytics-content-id={'media:' + String(props.media_id)} data-analytics-surface="thread_media">
              {mediaHref && <a
                  className="media-container"
                  href={mediaHref}
                  onClick={mediaClickHandler}
                  data-media-delivery={deliveryState}
                  data-media-target-kind={mediaHref.indexOf('blob:') === 0 ? 'blob' : 'server'}
                  title={props.torrent_stats.blobUrl || mediaHref}
                >
                  {mediaContents}
                </a>}
              {!mediaHref && <span
                  className="media-container media-container--static"
                  data-media-delivery={deliveryState}
                >
                  {mediaContents}
                </span>}
            </div>
          </div>
          <TorrentMetricLine
            expect_torrent={props.expect_torrent}
            transport_status={props.transport_status}
            torrent_stats={props.torrent_stats}
            seedbox_torrent_status={props.seedbox_torrent_status}
            direct_fallback_disabled={props.direct_fallback_disabled}
          />
          {props.spoiler && <div className="col">
                             <div className="row">
                               <small className="text-danger">Media contains spoilers!</small>
                             </div>
                           </div>}
          {props.is_animated && <div className="row">
                                 <noscript>
                                   <small className="text-muted">Animated - click to play</small>
                                 </noscript>
                                 {animatedTextStatus && <small className="text-muted">Animated - click or hover to play</small>} 
                               </div>}
          {viewerOpen && expandSource && <ImageLightbox src={expandSource} isVideo={canExpandVideo} isAudio={canExpandAudio} mimetype={props.mimetype} onClose={function () {
              setViewerOpen(false);
          }}/>}
        </div>
    );
}

function ReplyList(props) {
    function emitReply(reply, index) {
        const replyId = typeof reply === 'object' ? reply.post_id : reply;
        const replyUrl = typeof reply === 'object' ? reply.reply_url : '/threads/' + props.thread_id + '#' + replyId;
        return (
            <a
              key={replyId + '-' + index}
              className="post-reply"
              href={replyUrl}
              data-post-id={replyId}
              data-toggle="tooltip"
              data-placement="bottom"
              data-html="true"
              title="<i>Loading...</i>"
              data-loaded="false"
            >
              &gt;&gt;{replyId}
            </a>
        );
    }
    return (
        <>
          <small className="text-secondary">Replies:</small>
          <div className="post-replies">
            {props.replies.map(emitReply)}
          </div>
        </>
    );
}

function watermarkProps(props) {
    if (!props.is_imported) {
        return {className: "", style: undefined};
    }
    if (props.watermark_image_url) {
        return {
            className: " source-watermarked source-watermarked--custom",
            style: {"--source-watermark-image": 'url("' + props.watermark_image_url + '")'},
        };
    }
    return {
        className: " source-watermarked source-watermarked--" + props.source_type,
        style: undefined,
    };
}

// Bronze/silver/gold awards. Unlike a vote, an award moves REAL ANONCoins from
// the giver's wallet to the author's — this site holds no signing key, so the
// browser signs it and the server only verifies the receipt.
//
// Two ways it can be paid, and the server says which is available:
//
//     author runs a node   ->  a payment channel. No transaction, no gas
//     author has a wallet  ->  an ERC-20 transfer, as it always was
//
// The second is the floor, not a legacy path: most authors have a wallet and
// nothing else.
//
// Three states, in order: badges for awards already given (everyone sees these),
// an "Award" button (only when the server said this post can receive one), and a
// tier menu that is fetched on open rather than up front — the quote costs a
// query per post and almost nobody clicks it.
const AWARD_ICONS = {bronze: '\u{1F949}', silver: '\u{1F948}', gold: '\u{1F947}'};
const AWARD_ORDER = ['gold', 'silver', 'bronze'];
// ERC-20 transfer(address,uint256). A published constant; deriving it needs
// keccak, which this bundle does not ship.
const TRANSFER_SELECTOR = '0xa9059cbb';

function pad32(hexNo0x) {
    return hexNo0x.length >= 64 ? hexNo0x : new Array(64 - hexNo0x.length + 1).join('0') + hexNo0x;
}

function PostAwards(props) {
    const [awards, setAwards] = useState(props.awards || {});
    const [open, setOpen] = useState(false);
    const [tiers, setTiers] = useState(null);
    const [note, setNote] = useState('');
    const [busy, setBusy] = useState(false);

    useEffect(function () {
        setAwards(props.awards || {});
    }, [props.awards]);

    const given = AWARD_ORDER.filter(function (tier) { return (awards[tier] || 0) > 0; });

    function openMenu() {
        setOpen(!open);
        if (tiers || !props.awardUrl) { return; }
        fetch(props.awardUrl, {credentials: 'same-origin', headers: {Accept: 'application/json'}})
            .then(function (response) { return response.json(); })
            .then(function (payload) {
                if (payload && payload.tiers) { setTiers(payload); }
                else { setNote('Awards are not available on this post.'); }
            })
            .catch(function () { setNote('Could not load award options.'); });
    }

    // Import an ES module at a runtime URL.
    //
    // Built through a Function constructor because the build cannot carry a
    // literal import(): this babel does not parse dynamic import at all, and
    // the commonjs transform plus browserify would try to resolve it at build
    // time even if it did. The string body is opaque to both, so the browser
    // gets a real native import of a real URL.
    const importModule = new Function('u', 'return import(u);');

    // Load a script that is not in this bundle, once.
    //
    // The channel client needs ethers, and the ethers bundle is 640KB. Bundling
    // it into every thread page to serve the small minority who click Award on
    // an author who runs a node would be a poor trade, so both are fetched at
    // the moment they are actually needed.
    function loadScript(url) {
        if (window.PoFChain) { return Promise.resolve(); }
        return new Promise(function (resolve, reject) {
            const tag = document.createElement('script');
            tag.src = url;
            tag.onload = resolve;
            tag.onerror = function () { reject(new Error('Could not load ' + url)); };
            document.head.appendChild(tag);
        });
    }

    // An award paid over a payment channel — roadmap P9.
    //
    // No transaction, so no gas: the giver signs a new channel state and the
    // recipient's node co-signs it. What comes back to this server is that
    // co-signed state, which anyone can verify — this site holds no key and is
    // not a party to the payment.
    function giveOverChannel(tier) {
        const channel = tiers.channel;
        setBusy(true);
        setNote('Opening your wallet…');

        loadScript(channel.bundle_url)
            .then(function () { return importModule(channel.client_url); })
            .then(function (mod) {
                const tc = mod.createTipChannel(window.PoFChain.ethers);
                return tc.connect(window.ethereum).then(function (session) {
                    setNote('Confirm the payment in your wallet…');
                    return tc.tip(session, {
                        endpoint: channel.endpoint,
                        recipient: channel.recipient,
                        amount: tier.wei,
                        manager: channel.manager,
                    });
                });
            })
            .then(function (result) {
                if (result.outcome === 'rejected') {
                    // A definite no from the other side. Safe to say so.
                    setNote(result.detail || 'The recipient declined that payment.');
                    setBusy(false);
                    return;
                }
                if (result.outcome !== 'completed') {
                    // UNKNOWN. It may well have gone through, and telling
                    // somebody it failed is how they end up paying twice.
                    setNote('That may have gone through — check before sending it again.');
                    setBusy(false);
                    return;
                }
                return fetch(props.awardUrl, {
                    method: 'POST',
                    credentials: 'same-origin',
                    headers: {'Content-Type': 'application/json', Accept: 'application/json'},
                    body: JSON.stringify({tier: tier.tier, proof: result.proof}),
                }).then(function (response) {
                    return response.json().then(function (payload) {
                        if (response.ok) {
                            setAwards(payload.awards || {});
                            setNote('');
                            setOpen(false);
                        } else {
                            // The payment happened; only the record did not.
                            // Never reported as a failed payment.
                            setNote((payload.error || 'Could not record that.') +
                                ' The payment went through.');
                        }
                        setBusy(false);
                    });
                });
            })
            .catch(function (error) {
                setNote((error && error.message) || 'The wallet rejected that.');
                setBusy(false);
            });
    }

    function give(tier) {
        if (busy || !tiers) { return; }
        if (!window.ethereum) { setNote('No wallet detected — install MetaMask.'); return; }
        // The channel when the author runs a node, the on-chain transfer
        // otherwise. The server decides which is on offer; this only picks the
        // path it was given.
        if (tiers.channel) { return giveOverChannel(tier); }
        setBusy(true);
        setNote('Confirm the transfer in your wallet…');

        const amountHex = BigInt(tier.wei).toString(16);
        const data = TRANSFER_SELECTOR + pad32(tiers.recipient.slice(2).toLowerCase()) + pad32(amountHex);

        window.ethereum.request({method: 'eth_requestAccounts'}).then(function (accounts) {
            const from = ((accounts && accounts[0]) || '').toLowerCase();
            return window.ethereum.request({
                method: 'eth_sendTransaction',
                params: [{from: from, to: tiers.token, data: data}],
            });
        }).then(function (txHash) {
            // The receipt does not exist the instant the wallet returns, so the
            // server is asked repeatedly rather than once — a single call would
            // report a real, paid award as a failure most of the time.
            setNote('Sent — waiting for it to confirm…');
            let attempt = 0;
            function confirm() {
                return fetch(props.awardUrl, {
                    method: 'POST',
                    credentials: 'same-origin',
                    headers: {'Content-Type': 'application/json', Accept: 'application/json'},
                    body: JSON.stringify({tier: tier.tier, tx: txHash}),
                }).then(function (response) {
                    return response.json().then(function (payload) {
                        if (response.ok) {
                            setAwards(payload.awards || {});
                            setNote('');
                            setOpen(false);
                            setBusy(false);
                            return;
                        }
                        attempt += 1;
                        if (attempt >= 20) {
                            // The money moved; only the record did not. Say so,
                            // and leave the hash so it can be settled by hand.
                            setNote((payload.error || 'Could not confirm.') +
                                ' The transfer went through — tx ' + txHash);
                            setBusy(false);
                            return;
                        }
                        return new Promise(function (resolve) { setTimeout(resolve, 3000); }).then(confirm);
                    });
                });
            }
            return confirm();
        }).catch(function (error) {
            setNote((error && error.message) || 'The wallet rejected that.');
            setBusy(false);
        });
    }

    if (!given.length && !props.awardUrl) {
        return null;
    }
    return (
        <small className="post-awards">
          {given.map(function (tier) {
              return (
                  <span className="post-awards__badge" key={tier}
                        title={awards[tier] + ' ' + tier}>
                    {AWARD_ICONS[tier]}{awards[tier] > 1 ? ' ' + awards[tier] : ''}
                  </span>
              );
          })}
          {props.awardUrl && <button type="button" className="post-awards__btn"
                                     onClick={openMenu} disabled={busy}
                                     title="Give the author ANONCoins">Award</button>}
          {open && <span className="post-awards__menu">
            {tiers && tiers.tiers.map(function (tier) {
                return (
                    <button type="button" className="post-awards__tier" key={tier.tier}
                            onClick={function () { give(tier); }} disabled={busy}>
                      {tier.icon} {tier.label} · {tier.credits}
                    </button>
                );
            })}
            {!tiers && !note && <span className="post-awards__note">Loading…</span>}
            {note && <span className="post-awards__note">{note}</span>}
          </span>}
        </small>
    );
}

// Up/down voting. Slip-only (the server returns 401 otherwise), so for a logged
// -out viewer this renders the score read-only rather than buttons that fail.
// The score is optimistic-free: it is whatever the server returns, so a
// double-click or a stale page can't drift the displayed total.
function PostVote(props) {
    const [score, setScore] = useState(typeof props.score === 'number' ? props.score : 0);
    const [viewerVote, setViewerVote] = useState(props.viewerVote || 0);
    const [pending, setPending] = useState(false);

    useEffect(function () {
        if (typeof props.score === 'number') {
            setScore(props.score);
        }
    }, [props.score]);
    useEffect(function () {
        setViewerVote(props.viewerVote || 0);
    }, [props.viewerVote]);

    function submit(value) {
        if (pending || !props.voteUrl || !props.voteTarget) {
            return;
        }
        // Clicking the direction you already voted withdraws it.
        const nextValue = viewerVote === value ? 0 : value;
        setPending(true);
        fetch(props.voteUrl, {
            method: 'POST',
            credentials: 'same-origin',
            headers: {'Content-Type': 'application/json', 'Accept': 'application/json'},
            // The target identifies the post within the thread — a scraped post
            // has no post id to send.
            body: JSON.stringify({target: props.voteTarget, value: nextValue}),
        }).then(function (response) {
            return response.json().then(function (payload) {
                if (!response.ok) { throw new Error(payload.error || 'vote_failed'); }
                return payload;
            });
        }).then(function (payload) {
            setScore(payload.score);
            setViewerVote(payload.viewer_vote);
        }).catch(function () {
            // Leave the previous score showing; nothing was applied.
        }).then(function () {
            setPending(false);
        });
    }

    // No target means there is nothing stable to attach a vote to (an imported
    // post with no source id). Render nothing rather than a permanent 0.
    if (!props.voteUrl || !props.voteTarget) {
        return null;
    }
    if (!props.canVote) {
        return (
            <small className="post-vote post-vote--readonly" title="Log in with a slip to vote">
              <i className="fas fa-arrow-up" aria-hidden="true"></i>
              <span className="post-vote__score">{score}</span>
            </small>
        );
    }
    return (
        <small className="post-vote">
          <button
            type="button"
            className={'post-vote__btn' + (viewerVote === 1 ? ' post-vote__btn--active' : '')}
            onClick={function () { submit(1); }}
            disabled={pending}
            aria-pressed={viewerVote === 1}
            aria-label="Upvote this post"
            title="Upvote">
            <i className="fas fa-arrow-up" aria-hidden="true"></i>
          </button>
          <span className="post-vote__score">{score}</span>
          <button
            type="button"
            className={'post-vote__btn' + (viewerVote === -1 ? ' post-vote__btn--active' : '')}
            onClick={function () { submit(-1); }}
            disabled={pending}
            aria-pressed={viewerVote === -1}
            aria-label="Downvote this post"
            title="Downvote">
            <i className="fas fa-arrow-down" aria-hidden="true"></i>
          </button>
        </small>
    );
}

function originBadgeClass(origin) {
    return origin === "local" ? "badge-info" : "badge-secondary";
}

export default function Post(props) {
    const [onClient, setOnClient] = useState(false);
    const torrentState = useTorrentMediaSource(props);
    useEffect(() => {
        if(onClient == false) {
            setOnClient(true);
        }
    });
    function openReplyBox(event) {
        if(typeof window === 'undefined' || typeof window.dispatchEvent !== 'function' || typeof window.CustomEvent !== 'function') {
            return;
        }
        event.preventDefault();
        window.dispatchEvent(new CustomEvent(OPEN_REPLY_BOX_EVENT, {detail: {
            postId: props.id,
            sourcePostId: props.source_post_id || null,
            sourceType: props.source_type || 'local',
        }}));
    }
    function reportPost(event) {
        event.preventDefault();
        if (typeof window === 'undefined') { return; }
        var reason = window.prompt('Report this post to the moderators of this board?\n\nOptional reason:');
        if (reason === null) { return; }
        fetch('/boards/report', {
            method: 'POST',
            credentials: 'same-origin',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({post_id: String(props.id), thread_id: props.thread_id, reason: reason}),
        }).then(function () {
            window.alert('Thanks — this post has been reported to the moderators.');
        }).catch(function () {});
    }
    const watermark = watermarkProps(props);
    // The post body is React-owned (dangerouslySetInnerHTML). It always renders
    // props.body verbatim; sentiment coloring is an EPHEMERAL live-DOM decoration
    // applied on text selection and restored from a snapshot, so React re-renders
    // to the same HTML and never fights the injected spans.
    const renderedBody = props.body;
    const bodyRef = useRef(null);
    const snapshotRef = useRef(null);
    const wrappingRef = useRef(false);

    function clearSelectionHighlight() {
        if (snapshotRef.current != null && bodyRef.current) {
            bodyRef.current.innerHTML = snapshotRef.current;
        }
        snapshotRef.current = null;
    }

    function wrapWordsInTextNode(textNode, scoreMap) {
        const value = textNode.nodeValue || '';
        const matcher = /[A-Za-z0-9']+/g;
        let match = matcher.exec(value);
        if (!match) {
            return;
        }
        const fragment = document.createDocumentFragment();
        let lastIndex = 0;
        let wrappedAny = false;
        while (match) {
            const word = match[0];
            const start = match.index;
            if (start > lastIndex) {
                fragment.appendChild(document.createTextNode(value.slice(lastIndex, start)));
            }
            const normalized = normalizeTokenValue(word.toLowerCase());
            const token = normalized ? scoreMap.get(normalized) : null;
            if (token && highlightableSentimentToken(token)) {
                const palette = sentimentHighlightPalette(token);
                const span = document.createElement('span');
                span.className = 'sel-sentiment-word';
                span.style.setProperty('--sel-sentiment-bg', palette.background);
                span.style.setProperty('--sel-sentiment-border', palette.border);
                span.textContent = word; // preserve the original surface text
                fragment.appendChild(span);
                wrappedAny = true;
            } else {
                fragment.appendChild(document.createTextNode(word));
            }
            lastIndex = start + word.length;
            match = matcher.exec(value);
        }
        if (lastIndex < value.length) {
            fragment.appendChild(document.createTextNode(value.slice(lastIndex)));
        }
        if (wrappedAny && textNode.parentNode) {
            textNode.parentNode.replaceChild(fragment, textNode);
        }
    }

    function wrapRangeWords(range, scoreMap) {
        const root = bodyRef.current;
        if (!root) {
            return;
        }
        // Split the boundary text nodes so the range edges fall on node
        // boundaries; ranges auto-update on splitText, so intersectsNode then
        // returns only the fully-selected text nodes.
        const endContainer = range.endContainer;
        const endOffset = range.endOffset;
        if (endContainer.nodeType === 3 && endOffset > 0 && endOffset < endContainer.nodeValue.length) {
            endContainer.splitText(endOffset);
        }
        const startContainer = range.startContainer;
        const startOffset = range.startOffset;
        if (startContainer.nodeType === 3 && startOffset > 0 && startOffset < startContainer.nodeValue.length) {
            startContainer.splitText(startOffset);
        }
        const targets = [];
        const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT, null, false);
        let node = walker.nextNode();
        while (node) {
            const parent = node.parentNode;
            const alreadyWrapped = parent && parent.classList && parent.classList.contains('sel-sentiment-word');
            if (!alreadyWrapped && node.nodeValue && range.intersectsNode(node)) {
                targets.push(node);
            }
            node = walker.nextNode();
        }
        targets.forEach(function (textNode) {
            wrapWordsInTextNode(textNode, scoreMap);
        });
    }

    // Absolute character offset of (container, offset) measured from the start of
    // root. Used to remember where the selection is before wrapping mutates the
    // DOM, so it can be re-created afterwards (wrapping preserves the text, only
    // the node structure changes, so absolute offsets stay valid).
    function absoluteOffsetWithin(root, container, offset) {
        const probe = document.createRange();
        probe.selectNodeContents(root);
        try {
            probe.setEnd(container, offset);
        } catch (error) {
            return null;
        }
        return probe.toString().length;
    }

    function rangeFromAbsoluteOffsets(root, startAbs, endAbs) {
        if (startAbs == null || endAbs == null) {
            return null;
        }
        const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT, null, false);
        let acc = 0;
        let startNode = null;
        let startOffset = 0;
        let endNode = null;
        let endOffset = 0;
        let node = walker.nextNode();
        while (node) {
            const len = node.nodeValue.length;
            if (startNode === null && startAbs <= acc + len) {
                startNode = node;
                startOffset = startAbs - acc;
            }
            if (endAbs <= acc + len) {
                endNode = node;
                endOffset = endAbs - acc;
                break;
            }
            acc += len;
            node = walker.nextNode();
        }
        if (!startNode || !endNode) {
            return null;
        }
        const restored = document.createRange();
        try {
            restored.setStart(startNode, startOffset);
            restored.setEnd(endNode, endOffset);
        } catch (error) {
            return null;
        }
        return restored;
    }

    async function handleSelectionScore() {
        if (typeof window === 'undefined' || typeof window.getSelection !== 'function') {
            return;
        }
        const root = bodyRef.current;
        const selection = window.getSelection();
        if (!root || !selection || selection.isCollapsed || !selection.rangeCount) {
            clearSelectionHighlight();
            return;
        }
        const range = selection.getRangeAt(0);
        if (!root.contains(range.commonAncestorContainer)) {
            return;
        }
        clearSelectionHighlight();            // undo any prior wrap
        snapshotRef.current = root.innerHTML; // restore point
        const selectedText = selection.toString();
        const tokens = scoreSelectionText(selectedText);
        const scoreMap = new Map();
        tokens.forEach(function (token) {
            if (token && token.normalized) {
                scoreMap.set(token.normalized, token);
            }
        });
        // Refine client LM scores with persisted DB scores (DB wins only when
        // it is an LM anchor or a confident learned score).
        try {
            const response = await fetchWordScores(Array.from(scoreMap.keys()));
            const dbScores = (response && response.scores) || {};
            Object.keys(dbScores).forEach(function (word) {
                const entry = dbScores[word];
                if (!entry || !(entry.source === 'lm' || entry.confident)) {
                    return;
                }
                const base = scoreMap.get(word) || { normalized: word, token: word, stem: word };
                scoreMap.set(word, Object.assign({}, base, {
                    score: entry.score,
                    magnitude: entry.magnitude,
                    color: sentimentColor(entry.score),
                }));
            });
        } catch (error) {
            // Keep the in-bundle client scores on any failure.
        }
        if (snapshotRef.current == null) {
            return; // a restore fired while awaiting; abort the wrap
        }
        // Remember where the selection is (as absolute character offsets) before
        // wrapping mutates the DOM, so we can re-select the same span afterwards.
        const startAbs = absoluteOffsetWithin(root, range.startContainer, range.startOffset);
        const endAbs = absoluteOffsetWithin(root, range.endContainer, range.endOffset);
        wrappingRef.current = true;
        try {
            wrapRangeWords(range, scoreMap);
        } catch (error) {
            clearSelectionHighlight();
            wrappingRef.current = false;
            return;
        }
        // Re-establish the selection over the now-colored words. The browser paints
        // its (translucent) blue selection on top, so the reader sees BOTH where
        // they're dragging AND the per-word sentiment colors underneath.
        const restored = rangeFromAbsoluteOffsets(root, startAbs, endAbs);
        selection.removeAllRanges();
        if (restored) {
            try {
                selection.addRange(restored);
            } catch (error) {
                // Re-selection failed; the colors still show, just without the blue.
            }
        }
        // Keep the guard up through the async selectionchange that the
        // removeAllRanges/addRange dispatches, so the restore handler does not
        // immediately undo the wrap.
        setTimeout(function () {
            wrappingRef.current = false;
        }, 0);
        learnWords(selectedText); // fire-and-forget persistence
    }

    useEffect(function () {
        if (typeof document === 'undefined') {
            return undefined;
        }
        function onSelectionChange() {
            if (wrappingRef.current) {
                return;
            }
            const selection = typeof window !== 'undefined' && window.getSelection
                ? window.getSelection()
                : null;
            if (!selection || selection.isCollapsed) {
                if (snapshotRef.current != null && bodyRef.current) {
                    bodyRef.current.innerHTML = snapshotRef.current;
                }
                snapshotRef.current = null;
            }
        }
        document.addEventListener('selectionchange', onSelectionChange);
        return function () {
            document.removeEventListener('selectionchange', onSelectionChange);
        };
    }, []);
    const isImageMedia = !!(props.media && typeof props.mimetype === 'string' && props.mimetype.indexOf('image/') === 0);
    const forceTorrentMedia = !!(props.media && props.torrent && isImageMedia);
    const prefersTorrent = !!(props.media && props.torrent && (forceTorrentMedia || props.preferredMediaMode !== 'direct'));
    const directMediaUrl = props.direct_media_url || props.media_url;
    const directFallbackPeerThreshold = typeof props.directFallbackPeerThreshold === 'number'
        ? props.directFallbackPeerThreshold
        : viewerDirectFallbackPeerThreshold();
    const canUseDirectMedia = !!directMediaUrl;
    const canUseDirectFallbackNow = canUseDirectMedia && shouldUseDirectFallbackNow(torrentState, {
        preferredMode: props.preferredMediaMode,
        canDirectFallback: props.canDirectFallback,
        directFallbackPeerThreshold: directFallbackPeerThreshold,
    });
    const [directAssistLatched, setDirectAssistLatched] = useState(false);

    useEffect(function () {
        if (torrentState.blobUrl) {
            setDirectAssistLatched(false);
            return;
        }
        if (canUseDirectFallbackNow) {
            setDirectAssistLatched(true);
        }
    }, [canUseDirectFallbackNow, torrentState.blobUrl]);

    const directAssistActive = prefersTorrent && !torrentState.blobUrl && (canUseDirectFallbackNow || directAssistLatched);
    const resolvedMediaUrl = prefersTorrent
        ? (torrentState.blobUrl || (directAssistActive ? directMediaUrl : null))
        : directMediaUrl;
    const previewMediaUrl = prefersTorrent
        ? (torrentState.blobUrl || (directAssistActive ? directMediaUrl : null))
        : directMediaUrl;
    const displayImageUrl = prefersTorrent
        ? (torrentState.blobUrl || (directAssistActive ? props.thumb_url : null))
        : props.thumb_url;
    const expandMediaUrl = prefersTorrent
        ? (torrentState.blobUrl || (directAssistActive ? directMediaUrl : null))
        : directMediaUrl;
    const transportStatus = prefersTorrent ? torrentState.status : 'idle';
    const torrentPreviewPending = isImageMedia && prefersTorrent && !displayImageUrl;
    return (
        <div className={"post-container" + (props.className ? " " + props.className : "") + watermark.className} id={props.id} style={watermark.style} ref={props.innerRef}
             data-analytics-content-type="post" data-analytics-content-id={String(props.id)} data-analytics-surface="thread">
          {props.media && <PostThumbnail
              media_id={props.media}
              mimetype={props.mimetype}
              is_animated={props.is_animated}
              spoiler={props.spoiler}
              thumb_url={props.thumb_url}
              media_url={previewMediaUrl}
              href_url={resolvedMediaUrl}
              display_url={displayImageUrl}
              expand_url={expandMediaUrl}
              expect_torrent={prefersTorrent}
              transport_status={transportStatus}
              torrent_stats={torrentState}
              seedbox_torrent_status={props.seedbox_torrent_status}
              direct_fallback_disabled={!directAssistActive && !torrentState.blobUrl}
              direct_assist_active={directAssistActive}
              torrent_preview_pending={torrentPreviewPending}
          />}
          <div className="container-fluid watermark-content">
            {props.subject && <div className="row">
                                <div className="col"><b>{props.subject}</b></div></div>}
            {props.tags && props.tags.length > 0 && <div className="row">
                         <div className="col">
                           <small className="text-muted">Tags: </small>
                           <small>{props.tags.join(", ")}</small>
                         </div>
                       </div>}
            <div className="row">
              <div className="col-auto">
                {props.slip && props.slip.avatar_url && <img className="poster-avatar mr-1" src={props.slip.avatar_url} alt=""
                     style={{width: '1.5em', height: '1.5em', borderRadius: '50%', objectFit: 'cover', verticalAlign: '-.4em'}}/>}
                <small className="text-secondary">Poster:</small>
                <small className="text-info">
                  {props.slip && props.slip.profile_url
                      ? <a className="profile-name-link" href={props.slip.profile_url}
                           data-profile-preview={props.slip.profile_preview_url}>{props.poster}</a>
                      : props.poster}
                </small>
                {props.tripcode && <small className="text-muted ml-1">{props.tripcode}</small>}
                {props.poster_id && <small className="text-muted ml-2">ID {props.poster_id}</small>}
                {props.country_flag && <span className="country-flag ml-1" title={props.country_code}>{props.country_flag}</span>}
                {props.slip && props.slip.is_admin && <span className="badge badge-danger">Admin</span>}
                {props.slip && !props.slip.is_admin && props.slip.is_mod && <span className="badge badge-success">Mod</span>}
              </div>
              {(props.comment_origin_label || props.is_imported) && <div className="col-auto">
                <small className="text-secondary">Origin:</small>
                {props.comment_origin_label && <small><span className={"badge " + originBadgeClass(props.comment_origin)}>{props.comment_origin_label}</span></small>}
                {props.is_imported && !props.source_url && <small><span className="badge badge-secondary ml-1">{props.source_label}</span></small>}
                {props.is_imported && props.source_url && <small><a className="badge badge-secondary ml-1" href={props.source_url} target="_blank" rel="noreferrer">{props.source_label}</a></small>}
              </div>}
              <div className="col-auto">
                <small className="text-secondary">Posted: </small>
                {onClient && <small className="text-info"><TimeAgo date={props.datetime}/></small>}
                {!onClient && <small className="text-info">{props.datetime}</small>}
              </div>
              <div className="col-auto">
                <small className="text-secondary">Post #:</small>
                <small className="text-info">{props.id}</small>
              </div>
              <div className="w-100 d-block d-md-none"></div>
              <div className="col-auto">
                <small><a className="badge badge-primary" href={"#" + props.id}>Permalink</a></small>
                <small><a className="badge badge-light border" href="#" title="Report this post to moderators" onClick={reportPost}>Report</a></small>
              </div>
              <div className="col-auto">
                <small><a className="badge badge-primary" href={"/threads/" + props.thread_id + "/new?reply=" + props.id} onClick={openReplyBox}>Reply</a></small>
              </div>
              <div className="col-auto">
                <PostVote
                  postId={props.id}
                  voteUrl={props.vote_url}
                  voteTarget={props.vote_target}
                  canVote={props.can_vote}
                  score={props.score}
                  viewerVote={props.viewer_vote}
                />
              </div>
              <div className="col-auto">
                <PostAwards
                  awards={props.awards}
                  awardUrl={props.award_url}
                />
              </div>
              {props.viewer_can_moderate && <div className="col-auto">
                                    <details className="badge badge-danger">
                                      <summary>Moderation</summary>
                                      {props.move_url && <a className="mod-item" href={props.move_url}>Move</a>}
                                      {props.delete_url && <a className="mod-item" href={props.delete_url}>Delete</a>}
                                      {props.block_media_url && <form method="post" action={props.block_media_url}>
                                        <button type="submit" className="mod-item border-0">Ban image</button>
                                      </form>}
                                      {props.fingerprint_ban_url && <form method="post" action={props.fingerprint_ban_url}>
                                        <button type="submit" className="mod-item border-0" title="Ban this image and all near-duplicates by perceptual distance; broadcasts to NNTP peers">Ban image (distance)</button>
                                      </form>}
                                      {props.ban_url && <form method="post" action={props.ban_url}>
                                        <select name="duration" className="mod-item border-0" title="Ban duration">
                                          {BAN_DURATION_OPTIONS.map(function (d) { return <option key={d[0]} value={d[0]}>{d[1]}</option>; })}
                                        </select>
                                        <button type="submit" className="mod-item border-0">Ban poster</button>
                                      </form>}
                                      {props.shadowban_url && <form method="post" action={props.shadowban_url}>
                                        <select name="duration" className="mod-item border-0" title="Shadowban duration">
                                          {BAN_DURATION_OPTIONS.map(function (d) { return <option key={d[0]} value={d[0]}>{d[1]}</option>; })}
                                        </select>
                                        <button type="submit" className="mod-item border-0" title="Poster keeps posting, but no one else sees their content">Shadowban poster</button>
                                      </form>}
                                    </details>
                                  </div>}
            </div>
            {props.replies.length > 0 && <div className="row">
                                          <div className="col-auto">
                                            <ReplyList replies={props.replies} thread_id={props.thread_id}/>
                                          </div>
                                        </div>}
            <div className="row post-body" ref={bodyRef} onMouseDown={clearSelectionHighlight} onMouseUp={handleSelectionScore} dangerouslySetInnerHTML={{__html: renderedBody}}></div>
          </div>
        </div>
    );
}
