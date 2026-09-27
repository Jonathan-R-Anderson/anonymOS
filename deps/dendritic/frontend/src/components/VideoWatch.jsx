import React, { useEffect, useMemo, useRef, useState } from 'react';
import AnimeCaptcha from './AnimeCaptcha';

// WebTorrent is loaded from a CDN by the page template into window.WebTorrent,
// signalled by this event (see backend react-video-watch.html / react-catalog.html).
// It is NOT an npm import, so every reference is browser-only and guarded.
const WEBTORRENT_READY_EVENT = 'maniwani:webtorrent-ready';
const VIDEO_EXTENSIONS = ['.mp4', '.webm', '.m4v', '.mov', '.ogv', '.ogg', '.mkv', '.avi'];

function errorMessage(error) {
    if (!error) {
        return null;
    }
    return error.message || String(error);
}

// Start playback, working around the browser autoplay policy: an unmuted
// autoplay is rejected, which would leave the video loaded-but-paused. Retry
// muted so it actually starts; the viewer can unmute from the controls.
function attemptAutoplay(videoEl) {
    if (!videoEl) {
        return;
    }
    const playPromise = videoEl.play();
    if (playPromise && typeof playPromise.catch === 'function') {
        playPromise.catch(function () {
            videoEl.muted = true;
            const retry = videoEl.play();
            if (retry && typeof retry.catch === 'function') {
                retry.catch(function () {});
            }
        });
    }
}

// Mirrors the constructor resolution in media/torrentMedia.js: window.WebTorrent
// may be the constructor or a module namespace exposing `.default`.
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
    const ready = getWebTorrentCtor();
    if (ready || typeof window === 'undefined') {
        return Promise.resolve(ready);
    }
    return new Promise(function (resolve) {
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
            resolve(getWebTorrentCtor());
        }
        window.addEventListener(WEBTORRENT_READY_EVENT, finish);
        if (typeof window.setTimeout === 'function') {
            timeoutId = window.setTimeout(finish, 8000);
        }
    });
}

// Mirrors createTorrentClient() in media/torrentMedia.js (~:79-103): apply the
// viewer's ICE servers / TURN relay policy from mediaDelivery to the tracker
// rtcConfig so WebRTC peer connections use the same delivery config as the rest
// of the site.
function createTorrentClient(WebTorrentCtor, mediaDelivery) {
    if (!WebTorrentCtor || !WebTorrentCtor.WEBRTC_SUPPORT) {
        return null;
    }
    const delivery = mediaDelivery || {};
    const iceServers = Array.isArray(delivery.iceServers) ? delivery.iceServers : [];
    const forceTurnRelay = !!delivery.forceTurnRelay;
    const trackerConfig = {};
    if (iceServers.length || forceTurnRelay) {
        trackerConfig.rtcConfig = {
            iceServers: iceServers,
            iceTransportPolicy: forceTurnRelay ? 'relay' : 'all',
        };
    }
    const client = new WebTorrentCtor({ dht: false, lsd: false, tracker: trackerConfig });
    client.on('error', function (error) {
        console.error('[videowatch] WebTorrent client error', error);
    });
    return client;
}

// Pick the file to stream: the largest file whose name looks like a video (or,
// failing an extension match, the largest file overall).
function pickVideoFile(files, mimetype) {
    if (!files || !files.length) {
        return null;
    }
    const wanted = typeof mimetype === 'string' && mimetype.indexOf('/') > -1
        ? mimetype.split('/')[1].toLowerCase()
        : null;
    function isVideoName(name) {
        const lower = String(name || '').toLowerCase();
        if (wanted && lower.endsWith('.' + wanted)) {
            return true;
        }
        return VIDEO_EXTENSIONS.some(function (ext) { return lower.endsWith(ext); });
    }
    let pool = files.filter(function (file) { return isVideoName(file.name); });
    if (!pool.length) {
        pool = files.slice();
    }
    return pool.reduce(function (best, file) {
        if (!best) {
            return file;
        }
        return (file.length || 0) > (best.length || 0) ? file : best;
    }, null);
}

// clientId(): stable per-tab id for viewer counting, copied verbatim in spirit
// from backend/templates/includes/stream-scripts.html.
function clientId() {
    try {
        let id = sessionStorage.getItem('maniwani-stream-viewer');
        if (!id) {
            id = (Math.random().toString(36).slice(2) + Date.now().toString(36));
            sessionStorage.setItem('maniwani-stream-viewer', id);
        }
        return id;
    } catch (error) {
        return 'anon-' + Math.random().toString(36).slice(2);
    }
}

function formatBytes(bytes) {
    const value = Number(bytes) || 0;
    if (value < 1024) {
        return value + ' B';
    }
    const units = ['KB', 'MB', 'GB', 'TB'];
    let size = value / 1024;
    let unitIndex = 0;
    while (size >= 1024 && unitIndex < units.length - 1) {
        size = size / 1024;
        unitIndex += 1;
    }
    return size.toFixed(size < 10 ? 1 : 0) + ' ' + units[unitIndex];
}

function formatViews(views) {
    const value = Number(views) || 0;
    if (value < 1000) {
        return value + (value === 1 ? ' view' : ' views');
    }
    if (value < 1000000) {
        const thousands = value / 1000;
        return (thousands < 10 ? thousands.toFixed(1).replace(/\.0$/, '') : Math.round(thousands)) + 'K views';
    }
    return (value / 1000000).toFixed(1).replace(/\.0$/, '') + 'M views';
}

function relativeTime(value) {
    if (!value) {
        return '';
    }
    const then = new Date(value).getTime();
    if (isNaN(then)) {
        return '';
    }
    const seconds = Math.max(0, Math.floor((Date.now() - then) / 1000));
    if (seconds < 45) {
        return 'just now';
    }
    const minutes = Math.floor(seconds / 60);
    if (minutes < 60) {
        return (minutes || 1) + (minutes === 1 ? ' minute ago' : ' minutes ago');
    }
    const hours = Math.floor(minutes / 60);
    if (hours < 24) {
        return hours + (hours === 1 ? ' hour ago' : ' hours ago');
    }
    const days = Math.floor(hours / 24);
    if (days < 30) {
        return days + (days === 1 ? ' day ago' : ' days ago');
    }
    const months = Math.floor(days / 30);
    if (months < 12) {
        return months + (months === 1 ? ' month ago' : ' months ago');
    }
    const years = Math.floor(days / 365);
    return years + (years === 1 ? ' year ago' : ' years ago');
}

function authorLabel(author) {
    if (!author) {
        return 'Anonymous';
    }
    if (author.is_admin) {
        return 'sysop';
    }
    return author.name || 'Anonymous';
}

// Build a parentId-threaded tree from the flat comments list.
function buildCommentTree(comments) {
    const byId = {};
    const roots = [];
    (comments || []).forEach(function (comment) {
        byId[comment.id] = Object.assign({}, comment, { children: [] });
    });
    (comments || []).forEach(function (comment) {
        const node = byId[comment.id];
        const parentId = comment.parentId;
        if (parentId !== null && parentId !== undefined && byId[parentId]) {
            byId[parentId].children.push(node);
        } else {
            roots.push(node);
        }
    });
    return roots;
}

// A comment id plus all of its descendant reply ids — the server cascades a
// delete to replies (parent_id ON DELETE CASCADE), so the UI removes the whole
// subtree to match.
function collectDescendantIds(comments, rootId) {
    const ids = {};
    ids[rootId] = true;
    let changed = true;
    while (changed) {
        changed = false;
        (comments || []).forEach(function (comment) {
            const parentId = comment.parentId;
            if (parentId !== null && parentId !== undefined && ids[parentId] && !ids[comment.id]) {
                ids[comment.id] = true;
                changed = true;
            }
        });
    }
    return ids;
}

function Comment(props) {
    const comment = props.comment;
    const author = comment.author || {};
    return (
        <div className="video-comment mb-3">
          <div className="d-flex align-items-center flex-wrap">
            {author.avatar_url && <img src={author.avatar_url} alt=""
                 style={{width: '1.6em', height: '1.6em', borderRadius: '50%', objectFit: 'cover', marginRight: '.4rem'}}/>}
            <span className={'font-weight-bold mr-2' + (author.is_admin ? ' text-danger' : '')}>
              {authorLabel(author)}
            </span>
            {author.tripcode && <span className="text-muted small mr-2">!{author.tripcode}</span>}
            {comment.createdAt && <small className="text-muted">
              <time dateTime={comment.createdAt} suppressHydrationWarning>{relativeTime(comment.createdAt)}</time>
            </small>}
            {props.canModerate && comment.deleteUrl && <button type="button"
                 className="btn btn-link btn-sm text-danger p-0 ml-2" style={{lineHeight: 1}}
                 title="Delete comment"
                 onClick={function () { props.onDelete(comment); }}>
              <i className="fas fa-trash"></i>
            </button>}
          </div>
          <div className="video-comment__body" style={{whiteSpace: 'pre-wrap', wordBreak: 'break-word'}}>{comment.body}</div>
          {comment.children && comment.children.length > 0 && <div className="video-comment__children mt-2 pl-3" style={{borderLeft: '2px solid rgba(128,128,128,0.25)'}}>
            {comment.children.map(function (child) { return <Comment key={child.id} comment={child} canModerate={props.canModerate} onDelete={props.onDelete}/>; })}
          </div>}
        </div>
    );
}

const PLAYER_SHELL_STYLE = {
    position: 'relative',
    width: '100%',
    background: '#000',
    borderRadius: '0.4rem',
    overflow: 'hidden',
};

const VIDEO_STYLE = {
    width: '100%',
    maxHeight: '78vh',
    display: 'block',
    background: '#000',
};

const OVERLAY_STYLE = {
    position: 'absolute',
    top: 0,
    left: 0,
    right: 0,
    bottom: 0,
    display: 'flex',
    flexDirection: 'column',
    alignItems: 'center',
    justifyContent: 'center',
    color: '#fff',
    background: 'rgba(0,0,0,0.55)',
    textAlign: 'center',
    padding: '1rem',
    pointerEvents: 'none',
};

const RELATED_THUMB_STYLE = {
    position: 'relative',
    width: '168px',
    minWidth: '168px',
    paddingBottom: '94.5px',
    height: 0,
    overflow: 'hidden',
    borderRadius: '0.3rem',
    background: '#111',
};

const RELATED_THUMB_IMG_STYLE = {
    position: 'absolute',
    top: 0,
    left: 0,
    width: '100%',
    height: '100%',
    objectFit: 'cover',
};

// Related-video thumbnail: a faded, blurred still frame at rest (like the
// out-of-focus home-page marquee cards), playing in slow motion on hover.
function RelatedThumb(props) {
    const item = props.item;
    const videoRef = useRef(null);
    const [hovering, setHovering] = useState(false);
    const fellBackRef = useRef(false);

    function applyRate() {
        const el = videoRef.current;
        if (el) { try { el.playbackRate = 0.35; } catch (error) { /* pre-metadata */ } }
    }
    function onEnter() {
        setHovering(true);
        const el = videoRef.current;
        if (!el) { return; }
        applyRate();
        const playPromise = el.play();
        if (playPromise && typeof playPromise.catch === 'function') { playPromise.catch(function () {}); }
    }
    function onLeave() {
        setHovering(false);
        const el = videoRef.current;
        if (el) { try { el.pause(); } catch (error) { /* ignore */ } }
    }

    const mediaStyle = Object.assign({}, RELATED_THUMB_IMG_STYLE, {
        filter: hovering ? 'none' : 'blur(4px) saturate(.85) brightness(.82)',
        transform: hovering ? 'none' : 'scale(1.06)',
        transition: 'filter .2s ease, transform .2s ease',
    });

    return (
        <div style={RELATED_THUMB_STYLE} onMouseEnter={onEnter} onMouseLeave={onLeave}>
          {item.previewUrl
              ? <video ref={videoRef} muted loop playsInline preload="metadata"
                       poster={item.thumbUrl || undefined} style={mediaStyle}
                       onLoadedData={function () {
                           applyRate();
                           const el = videoRef.current;
                           if (el && !hovering && el.currentTime < 0.05 && (el.duration || 0) > 1) {
                               try { el.currentTime = Math.min(1, el.duration / 2); } catch (error) { /* ignore */ }
                           }
                       }}
                       onError={function () {
                           const el = videoRef.current;
                           if (el && item.mediaUrl && !fellBackRef.current) {
                               fellBackRef.current = true;
                               el.src = item.mediaUrl;
                               el.load();
                               if (hovering) { onEnter(); }
                           }
                       }}>
                  <source src={item.previewUrl} type="video/mp4"/>
                </video>
              : (item.thumbUrl
                  ? <img style={mediaStyle} src={item.thumbUrl} alt={item.title || 'video thumbnail'} loading="lazy"/>
                  : <div className="d-flex align-items-center justify-content-center" style={Object.assign({}, RELATED_THUMB_IMG_STYLE, {background: '#1b1b1b'})}>
                      <i className="fas fa-video text-muted"></i>
                    </div>)}
        </div>
    );
}

// ---------------------------------------------------------------------------
// Rich scrubber: thin line at rest that expands upward on hover into a seek
// heatmap (layer 1) behind a waveform (layer 2), with timestamped comment
// markers that open the comment on hover.
// ---------------------------------------------------------------------------
const SCRUBBER_RENDER_BARS = 160;

function formatClock(seconds) {
    if (!isFinite(seconds) || seconds < 0) { seconds = 0; }
    const whole = Math.floor(seconds);
    const mins = Math.floor(whole / 60);
    const secs = whole % 60;
    return mins + ':' + (secs < 10 ? '0' : '') + secs;
}

function downsampleSeries(values, target) {
    if (!values || !values.length) { return []; }
    if (values.length <= target) { return values.slice(); }
    const out = [];
    const size = values.length / target;
    for (let i = 0; i < target; i++) {
        let sum = 0;
        let count = 0;
        for (let j = Math.floor(i * size); j < Math.floor((i + 1) * size); j++) {
            sum += values[j] || 0;
            count += 1;
        }
        out.push(count ? sum / count : 0);
    }
    return out;
}

const SCRUBBER_CSS = [
    '.mwscrub{position:relative;width:100%;height:8px;margin-top:4px;cursor:pointer;',
    'user-select:none;-webkit-user-select:none;touch-action:none;transition:height .18s ease;}',
    '.mwscrub.is-hover{height:96px;}',
    '.mwscrub__layers{position:absolute;left:0;right:0;top:0;bottom:6px;opacity:0;overflow:hidden;',
    'pointer-events:none;transition:opacity .18s ease;}',
    '.mwscrub.is-hover .mwscrub__layers{opacity:1;}',
    '.mwscrub__heat{position:absolute;inset:0;display:flex;align-items:flex-end;}',
    '.mwscrub__heat span{flex:1 1 0;background:rgba(150,120,210,.30);}',
    '.mwscrub__wave{position:absolute;inset:0;display:flex;align-items:flex-end;gap:1px;}',
    '.mwscrub__wave span{flex:1 1 0;min-height:1px;border-radius:1px;background:rgba(255,255,255,.32);}',
    '.mwscrub__played{position:absolute;inset:0;}',
    '.mwscrub__played .mwscrub__wave span{background:#b07274;}',
    '.mwscrub__line{position:absolute;left:0;right:0;bottom:0;height:6px;border-radius:3px;',
    'overflow:hidden;background:rgba(255,255,255,.18);}',
    '.mwscrub__buffer{position:absolute;left:0;top:0;bottom:0;background:rgba(255,255,255,.28);}',
    '.mwscrub__fill{position:absolute;left:0;top:0;bottom:0;background:#b07274;}',
    '.mwscrub__head{position:absolute;top:0;bottom:0;width:2px;margin-left:-1px;background:#fff;',
    'pointer-events:none;z-index:4;}',
    '.mwscrub__time{position:absolute;bottom:100%;transform:translateX(-50%);margin-bottom:5px;',
    'background:#111;color:#fff;font-size:11px;line-height:1.4;padding:1px 6px;border-radius:3px;',
    'white-space:nowrap;pointer-events:none;z-index:6;}',
    '.mwscrub__comment{position:absolute;bottom:1px;transform:translateX(-50%);width:14px;height:14px;',
    'border-radius:50%;border:2px solid #fff;background:#6f42c1;color:#fff;font-size:8px;font-weight:700;',
    'display:flex;align-items:center;justify-content:center;cursor:pointer;z-index:3;',
    'transition:width .18s ease,height .18s ease,bottom .18s ease;}',
    '.mwscrub.is-hover .mwscrub__comment{bottom:10px;width:22px;height:22px;font-size:11px;}',
    '.mwscrub__comment:hover{filter:brightness(1.15);}',
    '.mwscrub__comment-pic{width:100%;height:100%;border-radius:50%;object-fit:cover;display:block;}',
    '.mwscrub__bubble{position:absolute;bottom:100%;left:50%;transform:translateX(-50%);',
    'margin-bottom:8px;width:230px;max-width:60vw;background:#1c1c24;color:#eee;border-radius:6px;',
    'border:1px solid rgba(255,255,255,.12);padding:8px 10px;font-size:12px;line-height:1.4;',
    'box-shadow:0 8px 24px rgba(0,0,0,.5);z-index:7;white-space:normal;word-break:break-word;cursor:auto;}',
    '.mwscrub__bubble b{color:#d994ff;}',
    // Player chrome overlaid on the video, YouTube-style: a bottom column of
    // [scrubber][button row]. The button row + gradient fade in on hover (or
    // while paused); the scrubber's thin line stays visible at rest.
    '.mwplayer__controls{position:absolute;left:0;right:0;bottom:0;z-index:5;display:flex;',
    'flex-direction:column;padding:0 10px 4px;background:linear-gradient(transparent,rgba(0,0,0,.6));}',
    '.mwplayer__buttons{display:flex;align-items:center;gap:14px;height:0;overflow:hidden;opacity:0;',
    'color:#fff;transition:height .18s ease,opacity .18s ease;}',
    '.mwplayer:hover .mwplayer__buttons,.mwplayer.is-paused .mwplayer__buttons{height:36px;opacity:1;}',
    '.mwplayer__btn{background:none;border:0;color:#fff;font-size:15px;cursor:pointer;padding:4px 5px;line-height:1;}',
    '.mwplayer__btn:hover{color:#d994ff;}',
    '.mwplayer__time{font-size:12px;font-variant-numeric:tabular-nums;color:#eee;}',
    '.mwplayer__spacer{flex:1 1 auto;}',
    // Fullscreen: the shell must fill the screen and the <video> expand into it.
    // The video's inline 78vh cap otherwise limits it to 78% of the fullscreen
    // height (the "doesn't fully expand" bug), so these override it. !important
    // is required to beat the element's inline styles. :fullscreen and
    // :-webkit-full-screen must be separate rules (one invalid selector would
    // drop the whole rule).
    '.mwplayer:fullscreen{width:100vw!important;height:100vh!important;border-radius:0!important;background:#000;}',
    '.mwplayer:fullscreen video{width:100%!important;height:100%!important;max-height:none!important;object-fit:contain;}',
    '.mwplayer:-webkit-full-screen{width:100vw!important;height:100vh!important;border-radius:0!important;background:#000;}',
    '.mwplayer:-webkit-full-screen video{width:100%!important;height:100%!important;max-height:none!important;object-fit:contain;}',
].join('');

function ensureScrubberStyles() {
    if (typeof document === 'undefined') { return; }
    if (document.getElementById('mwscrub-styles')) { return; }
    const style = document.createElement('style');
    style.id = 'mwscrub-styles';
    style.textContent = SCRUBBER_CSS;
    document.head.appendChild(style);
}

function VideoScrubber(props) {
    const videoRef = props.videoRef;
    const comments = props.comments || [];
    const [duration, setDuration] = useState(0);
    const [current, setCurrent] = useState(0);
    const [buffered, setBuffered] = useState(0);
    const [hovering, setHovering] = useState(false);
    const [hoverFrac, setHoverFrac] = useState(null);
    const [peaks, setPeaks] = useState([]);
    const [seeks, setSeeks] = useState([]);
    const [openComment, setOpenComment] = useState(null);
    const trackRef = useRef(null);
    const draggingRef = useRef(false);

    useEffect(function () { ensureScrubberStyles(); }, []);

    // Mirror the <video> element's clock, buffer, and seeks.
    useEffect(function () {
        if (typeof window === 'undefined') { return undefined; }
        const videoEl = videoRef.current;
        if (!videoEl) { return undefined; }
        function onTime() { setCurrent(videoEl.currentTime || 0); }
        function onDuration() { if (isFinite(videoEl.duration)) { setDuration(videoEl.duration || 0); } }
        function onProgress() {
            try {
                if (videoEl.buffered && videoEl.buffered.length) {
                    setBuffered(videoEl.buffered.end(videoEl.buffered.length - 1));
                }
            } catch (error) { /* buffered can throw before metadata */ }
        }
        function onSeeked() {
            if (!videoEl.duration || !props.seekUrl) { return; }
            const frac = Math.min(1, Math.max(0, videoEl.currentTime / videoEl.duration));
            const bucket = Math.min(479, Math.floor(frac * 480));
            fetch(props.seekUrl, {
                method: 'POST',
                credentials: 'same-origin',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ bucket: bucket }),
            }).catch(function () {});
            setSeeks(function (previous) {
                const next = previous.slice();
                while (next.length <= bucket) { next.push(0); }
                next[bucket] = (next[bucket] || 0) + 1;
                return next;
            });
        }
        onDuration();
        videoEl.addEventListener('timeupdate', onTime);
        videoEl.addEventListener('durationchange', onDuration);
        videoEl.addEventListener('loadedmetadata', onDuration);
        videoEl.addEventListener('progress', onProgress);
        videoEl.addEventListener('seeked', onSeeked);
        return function () {
            videoEl.removeEventListener('timeupdate', onTime);
            videoEl.removeEventListener('durationchange', onDuration);
            videoEl.removeEventListener('loadedmetadata', onDuration);
            videoEl.removeEventListener('progress', onProgress);
            videoEl.removeEventListener('seeked', onSeeked);
        };
    }, [videoRef, props.seekUrl]);

    // Load the waveform and seek heatmap once.
    useEffect(function () {
        if (typeof window === 'undefined') { return; }
        if (props.waveformUrl) {
            fetch(props.waveformUrl, { credentials: 'same-origin' })
                .then(function (response) { return response.ok ? response.json() : null; })
                .then(function (data) { if (data && data.peaks) { setPeaks(data.peaks); } })
                .catch(function () {});
        }
        if (props.seeksUrl) {
            fetch(props.seeksUrl, { credentials: 'same-origin' })
                .then(function (response) { return response.ok ? response.json() : null; })
                .then(function (data) { if (data && data.counts) { setSeeks(data.counts); } })
                .catch(function () {});
        }
    }, [props.waveformUrl, props.seeksUrl]);

    // End any in-progress drag no matter where the mouse is released.
    useEffect(function () {
        if (typeof window === 'undefined') { return undefined; }
        function stop() { draggingRef.current = false; }
        window.addEventListener('mouseup', stop);
        return function () { window.removeEventListener('mouseup', stop); };
    }, []);

    const waveBars = useMemo(function () { return downsampleSeries(peaks, SCRUBBER_RENDER_BARS); }, [peaks]);
    const heatBars = useMemo(function () {
        const reduced = downsampleSeries(seeks, SCRUBBER_RENDER_BARS);
        const max = reduced.reduce(function (a, b) { return b > a ? b : a; }, 0) || 1;
        return reduced.map(function (value) { return value / max; });
    }, [seeks]);

    function fracFromClientX(clientX) {
        const el = trackRef.current;
        if (!el) { return 0; }
        const rect = el.getBoundingClientRect();
        return Math.min(1, Math.max(0, (clientX - rect.left) / rect.width));
    }
    function seekTo(clientX) {
        const videoEl = videoRef.current;
        if (!videoEl || !isFinite(videoEl.duration)) { return; }
        videoEl.currentTime = fracFromClientX(clientX) * videoEl.duration;
    }

    const playedPct = duration ? Math.min(100, (current / duration) * 100) : 0;
    const bufferedPct = duration ? Math.min(100, (buffered / duration) * 100) : 0;

    const waveSpans = waveBars.map(function (peak, index) {
        return <span key={index} style={{ height: Math.max(2, peak * 100) + '%' }} />;
    });

    return (
        <div
            ref={trackRef}
            className={'mwscrub' + (hovering ? ' is-hover' : '')}
            onMouseEnter={function () { setHovering(true); }}
            onMouseLeave={function () { setHovering(false); setHoverFrac(null); setOpenComment(null); }}
            onMouseMove={function (event) {
                setHoverFrac(fracFromClientX(event.clientX));
                if (draggingRef.current) { seekTo(event.clientX); }
            }}
            onMouseDown={function (event) { draggingRef.current = true; seekTo(event.clientX); }}
        >
          <div className="mwscrub__layers">
            <div className="mwscrub__heat">
              {heatBars.map(function (value, index) {
                  return <span key={index} style={{ height: (6 + value * 94) + '%' }} />;
              })}
            </div>
            <div className="mwscrub__wave">{waveSpans}</div>
            <div className="mwscrub__played" style={{ clipPath: 'inset(0 ' + (100 - playedPct) + '% 0 0)' }}>
              <div className="mwscrub__wave">{waveSpans}</div>
            </div>
          </div>

          <div className="mwscrub__line">
            <div className="mwscrub__buffer" style={{ width: bufferedPct + '%' }} />
            <div className="mwscrub__fill" style={{ width: playedPct + '%' }} />
          </div>

          {hovering && <div className="mwscrub__head" style={{ left: playedPct + '%' }} />}
          {hovering && hoverFrac !== null && duration > 0 && (
            <div className="mwscrub__time" style={{ left: (hoverFrac * 100) + '%' }}>
              {formatClock(hoverFrac * duration)}
            </div>
          )}

          {duration > 0 && comments.filter(function (comment) {
              return typeof comment.videoTime === 'number' && comment.videoTime >= 0;
          }).map(function (comment) {
              const left = Math.min(100, (comment.videoTime / duration) * 100);
              const author = comment.author || {};
              const label = (author.name || 'A').slice(0, 1).toUpperCase();
              return (
                <div
                    key={comment.id}
                    className="mwscrub__comment"
                    style={{ left: left + '%' }}
                    title={'Comment at ' + formatClock(comment.videoTime)}
                    onMouseEnter={function () { setOpenComment(comment.id); }}
                    onMouseLeave={function () { setOpenComment(null); }}
                    onMouseDown={function (event) { event.stopPropagation(); }}
                    onClick={function (event) {
                        event.stopPropagation();
                        const videoEl = videoRef.current;
                        if (videoEl) { videoEl.currentTime = comment.videoTime; }
                    }}
                >
                  {author.avatar_url
                      ? <img src={author.avatar_url} alt="" className="mwscrub__comment-pic"/>
                      : label}
                  {openComment === comment.id && (
                    <div className="mwscrub__bubble" onMouseDown={function (event) { event.stopPropagation(); }}>
                      <div><b>{author.name || 'Anonymous'}</b> &middot; {formatClock(comment.videoTime)}</div>
                      <div style={{ marginTop: '4px' }}>{comment.body}</div>
                    </div>
                  )}
                </div>
              );
          })}
        </div>
    );
}

// Custom player chrome overlaid on the video: the rich scrubber plus a button
// row (play/pause, time, mute, fullscreen). Time/play state is tracked here so
// re-renders stay inside the player subtree, not the whole watch page.
function PlayerControls(props) {
    const videoRef = props.videoRef;
    const shellRef = props.shellRef;
    const [playing, setPlaying] = useState(false);
    const [muted, setMuted] = useState(false);
    const [current, setCurrent] = useState(0);
    const [duration, setDuration] = useState(0);
    const [isFullscreen, setIsFullscreen] = useState(false);

    useEffect(function () { ensureScrubberStyles(); }, []);

    useEffect(function () {
        if (typeof window === 'undefined') { return undefined; }
        const videoEl = videoRef.current;
        if (!videoEl) { return undefined; }
        function onPlay() { setPlaying(true); }
        function onPause() { setPlaying(false); }
        function onTime() { setCurrent(videoEl.currentTime || 0); }
        function onDuration() { if (isFinite(videoEl.duration)) { setDuration(videoEl.duration || 0); } }
        function onVolume() { setMuted(videoEl.muted); }
        setPlaying(!videoEl.paused);
        setMuted(videoEl.muted);
        onDuration();
        videoEl.addEventListener('play', onPlay);
        videoEl.addEventListener('pause', onPause);
        videoEl.addEventListener('timeupdate', onTime);
        videoEl.addEventListener('durationchange', onDuration);
        videoEl.addEventListener('loadedmetadata', onDuration);
        videoEl.addEventListener('volumechange', onVolume);
        return function () {
            videoEl.removeEventListener('play', onPlay);
            videoEl.removeEventListener('pause', onPause);
            videoEl.removeEventListener('timeupdate', onTime);
            videoEl.removeEventListener('durationchange', onDuration);
            videoEl.removeEventListener('loadedmetadata', onDuration);
            videoEl.removeEventListener('volumechange', onVolume);
        };
    }, [videoRef]);

    useEffect(function () {
        if (typeof document === 'undefined') { return undefined; }
        function onFullscreen() { setIsFullscreen(!!document.fullscreenElement); }
        document.addEventListener('fullscreenchange', onFullscreen);
        return function () { document.removeEventListener('fullscreenchange', onFullscreen); };
    }, []);

    function togglePlay() {
        const videoEl = videoRef.current;
        if (!videoEl) { return; }
        if (videoEl.paused) { videoEl.play().catch(function () {}); } else { videoEl.pause(); }
    }
    function toggleMute() {
        const videoEl = videoRef.current;
        if (videoEl) { videoEl.muted = !videoEl.muted; }
    }
    function toggleFullscreen() {
        const shell = shellRef.current;
        if (typeof document === 'undefined') { return; }
        if (document.fullscreenElement) {
            if (document.exitFullscreen) { document.exitFullscreen(); }
        } else if (shell && shell.requestFullscreen) {
            shell.requestFullscreen();
        }
    }

    return (
        <div className="mwplayer__controls" onClick={function (event) { event.stopPropagation(); }}>
          <VideoScrubber
              videoRef={videoRef}
              comments={props.comments}
              waveformUrl={props.waveformUrl}
              seeksUrl={props.seeksUrl}
              seekUrl={props.seekUrl}
          />
          <div className="mwplayer__buttons">
            <button type="button" className="mwplayer__btn" onClick={togglePlay} aria-label={playing ? 'Pause' : 'Play'}>
              <i className={'fas ' + (playing ? 'fa-pause' : 'fa-play')}></i>
            </button>
            <span className="mwplayer__time">{formatClock(current)} / {formatClock(duration)}</span>
            <span className="mwplayer__spacer"></span>
            <button type="button" className="mwplayer__btn" onClick={toggleMute} aria-label={muted ? 'Unmute' : 'Mute'}>
              <i className={'fas ' + (muted ? 'fa-volume-mute' : 'fa-volume-up')}></i>
            </button>
            <button type="button" className="mwplayer__btn" onClick={toggleFullscreen} aria-label="Toggle fullscreen">
              <i className={'fas ' + (isFullscreen ? 'fa-compress' : 'fa-expand')}></i>
            </button>
          </div>
        </div>
    );
}

function VideoWatch(props) {
    const store = props.store || (typeof window !== 'undefined' ? window._STORE : null) || {};
    const video = store.video || {};
    const torrent = video.torrent || null;
    const directMediaUrl = video.mediaUrl || null;
    const [comments, setComments] = useState(store.comments || []);
    const related = store.related || [];
    const mediaDelivery = store.mediaDelivery || (typeof window !== 'undefined' ? window._MEDIA_DELIVERY : null) || {};
    const viewerPingUrl = store.viewerPingUrl || null;
    const commentPostUrl = store.commentPostUrl || null;
    // Anti-spam challenge for the comment form; present only when the backend
    // decided one is needed (absent for admins / users on the captcha cooldown).
    const captcha = store.captcha || null;
    const currentSlip = store.currentSlip || null;
    // Admins + appointed sitewide moderators can remove the video.
    const voteUrl = store.voteUrl || null;
    const initialVote = store.vote || null;
    // Score and this viewer's vote are the only two things the control needs.
    // Both are seeded from the server render so the buttons are correct before
    // any JS runs; `votable` is false for media with no content hash, which
    // cannot be voted on at all (see model/MediaVote.py).
    const [voteScore, setVoteScore] = React.useState(initialVote ? initialVote.score : 0);
    const [viewerVote, setViewerVote] = React.useState(initialVote ? initialVote.viewerVote : 0);
    const [voteBusy, setVoteBusy] = React.useState(false);
    const [voteError, setVoteError] = React.useState('');
    const votable = !!(voteUrl && initialVote && initialVote.hash);
    const canModerate = !!store.canModerate;
    const deleteUrl = store.deleteUrl || null;
    const videosUrl = store.videosUrl || '/videos';
    const embedUrl = store.embedUrl || null;
    const tags = Array.isArray(video.tags) ? video.tags : [];

    const [showEmbed, setShowEmbed] = useState(false);
    const [embedCopied, setEmbedCopied] = useState(false);
    const embedCode = embedUrl
        ? '<iframe src="' + embedUrl + '" width="640" height="360" frameborder="0" allow="autoplay; fullscreen; picture-in-picture" allowfullscreen></iframe>'
        : '';
    function copyEmbed() {
        if (!embedCode) { return; }
        try {
            if (navigator.clipboard && navigator.clipboard.writeText) {
                navigator.clipboard.writeText(embedCode).then(function () {
                    setEmbedCopied(true);
                    window.setTimeout(function () { setEmbedCopied(false); }, 2000);
                });
            }
        } catch (error) { /* the field is selectable as a manual fallback */ }
    }

    // The video is torrent-hosted, so its magnet link lets viewers download the
    // full file in their own torrent client. It's the same magnet used to stream.
    const magnetUrl = (torrent && torrent.magnet_url) ? torrent.magnet_url : null;
    const [showMagnet, setShowMagnet] = useState(false);
    const [magnetCopied, setMagnetCopied] = useState(false);
    function copyMagnet() {
        if (!magnetUrl) { return; }
        try {
            if (navigator.clipboard && navigator.clipboard.writeText) {
                navigator.clipboard.writeText(magnetUrl).then(function () {
                    setMagnetCopied(true);
                    window.setTimeout(function () { setMagnetCopied(false); }, 2000);
                });
            }
        } catch (error) { /* the field is selectable as a manual fallback */ }
    }

    function castVote(value) {
        if (!votable || voteBusy) { return; }
        // Clicking the button you already chose withdraws the vote, matching
        // post voting.
        const next = (viewerVote === value) ? 0 : value;
        const previousScore = voteScore;
        const previousVote = viewerVote;
        // Optimistic: the delta is exact because a vote is only ever -1/0/+1.
        setVoteScore(previousScore - previousVote + next);
        setViewerVote(next);
        setVoteBusy(true);
        setVoteError('');
        fetch(voteUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'same-origin',
            body: JSON.stringify({ value: next }),
        }).then(function (response) {
            if (response.status === 401) { throw new Error('You need a slip to vote.'); }
            if (!response.ok) { throw new Error('Vote failed.'); }
            return response.json();
        }).then(function (data) {
            // Trust the server's number over the optimistic one.
            setVoteScore(data.score);
            setViewerVote(data.viewer_vote);
        }).catch(function (error) {
            setVoteScore(previousScore);
            setViewerVote(previousVote);
            setVoteError(error.message || 'Vote failed.');
        }).then(function () {
            setVoteBusy(false);
        });
    }

    function removeVideo() {
        if (!deleteUrl) { return; }
        if (typeof window !== 'undefined' &&
            !window.confirm('Remove this video for everyone? This cannot be undone.')) { return; }
        fetch(deleteUrl, {
            method: 'POST',
            headers: { 'X-Requested-With': 'XMLHttpRequest' },
            credentials: 'same-origin',
        })
            .then(function (response) { return response.ok ? response.json() : Promise.reject(response); })
            .then(function (data) { window.location.href = (data && data.redirect) || videosUrl; })
            .catch(function () { window.alert('Could not remove the video. You may not have permission.'); });
    }

    function deleteComment(comment) {
        if (!comment || !comment.deleteUrl) { return; }
        const hasReplies = comment.children && comment.children.length > 0;
        if (typeof window !== 'undefined' && !window.confirm(
            hasReplies ? 'Delete this comment and its replies?' : 'Delete this comment?')) { return; }
        fetch(comment.deleteUrl, {
            method: 'POST',
            headers: { 'X-Requested-With': 'XMLHttpRequest' },
            credentials: 'same-origin',
        })
            .then(function (response) { if (!response.ok) { return Promise.reject(response); } })
            .then(function () {
                const removing = collectDescendantIds(comments, comment.id);
                setComments(comments.filter(function (c) { return !removing[c.id]; }));
            })
            .catch(function () { window.alert('Could not delete the comment. You may not have permission.'); });
    }

    const videoRef = useRef(null);
    const playerShellRef = useRef(null);
    const commentTimeRef = useRef(null);

    function togglePlayback() {
        const videoEl = videoRef.current;
        if (!videoEl) { return; }
        if (videoEl.paused) { videoEl.play().catch(function () {}); } else { videoEl.pause(); }
    }
    // All player state starts at neutral defaults so the first client render
    // matches the SSR shell exactly (torrent work happens only in useEffect).
    const [status, setStatus] = useState('idle');
    const [playing, setPlaying] = useState(false);
    const [errorText, setErrorText] = useState(null);
    const [stats, setStats] = useState({ numPeers: 0, progress: 0, downloadSpeed: 0, downloaded: 0, length: 0 });
    const [viewerCount, setViewerCount] = useState(null);
    const [hiddenRelated, setHiddenRelated] = useState({});

    function markNotInterested(item) {
        setHiddenRelated(function (previous) {
            return Object.assign({}, previous, {[item.id]: true});
        });
        if (typeof window === 'undefined') return;
        fetch('/analytics/feedback', {
            method: 'POST',
            credentials: 'same-origin',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                action: 'not_interested', content_type: 'video', content_id: String(item.id),
                request_id: item._recommendation ? item._recommendation.request_id : undefined,
                model_id: item._recommendation ? item._recommendation.model_id : undefined,
            }),
        }).catch(function () { /* preference control remains locally hidden */ });
    }

    const commentTree = useMemo(function () { return buildCommentTree(comments); }, [comments]);

    // --- Torrent streaming (browser-only) ---
    useEffect(function () {
        if (typeof window === 'undefined') {
            return undefined;
        }
        const videoEl = videoRef.current;
        if (!videoEl) {
            return undefined;
        }
        if (!torrent || !torrent.magnet_url) {
            if (directMediaUrl) {
                videoEl.src = directMediaUrl;
                setStatus('direct');
                setErrorText(null);
                attemptAutoplay(videoEl);
            } else {
                setStatus('unavailable');
                setErrorText('No playable source is available for this video.');
            }
            return undefined;
        }
        if (mediaDelivery.preferredMode === 'direct' && directMediaUrl) {
            videoEl.src = directMediaUrl;
            setStatus('direct');
            setErrorText(null);
            attemptAutoplay(videoEl);
            return undefined;
        }

        let cancelled = false;
        let client = null;
        let currentTorrent = null;
        let currentFile = null;
        let fellBack = false;
        let statsTimer = null;
        let directFallbackTimer = null;

        setStatus('connecting');
        setErrorText(null);

        function serverFallback(message) {
            if (fellBack || cancelled || !directMediaUrl) {
                return false;
            }
            fellBack = true;
            currentFile = null;
            setStatus('direct');
            setErrorText(message || null);
            videoEl.src = directMediaUrl;
            videoEl.load();
            attemptAutoplay(videoEl);
            return true;
        }

        function blobFallback(file) {
            if (fellBack || cancelled) {
                return;
            }
            if (serverFallback()) {
                return;
            }
            if (typeof file.getBlobURL !== 'function') {
                setStatus('error');
                setErrorText('This browser cannot stream or download this video.');
                return;
            }
            fellBack = true;
            setStatus('fallback');
            // Whole-file buffering fallback, used only when MSE streaming is
            // unavailable for this codec/browser.
            file.getBlobURL(function (error, url) {
                if (cancelled) {
                    return;
                }
                if (error) {
                    setStatus('error');
                    setErrorText(errorMessage(error) || 'Failed to load video.');
                    return;
                }
                videoEl.src = url;
                attemptAutoplay(videoEl);
            });
        }

        // Prefer MSE streaming; never buffer the whole file up front.
        function startStreaming(file) {
            currentFile = file;
            setStatus('buffering');
            if (typeof file.select === 'function') {
                try { file.select(); } catch (error) { /* best-effort priority */ }
            }
            if (typeof file.streamTo === 'function') {
                try {
                    file.streamTo(videoEl);
                    attemptAutoplay(videoEl);
                    return;
                } catch (error) {
                    console.warn('[videowatch] streamTo failed, trying renderTo', error);
                }
            }
            if (typeof file.renderTo === 'function') {
                try {
                    file.renderTo(videoEl, { autoplay: true, controls: false }, function (error) {
                        if (error && !cancelled) {
                            console.warn('[videowatch] renderTo failed, using blob fallback', error);
                            blobFallback(file);
                        }
                    });
                    return;
                } catch (error) {
                    console.warn('[videowatch] renderTo threw, using blob fallback', error);
                }
            }
            blobFallback(file);
        }

        function onReady(torrentInstance) {
            if (cancelled || fellBack) {
                return;
            }
            if (directFallbackTimer !== null) {
                window.clearTimeout(directFallbackTimer);
                directFallbackTimer = null;
            }
            const file = pickVideoFile(torrentInstance.files, video.mimetype);
            if (!file) {
                setStatus('error');
                setErrorText('No video file found in this torrent.');
                return;
            }
            startStreaming(file);
        }

        // If MSE streaming yields a media error (unsupported codec), fall back to
        // a full blob download once.
        function onVideoError() {
            if (currentFile && !fellBack) {
                blobFallback(currentFile);
            }
        }
        function onPlaying() {
            if (!cancelled) {
                setPlaying(true);
            }
        }
        function onPauseOrEnd() {
            if (!cancelled) {
                setPlaying(false);
            }
        }
        videoEl.addEventListener('error', onVideoError);
        videoEl.addEventListener('playing', onPlaying);
        videoEl.addEventListener('pause', onPauseOrEnd);
        videoEl.addEventListener('ended', onPauseOrEnd);

        statsTimer = window.setInterval(function () {
            if (cancelled || !currentTorrent) {
                return;
            }
            setStats({
                numPeers: currentTorrent.numPeers || 0,
                progress: currentTorrent.progress || 0,
                downloadSpeed: currentTorrent.downloadSpeed || 0,
                downloaded: currentTorrent.downloaded || 0,
                length: currentTorrent.length || 0,
            });
        }, 1000);

        waitForWebTorrentCtor().then(function (WebTorrentCtor) {
            if (cancelled) {
                return;
            }
            client = createTorrentClient(WebTorrentCtor, mediaDelivery);
            if (!client) {
                if (!serverFallback()) {
                    setStatus('unsupported');
                    setErrorText('WebTorrent streaming is not supported in this browser.');
                }
                return;
            }

            function attachToTorrent(torrentInstance) {
                currentTorrent = torrentInstance;
                torrentInstance.on('error', function (error) {
                    if (!cancelled) {
                        if (!serverFallback()) {
                            setStatus('error');
                            setErrorText(errorMessage(error));
                        }
                    }
                });
                torrentInstance.on('warning', function (error) {
                    console.warn('[videowatch] torrent warning', errorMessage(error));
                });
                if (torrentInstance.ready) {
                    onReady(torrentInstance);
                } else {
                    torrentInstance.on('ready', function () { onReady(torrentInstance); });
                }
            }

            const existing = (client.torrents || []).find(function (item) {
                return item.infoHash === torrent.info_hash;
            });
            if (existing) {
                attachToTorrent(existing);
                return;
            }
            try {
                client.add(torrent.magnet_url, { announce: torrent.announce_urls || [] }, attachToTorrent);
            } catch (error) {
                if (!cancelled) {
                    if (!serverFallback()) {
                        setStatus('error');
                        setErrorText(errorMessage(error));
                    }
                }
            }
        }).catch(function (error) {
            if (!cancelled) {
                if (!serverFallback()) {
                    setStatus('error');
                    setErrorText(errorMessage(error));
                }
            }
        });

        if (directMediaUrl && mediaDelivery.canDirectFallback !== false) {
            directFallbackTimer = window.setTimeout(function () {
                serverFallback('Peer delivery is unavailable; playing from the server.');
            }, 4000);
        }

        return function cleanup() {
            cancelled = true;
            if (statsTimer !== null) {
                window.clearInterval(statsTimer);
            }
            if (directFallbackTimer !== null) {
                window.clearTimeout(directFallbackTimer);
            }
            videoEl.removeEventListener('error', onVideoError);
            videoEl.removeEventListener('playing', onPlaying);
            videoEl.removeEventListener('pause', onPauseOrEnd);
            videoEl.removeEventListener('ended', onPauseOrEnd);
            if (client) {
                try { client.destroy(); } catch (error) { /* already torn down */ }
            }
        };
    }, [
        torrent ? torrent.info_hash : null,
        torrent ? torrent.magnet_url : null,
        directMediaUrl,
        mediaDelivery.preferredMode,
        mediaDelivery.canDirectFallback,
    ]);

    // --- Viewer ping (browser-only) ---
    useEffect(function () {
        if (typeof window === 'undefined' || !viewerPingUrl) {
            return undefined;
        }
        const id = clientId();
        let stopped = false;

        function ping() {
            if (stopped) {
                return;
            }
            const videoEl = videoRef.current;
            const isPlaying = videoEl && !videoEl.paused && !videoEl.ended && videoEl.readyState > 2;
            const visible = typeof document === 'undefined' || !document.hidden;
            if (!isPlaying || !visible) {
                return;
            }
            try {
                fetch(viewerPingUrl, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ client_id: id }),
                    keepalive: true,
                }).then(function (response) {
                    return response.ok ? response.json() : null;
                }).then(function (data) {
                    if (stopped || !data) {
                        return;
                    }
                    if (typeof data.viewers === 'number') {
                        setViewerCount(data.viewers);
                    }
                }).catch(function () {});
            } catch (error) { /* network hiccup; retry next tick */ }
        }

        const timer = window.setInterval(ping, 10000);
        const videoEl = videoRef.current;
        if (videoEl) {
            videoEl.addEventListener('playing', ping);
        }
        if (typeof document !== 'undefined') {
            document.addEventListener('visibilitychange', ping);
        }
        ping();

        return function () {
            stopped = true;
            window.clearInterval(timer);
            if (videoEl) {
                videoEl.removeEventListener('playing', ping);
            }
            if (typeof document !== 'undefined') {
                document.removeEventListener('visibilitychange', ping);
            }
        };
    }, [viewerPingUrl]);

    const hardError = status === 'error' || status === 'unsupported' || status === 'unavailable';
    const showBufferingOverlay = !playing && !hardError;
    const progressPct = Math.round((stats.progress || 0) * 100);
    let overlayHeadline = 'Connecting to peers…';
    if (status === 'buffering') {
        overlayHeadline = 'Buffering…';
    } else if (status === 'fallback') {
        overlayHeadline = 'Downloading video…';
    } else if (status === 'direct') {
        overlayHeadline = 'Loading video…';
    }

    return (
        <div className="container-fluid video-watch py-3" data-analytics-content-type="video"
             data-analytics-content-id={String(video.id)} data-analytics-surface="video_watch">
          <div className="row">
            <div className="col-lg-8">
              <div ref={playerShellRef} style={PLAYER_SHELL_STYLE} className={'mwplayer' + (playing ? '' : ' is-paused')}>
                <video
                    ref={videoRef}
                    style={Object.assign({}, VIDEO_STYLE, { cursor: 'pointer' })}
                    playsInline
                    preload="metadata"
                    onClick={togglePlayback}
                    onPlaying={function () { setPlaying(true); }}
                    onPause={function () { setPlaying(false); }}
                    onEnded={function () { setPlaying(false); }}
                    onError={function () {
                        if (status === 'direct') {
                            setStatus('error');
                            setErrorText('Server playback failed for this video.');
                        }
                    }}
                ></video>
                {showBufferingOverlay && <div style={OVERLAY_STYLE}>
                  <div className="spinner-border text-light mb-2" role="status" aria-hidden="true"></div>
                  <div className="font-weight-bold">{overlayHeadline}</div>
                  <div className="small mt-1">
                    {stats.numPeers} {stats.numPeers === 1 ? 'peer' : 'peers'}
                    {progressPct > 0 && <span> &middot; {progressPct}% buffered</span>}
                  </div>
                </div>}
                {hardError && <div style={OVERLAY_STYLE}>
                  <i className="fas fa-exclamation-triangle fa-2x mb-2"></i>
                  <div className="font-weight-bold">Playback unavailable</div>
                  {errorText && <div className="small mt-1">{errorText}</div>}
                </div>}
                {!hardError && <PlayerControls
                    videoRef={videoRef}
                    shellRef={playerShellRef}
                    comments={comments}
                    waveformUrl={store.waveformUrl}
                    seeksUrl={store.seeksUrl}
                    seekUrl={store.seekUrl}
                />}
              </div>

              <h1 className="h3 mt-3 mb-1">{video.title || 'Untitled'}</h1>
              <div className="d-flex flex-wrap align-items-center text-muted small mb-2">
                <span>{formatViews(video.views)}</span>
                {video.createdAt && <span className="ml-2"><time dateTime={video.createdAt} suppressHydrationWarning>{relativeTime(video.createdAt)}</time></span>}
                <span className="ml-2">
                  <i className="fas fa-eye mr-1"></i>
                  {viewerCount === null ? '—' : viewerCount} watching
                </span>
              </div>
              <div className="d-flex flex-wrap align-items-center mb-2" style={{ gap: '.5rem' }}>
                {votable && <div className="btn-group btn-group-sm mr-1" role="group" aria-label="Vote on this video">
                  <button type="button"
                          className={'btn ' + (viewerVote === 1 ? 'btn-success' : 'btn-outline-success')}
                          disabled={voteBusy}
                          aria-pressed={viewerVote === 1}
                          title="Upvote"
                          onClick={function () { castVote(1); }}>
                    <i className="fas fa-arrow-up"></i>
                  </button>
                  <span className="btn btn-outline-secondary disabled" style={{ pointerEvents: 'none', minWidth: '3rem' }}>
                    {voteScore}
                  </span>
                  <button type="button"
                          className={'btn ' + (viewerVote === -1 ? 'btn-danger' : 'btn-outline-danger')}
                          disabled={voteBusy}
                          aria-pressed={viewerVote === -1}
                          title="Downvote"
                          onClick={function () { castVote(-1); }}>
                    <i className="fas fa-arrow-down"></i>
                  </button>
                </div>}
                {embedUrl && <button type="button" className="btn btn-sm btn-outline-secondary" onClick={function () { setShowEmbed(!showEmbed); }}>
                  <i className="fas fa-code mr-1"></i>Embed
                </button>}
                {magnetUrl && <button type="button" className="btn btn-sm btn-outline-secondary" onClick={function () { setShowMagnet(!showMagnet); }}>
                  <i className="fas fa-download mr-1"></i>Download
                </button>}
                {canModerate && deleteUrl && <button type="button" className="btn btn-sm btn-outline-danger" onClick={removeVideo}>
                  <i className="fas fa-trash mr-1"></i>Remove video
                </button>}
              </div>
              {voteError && <div className="small text-danger mb-2">{voteError}</div>}
              {showEmbed && embedUrl && <div className="mb-3">
                <div className="input-group input-group-sm">
                  <input type="text" className="form-control" readOnly value={embedCode}
                         onFocus={function (event) { event.target.select(); }} aria-label="Embed code"/>
                  <div className="input-group-append">
                    <button type="button" className="btn btn-outline-secondary" onClick={copyEmbed}>
                      {embedCopied ? 'Copied!' : 'Copy'}
                    </button>
                  </div>
                </div>
                <small className="text-muted">Paste this HTML into any website to embed the video.</small>
              </div>}
              {showMagnet && magnetUrl && <div className="mb-3">
                <a href={magnetUrl} className="btn btn-sm btn-primary mb-2"><i className="fas fa-magnet mr-1"></i>Open in torrent client</a>
                <div className="input-group input-group-sm">
                  <input type="text" className="form-control" readOnly value={magnetUrl}
                         onFocus={function (event) { event.target.select(); }} aria-label="Magnet link"/>
                  <div className="input-group-append">
                    <button type="button" className="btn btn-outline-secondary" onClick={copyMagnet}>
                      {magnetCopied ? 'Copied!' : 'Copy'}
                    </button>
                  </div>
                </div>
                <small className="text-muted">Open this magnet link in your torrent client (qBittorrent, Transmission, WebTorrent, …) to download the full video.</small>
              </div>}

              <div className="d-flex align-items-center mb-3">
                <div className="font-weight-bold d-flex align-items-center">
                  {video.uploader && video.uploader.avatar_url
                      ? <img src={video.uploader.avatar_url} alt="" style={{width: '1.8em', height: '1.8em', borderRadius: '50%', objectFit: 'cover', marginRight: '.4rem'}}/>
                      : <i className="fas fa-user-circle mr-1"></i>}
                  {video.uploader ? (video.uploader.is_admin ? 'sysop' : (video.uploader.name || 'Anonymous')) : 'Anonymous'}
                </div>
              </div>

              {!hardError && <div className="card card-body py-2 mb-3 small text-muted">
                <div className="d-flex flex-wrap">
                  <span className="mr-3"><i className="fas fa-network-wired mr-1"></i>{stats.numPeers} {stats.numPeers === 1 ? 'peer' : 'peers'}</span>
                  <span className="mr-3"><i className="fas fa-download mr-1"></i>{formatBytes(stats.downloadSpeed)}/s</span>
                  <span className="mr-3">{formatBytes(stats.downloaded)}{stats.length ? ' / ' + formatBytes(stats.length) : ''}</span>
                  <span className="mr-3">{progressPct}%</span>
                  <span className="text-uppercase">{status === 'fallback' || status === 'direct' ? 'direct playback' : 'streaming'}</span>
                </div>
              </div>}

              {video.description && <div className="mb-3" style={{whiteSpace: 'pre-wrap', wordBreak: 'break-word'}}>{video.description}</div>}

              {tags.length > 0 && <div className="mb-3">
                {tags.map(function (tag) {
                    return <span key={tag} className="badge badge-secondary mr-1">{tag}</span>;
                })}
              </div>}

              <hr/>

              <section className="video-comments">
                <h5 className="mb-3">{comments.length} {comments.length === 1 ? 'Comment' : 'Comments'}</h5>

                {commentPostUrl && <form method="post" action={commentPostUrl} className="card card-body mb-4"
                      onSubmit={function () {
                          // Pin the comment to the current playback position so it
                          // appears as a marker on the scrubber.
                          const videoEl = videoRef.current;
                          if (videoEl && commentTimeRef.current) {
                              commentTimeRef.current.value = String(videoEl.currentTime || 0);
                          }
                      }}>
                  <input type="hidden" name="video_time" ref={commentTimeRef} />
                  <div className="form-group mb-2">
                    <input
                        type="text"
                        name="name"
                        className="form-control"
                        placeholder="Name (optional)"
                        defaultValue={currentSlip ? (currentSlip.name || '') : ''}
                    />
                  </div>
                  <div className="form-group mb-2">
                    <textarea name="body" className="form-control" rows="3" placeholder="Add a comment…" required></textarea>
                  </div>
                  <div className="small text-muted mb-2">
                    <i className="fas fa-map-pin mr-1"></i>
                    Your comment will be pinned to the current playback time.
                  </div>
                  {captcha && captcha.token && <AnimeCaptcha {...captcha}/>}
                  <div>
                    <button type="submit" className="btn btn-primary">Comment</button>
                  </div>
                </form>}

                {commentTree.length === 0 && <div className="text-muted">No comments yet. Be the first!</div>}
                {commentTree.map(function (comment) { return <Comment key={comment.id} comment={comment} canModerate={canModerate} onDelete={deleteComment}/>; })}
              </section>
            </div>

            <aside className="col-lg-4">
              <h5 className="mb-3">Related</h5>
              {related.length === 0 && <div className="text-muted small">No related videos.</div>}
              {related.filter(function (item) { return !hiddenRelated[item.id]; }).map(function (item) {
                  return (
                      <div key={item.id} className="d-flex mb-3 align-items-start">
                        <a href={item.watchUrl} className="d-flex flex-grow-1 text-decoration-none text-body"
                           title={item._recommendation ? item._recommendation.explanation : undefined}
                           data-analytics-content-type="video" data-analytics-content-id={String(item.id)} data-analytics-surface="video_related"
                           data-recommendation-request-id={item._recommendation ? item._recommendation.request_id : undefined}
                           data-recommendation-model-id={item._recommendation ? item._recommendation.model_id : undefined}
                           data-recommendation-position={item._recommendation ? item._recommendation.position : undefined}
                           data-recommendation-experiments={item._recommendation ? (item._recommendation.experiment_ids || []).join(',') : undefined}
                           data-recommendation-propensity={item._recommendation ? item._recommendation.bandit_propensity : undefined}
                           data-recommendation-satisfaction-prompt={item._recommendation && item._recommendation.satisfaction_prompt ? 'true' : undefined}>
                          <RelatedThumb item={item}/>
                          <div className="ml-2">
                            <div className="font-weight-bold small" style={{lineHeight: 1.2}}>{item.title || 'Untitled'}</div>
                            <div className="text-muted small mt-1">{formatViews(item.views)}</div>
                          </div>
                        </a>
                        <button type="button" className="btn btn-link btn-sm text-muted p-1" title="Not interested" aria-label={'Not interested in ' + (item.title || 'this video')} onClick={function () { markNotInterested(item); }}>
                          <i className="fas fa-times"></i>
                        </button>
                      </div>
                  );
              })}
            </aside>
          </div>
        </div>
    );
}

export default VideoWatch;
