import React, { useEffect, useMemo, useRef, useState } from 'react';

// Client-side instant filter reuses the tokenizer/matcher approach from
// components/Catalog.jsx (normalizeSearchTokens / matchesThreadSearch). The
// server ?q= remains authoritative for what is loaded; this only filters the
// already-loaded videos[] carried in the store.
const SEARCH_STOP_WORDS = new Set([
    'a', 'about', 'above', 'after', 'again', 'against', 'all', 'also', 'am', 'an',
    'and', 'any', 'are', 'as', 'at', 'be', 'because', 'been', 'before', 'being',
    'below', 'between', 'both', 'but', 'by', 'can', 'cant', 'could', 'couldnt',
    'did', 'didnt', 'do', 'does', 'doesnt', 'doing', 'dont', 'down', 'during',
    'each', 'few', 'for', 'from', 'further', 'had', 'has', 'have', 'having', 'he',
    'her', 'here', 'hers', 'herself', 'him', 'himself', 'his', 'how', 'i', 'if',
    'im', 'in', 'into', 'is', 'isnt', 'it', 'its', 'itself', 'ive', 'just', 'me',
    'more', 'most', 'my', 'myself', 'no', 'nor', 'not', 'now', 'of', 'off', 'on',
    'once', 'only', 'or', 'other', 'our', 'ours', 'ourselves', 'out', 'over',
    'own', 'same', 'she', 'should', 'shouldnt', 'so', 'some', 'such', 'than',
    'that', 'thats', 'the', 'their', 'theirs', 'them', 'themselves', 'then',
    'there', 'theres', 'these', 'they', 'theyre', 'this', 'those', 'through', 'to',
    'too', 'under', 'until', 'up', 'very', 'was', 'wasnt', 'we', 'were', 'werent',
    'what', 'when', 'where', 'which', 'while', 'who', 'whom', 'why', 'will', 'with',
    'wont', 'would', 'wouldnt', 'you', 'your', 'youre', 'yours', 'yourself',
    'yourselves'
]);

function stripHtml(text) {
    return String(text || '').replace(/<[^>]*>/g, ' ');
}

function stemSearchToken(token) {
    let normalized = token;
    if (normalized.length > 5 && normalized.endsWith('ies')) {
        normalized = normalized.slice(0, -3) + 'y';
    } else if (normalized.length > 5 && normalized.endsWith('ing')) {
        normalized = normalized.slice(0, -3);
    } else if (normalized.length > 4 && normalized.endsWith('ed')) {
        normalized = normalized.slice(0, -2);
    } else if (normalized.length > 4 && normalized.endsWith('ly')) {
        normalized = normalized.slice(0, -2);
    } else if (normalized.length > 4 && normalized.endsWith('es')) {
        normalized = normalized.slice(0, -2);
    } else if (
        normalized.length > 3 &&
        normalized.endsWith('s') &&
        !normalized.endsWith('ss') &&
        !normalized.endsWith('us') &&
        !normalized.endsWith('ous') &&
        !normalized.endsWith('is')
    ) {
        normalized = normalized.slice(0, -1);
    }
    return normalized;
}

function normalizeSearchTokens(text) {
    const cleaned = stripHtml(text)
        .toLowerCase()
        .replace(/https?:\/\/\S+/g, ' ')
        .replace(/&gt;&gt;\d+/g, ' ')
        .replace(/>>\d+/g, ' ')
        .replace(/[‘’]/g, '\'')
        .replace(/[^a-z0-9'\s]+/g, ' ');
    const rawTokens = cleaned.match(/[a-z0-9']+/g) || [];
    return rawTokens
        .map((token) => stemSearchToken(token.replace(/^'+|'+$/g, '')))
        .filter((token) => token && token.length >= 2 && !SEARCH_STOP_WORDS.has(token));
}

function matchesVideoSearch(video, queryTokens) {
    if (!queryTokens.length) {
        return true;
    }
    const searchableTokens = new Set(
        normalizeSearchTokens([
            video.title || '',
            video.description || '',
            (video.keywords || []).join(' '),
        ].join(' '))
    );
    return queryTokens.every((token) => searchableTokens.has(token));
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

// Relative time depends on "now", which differs between the SSR render and the
// hydrating client render, so the enclosing <time> is marked
// suppressHydrationWarning to keep hydration from erroring on that text.
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

function uploaderLabel(uploader) {
    if (!uploader) {
        return 'Anonymous';
    }
    if (uploader.is_admin) {
        return 'sysop';
    }
    return uploader.name || 'Anonymous';
}

const GRID_STYLE = {
    display: 'grid',
    gridTemplateColumns: 'repeat(auto-fill, minmax(240px, 1fr))',
    gap: '1.25rem',
};

const THUMB_WRAP_STYLE = {
    position: 'relative',
    width: '100%',
    paddingBottom: '56.25%',
    overflow: 'hidden',
    borderRadius: '0.4rem',
    background: '#111',
};

const THUMB_IMG_STYLE = {
    position: 'absolute',
    top: 0,
    left: 0,
    width: '100%',
    height: '100%',
    objectFit: 'cover',
};

const SLOW_RATE = 0.35;

function VideoCard(props) {
    const video = props.video;
    const videoRef = useRef(null);
    const [hovering, setHovering] = useState(false);
    const fellBackRef = useRef(false);

    function applyRate() {
        const el = videoRef.current;
        if (el) { try { el.playbackRate = SLOW_RATE; } catch (error) { /* pre-metadata */ } }
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
    function resultClick() {
        if (props.searchActive && typeof window !== 'undefined' && window.maniwaniAnalytics) {
            window.maniwaniAnalytics.track('search_result_clicked', {
                surface: 'videos_search',
                content_type: 'video',
                content_id: String(video.id),
                properties: {source_category: 'video_local'}
            });
        }
    }

    // Faded, blurred still frame at rest (like the out-of-focus home-page
    // marquee cards); crisp + playing in slow motion on hover.
    const mediaStyle = Object.assign({}, THUMB_IMG_STYLE, {
        filter: hovering ? 'none' : 'blur(5px) saturate(.85) brightness(.82)',
        transform: hovering ? 'none' : 'scale(1.06)',
        transition: 'filter .2s ease, transform .2s ease',
    });

    return (
        <a href={video.watchUrl} className="video-card text-decoration-none text-body d-block"
           title={video._recommendation ? video._recommendation.explanation : undefined}
           data-analytics-content-type="video" data-analytics-content-id={String(video.id)} data-analytics-surface="videos"
           data-recommendation-request-id={video._recommendation ? video._recommendation.request_id : undefined}
           data-recommendation-model-id={video._recommendation ? video._recommendation.model_id : undefined}
           data-recommendation-position={video._recommendation ? video._recommendation.position : undefined}
           data-recommendation-experiments={video._recommendation ? (video._recommendation.experiment_ids || []).join(',') : undefined}
           data-recommendation-propensity={video._recommendation ? video._recommendation.bandit_propensity : undefined}
           data-recommendation-satisfaction-prompt={video._recommendation && video._recommendation.satisfaction_prompt ? 'true' : undefined}
           onClick={resultClick}>
          <div style={THUMB_WRAP_STYLE} onMouseEnter={onEnter} onMouseLeave={onLeave}>
            {video.previewUrl
                ? <video ref={videoRef} muted loop playsInline preload="metadata"
                         poster={video.thumbUrl || undefined} style={mediaStyle}
                         onLoadedData={function () {
                             applyRate();
                             // Park a beat into the clip so the resting frame is a
                             // real scene, never a black opening frame.
                             const el = videoRef.current;
                             if (el && !hovering && el.currentTime < 0.05 && (el.duration || 0) > 1) {
                                 try { el.currentTime = Math.min(1, el.duration / 2); } catch (error) { /* ignore */ }
                             }
                         }}
                         onError={function () {
                             // Derived preview missing/failed: fall back to the full
                             // media file so hover still plays.
                             const el = videoRef.current;
                             if (el && video.mediaUrl && !fellBackRef.current) {
                                 fellBackRef.current = true;
                                 el.src = video.mediaUrl;
                                 el.load();
                                 if (hovering) { onEnter(); }
                             }
                         }}>
                    <source src={video.previewUrl} type="video/mp4"/>
                  </video>
                : (video.thumbUrl
                    ? <img style={mediaStyle} src={video.thumbUrl} alt={video.title || 'video thumbnail'} loading="lazy"/>
                    : <div className="d-flex align-items-center justify-content-center" style={Object.assign({}, THUMB_IMG_STYLE, {background: '#1b1b1b'})}>
                        <i className="fas fa-video fa-2x text-muted"></i>
                      </div>)}
          </div>
          <div className="mt-2">
            <h6 className="mb-1 font-weight-bold text-truncate" title={video.title}>{video.title || 'Untitled'}</h6>
            <div className="small text-muted">{uploaderLabel(video.uploader)}</div>
            <div className="small text-muted">
              {formatViews(video.views)}
              {video.createdAt && <span> &middot; <time dateTime={video.createdAt} suppressHydrationWarning>{relativeTime(video.createdAt)}</time></span>}
            </div>
          </div>
        </a>
    );
}

function Videos(props) {
    const store = props.store || (typeof window !== 'undefined' ? window._STORE : null) || {};
    const videos = Array.isArray(store.videos) ? store.videos : [];
    const uploadUrl = store.uploadUrl || '/videos/upload';
    const [searchQuery, setSearchQuery] = useState(store.query || '');

    const queryTokens = useMemo(() => normalizeSearchTokens(searchQuery), [searchQuery]);
    const filteredVideos = useMemo(
        () => videos.filter((video) => matchesVideoSearch(video, queryTokens)),
        [videos, queryTokens]
    );

    useEffect(() => {
        if (!searchQuery.trim() || typeof window === 'undefined') return undefined;
        const timer = window.setTimeout(() => {
            if (window.maniwaniAnalytics) {
                window.maniwaniAnalytics.track('search_submitted', {
                    surface: 'videos_search',
                    content_type: 'search',
                    content_id: 'videos',
                    properties: {source_category: 'video_local'}
                });
            }
        }, 500);
        return () => window.clearTimeout(timer);
    }, [searchQuery]);

    return (
        <div className="container-fluid videos-page py-3">
          <div className="d-flex flex-column flex-lg-row align-items-lg-center justify-content-between mb-4">
            <h2 className="mb-3 mb-lg-0"><i className="fas fa-photo-video mr-2"></i>Videos</h2>
            <div className="d-flex flex-column flex-sm-row align-items-stretch align-items-sm-center">
              <div className="input-group mr-sm-2 mb-2 mb-sm-0" style={{maxWidth: '28rem'}}>
                <div className="input-group-prepend">
                  <span className="input-group-text"><i className="fas fa-search"></i></span>
                </div>
                <input
                    type="search"
                    className="form-control"
                    value={searchQuery}
                    onChange={(event) => setSearchQuery(event.target.value)}
                    placeholder="Search videos"
                    aria-label="Search videos"
                />
                {searchQuery && <div className="input-group-append">
                  <button type="button" className="btn btn-outline-secondary" onClick={() => setSearchQuery('')}>Clear</button>
                </div>}
              </div>
              <a href={uploadUrl} className="btn btn-primary text-nowrap"><i className="fas fa-upload mr-1"></i>Upload</a>
            </div>
          </div>

          {queryTokens.length > 0 && <div className="small text-muted mb-2">
            {filteredVideos.length} {filteredVideos.length === 1 ? 'video' : 'videos'} matching &ldquo;{searchQuery.trim()}&rdquo;
          </div>}

          <div style={GRID_STYLE}>
            {filteredVideos.map((video) => <VideoCard key={video.id} video={video} searchActive={queryTokens.length > 0}/>)}
          </div>

          {filteredVideos.length === 0 && <div className="text-center py-5 text-muted">
            <i className="fas fa-film fa-2x d-block mb-2"></i>
            {videos.length === 0 ? 'No videos have been uploaded yet.' : 'No videos match that search.'}
          </div>}
        </div>
    );
}

export default Videos;
