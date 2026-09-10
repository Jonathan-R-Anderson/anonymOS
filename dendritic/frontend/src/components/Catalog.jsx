import React, { useEffect, useRef, useLayoutEffect, useState } from 'react';
import { connect } from 'react-redux';
import {
    shouldUseDirectFallbackNow,
    subscribeToTorrentMedia,
    viewerCanDirectFallback,
    viewerDirectFallbackPeerThreshold,
    viewerPreferredMediaMode,
} from '../media/torrentMedia';


const INITIAL_THREAD_BATCH_SIZE = 48;
const THREAD_BATCH_SIZE = 24;
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
        .replace(/[\u2018\u2019]/g, '\'')
        .replace(/[^a-z0-9'\s]+/g, ' ');
    const rawTokens = cleaned.match(/[a-z0-9']+/g) || [];
    return rawTokens
        .map((token) => stemSearchToken(token.replace(/^'+|'+$/g, '')))
        .filter((token) => token && token.length >= 2 && !SEARCH_STOP_WORDS.has(token));
}

function appendSearchTerm(query, term) {
    const existingTerms = (query || '')
        .split(/\s+/)
        .map((value) => value.trim())
        .filter(Boolean);
    if (existingTerms.some((value) => value.toLowerCase() === String(term || '').toLowerCase())) {
        return query;
    }
    return [...existingTerms, term].join(' ').trim();
}

function matchesThreadSearch(thread, queryTokens) {
    if (!queryTokens.length) {
        return true;
    }
    const searchableTokens = new Set(
        normalizeSearchTokens([
            thread.subject || '',
            thread.body || '',
            (thread.tags || []).join(' '),
            (thread.keywords || []).join(' '),
        ].join(' '))
    );
    return queryTokens.every((token) => searchableTokens.has(token));
}

function threadMatchesFilter(thread, queryTokens, filterMode) {
    if (!queryTokens.length) {
        return true;
    }
    const matchesQuery = matchesThreadSearch(thread, queryTokens);
    if (filterMode === 'blacklist') {
        return matchesQuery === false;
    }
    return matchesQuery;
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

// Deterministic mosaic variety — NOT traffic-based. The same size cycle the
// boards page (board-index.html) uses, keyed by thread id so a tile's size is
// stable across reloads and live updates. Only threads WITH media are promoted
// to bigger cells (a big empty text panel looks broken); text-only threads stay
// 1x1. This makes the front page render identically to any per-board catalog
// and consistent with /boards/.
const MOSAIC_SIZE_CYCLE = ['big', 'tall', '', 'wide', 'tall', '', 'wide', ''];

function computeSizeMap(threads) {
    const sizeById = {};
    threads.forEach((thread) => {
        if (!thread.media) {
            return; // text-only -> default 1x1
        }
        const size = MOSAIC_SIZE_CYCLE[thread.id % MOSAIC_SIZE_CYCLE.length];
        if (size) {
            sizeById[thread.id] = size;
        }
    });
    return sizeById;
}

function emptyTorrentState(torrentPayload) {
    return {
        blobUrl: null,
        status: 'idle',
        mediaId: torrentPayload ? torrentPayload.media_id : null,
    };
}

function useTorrentThumbnail(thread, mediaDelivery) {
    const shouldUseTorrent = !!(
        mediaDelivery &&
        thread &&
        thread.media &&
        thread.torrent &&
        typeof thread.mimetype === 'string' &&
        thread.mimetype.indexOf('image/') === 0
    );
    const [torrentState, setTorrentState] = useState(emptyTorrentState(thread ? thread.torrent : null));

    useEffect(function () {
        if (!shouldUseTorrent) {
            setTorrentState(emptyTorrentState(thread ? thread.torrent : null));
            return undefined;
        }
        return subscribeToTorrentMedia(thread.torrent, setTorrentState);
    }, [
        shouldUseTorrent,
        thread ? thread.id : null,
        thread && thread.torrent ? thread.torrent.info_hash : null,
        thread && thread.torrent ? thread.torrent.magnet_url : null,
    ]);

    return torrentState;
}

function ThreadThumbnail(props) {
    const torrentState = useTorrentThumbnail(props, props.mediaDelivery);
    var bgStyle = "bg-light";
    var textStyle = "text-body";
    if(props.tags) {
        const mainTag = props.tags[0];
        if(mainTag in props.tag_styles) {
            if(props.tag_styles[mainTag].bg_style) {
                bgStyle = props.tag_styles[mainTag].bg_style;
            }
            if(props.tag_styles[mainTag].text_style) {
                textStyle = props.tag_styles[mainTag].text_style;
            }
        }
    }
    var imageClass = props.spoiler? "catalog-thumbnail thumbnail-spoiler" : "catalog-thumbnail";
    // TODO: use CSS to space the board display instead of a space character
    const watermark = watermarkProps(props);
    const prefersTorrent = !!(
        props.mediaDelivery &&
        props.media &&
        props.torrent &&
        typeof props.mimetype === 'string' &&
        props.mimetype.indexOf('image/') === 0
    );
    const preferredMode = props.mediaDelivery && props.mediaDelivery.preferredMode
        ? props.mediaDelivery.preferredMode
        : viewerPreferredMediaMode();
    const canDirectFallback = props.mediaDelivery && typeof props.mediaDelivery.canDirectFallback === 'boolean'
        ? props.mediaDelivery.canDirectFallback
        : viewerCanDirectFallback();
    const directFallbackPeerThreshold = props.mediaDelivery && typeof props.mediaDelivery.directFallbackPeerThreshold === 'number'
        ? props.mediaDelivery.directFallbackPeerThreshold
        : viewerDirectFallbackPeerThreshold();
    const canUseDirectFallbackNow = shouldUseDirectFallbackNow(torrentState, {
        preferredMode: preferredMode,
        canDirectFallback: canDirectFallback,
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

    const directAssistActive = canUseDirectFallbackNow || directAssistLatched;
    const serverThumbUrl = props.thumb_url || props.direct_media_url || props.media_url || null;
    const displayThumbUrl = prefersTorrent
        ? (torrentState.blobUrl || (directAssistActive ? serverThumbUrl : null))
        : serverThumbUrl;
    // Pinterest-style masonry (archive.org technique): the grid flows in fixed
    // 20px row increments and each tile carries an htN class that spans N+2
    // rows. Image heights aren't stored server-side, so the span is derived
    // deterministically from the thread id — stable across renders and
    // reflows, keeping tiles in DOM order with no layout JS.
    // A URL in the payload is not proof the image loads: mirrored media can be
    // pruned, and imported media is a remote fetch that can fail. Until this
    // existed, such a tile still claimed to have an image — and because the copy
    // shell is hidden behind a hover overlay for image tiles, it rendered as a
    // blank box with no text. Track the failure and fall back to the text tile,
    // which is what a thread with no image shows anyway.
    const [thumbFailed, setThumbFailed] = useState(false);
    useEffect(function () {
        // A new URL (torrent blob arriving, live update) deserves a fresh try.
        setThumbFailed(false);
    }, [displayThumbUrl]);
    const hasThumb = !!(props.media && displayThumbUrl && !thumbFailed);
    // Mosaic sizing (from activity, computed in the parent) + image-first mode.
    const sizeClass = props.size ? " thread--" + props.size : "";
    const noimgClass = hasThumb ? "" : " thread--noimg";
    return (
        <a ref={props.innerRef} href={props.thread_url} className={"thread" + sizeClass + noimgClass + " " + bgStyle + watermark.className} style={watermark.style}
           title={props._recommendation ? props._recommendation.explanation : undefined}
           data-analytics-content-type="thread" data-analytics-content-id={String(props.id)} data-analytics-surface="catalog"
           data-recommendation-request-id={props._recommendation ? props._recommendation.request_id : undefined}
           data-recommendation-model-id={props._recommendation ? props._recommendation.model_id : undefined}
           data-recommendation-position={props._recommendation ? props._recommendation.position : undefined}
           data-recommendation-experiments={props._recommendation ? (props._recommendation.experiment_ids || []).join(',') : undefined}
           data-recommendation-propensity={props._recommendation ? props._recommendation.bandit_propensity : undefined}
           data-recommendation-satisfaction-prompt={props._recommendation && props._recommendation.satisfaction_prompt ? 'true' : undefined}>
          {hasThumb && <div className="catalog-media-container">
            {props.spoiler && <span className="spoiler-label text-danger">!</span>}
            <img
              className={imageClass}
              src={displayThumbUrl}
              onError={function () { setThumbFailed(true); }}
            />
          </div>}
          {!hasThumb && <div className="catalog-media-container d-flex align-items-center justify-content-center catalog-placeholder">
            <i className="fas fa-image fa-2x text-muted"></i>
          </div>}
          <div className="thread-copy-shell watermark-content">
            <div className="thread-copy-header">
              {props.subject && <h6 className={"text-center font-weight-bold " + textStyle}>{props.subject}</h6>}
              {!props.subject && <h6 className="text-center text-muted">No subject</h6>}
              {props.is_imported && <div className="text-center">
                {!props.source_url && <small className={"badge badge-secondary " + textStyle}>{props.source_label}</small>}
                {props.source_url && <small><span className="badge badge-secondary">{props.source_label}</span></small>}
              </div>}
            </div>
            <div className="thread-copy-body">
              <div className={"thread-body " + textStyle} dangerouslySetInnerHTML={{__html: props.body}}>
              </div>
            </div>
            {props.canKeywordFilter && !!(props.keywords && props.keywords.length) && <div className="thread-keywords mt-2">
              {props.keywords.slice(0, 4).map((keyword) => (
                  <span
                      key={keyword}
                      className="badge badge-pill badge-light mr-1 mb-1"
                      role="button"
                      tabIndex={0}
                      onClick={(event) => {
                          event.preventDefault();
                          event.stopPropagation();
                          props.onKeywordSelect(keyword);
                      }}
                      onKeyDown={(event) => {
                          if (event.key !== 'Enter' && event.key !== ' ') {
                              return;
                          }
                          event.preventDefault();
                          event.stopPropagation();
                          props.onKeywordSelect(keyword);
                      }}
                  >
                    #{keyword}
                  </span>
              ))}
            </div>}
            <span className={"thread-stats-container " + textStyle}>
              {props.display_board && <small>/</small>}
              {props.display_board && <small>{props.board}</small>}
              {props.display_board && (<small>/ </small>)}
              <i className="fas fa-comment"></i>{props.num_replies}
              &nbsp;
              <i className="fas fa-image"></i>{props.num_media}
            </span>
          </div>
        </a>
    );
}

function mapStateToProps(state) {
    return {
        threads: state.threads,
        tag_styles: state.catalogInfo.styles,
        mediaDelivery: state.mediaDelivery || null,
    };
}

function Catalog(props) {
    const canKeywordFilter = props.display_board !== true;
    const [searchQuery, setSearchQuery] = useState('');
    const [filterMode, setFilterMode] = useState('whitelist');
    // The TF-IDF keyword whitelist/blacklist filter lives behind the board's
    // gear menu; that menu dispatches this event to reveal/hide the filter bar.
    const [showKeywordFilter, setShowKeywordFilter] = useState(false);
    const [visibleCount, setVisibleCount] = useState(
        Math.min(INITIAL_THREAD_BATCH_SIZE, props.threads.length)
    );
    const [supportsIntersectionObserver, setSupportsIntersectionObserver] = useState(null);
    const sentinelRef = useRef(null);
    // itemRefs holds the live DOM node for each thread by ID.
    const itemRefs = useRef({});
    // prevRectsRef holds the bounding rects captured during the last render,
    // used as the "First" position in the FLIP technique.
    const prevRectsRef = useRef({});
    // seenIdsRef holds every thread ID the board has ever had in the store, so a
    // genuinely-new (live-arriving) thread can be told apart from a lazy-scroll
    // reveal (already in the store) and faded into place. null until first render.
    const seenIdsRef = useRef(null);
    const previousFilterSignatureRef = useRef('');
    // Only filter while the keyword bar is open, so collapsing it never leaves
    // the board mysteriously filtered with no visible control.
    const queryTokens = (canKeywordFilter && showKeywordFilter) ? normalizeSearchTokens(searchQuery) : [];
    const filterSignature = filterMode + '::' + searchQuery + '::' + showKeywordFilter;
    const filteredThreads = props.threads.filter((thread) => threadMatchesFilter(thread, queryTokens, filterMode));
    const visibleThreads = filteredThreads.slice(0, visibleCount);
    const hasMoreThreads = visibleCount < filteredThreads.length;
    // Mosaic size classes, ranked across the full filtered set so a tile's size
    // is stable as more lazy-load into view.
    const sizeById = computeSizeMap(filteredThreads);

    useEffect(() => {
        setSupportsIntersectionObserver(typeof window !== 'undefined' && 'IntersectionObserver' in window);
    }, []);

    useEffect(() => {
        if (typeof window === 'undefined') {
            return undefined;
        }
        function toggle() {
            setShowKeywordFilter((visible) => !visible);
        }
        window.addEventListener('maniwani:toggle-keyword-filter', toggle);
        return () => window.removeEventListener('maniwani:toggle-keyword-filter', toggle);
    }, []);

    useEffect(() => {
        const filterChanged = previousFilterSignatureRef.current !== filterSignature;
        previousFilterSignatureRef.current = filterSignature;
        if (filteredThreads.length === 0) {
            setVisibleCount(0);
            return;
        }
        setVisibleCount((prevCount) => {
            if (filterChanged) {
                return Math.min(INITIAL_THREAD_BATCH_SIZE, filteredThreads.length);
            }
            if (prevCount === 0) {
                return Math.min(INITIAL_THREAD_BATCH_SIZE, filteredThreads.length);
            }
            return Math.min(prevCount, filteredThreads.length);
        });
    }, [filteredThreads.length, filterSignature]);

    useEffect(() => {
        if (hasMoreThreads === false || supportsIntersectionObserver !== true) {
            return undefined;
        }
        const sentinel = sentinelRef.current;
        if (!sentinel) {
            return undefined;
        }
        const observer = new window.IntersectionObserver((entries) => {
            entries.forEach((entry) => {
                if (entry.isIntersecting === false) {
                    return;
                }
                setVisibleCount((prevCount) => Math.min(prevCount + THREAD_BATCH_SIZE, filteredThreads.length));
            });
        }, {
            rootMargin: '700px 0px',
        });
        observer.observe(sentinel);
        return () => observer.disconnect();
    }, [visibleCount, hasMoreThreads, filteredThreads.length, supportsIntersectionObserver]);

    useLayoutEffect(() => {
        const prevRects = prevRectsRef.current;
        const nextRects = {};
        const seenIds = seenIdsRef.current; // null on the very first render

        Object.entries(itemRefs.current).forEach(([id, el]) => {
            if (!el) return;
            const curr = el.getBoundingClientRect();
            nextRects[id] = curr;

            // A thread that isn't part of the initial render (seenIds !== null)
            // and that the board hasn't shown before is a genuinely new/bumped
            // post arriving live — fade it into place. Lazy-scroll reveals were
            // already in the store (in seenIds), so they don't fade.
            if (seenIds !== null && !seenIds.has(id)) {
                el.style.transition = 'none';
                el.style.opacity = '0';
                el.style.transform = 'translateY(-14px) scale(0.985)';
                void el.getBoundingClientRect(); // register the start state
                el.style.transition = 'opacity 0.5s ease, transform 0.5s ease';
                el.style.opacity = '1';
                el.style.transform = '';
                return;
            }

            const prev = prevRects[id];
            if (!prev) return; // first time this element is measured, not live-new

            const dx = prev.left - curr.left;
            const dy = prev.top  - curr.top;
            if (Math.abs(dx) < 1 && Math.abs(dy) < 1) return; // didn't move

            // FLIP: jump to the previous position (no transition), then slide
            // back to the final rendered position so the browser animates the
            // "shift down" as new threads push the rest of the listing lower.
            el.style.transition = 'none';
            el.style.transform  = `translate(${dx}px,${dy}px)`;
            // Force a reflow so the browser registers the starting transform.
            void el.getBoundingClientRect();
            el.style.transition = 'transform 0.45s ease';
            el.style.transform  = '';
        });

        prevRectsRef.current = nextRects;
        // Remember every thread in the store (not just the rendered slice), so a
        // lazy-loaded thread scrolling into view isn't mistaken for a live arrival.
        seenIdsRef.current = new Set((props.threads || []).map((thread) => String(thread.id)));
    });

    return (
        <div className="container-fluid">
          {canKeywordFilter && showKeywordFilter && <div className="d-flex flex-column flex-lg-row align-items-lg-center justify-content-between mb-3">
            <div className="d-flex flex-column flex-lg-row align-items-lg-center w-100 mr-lg-3">
              <div className="input-group mb-2 mb-lg-0" style={{maxWidth: '36rem'}}>
                <div className="input-group-prepend">
                  <span className="input-group-text">
                    <i className="fas fa-search"></i>
                  </span>
                </div>
                <input
                    type="search"
                    className="form-control"
                    value={searchQuery}
                    onChange={(event) => setSearchQuery(event.target.value)}
                    placeholder="Filter threads by TF-IDF keywords"
                    aria-label="Filter threads by keyword"
                />
                {searchQuery && <div className="input-group-append">
                  <button type="button" className="btn btn-outline-secondary" onClick={() => setSearchQuery('')}>
                    Clear
                  </button>
                </div>}
              </div>
              <div className="btn-group ml-lg-2" role="group" aria-label="Keyword filter mode">
                <button
                    type="button"
                    className={filterMode === 'whitelist' ? 'btn btn-secondary' : 'btn btn-outline-secondary'}
                    onClick={() => setFilterMode('whitelist')}
                >
                  Whitelist
                </button>
                <button
                    type="button"
                    className={filterMode === 'blacklist' ? 'btn btn-secondary' : 'btn btn-outline-secondary'}
                    onClick={() => setFilterMode('blacklist')}
                >
                  Blacklist
                </button>
              </div>
            </div>
            <small className="text-muted">
              {filteredThreads.length} {filteredThreads.length === 1 ? 'thread' : 'threads'}
              {queryTokens.length
                  ? (filterMode === 'blacklist' ? ' remaining after blacklist filter' : ' matching this whitelist filter')
                  : ' in this board'}
            </small>
          </div>}
          <div className="catalog-grid">
            {visibleThreads.map((thread) => {
                return <ThreadThumbnail
                    key={thread.id}
                    innerRef={el => {
                        if (el) {
                            itemRefs.current[thread.id] = el;
                        } else {
                            delete itemRefs.current[thread.id];
                            delete prevRectsRef.current[thread.id];
                        }
                    }}
                    {...thread}
                    canKeywordFilter={canKeywordFilter}
                    display_board={props.display_board}
                    tag_styles={props.tag_styles}
                    mediaDelivery={props.mediaDelivery}
                    size={sizeById[thread.id]}
                    onKeywordSelect={(keyword) => setSearchQuery((prevQuery) => appendSearchTerm(prevQuery, keyword))}
                />;
            })}
          </div>
          {canKeywordFilter && !filteredThreads.length && <div className="text-center py-4 text-muted">
            <i className="fas fa-filter d-block mb-2"></i>
            {queryTokens.length && filterMode === 'blacklist'
                ? 'No threads remain after that blacklist filter.'
                : 'No threads match that keyword filter.'}
          </div>}
          {hasMoreThreads && <div ref={sentinelRef} style={{height: '1px'}} aria-hidden="true"></div>}
          {hasMoreThreads && supportsIntersectionObserver === false && <div className="text-center py-3">
            <button type="button" className="btn btn-outline-secondary" onClick={() => setVisibleCount((prevCount) => Math.min(prevCount + THREAD_BATCH_SIZE, filteredThreads.length))}>
              Load more threads
            </button>
          </div>}
        </div>
    );
}

export default connect(mapStateToProps)(Catalog);
