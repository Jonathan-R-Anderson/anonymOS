import React, { useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react';
import Post from './Post';
import OutboundReplyStatus from './OutboundReplyStatus';
import ThreadSemanticTree from './ThreadSemanticTree';
import { connect } from 'react-redux';
import { viewerCanDirectFallback, viewerDirectFallbackPeerThreshold, viewerPreferredMediaMode } from '../media/torrentMedia';
import { buildSemanticThreadGraph } from '../semantic/threadSemantic';

export const THREAD_RENDER_VERSION = 'semantic-v9';

function mapStateToProps(state) {
    return {
        posts: state.posts,
        mediaDelivery: state.mediaDelivery || {},
        remoteReply: state.remoteReply || {},
    };
}

function useSeedboxStatus(mediaDelivery) {
    const statusUrl = mediaDelivery && mediaDelivery.seedboxStatusUrl ? mediaDelivery.seedboxStatusUrl : null;
    const pollIntervalMs = mediaDelivery && mediaDelivery.statsPollIntervalMs ? mediaDelivery.statsPollIntervalMs : 5000;
    const [status, setStatus] = useState({
        loading: !!statusUrl,
        images: {},
        seedbox: {
            available: false,
            items: [],
            summary: {},
        },
        error: null,
    });

    useEffect(function () {
        if (!statusUrl || typeof window === 'undefined' || typeof window.fetch !== 'function') {
            return undefined;
        }

        let cancelled = false;
        let intervalId = null;

        function loadStatus() {
            fetch(statusUrl, {
                credentials: 'same-origin',
            }).then(function (response) {
                if (!response.ok) {
                    throw new Error('HTTP ' + response.status);
                }
                return response.json();
            }).then(function (payload) {
                if (cancelled) {
                    return;
                }
                setStatus({
                    loading: false,
                    images: payload && payload.images ? payload.images : {},
                    seedbox: payload && payload.seedbox ? payload.seedbox : {
                        available: false,
                        items: [],
                        summary: {},
                    },
                    error: null,
                });
            }).catch(function (error) {
                if (cancelled) {
                    return;
                }
                setStatus(function (currentStatus) {
                    return Object.assign({}, currentStatus, {
                        loading: false,
                        error: error.message || String(error),
                    });
                });
            });
        }

        loadStatus();
        intervalId = window.setInterval(loadStatus, Math.max(1000, pollIntervalMs));

        return function () {
            cancelled = true;
            if (intervalId !== null) {
                window.clearInterval(intervalId);
            }
        };
    }, [statusUrl, pollIntervalMs]);

    return status;
}

function Thread(props) {
    const allPosts = props.posts || [];
    const [activeFilter, setActiveFilter] = useState(null);
    const [treeDocked, setTreeDocked] = useState(false);
    const [scrollFocusPostId, setScrollFocusPostId] = useState(null);
    const treeRailRef = useRef(null);
    const postRefs = useRef({});
    const prevRectsRef = useRef({});
    const postsFeedRef = useRef(null);

    useEffect(function () {
        if (!activeFilter) {
            return;
        }
        const validPostIds = new Set(allPosts.map(function (post) {
            return post.id;
        }));
        const filteredIds = activeFilter.postIds.filter(function (postId) {
            return validPostIds.has(postId);
        });
        if (!filteredIds.length) {
            setActiveFilter(null);
            return;
        }
        if (filteredIds.length !== activeFilter.postIds.length) {
            setActiveFilter(Object.assign({}, activeFilter, {postIds: filteredIds}));
        }
    }, [allPosts, activeFilter]);

    const activeFilterPostIds = useMemo(function () {
        return new Set(activeFilter ? activeFilter.postIds : []);
    }, [activeFilter]);

    const visiblePosts = useMemo(function () {
        if (!activeFilter) {
            return allPosts;
        }
        return allPosts.filter(function (post) {
            return activeFilterPostIds.has(post.id);
        });
    }, [allPosts, activeFilter, activeFilterPostIds]);

    const semanticAnalysis = useMemo(function () {
        return buildSemanticThreadGraph(allPosts);
    }, [allPosts]);

    const semanticDocumentMap = useMemo(function () {
        return semanticAnalysis.documents.reduce(function (accumulator, document) {
            accumulator[document.postId] = document;
            return accumulator;
        }, {});
    }, [semanticAnalysis]);

    const preferredMediaMode = useMemo(function () {
        if (props.mediaDelivery && props.mediaDelivery.preferredMode) {
            return props.mediaDelivery.preferredMode;
        }
        return viewerPreferredMediaMode();
    }, [props.mediaDelivery]);

    const canDirectFallback = useMemo(function () {
        if (props.mediaDelivery && typeof props.mediaDelivery.canDirectFallback === 'boolean') {
            return props.mediaDelivery.canDirectFallback;
        }
        return viewerCanDirectFallback();
    }, [props.mediaDelivery]);
    const directFallbackPeerThreshold = useMemo(function () {
        if (props.mediaDelivery && typeof props.mediaDelivery.directFallbackPeerThreshold === 'number') {
            return props.mediaDelivery.directFallbackPeerThreshold;
        }
        return viewerDirectFallbackPeerThreshold();
    }, [props.mediaDelivery]);
    const seedboxStatus = useSeedboxStatus(props.mediaDelivery);
    const seedboxItemsByMediaId = useMemo(function () {
        const items = seedboxStatus.seedbox && Array.isArray(seedboxStatus.seedbox.items) ? seedboxStatus.seedbox.items : [];
        return items.reduce(function (accumulator, item) {
            if (!item || item.mediaId === null || typeof item.mediaId === 'undefined') {
                return accumulator;
            }
            accumulator[item.mediaId] = item;
            return accumulator;
        }, {});
    }, [seedboxStatus.seedbox]);

    useEffect(function () {
        if (typeof window === 'undefined') {
            return undefined;
        }

        let frameId = null;

        function updateTreeDockedState() {
            frameId = null;
            const shouldDock = window.innerWidth >= 1100;
            setTreeDocked(function (currentDocked) {
                return currentDocked === shouldDock ? currentDocked : shouldDock;
            });
        }

        function scheduleTreeDockedUpdate() {
            if (frameId !== null) {
                return;
            }
            frameId = window.requestAnimationFrame(updateTreeDockedState);
        }

        scheduleTreeDockedUpdate();
        window.addEventListener('resize', scheduleTreeDockedUpdate);

        return function () {
            window.removeEventListener('resize', scheduleTreeDockedUpdate);
            if (frameId !== null) {
                window.cancelAnimationFrame(frameId);
            }
        };
    }, []);

    useEffect(function () {
        if (typeof window === 'undefined') {
            return undefined;
        }

        let frameId = null;

        function updateScrollFocus() {
            frameId = null;
            const anchorY = Math.min(Math.max(window.innerHeight * 0.34, 120), 320);
            const visibleEntries = visiblePosts.map(function (post) {
                const element = postRefs.current[post.id];
                if (!element) {
                    return null;
                }
                const rect = element.getBoundingClientRect();
                if (rect.bottom <= 0 || rect.top >= window.innerHeight) {
                    return null;
                }
                return {
                    postId: post.id,
                    rect: rect
                };
            }).filter(Boolean);

            if (!visibleEntries.length) {
                setScrollFocusPostId(null);
                return;
            }

            let bestPostId = visibleEntries[0].postId;
            let bestScore = Number.POSITIVE_INFINITY;

            visibleEntries.forEach(function (entry) {
                const rect = entry.rect;
                const centerY = rect.top + (rect.height / 2);
                const spansAnchor = rect.top <= anchorY && rect.bottom >= anchorY;
                const distance = Math.abs(centerY - anchorY);
                const score = spansAnchor ? distance : distance + 1000;
                if (score < bestScore) {
                    bestScore = score;
                    bestPostId = entry.postId;
                }
            });

            setScrollFocusPostId(function (currentPostId) {
                return currentPostId === bestPostId ? currentPostId : bestPostId;
            });
        }

        function scheduleScrollFocusUpdate() {
            if (frameId !== null) {
                return;
            }
            frameId = window.requestAnimationFrame(updateScrollFocus);
        }

        scheduleScrollFocusUpdate();
        window.addEventListener('scroll', scheduleScrollFocusUpdate, {passive: true});
        window.addEventListener('resize', scheduleScrollFocusUpdate);

        return function () {
            window.removeEventListener('scroll', scheduleScrollFocusUpdate);
            window.removeEventListener('resize', scheduleScrollFocusUpdate);
            if (frameId !== null) {
                window.cancelAnimationFrame(frameId);
            }
        };
    }, [visiblePosts]);

    const handleFilterChange = useCallback(function (filterPayload) {
        setActiveFilter(function (currentFilter) {
            if (!filterPayload || !filterPayload.postIds || filterPayload.postIds.length === 0) {
                return null;
            }
            if (
                currentFilter &&
                currentFilter.label === filterPayload.label &&
                currentFilter.summary === filterPayload.summary &&
                currentFilter.postIds.length === filterPayload.postIds.length &&
                currentFilter.postIds.every(function (postId, index) {
                    return postId === filterPayload.postIds[index];
                })
            ) {
                return currentFilter;
            }
            return filterPayload;
        });
    }, []);

    useLayoutEffect(function () {
        const previousRects = prevRectsRef.current;
        const nextRects = {};

        Object.entries(postRefs.current).forEach(function (entry) {
            const postId = entry[0];
            const element = entry[1];
            if (!element) {
                return;
            }

            const currentRect = element.getBoundingClientRect();
            nextRects[postId] = currentRect;

            const previousRect = previousRects[postId];
            if (!previousRect) {
                return;
            }

            const dx = previousRect.left - currentRect.left;
            const dy = previousRect.top - currentRect.top;
            if (Math.abs(dx) < 1 && Math.abs(dy) < 1) {
                return;
            }

            element.style.transition = 'none';
            element.style.transform = 'translate(' + dx + 'px,' + dy + 'px)';
            void element.getBoundingClientRect();
            element.style.transition = 'transform 0.58s cubic-bezier(0.22, 1, 0.36, 1)';
            element.style.transform = '';
        });

        prevRectsRef.current = nextRects;
    });

    return (
        <div
          data-thread-render-version={THREAD_RENDER_VERSION}
          className={'thread-reading-layout' + (treeDocked ? ' thread-reading-layout--docked' : '')}
        >
          <aside className="thread-reading-layout__tree">
            <div className="thread-semantic-rail" ref={treeRailRef}>
              <ThreadSemanticTree
                analysis={semanticAnalysis}
                posts={allPosts}
                onFilterChange={handleFilterChange}
                scrollFocusPostId={scrollFocusPostId}
                docked={treeDocked}
              />
            </div>
          </aside>
          <div className="thread-post-feed thread-reading-layout__posts" ref={postsFeedRef}>
            <div className="container">
            {props.remoteReply && props.remoteReply.isImported &&
              <OutboundReplyStatus threadId={props.remoteReply.threadId}/>}
            {visiblePosts.map((post) => {
                return <Post
                    key={post.id}
                    className={scrollFocusPostId === post.id ? 'post-container--reading' : ''}
                    innerRef={function (element) {
                        if (element) {
                            postRefs.current[post.id] = element;
                        } else {
                            delete postRefs.current[post.id];
                            delete prevRectsRef.current[post.id];
                        }
                    }}
                    preferredMediaMode={preferredMediaMode}
                    canDirectFallback={canDirectFallback}
                    directFallbackPeerThreshold={directFallbackPeerThreshold}
                    seedbox_torrent_status={post.torrent && typeof post.torrent.media_id !== 'undefined'
                        ? seedboxItemsByMediaId[post.torrent.media_id] || null
                        : null}
                    {...post}
                />;
            })}
            </div>
          </div>
        </div>
    );
}

export default connect(mapStateToProps)(Thread);
