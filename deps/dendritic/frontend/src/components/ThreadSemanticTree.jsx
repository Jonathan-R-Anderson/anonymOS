import React, { useEffect, useMemo, useRef, useState } from 'react';

import {
    buildSemanticThreadGraph,
    layoutTree
} from '../semantic/threadSemantic';

const VIEWBOX_SIZE = 900;
const HALF_VIEWBOX = VIEWBOX_SIZE / 2;
const TREE_OUTER_GUIDE_RADIUS = 388;
const CLUSTER_BAND_INNER_RADIUS = 396;
const CLUSTER_BAND_OUTER_RADIUS = 438;
const LEAF_LABEL_RADIUS = 404;
const CLADE_PALETTE = [
    '#4f46e5',
    '#2563eb',
    '#0891b2',
    '#16a34a',
    '#84cc16',
    '#ca8a04',
    '#ea580c',
    '#dc2626',
    '#db2777',
    '#9333ea'
];

const SENTIMENT_PROFILE_KEYS = [
    'positive',
    'negative',
    'uncertainty',
    'litigious',
    'constraining',
    'strongModal',
    'weakModal'
];

const SENTIMENT_DIMENSION_LABELS = {
    positive: 'Positive',
    negative: 'Negative',
    uncertainty: 'Uncertainty',
    litigious: 'Litigious',
    constraining: 'Constraining',
    strongModal: 'Strong modal',
    weakModal: 'Weak modal'
};

function loadD3() {
    if (typeof window === 'undefined') {
        return Promise.resolve(null);
    }
    if (window.d3) {
        return Promise.resolve(window.d3);
    }
    if (window.__maniwaniD3Promise) {
        return window.__maniwaniD3Promise;
    }
    window.__maniwaniD3Promise = new Promise(function (resolve) {
        const script = document.createElement('script');
        script.src = 'https://cdn.jsdelivr.net/npm/d3@7/dist/d3.min.js';
        script.async = true;
        script.onload = function () {
            resolve(window.d3 || null);
        };
        script.onerror = function () {
            resolve(null);
        };
        document.head.appendChild(script);
    });
    return window.__maniwaniD3Promise;
}

function uniqueValues(values) {
    return Array.from(new Set(values));
}

function polarPoint(angle, radius) {
    return {
        x: radius * Math.cos(angle - (Math.PI / 2)),
        y: radius * Math.sin(angle - (Math.PI / 2))
    };
}

function arcSweepFlag(sourceAngle, targetAngle) {
    return targetAngle >= sourceAngle ? 1 : 0;
}

function largeArcFlag(sourceAngle, targetAngle) {
    return Math.abs(targetAngle - sourceAngle) > Math.PI ? 1 : 0;
}

function bandPath(innerRadius, outerRadius, startAngle, endAngle) {
    if (!isFinite(startAngle) || !isFinite(endAngle) || endAngle <= startAngle) {
        return '';
    }
    const outerStart = polarPoint(startAngle, outerRadius);
    const outerEnd = polarPoint(endAngle, outerRadius);
    const innerEnd = polarPoint(endAngle, innerRadius);
    const innerStart = polarPoint(startAngle, innerRadius);
    const largeArc = largeArcFlag(startAngle, endAngle);
    const sweep = arcSweepFlag(startAngle, endAngle);
    return [
        'M', outerStart.x, outerStart.y,
        'A', outerRadius, outerRadius, 0, largeArc, sweep, outerEnd.x, outerEnd.y,
        'L', innerEnd.x, innerEnd.y,
        'A', innerRadius, innerRadius, 0, largeArc, sweep ? 0 : 1, innerStart.x, innerStart.y,
        'Z'
    ].join(' ');
}

function radialTextProps(angle, radius) {
    const point = polarPoint(angle, radius);
    const angleDegrees = ((angle * 180) / Math.PI) - 90;
    const flipped = angle > Math.PI;
    return {
        x: point.x,
        y: point.y,
        transform: 'rotate(' + (flipped ? angleDegrees + 180 : angleDegrees) + ' ' + point.x + ' ' + point.y + ')',
        textAnchor: flipped ? 'end' : 'start',
        dx: flipped ? -5 : 5
    };
}

function branchPath(source, target) {
    if (!source || !target) {
        return '';
    }
    if (source.radius <= 0 || target.radius <= 0) {
        return ['M', source.x, source.y, 'L', target.x, target.y].join(' ');
    }
    if (Math.abs(source.radius - target.radius) < 0.0001) {
        return [
            'M', source.x, source.y,
            'A', source.radius, source.radius, 0, largeArcFlag(source.angle, target.angle), arcSweepFlag(source.angle, target.angle), target.x, target.y
        ].join(' ');
    }
    const orbitTurn = polarPoint(target.angle, source.radius);
    return [
        'M', source.x, source.y,
        'A', source.radius, source.radius, 0, largeArcFlag(source.angle, target.angle), arcSweepFlag(source.angle, target.angle), orbitTurn.x, orbitTurn.y,
        'L', target.x, target.y
    ].join(' ');
}

function emptySentimentProfile() {
    return {
        positive: 0,
        negative: 0,
        uncertainty: 0,
        litigious: 0,
        constraining: 0,
        strongModal: 0,
        weakModal: 0
    };
}

function averageSentimentProfiles(profiles) {
    if (!profiles.length) {
        return emptySentimentProfile();
    }
    const aggregate = emptySentimentProfile();
    profiles.forEach(function (profile) {
        if (!profile) {
            return;
        }
        SENTIMENT_PROFILE_KEYS.forEach(function (key) {
            aggregate[key] += profile[key] || 0;
        });
    });
    SENTIMENT_PROFILE_KEYS.forEach(function (key) {
        aggregate[key] = aggregate[key] / profiles.length;
    });
    return aggregate;
}

function describeSelectionTone(sentiment, profile) {
    if (profile) {
        if (sentiment >= 0.48 && (profile.positive || 0) >= 0.24) {
            return (profile.strongModal || 0) >= 0.24
                ? 'conviction positive'
                : 'positive';
        }
        if (sentiment >= 0.18) {
            return (profile.strongModal || 0) >= 0.24 ? 'confident' : 'leaning positive';
        }
        if (sentiment <= -0.48) {
            if ((profile.litigious || 0) >= Math.max(profile.negative || 0, profile.uncertainty || 0, profile.constraining || 0)) {
                return 'legalistic';
            }
            if ((profile.constraining || 0) >= Math.max(profile.negative || 0, profile.uncertainty || 0, profile.litigious || 0)) {
                return 'restrictive';
            }
            return 'negative';
        }
        if (sentiment <= -0.18) {
            if ((profile.weakModal || 0) >= 0.24) {
                return 'hedged';
            }
            return (profile.uncertainty || 0) >= 0.24 ? 'uncertain' : 'leaning negative';
        }
        if ((profile.uncertainty || 0) >= 0.28) {
            return 'uncertain';
        }
        if ((profile.litigious || 0) >= 0.24) {
            return 'legalistic';
        }
        if ((profile.constraining || 0) >= 0.24) {
            return 'restrictive';
        }
        if ((profile.strongModal || 0) >= 0.24) {
            return 'forceful';
        }
        if ((profile.weakModal || 0) >= 0.24) {
            return 'hedged';
        }
    }
    if (sentiment > 0.48) {
        return 'positive';
    }
    if (sentiment > 0.18) {
        return 'leaning positive';
    }
    if (sentiment < -0.48) {
        return 'negative';
    }
    if (sentiment < -0.18) {
        return 'leaning negative';
    }
    return 'mixed';
}

function summarizeSelection(commentCount, keywords, sentiment, profile) {
    if (!commentCount) {
        return 'No comments intersect the current selection.';
    }
    const tone = describeSelectionTone(sentiment, profile);
    if (!keywords.length) {
        return commentCount + ' comments selected with a ' + tone + ' tone.';
    }
    return commentCount + ' comments selected around ' + keywords.slice(0, 4).join(', ') + ' with a ' + tone + ' tone.';
}

function bigramFillStyle(bigram) {
    if (!bigram || !bigram.words || !bigram.words.length) {
        // Themed neutral (see --st-ink-muted in board-sidebar-styles.html); the
        // literal is the light-theme value this used to be hardcoded to.
        return {backgroundColor: 'var(--st-ink-muted, #94a3b8)'};
    }
    if (bigram.words.length === 1) {
        return {backgroundColor: bigram.words[0].color};
    }
    const leftColor = bigram.words[0].color;
    const rightColor = bigram.words[1].color;
    return {
        backgroundImage: 'linear-gradient(90deg, ' + leftColor + ' 0%, ' + leftColor + ' 48%, ' + rightColor + ' 52%, ' + rightColor + ' 100%)'
    };
}

function buildBigramChartData(bigrams, docked) {
    if (!bigrams || !bigrams.length) {
        return {segments: []};
    }
    const chartBigrams = bigrams
        .slice()
        .filter(function (bigram) {
            return (bigram.magnitude || 0) > 0.04;
        })
        .slice(0, docked ? 10 : 14);
    const totalMagnitude = chartBigrams.reduce(function (sum, bigram) {
        return sum + Math.max(bigram.magnitude || 0.12, 0.12);
    }, 0);
    const segments = chartBigrams.map(function (bigram) {
        const value = Math.max(bigram.magnitude || 0.12, 0.12);
        const dominantDimension = SENTIMENT_PROFILE_KEYS.reduce(function (bestKey, key) {
            const currentValue = (bigram.profile && bigram.profile[key]) || 0;
            const bestValue = bestKey ? ((bigram.profile && bigram.profile[bestKey]) || 0) : -1;
            return currentValue > bestValue ? key : bestKey;
        }, null);
        return {
            id: bigram.id,
            label: bigram.label,
            tone: bigram.tone,
            fillStyle: bigramFillStyle(bigram),
            percent: totalMagnitude ? (value / totalMagnitude) * 100 : 0,
            score: bigram.score || 0,
            dominantDimension: dominantDimension ? (SENTIMENT_DIMENSION_LABELS[dominantDimension] || dominantDimension) : 'Mixed'
        };
    });
    return {
        segments: segments
    };
}

function summarizeNodeSet(nodes) {
    if (nodes.length === 1) {
        return nodes[0].label;
    }
    if (nodes.every(function (node) { return node.kind === 'cluster'; })) {
        return nodes.length + ' clusters selected';
    }
    if (nodes.every(function (node) { return node.kind === 'subcluster'; })) {
        return nodes.length + ' branches selected';
    }
    if (nodes.every(function (node) { return node.kind === 'comment'; })) {
        return nodes.length + ' comments selected';
    }
    return nodes.length + ' nodes selected';
}

function baseNodeRadius(node, totalLeaves) {
    if (node.kind === 'root') {
        return 0;
    }
    if (node.kind === 'op') {
        return 4.6;
    }
    if (node.kind === 'cluster') {
        return 3.8;
    }
    if (node.kind === 'merge') {
        return totalLeaves > 120 ? 1.2 : 1.7;
    }
    if (node.kind === 'comment') {
        if (!node.leaf) {
            return 2.6;
        }
        return totalLeaves > 120 ? 1.4 : 1.9;
    }
    return 2.2;
}

// How far a well-received post can grow, and how far a buried one can shrink.
// Bounded on both sides so the tree stays readable: an unbounded radius would
// let one popular post swallow its neighbours, and an unbounded floor would make
// downvoted nodes vanish (they still need to be visible and clickable).
const VOTE_RADIUS_MAX_SCALE = 2.6;
const VOTE_RADIUS_MIN_SCALE = 0.55;

/**
 * Build {postId: scale} from the vote scores in a thread.
 *
 * Relative, not absolute, as asked: a post is sized against the rest of THIS
 * thread, so a +3 post in a quiet thread reads as big while +3 in a busy one
 * does not. The mapping walks outward from 0 in each direction independently —
 * the most-upvoted post hits the ceiling, the most-downvoted hits the floor,
 * and 0 always lands on 1.0. Doing it in one span instead would make "no votes"
 * drift off centre as soon as a thread skewed one way.
 */
function buildVoteScaleMap(posts) {
    const scales = {};
    if (!posts || !posts.length) {
        return scales;
    }
    let maxPositive = 0;
    let maxNegative = 0;
    for (const post of posts) {
        const score = typeof post.score === 'number' ? post.score : 0;
        if (score > maxPositive) { maxPositive = score; }
        if (score < maxNegative) { maxNegative = score; }
    }
    // Every post at zero: nothing to differentiate, leave the tree at base size.
    if (maxPositive === 0 && maxNegative === 0) {
        return scales;
    }
    for (const post of posts) {
        const score = typeof post.score === 'number' ? post.score : 0;
        let scale = 1;
        if (score > 0 && maxPositive > 0) {
            scale = 1 + (score / maxPositive) * (VOTE_RADIUS_MAX_SCALE - 1);
        } else if (score < 0 && maxNegative < 0) {
            scale = 1 - (score / maxNegative) * (1 - VOTE_RADIUS_MIN_SCALE);
        }
        scales[String(post.id)] = scale;
    }
    return scales;
}

// Controversy tiers. A node's SHAPE says how contested the post is, which is a
// different axis from its SIZE (net score) — a post can be huge and unanimous,
// or small and bitterly split, and the two must stay readable independently.
const CONTROVERSY_CALM = 0.18;      // below this: a plain circle
const CONTROVERSY_CONTESTED = 0.5;  // above this: a spiked burst

/**
 * Build {postId: controversy} in 0..1 for a thread.
 *
 * Controversy needs BOTH halves of the vote, because a net score cannot tell
 * +10/-10 from 0/0 — one is a fight, the other is silence.
 *
 *   balance = min(up,down)/max(up,down)   1.0 when evenly split, 0 when one-sided
 *   weight  = total votes / the thread's busiest post
 *
 * Multiplying them is what makes it "relative to all of the comments in the
 * thread": a 3-vs-3 split is maximally contested in a quiet thread but barely
 * registers next to a post with 200 votes. Without the weight, a single 1-vs-1
 * post would outrank a genuine 90-vs-80 brawl.
 */
function buildControversyMap(posts) {
    const controversy = {};
    if (!posts || !posts.length) {
        return controversy;
    }
    let maxTotal = 0;
    for (const post of posts) {
        const up = typeof post.upvotes === 'number' ? post.upvotes : 0;
        const down = typeof post.downvotes === 'number' ? post.downvotes : 0;
        if (up + down > maxTotal) { maxTotal = up + down; }
    }
    if (maxTotal <= 0) {
        return controversy;
    }
    for (const post of posts) {
        const up = typeof post.upvotes === 'number' ? post.upvotes : 0;
        const down = typeof post.downvotes === 'number' ? post.downvotes : 0;
        const total = up + down;
        if (total <= 0 || up === 0 || down === 0) {
            continue;  // unopposed is not controversial, however loud
        }
        const balance = Math.min(up, down) / Math.max(up, down);
        controversy[String(post.id)] = balance * (total / maxTotal);
    }
    return controversy;
}

/** Points for a star/burst polygon, used for contested nodes. */
function burstPoints(radius, spikes, innerRatio) {
    const points = [];
    for (let i = 0; i < spikes * 2; i++) {
        const r = i % 2 === 0 ? radius : radius * innerRatio;
        // Start at -90deg so the shape reads upright rather than rotated.
        const angle = (Math.PI * i) / spikes - Math.PI / 2;
        points.push((Math.cos(angle) * r).toFixed(2) + ',' + (Math.sin(angle) * r).toFixed(2));
    }
    return points.join(' ');
}

function nodeControversy(node, controversyMap) {
    if (!controversyMap || !node || node.post_id === undefined || node.post_id === null) {
        return 0;
    }
    return controversyMap[String(node.post_id)] || 0;
}

function nodeRadius(node, totalLeaves, voteScales) {
    const base = baseNodeRadius(node, totalLeaves);
    if (!voteScales || !node || node.post_id === undefined || node.post_id === null) {
        return base;
    }
    const scale = voteScales[String(node.post_id)];
    return typeof scale === 'number' ? base * scale : base;
}

function labelProps(node) {
    if (node.kind === 'root') {
        return {
            transform: '',
            x: 16,
            y: -16,
            textAnchor: 'start'
        };
    }
    const angleDegrees = ((node.angle * 180) / Math.PI) - 90;
    const flipped = node.angle > Math.PI;
    return {
        transform: 'rotate(' + (flipped ? angleDegrees + 180 : angleDegrees) + ')',
        x: flipped ? -14 : 14,
        y: 4,
        textAnchor: flipped ? 'end' : 'start'
    };
}

function nodeCladeColor(node, cladeColors) {
    if (!node || !node.topClusterId) {
        return null;
    }
    return cladeColors[node.topClusterId] || null;
}

// The clade palette above is DATA — which clade a node belongs to — so it stays
// fixed across themes. These fallbacks are chrome: the trunk and the root node,
// which were a hardcoded near-black and vanished against a dark page. They are
// applied as SVG fill/stroke attributes, so `currentColor` resolves to whatever
// text colour the active theme sets on the page.
const TREE_STRUCTURAL_COLOR = 'currentColor';

function branchStrokeColor(source, target, cladeColors) {
    return nodeCladeColor(target, cladeColors)
        || nodeCladeColor(source, cladeColors)
        || TREE_STRUCTURAL_COLOR;
}

function displayNodeColor(node, cladeColors) {
    if (!node) {
        return TREE_STRUCTURAL_COLOR;
    }
    if (node.kind === 'root') {
        return TREE_STRUCTURAL_COLOR;
    }
    return nodeCladeColor(node, cladeColors) || node.color;
}

export default function ThreadSemanticTree(props) {
    const svgRef = useRef(null);
    const zoomBehaviorRef = useRef(null);
    const d3SelectionRef = useRef(null);
    const onFilterChangeRef = useRef(props.onFilterChange);
    const [viewport, setViewport] = useState({x: 0, y: 0, k: 1});
    const [isDraggingViewport, setIsDraggingViewport] = useState(false);
    const [hoveredNodeId, setHoveredNodeId] = useState(null);
    const [pinnedNodeId, setPinnedNodeId] = useState(null);

    const analysis = useMemo(function () {
        return props.analysis || buildSemanticThreadGraph(props.posts || []);
    }, [props.analysis, props.posts]);

    // Node size follows each post's score relative to the rest of the thread.
    // Keyed off props.posts (not the analysis) so a vote resizes its dot without
    // recomputing the TF-IDF graph.
    const voteScales = useMemo(function () {
        return buildVoteScaleMap(props.posts || []);
    }, [props.posts]);

    // How contested each post is, which drives node SHAPE (size stays on score).
    const controversyMap = useMemo(function () {
        return buildControversyMap(props.posts || []);
    }, [props.posts]);

    const commentNodeMap = useMemo(function () {
        const mapped = {};
        analysis.documents.forEach(function (document) {
            mapped['comment-' + document.id] = document;
        });
        return mapped;
    }, [analysis]);

    const currentLayout = useMemo(function () {
        return layoutTree(analysis.tree, new Set());
    }, [analysis]);

    useEffect(function () {
        setPinnedNodeId(function (previous) {
            if (!previous || currentLayout.nodeMap[previous]) {
                return previous;
            }
            return null;
        });
    }, [currentLayout]);

    const cladeColors = useMemo(function () {
        const nextColors = {};
        currentLayout.nodes
            .filter(function (node) {
                return node.band;
            })
            .sort(function (left, right) {
                return left.startAngle - right.startAngle;
            })
            .forEach(function (node, index) {
                nextColors[node.id] = CLADE_PALETTE[index % CLADE_PALETTE.length];
            });
        return nextColors;
    }, [currentLayout]);

    useEffect(function () {
        onFilterChangeRef.current = props.onFilterChange;
    }, [props.onFilterChange]);

    useEffect(function () {
        return function () {
            if (onFilterChangeRef.current) {
                onFilterChangeRef.current(null);
            }
        };
    }, []);

    useEffect(function () {
        let mounted = true;
        loadD3().then(function (d3) {
            if (!mounted || !d3 || !svgRef.current) {
                return;
            }
            const selectionHandle = d3.select(svgRef.current);
            const zoom = d3.zoom()
                .scaleExtent([0.55, 4.5])
                .filter(function (event) {
                    if (event.type === 'wheel') {
                        return true;
                    }
                    if (event.type === 'mousedown') {
                        return event.button === 0 && !event.shiftKey;
                    }
                    return event.type === 'touchstart' || event.type === 'touchmove';
                })
                .on('start', function (event) {
                    if (event.sourceEvent && event.sourceEvent.type === 'mousedown') {
                        setIsDraggingViewport(true);
                    }
                })
                .on('zoom', function (event) {
                    setViewport({
                        x: event.transform.x,
                        y: event.transform.y,
                        k: event.transform.k
                    });
                })
                .on('end', function (event) {
                    if (event.sourceEvent && event.sourceEvent.type === 'mousedown') {
                        setIsDraggingViewport(false);
                    }
                });
            selectionHandle.call(zoom);
            selectionHandle.on('dblclick.zoom', null);
            zoomBehaviorRef.current = zoom;
            d3SelectionRef.current = selectionHandle;
        });
        return function () {
            mounted = false;
            if (d3SelectionRef.current) {
                d3SelectionRef.current.on('.zoom', null);
            }
        };
    }, []);

    function clearFocus() {
        setPinnedNodeId(null);
        setHoveredNodeId(null);
    }

    function focusNode(nodeId) {
        setPinnedNodeId(function (previous) {
            return previous === nodeId ? null : nodeId;
        });
    }

    function buildNodeSelection(nodeIds) {
        const uniqueNodeIds = uniqueValues((nodeIds || []).filter(function (nodeId) {
            return !!currentLayout.nodeMap[nodeId];
        }));
        if (!uniqueNodeIds.length) {
            return null;
        }
        const nodes = uniqueNodeIds.map(function (nodeId) {
            return currentLayout.nodeMap[nodeId];
        }).filter(Boolean);
        const commentIds = uniqueValues(uniqueNodeIds.reduce(function (accumulator, nodeId) {
            return accumulator.concat(currentLayout.descendantCommentIds[nodeId] || []);
        }, []));
        const keywords = uniqueValues(nodes.reduce(function (accumulator, node) {
            return accumulator.concat(node.keywords || []);
        }, [])).slice(0, 8);
        const sentimentProfile = commentIds.length
            ? averageSentimentProfiles(commentIds.map(function (commentNodeId) {
                const document = commentNodeMap[commentNodeId];
                return document ? document.sentimentProfile : null;
            }).filter(Boolean))
            : null;
        const sentiment = commentIds.length
            ? commentIds.reduce(function (total, commentNodeId) {
                const document = commentNodeMap[commentNodeId];
                return total + (document ? document.sentiment : 0);
            }, 0) / commentIds.length
            : (
                nodes.length
                    ? nodes.reduce(function (total, node) {
                        return total + (node.sentiment || 0);
                    }, 0) / nodes.length
                    : 0
            );
        return {
            nodeIds: uniqueNodeIds,
            commentIds: commentIds,
            keywords: keywords,
            sentiment: sentiment,
            sentimentProfile: sentimentProfile,
            nodes: nodes,
            label: summarizeNodeSet(nodes),
            summary: nodes.length === 1
                ? nodes[0].summary
                : summarizeSelection(commentIds.length, keywords, sentiment, sentimentProfile)
        };
    }

    const pinnedSelection = useMemo(function () {
        return pinnedNodeId ? buildNodeSelection([pinnedNodeId]) : null;
    }, [pinnedNodeId, currentLayout, commentNodeMap]);

    const hoverSelection = useMemo(function () {
        return hoveredNodeId ? buildNodeSelection([hoveredNodeId]) : null;
    }, [hoveredNodeId, currentLayout, commentNodeMap]);

    const scrollSelection = useMemo(function () {
        if (!props.scrollFocusPostId) {
            return null;
        }
        return buildNodeSelection(['comment-' + props.scrollFocusPostId]);
    }, [props.scrollFocusPostId, currentLayout, commentNodeMap]);

    const activeCommentDocument = useMemo(function () {
        function selectionComment(selection) {
            if (!selection || !selection.nodes || selection.nodes.length !== 1) {
                return null;
            }
            const node = selection.nodes[0];
            if (node.kind !== 'comment' && node.kind !== 'op') {
                return null;
            }
            return commentNodeMap[node.id] || null;
        }

        const hoveredComment = selectionComment(hoverSelection);
        if (hoveredComment) {
            return hoveredComment;
        }

        const pinnedComment = selectionComment(pinnedSelection);
        if (pinnedComment) {
            return pinnedComment;
        }

        const scrollNodeId = props.scrollFocusPostId ? ('comment-' + props.scrollFocusPostId) : null;
        if (scrollNodeId && commentNodeMap[scrollNodeId]) {
            if (!pinnedSelection || !pinnedSelection.commentIds.length || pinnedSelection.commentIds.indexOf(scrollNodeId) !== -1) {
                return commentNodeMap[scrollNodeId];
            }
        }

        if (pinnedSelection && pinnedSelection.commentIds.length) {
            return commentNodeMap[pinnedSelection.commentIds[0]] || null;
        }

        if (scrollNodeId) {
            return commentNodeMap[scrollNodeId] || null;
        }

        return null;
    }, [hoverSelection, pinnedSelection, props.scrollFocusPostId, commentNodeMap]);

    const highlightNodeIds = new Set(
        uniqueValues(
            []
                .concat(pinnedSelection ? pinnedSelection.nodeIds : [])
                .concat(pinnedSelection ? pinnedSelection.commentIds : [])
                .concat(hoverSelection ? hoverSelection.nodeIds : [])
                .concat(hoverSelection ? hoverSelection.commentIds : [])
                .concat(scrollSelection ? scrollSelection.nodeIds : [])
                .concat(scrollSelection ? scrollSelection.commentIds : [])
        )
    );
    const highlightCommentIds = new Set(
        uniqueValues(
            []
                .concat(pinnedSelection ? pinnedSelection.commentIds : [])
                .concat(hoverSelection ? hoverSelection.commentIds : [])
                .concat(scrollSelection ? scrollSelection.commentIds : [])
        )
    );

    const activeFilteredComments = pinnedSelection && pinnedSelection.commentIds.length
        ? pinnedSelection.commentIds
        : [];
    const activeFilteredPosts = uniqueValues(activeFilteredComments.map(function (commentNodeId) {
        const document = commentNodeMap[commentNodeId];
        return document ? document.postId : null;
    }).filter(function (postId) {
        return postId !== null;
    }));
    const activeFilterLabel = pinnedSelection ? pinnedSelection.label : null;
    const activeFilterSummary = pinnedSelection ? pinnedSelection.summary : null;
    const activeFilterKeywords = pinnedSelection && pinnedSelection.keywords
        ? pinnedSelection.keywords
        : analysis.summary.keywords;
    const activeFilterSentiment = pinnedSelection && pinnedSelection.commentIds.length
        ? pinnedSelection.sentiment
        : analysis.summary.sentiment;
    const activeFilterSentimentProfile = pinnedSelection && pinnedSelection.commentIds.length
        ? pinnedSelection.sentimentProfile
        : analysis.summary.sentiment_profile;
    const activeCommentBigrams = activeCommentDocument && activeCommentDocument.sentimentBigrams
        ? activeCommentDocument.sentimentBigrams
        : [];
    const activeBigramChart = useMemo(function () {
        return buildBigramChartData(activeCommentBigrams, props.docked);
    }, [activeCommentBigrams, props.docked]);

    useEffect(function () {
        if (!props.onFilterChange) {
            return;
        }
        if (!activeFilteredPosts.length) {
            props.onFilterChange(null);
            return;
        }
        props.onFilterChange({
            postIds: activeFilteredPosts,
            label: activeFilterLabel || 'Selection',
            summary: activeFilterSummary || summarizeSelection(
                activeFilteredPosts.length,
                activeFilterKeywords,
                activeFilterSentiment,
                activeFilterSentimentProfile
            ),
            sentiment: activeFilterSentiment
        });
    }, [
        props.onFilterChange,
        activeFilteredPosts,
        activeFilterLabel,
        activeFilterSummary,
        activeFilterKeywords,
        activeFilterSentiment,
        activeFilterSentimentProfile
    ]);
    const clusterBandNodes = currentLayout.nodes.filter(function (node) {
        return node.kind === 'cluster' && node.band && !node.collapsed;
    });
    const commentLeafNodes = currentLayout.visibleLeafNodes.filter(function (node) {
        return node.kind === 'comment';
    });
    const compactLeafLabels = commentLeafNodes.length > 110;

    function handleTreeBackgroundClick(event) {
        if (event.target && typeof event.target.closest === 'function' && event.target.closest('[data-semantic-node="true"]')) {
            return;
        }
        clearFocus();
    }

    return (
        <section className={'semantic-thread-shell semantic-thread-shell--tree-only' + (props.docked ? ' semantic-thread-shell--rail' : '')}>
          <div className="semantic-card semantic-card--tree-only">
            <div className="semantic-svg-shell semantic-svg-shell--tree-only">
                  <svg
                    ref={svgRef}
                    className="semantic-svg"
                    viewBox={'0 0 ' + VIEWBOX_SIZE + ' ' + VIEWBOX_SIZE}
                    style={{cursor: isDraggingViewport ? 'grabbing' : 'grab'}}
                    onClick={handleTreeBackgroundClick}
                    onMouseLeave={function () {
                        setHoveredNodeId(null);
                    }}
                  >
                    <g transform={'translate(' + (HALF_VIEWBOX + viewport.x) + ' ' + (HALF_VIEWBOX + viewport.y) + ') scale(' + viewport.k + ')'}>
                      <g className="semantic-cluster-band-layer">
                        {clusterBandNodes.map(function (clusterNode) {
                            const band = bandPath(
                                CLUSTER_BAND_INNER_RADIUS,
                                CLUSTER_BAND_OUTER_RADIUS,
                                clusterNode.startAngle,
                                clusterNode.endAngle
                            );
                            if (!band) {
                                return null;
                            }
                            return (
                                <path
                                  key={clusterNode.id}
                                  className={'semantic-cluster-band' + (highlightNodeIds.has(clusterNode.id) ? ' semantic-cluster-band--active' : '')}
                                  d={band}
                                  fill={cladeColors[clusterNode.id] || clusterNode.color}
                                  data-semantic-node="true"
                                  onMouseEnter={function () {
                                      setHoveredNodeId(clusterNode.id);
                                  }}
                                  onMouseLeave={function () {
                                      setHoveredNodeId(null);
                                  }}
                                  onClick={function (event) {
                                      event.stopPropagation();
                                      focusNode(clusterNode.id);
                                  }}
                                />
                            );
                        })}
                      </g>

                      {currentLayout.edges.map(function (edge) {
                          const source = currentLayout.nodeMap[edge.source];
                          const target = currentLayout.nodeMap[edge.target];
                          if (!source || !target) {
                              return null;
                          }
                          const highlighted = highlightNodeIds.has(target.id) || target.commentIds.some(function (commentId) {
                              return highlightCommentIds.has(commentId);
                          });
                          const path = branchPath(source, target);
                          const branchColor = branchStrokeColor(source, target, cladeColors);
                          return (
                              <g key={edge.id}>
                                <path
                                  className={'semantic-lineage semantic-lineage--' + target.kind + (highlighted ? ' semantic-lineage--active' : '')}
                                  d={path}
                                />
                                <path
                                  className={'semantic-branch semantic-branch--' + target.kind + (highlighted ? ' semantic-branch--active' : '')}
                                  d={path}
                                  stroke={branchColor}
                                  data-semantic-node="true"
                                  onMouseEnter={function () {
                                      setHoveredNodeId(target.id);
                                  }}
                                  onMouseLeave={function () {
                                      setHoveredNodeId(null);
                                  }}
                                  onClick={function (event) {
                                      event.stopPropagation();
                                      focusNode(target.id);
                                  }}
                                />
                              </g>
                          );
                      })}

                      {commentLeafNodes.map(function (node) {
                          const highlighted = highlightCommentIds.has(node.id) || highlightNodeIds.has(node.id);
                          const guideEnd = polarPoint(node.angle, TREE_OUTER_GUIDE_RADIUS);
                          return (
                              <line
                                key={'guide-' + node.id}
                                className={'semantic-leaf-guide' + (highlighted ? ' semantic-leaf-guide--active' : '')}
                                x1={node.x}
                                y1={node.y}
                                x2={guideEnd.x}
                                y2={guideEnd.y}
                              />
                          );
                      })}

                      {currentLayout.nodes.map(function (node) {
                          const highlighted = highlightNodeIds.has(node.id) || node.commentIds.some(function (commentId) {
                              return highlightCommentIds.has(commentId);
                          });
                          const radius = nodeRadius(node, currentLayout.visibleLeafNodes.length, voteScales);
                          const nodeLabelProps = labelProps(node);
                          const nodeFill = displayNodeColor(node, cladeColors);
                          // Shape = how contested; radius = net score. Two
                          // independent readings of the same dot.
                          const controversy = nodeControversy(node, controversyMap);
                          const shapeClass =
                              controversy >= CONTROVERSY_CONTESTED ? ' semantic-node--contested'
                              : controversy >= CONTROVERSY_CALM ? ' semantic-node--divided'
                              : '';
                          const nodeClassName =
                              'semantic-node semantic-node--' + node.kind +
                              (node.leaf ? ' semantic-node--leaf' : ' semantic-node--internal') +
                              (highlighted ? ' semantic-node--active' : '') +
                              shapeClass;
                          const nodeHandlers = {
                              fill: nodeFill,
                              'data-semantic-node': 'true',
                              onMouseEnter: function () { setHoveredNodeId(node.id); },
                              onMouseLeave: function () { setHoveredNodeId(null); },
                              onClick: function (event) {
                                  event.stopPropagation();
                                  focusNode(node.id);
                              },
                          };
                          return (
                              <g key={node.id} transform={'translate(' + node.x + ' ' + node.y + ')'}>
                                {controversy < CONTROVERSY_CALM && (
                                  <circle className={nodeClassName} r={radius} {...nodeHandlers}/>
                                )}
                                {controversy >= CONTROVERSY_CALM && controversy < CONTROVERSY_CONTESTED && (
                                  // Divided: a diamond — still compact, but the
                                  // corners break the circle's calm at a glance.
                                  <polygon
                                    className={nodeClassName}
                                    points={burstPoints(radius * 1.35, 2, 0.62)}
                                    {...nodeHandlers}/>
                                )}
                                {controversy >= CONTROVERSY_CONTESTED && (
                                  // Contested: a spiked burst. Deliberately the
                                  // loudest shape on the tree.
                                  <polygon
                                    className={nodeClassName}
                                    points={burstPoints(radius * 1.7, 5, 0.45)}
                                    {...nodeHandlers}/>
                                )}
                                {node.kind === 'cluster' && node.collapsed && (
                                    <text
                                      className="semantic-node-label"
                                      transform={nodeLabelProps.transform}
                                      x={nodeLabelProps.x}
                                      y={nodeLabelProps.y}
                                      textAnchor={nodeLabelProps.textAnchor}
                                    >
                                      {node.label}
                                      {node.collapsed ? ' +' : ''}
                                    </text>
                                )}
                              </g>
                          );
                      })}

                      {commentLeafNodes.map(function (node) {
                          const highlighted = highlightCommentIds.has(node.id) || highlightNodeIds.has(node.id);
                          const textProps = radialTextProps(node.angle, LEAF_LABEL_RADIUS);
                          const compactLabel = node.label.split(' ')[0];
                          return (
                              <text
                                key={'label-' + node.id}
                                className={'semantic-leaf-label' + (highlighted ? ' semantic-leaf-label--active' : '')}
                                x={textProps.x}
                                y={textProps.y}
                                dx={textProps.dx}
                                dy="0.32em"
                                textAnchor={textProps.textAnchor}
                                transform={textProps.transform}
                              >
                                {compactLeafLabels ? compactLabel : node.label}
                              </text>
                          );
                      })}
                    </g>
                  </svg>
            </div>
            <section className="semantic-bigram-panel">
              <div className="semantic-bigram-panel__header">
                <h3>
                  {activeCommentDocument
                      ? ('Comment #' + activeCommentDocument.postId + ' sentiment by bigram')
                      : 'Highlighted comment sentiment'}
                </h3>
                {activeCommentDocument && (
                    <span className="semantic-bigram-panel__tone">
                      {activeCommentDocument.sentimentTone || describeSelectionTone(activeCommentDocument.sentiment, activeCommentDocument.sentimentProfile)}
                    </span>
                )}
              </div>
              {activeCommentDocument && activeBigramChart.segments.length > 0 && (
                  <div className="semantic-bigram-chart">
                    <div className="semantic-bigram-chart__axis-label">Bigram sentiment stack</div>
                    <div className="semantic-bigram-chart__layout">
                      <div className="semantic-bigram-chart__stack-wrap">
                        <div className="semantic-bigram-chart__stack-label">Highlighted comment</div>
                        <div className="semantic-bigram-chart__stack">
                          {activeBigramChart.segments.map(function (segment) {
                              return (
                                  <span
                                    key={segment.id}
                                    className="semantic-bigram-chart-segment"
                                    style={Object.assign({
                                        width: segment.percent + '%'
                                    }, segment.fillStyle)}
                                    title={
                                        segment.label +
                                        ' • ' +
                                        segment.tone +
                                        ' • ' +
                                        segment.dominantDimension +
                                        ' • ' +
                                        segment.percent.toFixed(1) +
                                        '%'
                                    }
                                  />
                              );
                          })}
                        </div>
                        <div className="semantic-bigram-chart-axis">
                          <div className="semantic-bigram-chart-axis__ticks">
                            <span>0</span>
                            <span>25</span>
                            <span>50</span>
                            <span>75</span>
                            <span>100%</span>
                          </div>
                        </div>
                      </div>
                    </div>
                  </div>
              )}
              {activeCommentDocument && !activeBigramChart.segments.length && (
                  <p className="semantic-bigram-empty">
                    This comment does not have enough sentiment-bearing word pairs to chart.
                  </p>
              )}
              {!activeCommentDocument && (
                  <p className="semantic-bigram-empty">
                    Scroll the thread or hover a comment node to inspect its bigram sentiment.
                  </p>
              )}
            </section>
          </div>
        </section>
    );
}
