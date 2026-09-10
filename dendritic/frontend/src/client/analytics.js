'use strict';

const ENDPOINT = '/events';
const CONSENT_ENDPOINT = '/analytics/consent';
const BATCH_SIZE = 20;
const FLUSH_MS = 5000;
const IDLE_MS = 45000;
const RETRY_KEY = 'maniwani.analytics.pending.v1';

let consent = null;
let pending = [];
let flushTimer = null;
let lastActivity = Date.now();
let activeStarted = null;
const pageLoadedAt = Date.now();
let totalActiveMs = 0;
let visibleStarted = document.visibilityState === 'visible' ? Date.now() : null;
let totalVisibleMs = 0;
let maxScrollRatio = 0;

function uuid() {
    if (window.crypto && typeof window.crypto.randomUUID === 'function') return window.crypto.randomUUID();
    const bytes = new Uint8Array(16);
    window.crypto.getRandomValues(bytes);
    bytes[6] = (bytes[6] & 15) | 64;
    bytes[8] = (bytes[8] & 63) | 128;
    return Array.from(bytes).map((b, i) => ([4, 6, 8, 10].indexOf(i) >= 0 ? '-' : '') + b.toString(16).padStart(2, '0')).join('');
}

function sessionId() {
    let value = sessionStorage.getItem('maniwani.analytics.session.v1');
    if (!value) {
        value = uuid();
        sessionStorage.setItem('maniwani.analytics.session.v1', value);
    }
    return value;
}

function browserFamily() {
    const ua = navigator.userAgent || '';
    if (/Firefox\//.test(ua)) return 'Firefox';
    if (/Edg\//.test(ua)) return 'Edge';
    if (/Chrom(e|ium)\//.test(ua)) return 'Chromium';
    if (/Safari\//.test(ua)) return 'Safari';
    return 'Other';
}

function viewportClass() {
    if (window.innerWidth < 576) return 'mobile';
    if (window.innerWidth < 992) return 'tablet';
    if (window.innerWidth < 1440) return 'desktop';
    return 'desktop_large';
}

function surface() {
    return document.body.getAttribute('data-analytics-surface') || location.pathname.split('/').filter(Boolean)[0] || 'home';
}

function baseEvent(name, fields) {
    const extra = fields || {};
    return Object.assign({
        event_id: uuid(),
        event_name: name,
        event_version: 1,
        event_time: new Date().toISOString(),
        anonymous_id: consent.anonymous_id,
        session_id: sessionId(),
        page_id: (location.pathname.slice(0, 64).replace(/[^A-Za-z0-9_.:-]+/g, '_').replace(/^_+|_+$/g, '') || 'home'),
        surface: extra.surface || surface(),
        experiment_ids: [],
        client: {
            platform: 'web',
            app_version: 'phase5',
            browser_family: browserFamily(),
            viewport_class: viewportClass()
        },
        context: {
            authenticated: document.body.getAttribute('data-analytics-authenticated') === 'true',
            focused: document.hasFocus(),
            visible: document.visibilityState === 'visible',
            idle: Date.now() - lastActivity >= IDLE_MS
        },
        properties: {},
        consent: {
            analytics: true,
            personalization: !!consent.personalization,
            policy_version: consent.policy_version
        }
    }, extra);
}

function persistPending() {
    if (!consent || !consent.analytics) return;
    try { localStorage.setItem(RETRY_KEY, JSON.stringify(pending.slice(-100))); } catch (error) { /* quota/privacy mode */ }
}

function track(name, fields) {
    if (!consent || !consent.analytics) return false;
    const configuredRates = window._ANALYTICS_SAMPLE_RATES || {};
    const rate = Object.prototype.hasOwnProperty.call(configuredRates, name) ? Number(configuredRates[name]) : 1;
    if (!Number.isFinite(rate) || rate <= 0 || (rate < 1 && Math.random() >= rate)) return false;
    pending.push(baseEvent(name, fields));
    persistPending();
    if (pending.length >= BATCH_SIZE) flush(false);
    return true;
}

function flush(beacon) {
    if (!consent || !consent.analytics || pending.length === 0) return Promise.resolve(false);
    const events = pending.splice(0, BATCH_SIZE);
    persistPending();
    const body = JSON.stringify({events: events});
    if (beacon && navigator.sendBeacon) {
        const accepted = navigator.sendBeacon(ENDPOINT, new Blob([body], {type: 'application/json'}));
        if (!accepted) pending = events.concat(pending);
        persistPending();
        return Promise.resolve(accepted);
    }
    return fetch(ENDPOINT, {method: 'POST', credentials: 'same-origin', headers: {'Content-Type': 'application/json'}, body: body})
        .then((response) => {
            if (!response.ok && response.status !== 409) throw new Error('analytics delivery failed');
            persistPending();
            if (pending.length) window.setTimeout(() => flush(false), 0);
            return true;
        })
        .catch(() => {
            pending = events.concat(pending).slice(-100);
            persistPending();
            return false;
        });
}

function restorePending() {
    try {
        const saved = JSON.parse(localStorage.getItem(RETRY_KEY) || '[]');
        if (Array.isArray(saved)) pending = saved.slice(-100);
    } catch (error) { pending = []; }
}

function contentFields(element, properties) {
    const rawPosition = element.getAttribute('data-recommendation-position') || element.getAttribute('data-analytics-position');
    const experimentIds = (element.getAttribute('data-recommendation-experiments') || '').split(',').filter(Boolean).slice(0, 20);
    const eventProperties = Object.assign({}, properties || {});
    const propensity = Number(element.getAttribute('data-recommendation-propensity'));
    if (Number.isFinite(propensity) && propensity > 0) eventProperties.exploration_propensity = propensity;
    return {
        surface: element.getAttribute('data-analytics-surface') || surface(),
        content_type: element.getAttribute('data-analytics-content-type'),
        content_id: element.getAttribute('data-analytics-content-id'),
        position: rawPosition !== null && rawPosition !== '' && Number.isFinite(Number(rawPosition)) ? Number(rawPosition) : undefined,
        request_id: element.getAttribute('data-recommendation-request-id') || undefined,
        model_id: element.getAttribute('data-recommendation-model-id') || undefined,
        experiment_ids: experimentIds,
        properties: eventProperties
    };
}

function wireSatisfactionPrompt() {
    const source = document.querySelector('[data-recommendation-satisfaction-prompt="true"]');
    if (!source || document.getElementById('recommendation-satisfaction-prompt')) return;
    const requestId = source.getAttribute('data-recommendation-request-id');
    if (!requestId) return;
    const prompt = document.createElement('aside');
    prompt.id = 'recommendation-satisfaction-prompt';
    prompt.setAttribute('role', 'dialog');
    prompt.setAttribute('aria-label', 'Recommendation satisfaction');
    prompt.style.cssText = 'position:fixed;right:16px;bottom:16px;z-index:1050;background:#fff;color:#222;border:1px solid #bbb;border-radius:6px;padding:12px;box-shadow:0 3px 14px rgba(0,0,0,.25);max-width:320px';
    const label = document.createElement('div');
    label.textContent = 'How useful were these recommendations?';
    label.style.marginBottom = '8px';
    prompt.appendChild(label);
    [1, 2, 3, 4, 5].forEach((rating) => {
        const button = document.createElement('button');
        button.type = 'button';
        button.className = 'btn btn-sm btn-outline-secondary mr-1';
        button.textContent = String(rating);
        button.setAttribute('aria-label', rating + ' out of 5');
        button.addEventListener('click', () => {
            fetch('/api/v1/recommendations/satisfaction', {
                method: 'POST', credentials: 'same-origin', headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({request_id: requestId, rating: rating})
            }).then(() => prompt.remove()).catch(() => {});
        });
        prompt.appendChild(button);
    });
    document.body.appendChild(prompt);
}

function observeContent() {
    if (!window.IntersectionObserver) return;
    const timers = new WeakMap();
    const seen = new WeakSet();
    const enteredAt = new WeakMap();
    const observer = new IntersectionObserver((entries) => {
        entries.forEach((entry) => {
            const element = entry.target;
            if (entry.intersectionRatio >= 0.5 && !seen.has(element)) {
                if (!timers.has(element)) timers.set(element, window.setTimeout(() => {
                    timers.delete(element);
                    seen.add(element);
                    enteredAt.set(element, Date.now());
                    const type = element.getAttribute('data-analytics-content-type');
                    track(type + '_impression', contentFields(element, {visible_ratio: entry.intersectionRatio, visible_ms: 500}));
                    if (element.getAttribute('data-recommendation-request-id')) {
                        track('recommendation_impression', contentFields(element, {visible_ratio: entry.intersectionRatio, visible_ms: 500}));
                    }
                    track('content_entered_viewport', contentFields(element, {visible_ratio: entry.intersectionRatio}));
                }, 500));
            } else if (timers.has(element)) {
                window.clearTimeout(timers.get(element));
                timers.delete(element);
            } else if (seen.has(element) && !entry.isIntersecting) {
                const visibleMs = enteredAt.has(element) ? Date.now() - enteredAt.get(element) : 0;
                enteredAt.delete(element);
                track('content_left_viewport', contentFields(element, {
                    visible_ratio: 0,
                    content_visible_ms: visibleMs,
                    engaged_ms: document.hasFocus() && Date.now() - lastActivity < IDLE_MS ? visibleMs : 0,
                    scroll_ratio: maxScrollRatio
                }));
            }
        });
    }, {threshold: [0, 0.5]});
    document.querySelectorAll('[data-analytics-content-type][data-analytics-content-id]').forEach((element) => observer.observe(element));
    const mutations = new MutationObserver((records) => records.forEach((record) => record.addedNodes.forEach((node) => {
        if (node.nodeType !== 1) return;
        if (node.matches && node.matches('[data-analytics-content-type][data-analytics-content-id]')) observer.observe(node);
        if (node.querySelectorAll) node.querySelectorAll('[data-analytics-content-type][data-analytics-content-id]').forEach((element) => observer.observe(element));
    })));
    mutations.observe(document.body, {childList: true, subtree: true});
}

function wireMedia() {
    const started = new WeakSet();
    document.addEventListener('play', (event) => {
        if (event.target.tagName === 'VIDEO') {
            const name = started.has(event.target) ? 'video_resumed' : 'video_started';
            started.add(event.target);
            track(name, contentFields(event.target.closest('[data-analytics-content-id]') || event.target, {user_initiated: !!event.isTrusted}));
        }
    }, true);
    document.addEventListener('pause', (event) => {
        if (event.target.tagName === 'VIDEO' && !event.target.ended) track('video_paused', contentFields(event.target.closest('[data-analytics-content-id]') || event.target, {playback_seconds: event.target.currentTime || 0}));
    }, true);
    document.addEventListener('ended', (event) => {
        if (event.target.tagName === 'VIDEO') track('video_completed', contentFields(event.target.closest('[data-analytics-content-id]') || event.target, {progress_ratio: 1, playback_seconds: event.target.duration || 0}));
    }, true);
    document.addEventListener('seeked', (event) => {
        if (event.target.tagName === 'VIDEO') track('video_seeked', contentFields(event.target.closest('[data-analytics-content-id]') || event.target, {playback_seconds: event.target.currentTime || 0}));
    }, true);
    document.addEventListener('volumechange', (event) => {
        if (event.target.tagName === 'VIDEO') track(event.target.muted ? 'video_muted' : 'video_unmuted', contentFields(event.target.closest('[data-analytics-content-id]') || event.target));
    }, true);
    document.addEventListener('ratechange', (event) => {
        if (event.target.tagName === 'VIDEO') track('playback_speed_changed', contentFields(event.target.closest('[data-analytics-content-id]') || event.target, {playback_rate: event.target.playbackRate}));
    }, true);
    document.addEventListener('click', (event) => {
        const item = event.target.closest ? event.target.closest('[data-analytics-content-type="image"]') : null;
        if (item) track('image_clicked', contentFields(item, {interaction_type: 'open'}));
    }, true);
    document.addEventListener('fullscreenchange', () => {
        track(document.fullscreenElement ? 'fullscreen_entered' : 'fullscreen_exited');
    });
}

function wireInteractions() {
    const replyStarted = new WeakSet();
    document.addEventListener('focusin', (event) => {
        if (event.target.matches && event.target.matches('textarea[name="body"]') && !replyStarted.has(event.target)) {
            replyStarted.add(event.target);
            track('reply_started', {
                content_type: window._THREAD ? 'thread' : undefined,
                content_id: window._THREAD ? String(window._THREAD) : undefined,
                properties: {interaction_type: 'compose'}
            });
        }
    });
    document.addEventListener('click', (event) => {
        const link = event.target.closest ? event.target.closest('a[href]') : null;
        if (!link || !link.href || link.href.indexOf('javascript:') === 0) return;
        if (link.getAttribute('data-recommendation-request-id')) {
            track('recommendation_clicked', contentFields(link, {interaction_type: 'open'}));
        }
        let destination;
        try { destination = new URL(link.href, location.href); } catch (error) { return; }
        track(destination.origin === location.origin ? 'internal_navigation' : 'external_navigation', {
            properties: {source_category: destination.origin === location.origin ? 'same_origin' : 'external'}
        });
    }, true);
}

function startAttention() {
    activeStarted = Date.now();
    track('active_dwell_started');
    ['pointerdown', 'keydown', 'scroll', 'touchstart'].forEach((name) => window.addEventListener(name, () => {
        const wasIdle = Date.now() - lastActivity >= IDLE_MS;
        lastActivity = Date.now();
        if (wasIdle) { track('window_active'); activeStarted = lastActivity; track('active_dwell_started'); }
        const scrollable = Math.max(1, document.documentElement.scrollHeight - window.innerHeight);
        maxScrollRatio = Math.max(maxScrollRatio, Math.min(1, window.scrollY / scrollable));
    }, {passive: true}));
    window.setInterval(() => {
        if (Date.now() - lastActivity >= IDLE_MS && activeStarted) {
            track('window_idle');
            totalActiveMs += Date.now() - activeStarted;
            track('active_dwell_stopped', {properties: {active_ms: Date.now() - activeStarted}});
            activeStarted = null;
        }
    }, 5000);
    document.addEventListener('visibilitychange', () => {
        const visible = document.visibilityState === 'visible';
        track(visible ? 'page_visible' : 'page_hidden');
        if (visible) { visibleStarted = Date.now(); activeStarted = Date.now(); track('active_dwell_started'); }
        else {
            if (visibleStarted) { totalVisibleMs += Date.now() - visibleStarted; visibleStarted = null; }
            if (activeStarted) { totalActiveMs += Date.now() - activeStarted; track('active_dwell_stopped', {properties: {active_ms: Date.now() - activeStarted}}); activeStarted = null; }
            flush(true);
        }
    });
    window.addEventListener('focus', () => track('tab_focused'));
    window.addEventListener('blur', () => track('tab_blurred'));
    window.addEventListener('pagehide', () => {
        if (visibleStarted) totalVisibleMs += Date.now() - visibleStarted;
        if (activeStarted) totalActiveMs += Date.now() - activeStarted;
        track('page_exit', {properties: {
            loaded_ms: Date.now() - pageLoadedAt,
            visible_ms: totalVisibleMs,
            active_ms: totalActiveMs,
            engaged_ms: Math.min(totalVisibleMs, totalActiveMs),
            scroll_ratio: maxScrollRatio
        }});
        flush(true);
    });
}

function initialize() {
    return fetch(CONSENT_ENDPOINT, {credentials: 'same-origin'})
        .then((response) => response.json())
        .then((value) => {
            consent = value;
            if (!consent.analytics || !consent.anonymous_id) {
                try { localStorage.removeItem(RETRY_KEY); } catch (error) { /* privacy mode */ }
                return;
            }
            restorePending();
            track('session_start');
            track('page_view');
            if (document.referrer) {
                let category = 'external';
                try { if (new URL(document.referrer).origin === location.origin) category = 'same_origin'; } catch (error) { category = 'unknown'; }
                track('referrer_received', {properties: {source_category: category}});
            }
            if (window._THREAD) track('thread_opened', {content_type: 'thread', content_id: String(window._THREAD)});
            observeContent();
            wireSatisfactionPrompt();
            wireMedia();
            wireInteractions();
            startAttention();
            flushTimer = window.setInterval(() => flush(false), FLUSH_MS);
        })
        .catch(() => {});
}

window.maniwaniAnalytics = {track: track, flush: flush, ready: initialize()};
