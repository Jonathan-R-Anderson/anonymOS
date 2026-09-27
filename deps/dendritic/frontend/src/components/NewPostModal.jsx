import React, { useState, useEffect, useRef } from 'react';
import { connect } from 'react-redux';
import { NewPostForm } from './PostForm';

const OPEN_REPLY_BOX_EVENT = 'maniwani:open-reply-box';
const MOBILE_BREAKPOINT = 768;
const WINDOW_MARGIN = 12;
const DEFAULT_WIDTH = 420;
const DEFAULT_HEIGHT = 520;


function buildAction(threadId) {
    return '/threads/' + threadId + '/new';
}

function clamp(value, min, max) {
    return Math.min(Math.max(value, min), max);
}

function defaultPosition() {
    if(typeof window === 'undefined') {
        return {x: WINDOW_MARGIN, y: 88};
    }
    const windowWidth = window.innerWidth;
    const boxWidth = windowWidth < MOBILE_BREAKPOINT
        ? windowWidth - (WINDOW_MARGIN * 2)
        : DEFAULT_WIDTH;
    return {
        x: Math.max(WINDOW_MARGIN, windowWidth - boxWidth - WINDOW_MARGIN),
        y: windowWidth < MOBILE_BREAKPOINT ? 72 : 88,
    };
}

function appendQuote(body, postId) {
    const quote = '>>' + postId;
    if(!body) {
        return quote + '\n';
    }
    return body + (body.endsWith('\n') ? '' : '\n') + quote + '\n';
}

function constrainPosition(position, container) {
    if(typeof window === 'undefined') {
        return position;
    }
    if(window.innerWidth < MOBILE_BREAKPOINT) {
        return {x: WINDOW_MARGIN, y: 72};
    }
    const width = container ? container.offsetWidth : DEFAULT_WIDTH;
    const height = container ? container.offsetHeight : DEFAULT_HEIGHT;
    const maxX = Math.max(WINDOW_MARGIN, window.innerWidth - width - WINDOW_MARGIN);
    const maxY = Math.max(WINDOW_MARGIN, window.innerHeight - Math.min(height, window.innerHeight - (WINDOW_MARGIN * 2)) - WINDOW_MARGIN);
    return {
        x: clamp(position.x, WINDOW_MARGIN, maxX),
        y: clamp(position.y, WINDOW_MARGIN, maxY),
    };
}

function mapStateToProps(state) {
    return Object.assign({}, state.captcha, {remoteReply: state.remoteReply || {}});
}

function NewPostModal(props) {
    const [composerOpen, setComposerOpen] = useState(false);
    const [bodyValue, setBodyValue] = useState('');
    const [sourceQuoteMap, setSourceQuoteMap] = useState({});
    const [postingMode, setPostingMode] = useState(
        props.remoteReply && props.remoteReply.defaultMode === 'local' ? 'local' : 'forward'
    );
    const [position, setPosition] = useState(defaultPosition);
    const composerRef = useRef(null);
    const bodyRef = useRef(null);
    const dragStateRef = useRef(null);
    const focusBodyRef = useRef(false);

    useEffect(() => {
        const menuLink = document.getElementById('newPostLink');
        if(!menuLink) {
            return undefined;
        }
        function openFromNav(event) {
            event.preventDefault();
            focusBodyRef.current = true;
            setComposerOpen(true);
        }
        menuLink.addEventListener('click', openFromNav);
        return () => {
            menuLink.removeEventListener('click', openFromNav);
        };
    }, []);

    useEffect(() => {
        function openReplyBox(event) {
            const postId = event.detail ? event.detail.postId : undefined;
            const sourcePostId = event.detail ? event.detail.sourcePostId : undefined;
            focusBodyRef.current = true;
            setComposerOpen(true);
            if(postId !== undefined) {
                setBodyValue((currentBody) => appendQuote(currentBody, postId));
                if(sourcePostId) {
                    setSourceQuoteMap((currentMap) => Object.assign({}, currentMap, {
                        [String(postId)]: String(sourcePostId),
                    }));
                }
            }
        }
        window.addEventListener(OPEN_REPLY_BOX_EVENT, openReplyBox);
        return () => {
            window.removeEventListener(OPEN_REPLY_BOX_EVENT, openReplyBox);
        };
    }, []);

    useEffect(() => {
        function handleMouseMove(event) {
            if(!dragStateRef.current) {
                return;
            }
            event.preventDefault();
            const nextPosition = {
                x: event.clientX - dragStateRef.current.offsetX,
                y: event.clientY - dragStateRef.current.offsetY,
            };
            setPosition(constrainPosition(nextPosition, composerRef.current));
        }
        function stopDragging() {
            if(!dragStateRef.current) {
                return;
            }
            dragStateRef.current = null;
            document.body.classList.remove('reply-window-dragging');
        }
        document.addEventListener('mousemove', handleMouseMove);
        document.addEventListener('mouseup', stopDragging);
        return () => {
            document.removeEventListener('mousemove', handleMouseMove);
            document.removeEventListener('mouseup', stopDragging);
        };
    }, []);

    useEffect(() => {
        if(!composerOpen) {
            return undefined;
        }
        function handleResize() {
            setPosition((currentPosition) => constrainPosition(currentPosition, composerRef.current));
        }
        function handleEscape(event) {
            if(event.key === 'Escape') {
                setComposerOpen(false);
            }
        }
        handleResize();
        window.addEventListener('resize', handleResize);
        window.addEventListener('keydown', handleEscape);
        return () => {
            window.removeEventListener('resize', handleResize);
            window.removeEventListener('keydown', handleEscape);
        };
    }, [composerOpen]);

    useEffect(() => {
        if(!composerOpen || !focusBodyRef.current || !bodyRef.current) {
            return;
        }
        focusBodyRef.current = false;
        bodyRef.current.focus();
        const caretPosition = bodyRef.current.value.length;
        bodyRef.current.setSelectionRange(caretPosition, caretPosition);
    }, [composerOpen, bodyValue]);

    function beginDragging(event) {
        if(window.innerWidth < MOBILE_BREAKPOINT || !composerRef.current) {
            return;
        }
        if(event.target.closest && event.target.closest('.floating-reply-window__close')) {
            return;
        }
        const rect = composerRef.current.getBoundingClientRect();
        dragStateRef.current = {
            offsetX: event.clientX - rect.left,
            offsetY: event.clientY - rect.top,
        };
        document.body.classList.add('reply-window-dragging');
    }

    if(!composerOpen) {
        return null;
    }

    return (
        <div className="floating-reply-window" ref={composerRef} style={{left: position.x, top: position.y}}>
          <div className="floating-reply-window__header" onMouseDown={beginDragging}>
            <div>
              <div className="floating-reply-window__title">Reply to thread</div>
              <small className="text-muted">Drag this window around while you quote posts.</small>
            </div>
            <button type="button" className="floating-reply-window__close" onClick={() => setComposerOpen(false)} aria-label="Close reply box">&times;</button>
          </div>
          <div className="floating-reply-window__body">
            <NewPostForm
              action={buildAction(props.thread_id)}
              body_value={bodyValue}
              on_body_change={(event) => setBodyValue(event.target.value)}
              body_ref={bodyRef}
              source_quote_map={JSON.stringify(sourceQuoteMap)}
              posting_mode={postingMode}
              on_posting_mode_change={setPostingMode}
              embed_submit={false}
              {...props}
            />
          </div>
          <div className="floating-reply-window__footer">
            <button type="button" className="btn btn-outline-secondary btn-sm" onClick={() => setComposerOpen(false)}>Close</button>
            <button type="submit" className="btn btn-primary btn-sm" form="postForm">
              {props.remoteReply && props.remoteReply.isImported && postingMode === 'forward'
                ? 'Continue on source site'
                : 'Post locally on Maniwani'}
            </button>
          </div>
        </div>
    );
}

export default connect(mapStateToProps)(NewPostModal);
