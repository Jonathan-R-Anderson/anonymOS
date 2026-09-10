import React, { useEffect, useState } from 'react';


const STATUS_LABELS = {
    ready_for_handoff: 'Ready to open the source',
    remote_page_open: 'Waiting for you on the source site',
    waiting_for_user: 'Waiting for you on the source site',
    submitted_unconfirmed: 'Submitted; checking the source',
    confirmed: 'Confirmed on the source',
    ambiguous: 'Could not uniquely identify the source reply',
    failed: 'Not forwarded',
    expired: 'Draft expired',
};


function OutboundReplyStatus(props) {
    const [replies, setReplies] = useState([]);
    const [loadError, setLoadError] = useState(false);

    useEffect(function () {
        if (!props.threadId || typeof window === 'undefined' || typeof window.fetch !== 'function') {
            return undefined;
        }
        let cancelled = false;
        let intervalId = null;

        function load() {
            fetch('/threads/' + props.threadId + '/outbound-replies', {
                credentials: 'same-origin',
                headers: {'Accept': 'application/json'},
            }).then(function (response) {
                if (!response.ok) {
                    throw new Error('HTTP ' + response.status);
                }
                return response.json();
            }).then(function (payload) {
                if (cancelled) {
                    return;
                }
                setReplies(payload && Array.isArray(payload.replies) ? payload.replies : []);
                setLoadError(false);
            }).catch(function () {
                if (!cancelled) {
                    setLoadError(true);
                }
            });
        }

        load();
        intervalId = window.setInterval(load, 5000);
        return function () {
            cancelled = true;
            if (intervalId !== null) {
                window.clearInterval(intervalId);
            }
        };
    }, [props.threadId]);

    if (!replies.length && !loadError) {
        return null;
    }

    return (
        <div className="card mb-3 outbound-reply-status">
          <div className="card-header">Your source reply drafts</div>
          <div className="list-group list-group-flush">
            {replies.map(function (reply) {
                return (
                    <div className="list-group-item" key={reply.id}>
                      <div className="d-flex flex-wrap justify-content-between align-items-center">
                        <div>
                          <strong>{STATUS_LABELS[reply.status] || reply.status}</strong>
                          <small className="text-muted ml-2">{reply.source_type}</small>
                        </div>
                        <div>
                          {(reply.status === 'ready_for_handoff' || reply.status === 'remote_page_open') &&
                            <a className="btn btn-sm btn-primary ml-1" href={reply.handoff_url}>Continue</a>}
                          {reply.source_post_url &&
                            <a className="btn btn-sm btn-outline-primary ml-1" href={reply.source_post_url} target="_blank" rel="noopener noreferrer">View source post</a>}
                          {reply.local_fallback_url &&
                            <a className="btn btn-sm btn-outline-secondary ml-1" href={reply.local_fallback_url}>Post locally instead</a>}
                        </div>
                      </div>
                      {reply.status === 'ambiguous' &&
                        <small className="text-warning">Check the source thread before trying again; the source may already contain your reply.</small>}
                    </div>
                );
            })}
            {loadError && <div className="list-group-item text-muted">Reply status is temporarily unavailable.</div>}
          </div>
        </div>
    );
}


export default OutboundReplyStatus;

