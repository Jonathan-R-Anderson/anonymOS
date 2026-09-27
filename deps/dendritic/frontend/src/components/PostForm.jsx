import React, { useState } from 'react';
import AnimeCaptcha from './AnimeCaptcha';

function NewThreadForm(props) {
    return (<React.Fragment>
             <PostFormBase tag_entry={true} {...props}/>
             <input type="hidden" form="postForm" name="board" value={props.board_id}/>
            </React.Fragment>);
}

function NewPostForm(props) {
    return (<React.Fragment>
              <PostFormBase tag_entry={false} {...props}/>
             <input type="hidden" form="postForm" name="thread" value={props.thread_id}/>
            </React.Fragment>);
}

function PostFormBase(props) {
    const remoteReply = props.remoteReply || {};
    const importedThread = !!remoteReply.isImported;
    const initialMode = remoteReply.defaultMode === 'local' ? 'local' : 'forward';
    const [uncontrolledMode, setUncontrolledMode] = useState(initialMode);
    const postingMode = props.posting_mode || uncontrolledMode;
    function setPostingMode(nextMode) {
        if(props.on_posting_mode_change) {
            props.on_posting_mode_change(nextMode);
        } else {
            setUncontrolledMode(nextMode);
        }
    }
    const bodyFieldProps = props.body_value !== undefined
        ? (props.on_body_change
            ? {
                value: props.body_value,
                onChange: props.on_body_change,
            }
            : {
                defaultValue: props.body_value,
            })
        : {
            defaultValue: props.reply_to ? ">>" + props.reply_to + "\n" : "",
        };
	return (
		<form id="postForm" method="post" encType="multipart/form-data" action={props.action}>
          {props.cancel_outbound_id && <input type="hidden" name="cancel_outbound_id" value={props.cancel_outbound_id}/>}
          {importedThread && <input type="hidden" name="idempotency_key" value={remoteReply.idempotencyKey || ''}/>}
          {importedThread && <div className="form-group border rounded p-3">
            <div className="form-check">
              <input
                className="form-check-input"
                type="radio"
                id="forwardRemoteReplyForward"
                name="posting_mode"
                value="forward"
                checked={postingMode === 'forward'}
                onChange={() => setPostingMode('forward')}
              />
              <label className="form-check-label" htmlFor="forwardRemoteReplyForward">
                Forward this reply to {remoteReply.sourceType || 'the source site'}
              </label>
            </div>
            <div className="form-check">
              <input
                className="form-check-input"
                type="radio"
                id="forwardRemoteReplyLocal"
                name="posting_mode"
                value="local"
                checked={postingMode === 'local'}
                onChange={() => setPostingMode('local')}
              />
              <label className="form-check-label" htmlFor="forwardRemoteReplyLocal">
                Post only on Maniwani
              </label>
            </div>
            <input type="hidden" name="source_quote_map" value={props.source_quote_map || '{}'}/>
            <small className="form-text text-muted">
              {postingMode === 'forward'
                ? 'You will continue on the source site, where its CAPTCHA and network rules apply.'
                : 'Local only — the source site will not receive this reply.'}
            </small>
            {remoteReply.canSavePreference && <div className="form-check mt-2">
              <input className="form-check-input" type="checkbox" id="savePostingMode" name="save_posting_mode" value="true"/>
              <label className="form-check-label" htmlFor="savePostingMode">Save this as my slip account default</label>
            </div>}
          </div>}
          <div className="form-group">
            <label htmlFor="name">Name / tripcode</label>
            <input className="form-control" type="text" id="name" name="name" defaultValue={props.name_value} placeholder="Anonymous#tripcode"/>
            <small className="form-text text-muted">Optional. Use <code>name#trip</code> or <code>name#trip##salt</code>.</small>
          </div>
          <div className="form-group">
            <label htmlFor="subject">Subject</label>
            <input className="form-control" type="text" id="subject" name="subject" defaultValue={props.subject_value}/>
          </div>
          {props.privileged_slip && <SlipEntry/>}
          {props.tag_entry && <TagEntry/>}
          <div className="form-group">
            <label htmlFor="body">Body</label>
            <textarea className="form-control" id="body" name="body" ref={props.body_ref} {...bodyFieldProps}/>
          </div>
          <div className="form-group">
            <div className="form-check">
              <input type="checkbox" className="form-check-input" id="spoiler" name="spoiler" value="true"/>
              <label htmlFor="spoiler" className="form-check-label">Spoiler?</label>
            </div>
          </div>
          <div className="form-group">
            <label htmlFor="media">Media upload</label>
            <input type="file" id="media" name="media" disabled={importedThread && postingMode === 'forward'}/>
            <small className="form-text text-muted">
              {importedThread && postingMode === 'forward'
                ? 'For forwarded replies, select the attachment again on the source site.'
                : 'Maximum attachment size: ' + props.max_upload_size + '. Check the rules to see what kind of files can be uploaded.'}
            </small>
          </div>
          {props.token && <AnimeCaptcha {...props}/>}
          {props.embed_submit && <input
            type="submit"
            className="m-1 btn btn-primary"
            value={importedThread ? 'Submit selected destination' : 'Post'}
          />}
		</form>
	);
}

function TagEntry(props) {
    return (
        <div className="form-group">
          <label htmlFor="tags">Tags</label>
          <input type="text" className="form-control" id="tags" name="tags"/>
          <small className="form-text text-muted">Enter tags for this thread separated by commas.</small>
        </div>
    );
}

function SlipEntry(props) {
    return (
        <div className="form-check">
          <input type="checkbox" className="form-check-input" id="useslip" name="useslip" value="true"/>
          <label htmlFor="useslip" className="form-check-label"/>
          <small className="form-text text-muted">This will only have an effect if your slip
            has special permissions enabled for this board (admin, mod, etc.).
          </small>
        </div>
    );
}

export { NewThreadForm, NewPostForm };
