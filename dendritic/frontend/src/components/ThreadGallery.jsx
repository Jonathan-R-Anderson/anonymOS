import React, { useEffect, useMemo, useState } from 'react';
import {
    shouldUseDirectFallbackNow,
    subscribeToTorrentMedia,
    viewerCanDirectFallback,
    viewerDirectFallbackPeerThreshold,
    viewerPreferredMediaMode,
} from '../media/torrentMedia';


function emptyTorrentState(torrentPayload) {
    return {
        blobUrl: null,
        status: 'idle',
        mediaId: torrentPayload ? torrentPayload.media_id : null,
        magnetUrl: torrentPayload ? torrentPayload.magnet_url : null,
        magnetSource: torrentPayload ? torrentPayload.magnet_source : null,
    };
}

function useGalleryTorrent(post, mediaDelivery) {
    const preferredMode = mediaDelivery && mediaDelivery.preferredMode
        ? mediaDelivery.preferredMode
        : viewerPreferredMediaMode();
    const shouldUseTorrent = !!(
        post &&
        post.media &&
        post.torrent &&
        typeof post.mimetype === 'string' &&
        post.mimetype.indexOf('image/') === 0 &&
        preferredMode !== 'direct'
    );
    const [torrentState, setTorrentState] = useState(emptyTorrentState(post ? post.torrent : null));

    useEffect(function () {
        if (!shouldUseTorrent) {
            setTorrentState(emptyTorrentState(post ? post.torrent : null));
            return undefined;
        }
        return subscribeToTorrentMedia(post.torrent, setTorrentState);
    }, [
        shouldUseTorrent,
        post ? post.id : null,
        post && post.torrent ? post.torrent.info_hash : null,
        post && post.torrent ? post.torrent.magnet_url : null,
    ]);

    return {
        preferredMode: preferredMode,
        shouldUseTorrent: shouldUseTorrent,
        torrentState: torrentState,
    };
}

function GalleryTile(props) {
    const canDirectFallback = props.mediaDelivery && typeof props.mediaDelivery.canDirectFallback === 'boolean'
        ? props.mediaDelivery.canDirectFallback
        : viewerCanDirectFallback();
    const directFallbackPeerThreshold = props.mediaDelivery && typeof props.mediaDelivery.directFallbackPeerThreshold === 'number'
        ? props.mediaDelivery.directFallbackPeerThreshold
        : viewerDirectFallbackPeerThreshold();
    const torrentBinding = useGalleryTorrent(props.post, props.mediaDelivery);
    const directMediaUrl = props.post.direct_media_url || props.post.media_url || null;
    const serverPreviewUrl = props.post.thumb_url || directMediaUrl;
    const canUseDirectFallbackNow = shouldUseDirectFallbackNow(torrentBinding.torrentState, {
        preferredMode: torrentBinding.preferredMode,
        canDirectFallback: canDirectFallback,
        directFallbackPeerThreshold: directFallbackPeerThreshold,
    });
    const [directAssistLatched, setDirectAssistLatched] = useState(false);

    useEffect(function () {
        if (torrentBinding.torrentState.blobUrl) {
            setDirectAssistLatched(false);
            return;
        }
        if (canUseDirectFallbackNow) {
            setDirectAssistLatched(true);
        }
    }, [canUseDirectFallbackNow, torrentBinding.torrentState.blobUrl]);

    const directAssistActive = canUseDirectFallbackNow || directAssistLatched;
    const resolvedMediaUrl = torrentBinding.shouldUseTorrent
        ? (torrentBinding.torrentState.blobUrl || (directAssistActive ? serverPreviewUrl : null))
        : serverPreviewUrl;
    const linkMediaUrl = torrentBinding.shouldUseTorrent
        ? (torrentBinding.torrentState.blobUrl || (directAssistActive ? directMediaUrl || serverPreviewUrl : null))
        : directMediaUrl || serverPreviewUrl;
    const deliveryState = torrentBinding.shouldUseTorrent
        ? (torrentBinding.torrentState.blobUrl
            ? 'torrent-blob'
            : (directAssistActive ? 'torrent-server-assist' : ('torrent-' + torrentBinding.torrentState.status)))
        : 'direct-server';
    const tileStyle = resolvedMediaUrl
        ? {backgroundImage: 'url("' + resolvedMediaUrl + '")'}
        : undefined;
    const statusLabel = torrentBinding.shouldUseTorrent
        ? (torrentBinding.torrentState.blobUrl ? 'blob' : (directAssistActive ? 'server assist' : 'torrent pending'))
        : 'direct';

    const shell = (
        <div
          style={tileStyle}
          className={'media-element' + (resolvedMediaUrl ? '' : ' d-flex align-items-center justify-content-center bg-light text-muted')}
          data-media-delivery={deliveryState}
          data-media-target-kind={resolvedMediaUrl ? (resolvedMediaUrl.indexOf('blob:') === 0 ? 'blob' : 'server') : 'pending'}
        >
          {!resolvedMediaUrl && <small>Loading torrent...</small>}
        </div>
    );

    return (
        <div className="media-grid__item">
          {linkMediaUrl && <a href={linkMediaUrl} title={linkMediaUrl}>{shell}</a>}
          {!resolvedMediaUrl && <span title={torrentBinding.torrentState.magnetUrl || ''}>{shell}</span>}
          <div className="post-media-metrics">
            <small className={torrentBinding.torrentState.blobUrl ? 'text-success' : 'text-muted'}>
              {statusLabel}
              {torrentBinding.torrentState.magnetSource ? ' · ' + torrentBinding.torrentState.magnetSource + ' magnet' : ''}
            </small>
          </div>
        </div>
    );
}

function ThreadGallery(props) {
    const mediaDelivery = props.mediaDelivery || null;
    const posts = useMemo(function () {
        return Array.isArray(props.posts) ? props.posts : [];
    }, [props.posts]);

    return (
        <div className="media-grid">
          {posts.map(function (post) {
              return <GalleryTile key={post.id} post={post} mediaDelivery={mediaDelivery}/>;
          })}
        </div>
    );
}

export default ThreadGallery;
