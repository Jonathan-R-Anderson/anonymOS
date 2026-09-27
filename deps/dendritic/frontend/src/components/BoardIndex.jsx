import React from 'react';

const INITIAL_VISIBLE_ITEMS = 18;

// Activity score for mosaic sizing on the boards page.
function boardItemScore(item) {
    return (Number(item.num_replies) || 0) * 3 + (Number(item.num_media) || 0) + (Number(item.views) || 0);
}

// Rank items by activity WITHIN the set so hotter threads get bigger tiles.
// Only threads with an image are promoted; the rest stay square.
function computeVariantMap(items) {
    const ranked = items
        .filter((item) => item.media && item.thumb_url)
        .slice()
        .sort((a, b) => boardItemScore(b) - boardItemScore(a));
    const total = ranked.length;
    const featuredCount = Math.round(total * 0.06);
    const bigCount = Math.round(total * 0.20);
    const variantById = {};
    ranked.forEach((item, rank) => {
        if (rank < featuredCount) {
            variantById[item.id] = "board-activity-tile--featured";
        } else if (rank < featuredCount + bigCount) {
            variantById[item.id] = (item.id % 2 === 0) ? "board-activity-tile--wide" : "board-activity-tile--tall";
        } else {
            variantById[item.id] = "board-activity-tile--square";
        }
    });
    return variantById;
}

function tileVariant(item, variantMap) {
    if (!item.media || !item.thumb_url) {
        return "board-activity-tile--square board-activity-tile--text";
    }
    return variantMap[item.id] || "board-activity-tile--square";
}

function watermarkProps(item) {
    if (!item.is_imported) {
        return {className: "", style: undefined};
    }
    if (item.watermark_image_url) {
        return {
            className: "source-watermarked source-watermarked--custom",
            style: {"--source-watermark-image": 'url("' + item.watermark_image_url + '")'},
        };
    }
    return {
        className: "source-watermarked source-watermarked--" + item.source_type,
        style: undefined,
    };
}

function mediaStyle(item) {
    if (item.torrent && item.media_url) {
        return item.media_url;
    }
    return item.thumb_url || null;
}

function sourceBadge(item) {
    if (!item.is_imported) {
        return null;
    }
    return <small className="badge badge-secondary board-activity-source">{item.source_label}</small>;
}

function boardBadge(item) {
    return <small className="badge badge-light board-activity-board">/{item.board}/</small>;
}

export default function BoardIndex(props) {
    const variantMap = computeVariantMap(props.items);
    return (
        <div className="board-activity-grid" id="board-activity-grid">
          {props.items.map((item, index) => {
              const hiddenClass = index >= INITIAL_VISIBLE_ITEMS ? "board-activity-hidden" : "";
              const watermark = watermarkProps(item);
              const tileClass = [
                  "board-activity-tile",
                  tileVariant(item, variantMap),
                  watermark.className,
                  hiddenClass
              ].filter(Boolean).join(" ");
              return (
                  <a
                    key={item.id}
                    href={item.thread_url}
                      className={tileClass}
                      style={watermark.style}
                      data-activity-tile="true">
                    {mediaStyle(item) && <img
                        className="board-activity-media"
                        src={mediaStyle(item)}
                        alt=""
                        style={{objectFit: "cover", width: "100%", height: "100%"}}
                    />}
                    {!mediaStyle(item) && <div className="board-activity-media"></div>}
                    <div className="board-activity-content watermark-content">
                      <div className="board-activity-topline">
                        {boardBadge(item)}
                        {sourceBadge(item)}
                      </div>
                      {item.subject && <h5 className="board-activity-title">{item.subject}</h5>}
                      {!item.subject && <h5 className="board-activity-title text-muted">No subject</h5>}
                      <div className="board-activity-body" dangerouslySetInnerHTML={{__html: item.body}}></div>
                      <div className="board-activity-stats">
                        <small>{item.num_replies} replies</small>
                        <small>{item.num_media} files</small>
                      </div>
                    </div>
                  </a>
              );
          })}
          <div id="board-activity-sentinel" className="board-activity-sentinel"></div>
        </div>
    );
}
