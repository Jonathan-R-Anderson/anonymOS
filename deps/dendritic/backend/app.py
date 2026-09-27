import sys
import os
import traceback
import gevent.monkey
# Monkey-patch the stdlib for gevent compatibility. uWSGI's gevent plugin
# may also call this internally, but calling it idempotently here ensures
# psycopg2 and all I/O is properly async before any DB pools are created.
gevent.monkey.patch_all(contextvars=True)
import psycogreen.gevent
psycogreen.gevent.patch_psycopg()


def _patch_contextvars_greenlet_local():
    """
    Replace contextvars.ContextVar with a greenlet-local implementation.

    gevent < 20.5 ignores the contextvars=True argument in patch_all, leaving
    ContextVars thread-local. In a gevent app every request runs in a different
    greenlet within the same OS thread, so thread-local means ALL concurrent
    requests share a single _cv_request / _cv_app — causing Flask to throw
    "Popped wrong request context" under any concurrent load.

    This replacement must happen BEFORE Flask is imported so that Flask's own
    module-level  ContextVar("flask._app_ctx") / ContextVar("flask._request_ctx")
    calls produce greenlet-local instances.
    """
    import contextvars as _cv

    # Already patched (either by us or by a newer gevent).
    if getattr(_cv.ContextVar, '_greenlet_local', False):
        return

    try:
        from greenlet import getcurrent as _getcurrent
    except ImportError:
        return  # No greenlet — nothing to do.

    _MISSING = object()

    class _Token:
        __slots__ = ('_var', '_key', '_idx')

    class GreenletContextVar:
        """ContextVar whose storage is keyed by the current greenlet id."""

        _greenlet_local = True

        def __init__(self, name, *, default=_MISSING):
            self.__name = name
            self.__default = default
            # greenlet_id (int) -> list of values (stack so nested set/reset works)
            self.__data = {}

        @property
        def name(self):
            return self.__name

        def get(self, default=_MISSING):
            stack = self.__data.get(id(_getcurrent()))
            if stack:
                return stack[-1]
            if default is not _MISSING:
                return default
            if self.__default is not _MISSING:
                return self.__default
            raise LookupError(repr(self))

        def set(self, value):
            key = id(_getcurrent())
            stack = self.__data.setdefault(key, [])
            idx = len(stack)
            stack.append(value)
            tok = _Token()
            tok._var = self
            tok._key = key
            tok._idx = idx
            return tok

        def reset(self, token):
            if not isinstance(token, _Token) or token._var is not self:
                raise ValueError("Token was created by a different ContextVar")
            stack = self.__data.get(token._key)
            if stack is not None:
                del stack[token._idx:]
                if not stack:
                    del self.__data[token._key]

        def __repr__(self):
            return f'<ContextVar name={self.__name!r} at {hex(id(self))}>'

    _cv.ContextVar = GreenletContextVar
    sys.modules['contextvars'].ContextVar = GreenletContextVar


_patch_contextvars_greenlet_local()

from flask import render_template, send_from_directory

from blueprints.admin import admin_blueprint
from blueprints.main import main_blueprint
from blueprints.slip import slip_blueprint
from blueprints.profiles import profiles_blueprint
from blueprints.theme import theme_blueprint
from blueprints.dao import dao_blueprint
from blueprints.credits import credits_blueprint
from blueprints.storage_nodes import storage_nodes_blueprint
from blueprints.status import status_blueprint
from model.Analytics import AnalyticsAnonProfile, AnalyticsConsent, AnalyticsDeletion, AnalyticsEvent, AnalyticsIngestIssue, AnalyticsJobState, AnalyticsSession, AnalyticsUserProfile, ContentFeature, ensure_analytics_schema, secure_analytics_schema  # noqa: F401
from model.Recommendation import CollaborativeSimilarity, RecommendationInteraction, RecommendationLog  # noqa: F401
from model.Experiment import BehaviorMetricDaily, ExperimentDefinition, ExperimentExposure, ExperimentGuardrailSnapshot, RecommendationSatisfaction  # noqa: F401
from model.AdvancedRecommendation import AlgorithmAudit, BehaviorSequence, ContextualBanditArm, CreatorExposureDaily, ModelHealthSnapshot, NotificationRecommendation, RecommendationPreference, UserValuePrediction  # noqa: F401
from model.Codeplay import CodeplayAttempt, CodeplayProgress  # noqa: F401
from model.CodeplayContent import CodeplayContent  # noqa: F401
from model.LabInstance import LabInstance  # noqa: F401
from model.LabChallenge import LabChallenge  # noqa: F401
from model.LabQuestion import LabQuestion  # noqa: F401
from model.LabSolve import LabSolve  # noqa: F401
from model.LabAttempt import LabAttempt  # noqa: F401
from model.LabRating import LabRating  # noqa: F401
from model.Dao import DaoProposal, DaoVote  # noqa: F401
from model.PofRegistration import PofPayout, PofRegistration  # noqa: F401
from model.PofRelay import PofAssignment, PofReceipt  # noqa: F401
from model.PofSettlement import PofSettlement  # noqa: F401
from model.ThreatEvent import ThreatEvent  # noqa: F401
from model.Store import StoreItem, StoreOrder  # noqa: F401
from model.CreditPurchase import CreditPurchase  # noqa: F401
from model.ComputeEarning import ComputeEarning  # noqa: F401
from model.ComputeCluster import ComputeCluster  # noqa: F401
from model.BlockedMediaHash import BlockedMediaHash  # noqa: F401
from model.BlockedSourcePost import BlockedSourcePost  # noqa: F401
from model.FrontPageUpdate import FrontPageUpdate  # noqa: F401
from model.BanPageAsset import BanPageAsset  # noqa: F401
from model.WarrantCanary import WarrantCanaryEntry  # noqa: F401
from model.ShadowBan import ShadowBan  # noqa: F401
from model.VideoStatsArchive import VideoStatsArchive  # noqa: F401
from model.Stream import Stream  # noqa: F401
from model.BoardVisit import BoardVisit  # noqa: F401
from model.BoardBanner import BoardBanner  # noqa: F401
from model.BoardBookmark import BoardBookmark  # noqa: F401
from model.PostVote import PostVote  # noqa: F401
from model.MediaVote import MediaVote  # noqa: F401
from model.ScrapedThreadStub import ScrapedThreadStub  # noqa: F401
from model.ImageMagnet import ImageMagnet  # noqa: F401
from model.ImportedMedia import ImportedMedia  # noqa: F401
from model.RejectedImportedAsset import RejectedImportedAsset  # noqa: F401
from model.OutboundReply import OutboundReply  # noqa: F401
from captcha import get_template_context
from model.WordSentiment import WordSentiment  # noqa: F401
from model.WordFilter import WordFilter, WordFilterBoard  # noqa: F401
from model.Video import Video, VideoComment  # noqa: F401
from resources import (
    BoardCatalogResource, BoardListResource, FirehoseResource,
    NewPostResource, NewThreadResource, PostRemovalResource,
    ThreadPostsResource, SinglePostResource
)
from shared import app, db, rest_api

sys.stderr.write("DEBUG: [app.py] IMPORTS COMPLETE. app type is " + str(type(app)) + " db type is " + str(type(db)) + "\n")
sys.stderr.flush()

def _env_flag(*names):
    for name in names:
        value = os.getenv(name)
        if value is None:
            continue
        return str(value).strip().lower() not in ("", "0", "false", "no", "off")
    return False


def _config_flag(name):
    value = app.config.get(name)
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    return str(value).strip().lower() not in ("", "0", "false", "no", "off")


if _config_flag("DEV_MODE") or _env_flag("MANIWANI_DEV", "DEV_MODE", "dev_mode"):
    app.config["DEV_MODE"] = True
    from blueprints.devmode import devmode_blueprint
    app.register_blueprint(devmode_blueprint, url_prefix="/dev")

app.register_blueprint(main_blueprint, url_prefix="/")
app.register_blueprint(admin_blueprint, url_prefix="/admin")
app.register_blueprint(theme_blueprint, url_prefix="/theme")
# Public-interest intake: civil-rights reports and the newsroom tips line. Its
# own prefix rather than a route under /main, so the URL a person is asked to
# visit says what it is.
# The reviewer desk. Under /admin so it inherits that path's expectations, but
# its own module -- and it reuses admin's `_admin_required` rather than gating
# itself, so there is one answer to who may read a civil-rights complaint.
app.register_blueprint(slip_blueprint, url_prefix="/slip")
app.register_blueprint(profiles_blueprint, url_prefix="/profile")
app.register_blueprint(dao_blueprint, url_prefix="/dao")
app.register_blueprint(credits_blueprint, url_prefix="/credits")
# Gamified coding practice ported from CodePlay. Mounted at /arcade, not "/":
# the site keeps its own front page, and the upstream landing page was dropped.
# Rented compute lives beside codeplay: same audience, same mental model.
# Attack Range lab control surface (DCS-backed, slip-gated).
app.register_blueprint(storage_nodes_blueprint)
app.register_blueprint(status_blueprint)
# The newsroom, in four pieces, because three different people are allowed three
# different things and one blueprint would have made that one gate.
#
# Reading. Its own top-level prefix rather than a section of the boards: a
# published article is cited from outside the site, and /news/2026/08/<slug> has
# to keep working when the board it grew out of is pruned. The dated path is the
# canonical one -- see blueprints/news.py, which 301s a wrong month rather than
# 404ing a URL that may already be in print.
# Writing. NOT under /news, deliberately. /news is the archive a reader trusts,
# and a draft served from under it is one search engine mistake away from being
# read as published. Slip-gated, not admin-gated: contributors are members, not
# staff.
# Editing. Under /admin because that path already carries "you are acting on
# other people's work and it is written down", but its own module with its own
# gate -- `slip_is_editor`, which admits editors holding no admin grant. An
# editor may approve a story and may not touch the DHT purge screen.
# Voting. A JSON endpoint under the reading prefix because that is where the
# buttons are, and nested under /news rather than /api so a reader blocking the
# API surface does not silently get a page whose votes never land.

# Memberships and the monthly free-lab grant.
import model.Membership  # noqa: F401,E402
import model.CreditGrant  # noqa: F401,E402
import model.GatewayAudit  # noqa: F401,E402

# Register NNTPChan (route-B) models so db.create_all() builds their tables.
import model.NntpPeer  # noqa: E402,F401
import model.StorageNode  # noqa: E402,F401
# Probed I2P reachability per bootstrap destination. A NEW table, so
# db.create_all() builds it and no ALTER TABLE joins the startup DDL block.
import model.PeerLiveness  # noqa: E402,F401
import model.CodeplayDaily  # noqa: E402,F401  (per-player daily challenges)
import model.PostAward  # noqa: E402,F401  (bronze/silver/gold awards on posts)
import model.Bounty  # noqa: E402,F401  (bug bounties, submissions, ratings)
import model.SignupGrant  # noqa: E402,F401  (welcome grants + sybil signals)
import model.MlContest  # noqa: E402,F401  (ML competitions, datasets, submissions)
import model.SchoolProgress  # noqa: E402,F401  (chapters a slip has read)
import model.NntpGroupMap  # noqa: E402,F401
import model.NntpArticle  # noqa: E402,F401
import model.NntpAddressBlock  # noqa: E402,F401
import model.BannedImageFingerprint  # noqa: E402,F401
import model.NntpSourceWatermark  # noqa: E402,F401
import model.NntpDeletedThread  # noqa: E402,F401
import model.FalcoAlert  # noqa: E402,F401  (Falco runtime-security alerts table)
import model.BotToken  # noqa: E402,F401  (per-slip bot API credentials table)
import model.Federation  # noqa: E402,F401  (aggregated-chans list + requests tables)
import model.SourceModeration  # noqa: E402,F401  (3-strike illegal-content ban tables)
import model.UrlBlocklist  # noqa: E402,F401  (spam URL/token blocklist table)
import model.ChanBoard  # noqa: E402,F401  (per-chan discovered board lists)
import model.DhtPurgeAudit  # noqa: E402,F401  (who purged what out of the DHT)
# Which origin gateway placed each DHT object. Must be imported HERE and not
# only where it is used: db.create_all() below only creates tables whose model
# class has been imported, and a table that never gets created turns every
# recall into "the ownership record could not be read" -- which fails closed, so
# it would present as recall silently refusing rather than as a missing table.
# No ALTER is needed for it in the block below: create_all() does create NEW
# tables, it only declines to alter existing ones.
import model.DhtObjectOwner  # noqa: E402,F401  (object_id -> origin that placed it)
# Public-interest submissions: civil-rights reports and newsroom tips. THREE NEW
# tables, so create_all() builds them and none of them joins the ALTER block
# below. The index row deliberately holds no personally identifying information
# -- everything the submitter typed lives encrypted in the DHT, and
# tests/test_public_interest_report.py asserts the absence so that a later,
# well-meant column addition trips a test instead of quietly widening it.
import model.PublicInterestReport  # noqa: E402,F401
import model.PublicInterestReportNote  # noqa: E402,F401  (reviewer notes, kept apart)
import model.PublicInterestReportAudit  # noqa: E402,F401  (append-only admin trail)
# Permission to publish something a person told us in confidence. A NEW table,
# so create_all() builds it. Separate from the submission because consent to be
# helped is not consent to be named, and revocable up to publication.
import model.ReportConsent  # noqa: E402,F401
# The citizen newsroom. FOUR NEW tables, so create_all() builds them and none
# joins the ALTER block below. Contributor is a slip's standing in the newsroom
# rather than a second account; PenName's slug shares the Profile slug namespace
# on purpose, so model.PenName.slug_is_available() checks BOTH -- a uniqueness
# constraint on pen_name alone would pass and still shadow somebody's profile URL.
import model.Contributor  # noqa: E402,F401
import model.PenName  # noqa: E402,F401
import model.NewsStory  # noqa: E402,F401
# THREE MORE NEW tables, so create_all() builds them and none joins the ALTER
# block below. StoryRevision keeps every published version so a correction can
# be additive rather than an overwrite; StoryVote is per-slip like PostVote;
# EditorialAction is the append-only "who did what" trail. Slip.is_editor is the
# one thing here that lands on an EXISTING table, so it does have an ALTER.
import model.StoryRevision  # noqa: E402,F401
import model.StoryVote  # noqa: E402,F401
import model.EditorialAction  # noqa: E402,F401

with app.app_context():
    sys.stderr.write("DEBUG: [app.py] CALLING db.create_all()\n")
    sys.stderr.flush()
    try:
        ensure_analytics_schema()
        db.create_all()
        secure_analytics_schema()
    except Exception as e:
        sys.stderr.write(f"DEBUG: [app.py] db.create_all() failed (possibly already created): {e}\n")
        sys.stderr.flush()
    # Idempotently add columns that were introduced on existing tables (which
    # db.create_all() never alters). Postgres ADD COLUMN IF NOT EXISTS makes
    # this a no-op on fresh installs and on reboots once the column exists.
    try:
        from sqlalchemy import text
        # NNTP peers may be clearnet again. The I2P-only CHECK made federation
        # impossible here: there is no I2P NNTP peer to federate with and no I2P
        # router this deployment can reach, and an anonymity guarantee on a
        # feature that cannot run protects nobody. The transport is now chosen
        # per peer and shown in the admin card. See migration c1a5f70b3d29 —
        # repeated here because this deployment builds its schema with
        # create_all() rather than by running migrations.
        db.session.execute(text(
            "ALTER TABLE nntp_peer DROP CONSTRAINT IF EXISTS ck_nntp_peer_enabled_i2p_host"
        ))
        db.session.execute(text(
            "ALTER TABLE lab_challenge ADD COLUMN IF NOT EXISTS codename varchar(48)"
        ))
        # Per-node usage, for levelling the storage pools. NULLable on purpose:
        # NULL means "this node has not reported", 0 means "reported, and empty",
        # and the pool-levelling planner has to tell those apart or it aims every
        # surplus shard at a node that merely runs an older build. See
        # roadmap/dht-storage-roadmap.md phase 2b.
        db.session.execute(text(
            "ALTER TABLE storage_node ADD COLUMN IF NOT EXISTS used_bytes bigint"
        ))
        # A node whose operator is retiring it. NOT NULL DEFAULT false, unlike
        # used_bytes above: a build old enough not to report the field has no
        # drain to describe, so false is the honest reading rather than a
        # missing measurement. See roadmap phase 2b step 4.
        db.session.execute(text(
            "ALTER TABLE storage_node ADD COLUMN IF NOT EXISTS draining "
            "boolean NOT NULL DEFAULT false"
        ))
        # Whether dispersal is WORKING on that node -- ledger totals, per-pass
        # placed/failed, which peers are refusing and why. NULLable like
        # used_bytes and for the same reason, but it matters more here: NULL is
        # "this node has not reported", and drawing that as a node with zero
        # failures is precisely the blindness phase 4.3 exists to remove. The
        # timestamp is separate from last_seen_at because a node can keep
        # heartbeating long after its replicate loop stops reporting.
        db.session.execute(text(
            "ALTER TABLE storage_node ADD COLUMN IF NOT EXISTS placement_health text"
        ))
        db.session.execute(text(
            "ALTER TABLE storage_node ADD COLUMN IF NOT EXISTS "
            "placement_reported_at timestamp"
        ))
        # Memberships arrived after these tables existed on deployed databases;
        # create_all() adds new tables but never alters old ones, so the columns
        # a later change adds have to be named here.
        db.session.execute(text(
            "ALTER TABLE membership ADD COLUMN IF NOT EXISTS cancel_at_period_end "
            "boolean NOT NULL DEFAULT false"
        ))
        db.session.execute(text(
            "ALTER TABLE video_comment ADD COLUMN IF NOT EXISTS video_time double precision"
        ))
        db.session.execute(text(
            "ALTER TABLE profile ADD COLUMN IF NOT EXISTS link_on_comments boolean NOT NULL DEFAULT true"
        ))
        db.session.execute(text(
            "ALTER TABLE board ADD COLUMN IF NOT EXISTS show_country_flags boolean NOT NULL DEFAULT false"
        ))
        db.session.execute(text(
            "ALTER TABLE poster ADD COLUMN IF NOT EXISTS country_code varchar(2)"
        ))
        db.session.execute(text(
            "ALTER TABLE media ADD COLUMN IF NOT EXISTS fingerprint varchar(1024)"
        ))
        db.session.execute(text(
            "ALTER TABLE post ADD COLUMN IF NOT EXISTS source_watermark_url varchar"
        ))
        db.session.execute(text(
            "ALTER TABLE post ADD COLUMN IF NOT EXISTS source_watermark_label varchar(128)"
        ))
        db.session.execute(text(
            "ALTER TABLE profile ADD COLUMN IF NOT EXISTS enable_chat boolean NOT NULL DEFAULT false"
        ))
        db.session.execute(text(
            "ALTER TABLE board ADD COLUMN IF NOT EXISTS created_at timestamp DEFAULT now()"
        ))
        db.session.execute(text(
            "ALTER TABLE profile ADD COLUMN IF NOT EXISTS avatar_media_id integer REFERENCES media(id)"
        ))
        db.session.execute(text(
            "ALTER TABLE profile ADD COLUMN IF NOT EXISTS show_avatar boolean NOT NULL DEFAULT false"
        ))
        db.session.execute(text(
            "ALTER TABLE profile ADD COLUMN IF NOT EXISTS chat_theme varchar(8) NOT NULL DEFAULT 'light'"
        ))
        db.session.execute(text(
            "ALTER TABLE profile ADD COLUMN IF NOT EXISTS chat_accent varchar(7)"
        ))
        db.session.execute(text(
            "ALTER TABLE profile ADD COLUMN IF NOT EXISTS enable_place boolean NOT NULL DEFAULT false"
        ))
        db.session.execute(text(
            "ALTER TABLE video ADD COLUMN IF NOT EXISTS last_seen_at timestamp DEFAULT now()"
        ))
        db.session.execute(text(
            "ALTER TABLE profile ADD COLUMN IF NOT EXISTS place_timelapse_days integer NOT NULL DEFAULT 7"
        ))
        db.session.execute(text(
            "ALTER TABLE profile ADD COLUMN IF NOT EXISTS session_timeout_minutes integer NOT NULL DEFAULT 0"
        ))
        db.session.execute(text(
            "ALTER TABLE board ADD COLUMN IF NOT EXISTS custom_js text"
        ))
        db.session.execute(text(
            "ALTER TABLE board ADD COLUMN IF NOT EXISTS custom_html text"
        ))
        # Ban durations: NULL expires_at == permanent (see model/Ban.py).
        db.session.execute(text(
            "ALTER TABLE ban ADD COLUMN IF NOT EXISTS expires_at timestamp"
        ))
        db.session.execute(text(
            "ALTER TABLE board_ban ADD COLUMN IF NOT EXISTS expires_at timestamp"
        ))
        # Thread flush: when the thread page was last directly viewed.
        db.session.execute(text(
            "ALTER TABLE thread ADD COLUMN IF NOT EXISTS last_viewed_at timestamp"
        ))
        # Scraped-thread retirement (stop monitoring dead source threads).
        db.session.execute(text(
            "ALTER TABLE board_source ADD COLUMN IF NOT EXISTS created_at timestamp DEFAULT now()"
        ))
        db.session.execute(text(
            "ALTER TABLE board_source ADD COLUMN IF NOT EXISTS retired boolean NOT NULL DEFAULT false"
        ))
        db.session.execute(text(
            "ALTER TABLE board ADD COLUMN IF NOT EXISTS api_only boolean NOT NULL DEFAULT false"
        ))
        db.session.execute(text(
            "ALTER TABLE board ADD COLUMN IF NOT EXISTS api_description text"
        ))
        # NSFW image filter: default TRUE so every existing board becomes filtered
        # on upgrade, matching "on by default for each board".
        db.session.execute(text(
            "ALTER TABLE board ADD COLUMN IF NOT EXISTS nsfw_filter boolean NOT NULL DEFAULT true"
        ))
        db.session.execute(text(
            "ALTER TABLE media ADD COLUMN IF NOT EXISTS nsfw_score double precision"
        ))
        # Generic aggregated chans use their HOST as source_type, and 40 of the
        # ~300 listed hosts are longer than the original varchar(16) (max 62 — an
        # I2P b32 address). Widening a varchar is a metadata-only operation in
        # Postgres, so this is cheap even on large tables.
        for _source_type_table in ("thread", "post", "board_source"):
            db.session.execute(text(
                "ALTER TABLE %s ALTER COLUMN source_type TYPE varchar(128)"
                % _source_type_table
            ))
        db.session.execute(text(
            "ALTER TABLE board_source ADD COLUMN IF NOT EXISTS source_site varchar(500)"
        ))
        # DCS lab instances: the worker's own garlic address and the container id
        # the worker assigned, so the bridge can reopen an RPC stream to poll or
        # destroy the exact container later.
        db.session.execute(text(
            "ALTER TABLE lab_instance ADD COLUMN IF NOT EXISTS worker_destination varchar(70)"
        ))
        db.session.execute(text(
            "ALTER TABLE lab_instance ADD COLUMN IF NOT EXISTS container_id varchar(80)"
        ))
        # Per-boot random secret injected into a lab container; the answer to an
        # "instance_secret" lab question is checked against it, so it can't be shared.
        db.session.execute(text(
            "ALTER TABLE lab_instance ADD COLUMN IF NOT EXISTS container_password varchar(64)"
        ))
        # Lab challenges gained a kind ("dockerfile"|"compose") for vulhub-style
        # docker-compose projects, and vulhub slugs need more room than 64 chars.
        db.session.execute(text(
            "ALTER TABLE lab_challenge ADD COLUMN IF NOT EXISTS kind varchar(16) NOT NULL DEFAULT 'dockerfile'"
        ))
        db.session.execute(text(
            "ALTER TABLE lab_challenge ALTER COLUMN slug TYPE varchar(128)"
        ))
        # Machines UI presentation metadata.
        db.session.execute(text(
            "ALTER TABLE lab_challenge ADD COLUMN IF NOT EXISTS difficulty varchar(12) NOT NULL DEFAULT 'Medium'"
        ))
        db.session.execute(text(
            "ALTER TABLE lab_challenge ADD COLUMN IF NOT EXISTS os varchar(12) NOT NULL DEFAULT 'Linux'"
        ))
        # DCS worker role on the node map (yellow dot).
        db.session.execute(text(
            "ALTER TABLE storage_node ADD COLUMN IF NOT EXISTS dcs_worker boolean NOT NULL DEFAULT false"
        ))
        # Compute roles on the node map (orange = GPU, pink = CPU) and whether
        # the node settles through a payment channel (cyan). Separate columns
        # rather than one bitmask: each is queried on its own to answer "how
        # much of X does the network have", and a bitmask makes that a scan.
        # Whether a submitted job is arbitrary code (microVM only) and where it
        # ran. See model/ComputeRental.py on why these are separate columns.
        db.session.execute(text(
            "ALTER TABLE compute_rental ADD COLUMN IF NOT EXISTS arbitrary boolean NOT NULL DEFAULT false"
        ))
        db.session.execute(text(
            "ALTER TABLE compute_rental ADD COLUMN IF NOT EXISTS cores integer NOT NULL DEFAULT 1"
        ))
        # What a node earned for running a job. Created here rather than by a
        # migration because the rest of this schema is, and one table appearing
        # by a different route is how a deploy half-applies.
        db.session.execute(text(
            "CREATE TABLE IF NOT EXISTS compute_earning ("
            " id SERIAL PRIMARY KEY,"
            " rental_id integer NOT NULL REFERENCES compute_rental(id),"
            " node_id varchar(80) NOT NULL,"
            " amount bigint NOT NULL,"
            " device varchar(8) NOT NULL DEFAULT 'cpu',"
            " succeeded boolean NOT NULL DEFAULT true,"
            " created_at timestamp NOT NULL DEFAULT now(),"
            " CONSTRAINT uq_earning_job_node UNIQUE (rental_id, node_id))"
        ))
        db.session.execute(text(
            "CREATE INDEX IF NOT EXISTS ix_compute_earning_node ON compute_earning (node_id)"
        ))
        db.session.execute(text(
            "ALTER TABLE compute_rental ADD COLUMN IF NOT EXISTS seconds integer NOT NULL DEFAULT 60"
        ))
        db.session.execute(text(
            "ALTER TABLE compute_rental ADD COLUMN IF NOT EXISTS verdict varchar(16)"
        ))
        db.session.execute(text(
            "ALTER TABLE compute_rental ADD COLUMN IF NOT EXISTS verified_by varchar(200)"
        ))
        db.session.execute(text(
            "ALTER TABLE compute_rental ADD COLUMN IF NOT EXISTS worker_node_id varchar(80)"
        ))
        db.session.execute(text(
            "ALTER TABLE compute_rental ADD COLUMN IF NOT EXISTS isolation varchar(16)"
        ))
        # M10 clusters: N machines running one catalogue workload over one
        # corpus. The parent row lands here BEFORE the compute_rental columns
        # below, because one of those columns references it.
        db.session.execute(text(
            "CREATE TABLE IF NOT EXISTS compute_cluster ("
            " id SERIAL PRIMARY KEY,"
            " slip_id integer NOT NULL REFERENCES slip(id),"
            " name varchar(120) NOT NULL DEFAULT '',"
            " workload varchar(32) NOT NULL DEFAULT 'embed',"
            " device varchar(8) NOT NULL DEFAULT 'cpu',"
            " node_count integer NOT NULL DEFAULT 1,"
            " seconds integer NOT NULL DEFAULT 120,"
            " cores integer NOT NULL DEFAULT 1,"
            " priority integer NOT NULL DEFAULT 0,"
            " status varchar(16) NOT NULL DEFAULT 'queued',"
            # 1.0 rather than the rental default of 0.25: slice-1 embeddings
            # are bit-exact, so the second run is cheap and the user's vectors
            # need not rest on one anonymous machine's word.
            " verify_rate double precision NOT NULL DEFAULT 1.0,"
            " credits_paid integer NOT NULL DEFAULT 0,"
            " corpus_lines integer,"
            " created_at timestamp NOT NULL DEFAULT now(),"
            " started_at timestamp,"
            " finished_at timestamp)"
        ))
        db.session.execute(text(
            "CREATE INDEX IF NOT EXISTS ix_compute_cluster_slip_id "
            "ON compute_cluster (slip_id)"
        ))
        # What the drainer scans on every pass, and what the user's list orders
        # by. device and priority are not indexed: one row per cluster makes an
        # index on a two-value column something the planner reads past.
        db.session.execute(text(
            "CREATE INDEX IF NOT EXISTS ix_compute_cluster_status "
            "ON compute_cluster (status)"
        ))
        db.session.execute(text(
            "CREATE INDEX IF NOT EXISTS ix_compute_cluster_created_at "
            "ON compute_cluster (created_at)"
        ))
        # A rental is also one UNIT of a cluster. Which workload it runs, which
        # cluster it belongs to, which shard it was handed, and the file it
        # produced. All nullable: every job that existed before M10 is a
        # language job with none of them.
        db.session.execute(text(
            "ALTER TABLE compute_rental ADD COLUMN IF NOT EXISTS workload varchar(32)"
        ))
        db.session.execute(text(
            "ALTER TABLE compute_rental ADD COLUMN IF NOT EXISTS cluster_id integer "
            "REFERENCES compute_cluster(id) ON DELETE CASCADE"
        ))
        db.session.execute(text(
            "ALTER TABLE compute_rental ADD COLUMN IF NOT EXISTS shard_index integer"
        ))
        db.session.execute(text(
            "ALTER TABLE compute_rental ADD COLUMN IF NOT EXISTS output_text text"
        ))
        # A data-only workload has no entry point of the submitter's to name —
        # the signed image ships its own. The NOT NULL here would otherwise
        # force every cluster unit to claim it runs a file that does not exist.
        db.session.execute(text(
            "ALTER TABLE compute_rental ALTER COLUMN entrypoint DROP NOT NULL"
        ))
        db.session.execute(text(
            "CREATE INDEX IF NOT EXISTS ix_compute_rental_cluster_id "
            "ON compute_rental (cluster_id)"
        ))
        db.session.execute(text(
            "CREATE INDEX IF NOT EXISTS ix_compute_rental_workload "
            "ON compute_rental (workload)"
        ))
        db.session.execute(text(
            "ALTER TABLE storage_node ADD COLUMN IF NOT EXISTS gpu_compute boolean NOT NULL DEFAULT false"
        ))
        db.session.execute(text(
            "ALTER TABLE storage_node ADD COLUMN IF NOT EXISTS cpu_compute boolean NOT NULL DEFAULT false"
        ))
        db.session.execute(text(
            "ALTER TABLE storage_node ADD COLUMN IF NOT EXISTS payment_channel boolean NOT NULL DEFAULT false"
        ))
        db.session.execute(text(
            "ALTER TABLE storage_node ADD COLUMN IF NOT EXISTS microvm boolean NOT NULL DEFAULT false"
        ))
        # Self-reported garlic destination, so the live bootstrap service can hand
        # this node out as a reachable peer.
        db.session.execute(text(
            "ALTER TABLE storage_node ADD COLUMN IF NOT EXISTS i2p_destination varchar(70)"
        ))
        # Whether an audited identity was a registered gateway when observed.
        # The table shipped one release earlier, so create_all() built it
        # without this column and will never add it.
        db.session.execute(text(
            "ALTER TABLE gateway_audit ADD COLUMN IF NOT EXISTS "
            "gateway_registered boolean NOT NULL DEFAULT false"
        ))
        # The other gateway in a cross-gateway comparison (phase 3, item 10).
        db.session.execute(text(
            "ALTER TABLE gateway_audit ADD COLUMN IF NOT EXISTS "
            "peer_gateway varchar(64)"
        ))
        # Reachability ping for each aggregated chan (admin chan list).
        for _ping_col, _ping_type in (
            ("last_ping_at", "timestamp"), ("ping_status_code", "integer"),
            ("ping_ms", "integer"), ("ping_error", "varchar(200)"),
            ("ping_ok", "boolean"),
        ):
            db.session.execute(text(
                "ALTER TABLE chan_board_scan ADD COLUMN IF NOT EXISTS %s %s"
                % (_ping_col, _ping_type)
            ))
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        sys.stderr.write(f"DEBUG: [app.py] source_type widen/source_site ensure skipped: {e}\n")
        sys.stderr.flush()
    # The editorial grant. `slip` is an existing table, so create_all() will
    # never add this column, and once the model declares it EVERY query against
    # Slip selects it — so a deployment that misses this ALTER does not lose the
    # newsroom, it loses sign-in. That is why it gets its own try block instead
    # of joining the one above: forty other idempotent statements share that
    # block, and any one of them failing rolls back the whole transaction,
    # taking this with it. NOT NULL DEFAULT false because an install predating
    # the newsroom has no editors, and "unknown" is not a state a permission
    # check should have to reason about.
    try:
        from sqlalchemy import text as _text
        db.session.execute(_text(
            "ALTER TABLE slip ADD COLUMN IF NOT EXISTS is_editor "
            "boolean NOT NULL DEFAULT false"
        ))
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        sys.stderr.write(f"DEBUG: [app.py] slip.is_editor ensure skipped: {e}\n")
        sys.stderr.flush()
    # Both columns were NOT NULL and are now nullable, for account deletion
    # only -- see model/NewsStory.py. create_all() never alters an existing
    # table, so a deployment that already built news_story would keep the old
    # constraint, and _release_published_work would fail with a not-null
    # violation at exactly the moment somebody deleted an account. Its own
    # block for the same reason is_editor has one: a shared block rolls back
    # entirely when any one of its forty statements fails.
    try:
        from sqlalchemy import text as _text
        db.session.execute(_text(
            "ALTER TABLE news_story ALTER COLUMN slip_id DROP NOT NULL"))
        db.session.execute(_text(
            "ALTER TABLE pen_name ALTER COLUMN owner_slip_id DROP NOT NULL"))
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        sys.stderr.write(f"DEBUG: [app.py] newsroom nullability ensure skipped: {e}\n")
        sys.stderr.flush()
    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        sys.stderr.write(f"DEBUG: [app.py] video_comment.video_time ensure skipped: {e}\n")
        sys.stderr.flush()
    # Give every lab machine its codename. Idempotent — it only touches rows
    # that have none — so it costs one indexed query on a restart where there is
    # nothing to do.
    try:
        from model.LabChallenge import assign_missing_codenames
        _named = assign_missing_codenames()
        if _named:
            sys.stderr.write(f"DEBUG: [app.py] named {_named} lab machine(s)\n")
            sys.stderr.flush()
    except Exception as e:
        db.session.rollback()
        sys.stderr.write(f"DEBUG: [app.py] lab codename backfill skipped: {e}\n")
        sys.stderr.flush()
    # One-time import of the built-in captcha datasets into the DB so the admin
    # panel starts populated and the sysop can add/remove challenges from there.
    try:
        from captcha.anime import FILE_DATASETS
        from model.CaptchaChallenge import seed_from_file_datasets
        if seed_from_file_datasets(FILE_DATASETS):
            db.session.commit()
    except Exception as e:
        db.session.rollback()
        sys.stderr.write(f"DEBUG: [app.py] captcha challenge seed skipped: {e}\n")
        sys.stderr.flush()
    # One-time seed of codeplay content (mcq/problems/flashcards/bughunter/daily)
    # from the bundled JSON into the editable CodeplayContent table, so the admin
    # can add/edit questions and the content can be published to the DHT. No-op
    # once the table has rows (admin edits are never overwritten).
    try:
        from services.codeplay_content import seed_from_bundled
        _cp_added = seed_from_bundled()
        if _cp_added:
            sys.stderr.write(f"DEBUG: [app.py] codeplay content seeded: {_cp_added}\n")
            sys.stderr.flush()
    except Exception as e:
        db.session.rollback()
        sys.stderr.write(f"DEBUG: [app.py] codeplay content seed skipped: {e}\n")
        sys.stderr.flush()
    # Reconcile the public "chans we aggregate from" list against the bundled
    # file (resources/aggregated_chans.txt): add anything missing, skip anything
    # deliberately removed. Runs every startup so a partially populated list
    # repairs itself instead of being stuck forever.
    try:
        from model.Federation import seed_aggregated_chans
        _chans_added = seed_aggregated_chans()
        if _chans_added:
            sys.stderr.write(
                "DEBUG: [app.py] aggregated-chans reconcile added %d chan(s)\n" % _chans_added
            )
            sys.stderr.flush()
    except Exception as e:
        db.session.rollback()
        sys.stderr.write(f"DEBUG: [app.py] aggregated-chans seed skipped: {e}\n")
        sys.stderr.flush()
    # Seed the spam URL blocklist once from resources/url_blocklist.txt so a fresh
    # install never runs with an empty list; afterwards it is DB-managed and an
    # admin's removals stick (see model/UrlBlocklist.seed_url_blocklist).
    try:
        from model.UrlBlocklist import seed_url_blocklist
        seed_url_blocklist()
    except Exception as e:
        db.session.rollback()
        sys.stderr.write(f"DEBUG: [app.py] url blocklist seed skipped: {e}\n")
        sys.stderr.flush()
    # Discover each aggregated chan's boards (paths + names) in the background:
    # once for chans never scanned, then weekly. Never inline — one pass is many
    # HTTP requests against remote sites.
    try:
        from services.chan_ping import start_chan_ping
        start_chan_ping(app)
        from services.media_rescan import start_media_rescan
        start_media_rescan(app)
        from services.chan_board_discovery import start_background_discovery
        if start_background_discovery():
            sys.stderr.write("DEBUG: [app.py] chan board discovery loop started\n")
            sys.stderr.flush()
    except Exception as e:
        sys.stderr.write(f"DEBUG: [app.py] chan board discovery not started: {e}\n")
        sys.stderr.flush()
    # Board custom HTML/JS are now sysop-only and rendered inline (un-sandboxed)
    # on the board page. The write gate only governs NEW writes, so any scripts a
    # non-sysop board owner saved earlier (while the fields were owner-editable
    # and confined to a sandboxed iframe) would otherwise keep running with full
    # origin access after the sandbox was removed. Purge those legacy values
    # once: clear custom_js/custom_html on every board owned by a non-admin slip,
    # so only sysop-authored scripts survive. Guarded by a one-time flag so it
    # never wipes scripts a sysop legitimately sets on a user's board later.
    try:
        from sqlalchemy import text
        from model.SiteSetting import get_setting, set_setting
        if get_setting("board_owner_custom_scripts_purged", "") != "1":
            db.session.execute(text(
                "UPDATE board SET custom_js = NULL, custom_html = NULL "
                "WHERE owner_slip_id IN (SELECT id FROM slip WHERE is_admin = false)"
            ))
            set_setting("board_owner_custom_scripts_purged", "1")
            db.session.commit()
    except Exception as e:
        db.session.rollback()
        sys.stderr.write(f"DEBUG: [app.py] board owner custom-script purge skipped: {e}\n")
        sys.stderr.flush()

if app.config["SERVE_REST"]:
    rest_api.add_resource(BoardListResource, "/api/v1/boards/")
    rest_api.add_resource(BoardCatalogResource, "/api/v1/board/<int:board_id>/catalog")
    rest_api.add_resource(ThreadPostsResource, "/api/v1/thread/<int:thread_id>")
    rest_api.add_resource(NewThreadResource, "/api/v1/thread/new")
    rest_api.add_resource(PostRemovalResource, "/api/v1/thread/post/<int:post_id>")
    rest_api.add_resource(NewPostResource, "/api/v1/thread/<int:thread_id>/new")
    rest_api.add_resource(SinglePostResource, "/api/v1/post/<int:post_id>")
    rest_api.add_resource(FirehoseResource, "/api/v1/firehose")



try:
    # START THE CAPPED SCRAPE QUEUES BEFORE the sync loops that feed them.
    # Everything that scrapes or imports goes through here so it can never
    # consume more than a fixed slice of the process. See services/scrape_queue.py
    # for the outage this prevents.
    #
    # Caps are deliberately small. All import work serializes behind
    # _global_sync_lock (services/aggregator_sync/state.py), so a higher cap
    # would only park more DB connections on that mutex — worse, not faster.
    from services.scrape_queue import configure_queue, start_scrape_queues

    configure_queue("media-repair", cap=2)   # render-triggered; the highest-volume producer
    configure_queue("board-refresh", cap=1)  # catalog-view triggered; serialized anyway
    configure_queue("board-prime", cap=1)    # board-save; each job polls up to 120s
    configure_queue("sync-forced", cap=1)    # admin button
    # Re-scan sweep: each job is a storage read plus up to two sidecar calls.
    configure_queue("media-rescan", cap=2)
    start_scrape_queues(app)
except Exception:
    app.logger.exception("Could not start the scrape queues")

try:
    from aggregator_sync import start_background_sync
    start_background_sync(app)
except Exception:
    app.logger.exception("Could not start background aggregator sync")

try:
    from services.board_cleanup import start_board_cleanup
    start_board_cleanup(app)
except Exception:
    app.logger.exception("Failed to start board inactivity cleanup")

try:
    from services.video_cleanup import start_video_cleanup
    start_video_cleanup(app)
except Exception:
    app.logger.exception("Failed to start video inactivity cleanup")

try:
    from services.shadowban_cleanup import start_shadowban_cleanup
    start_shadowban_cleanup(app)
except Exception:
    app.logger.exception("Failed to start shadowban content cleanup")

try:
    from services.thread_flush import start_thread_flush
    start_thread_flush(app)
except Exception:
    app.logger.exception("Failed to start unviewed-thread flush")

try:
    from services.scraped_thread_retire import start_scraped_thread_retire
    start_scraped_thread_retire(app)
    # Age-bounded scraped content: purge threads outside the scrape window and
    # expire the identity stubs left behind. See services/scraped_retention.py.
    from services.scraped_retention_sweep import start_scraped_retention_sweep
    start_scraped_retention_sweep(app)
    # Continuously push newly uploaded/scraped media to the storage DHT, but
    # only once it has cleared the blocked-hash and NSFW gates.
    from services.storage_offload import start_storage_offload_sweep
    start_storage_offload_sweep(app)
    # Probe each bootstrap destination over I2P in the background and cache the
    # verdict, so the bootstrap document and every heartbeat reply can withhold
    # destinations whose LeaseSet is gone WITHOUT any request handler ever making
    # an I2P call. See services/peer_liveness_loop.py for why it is not inline.
    from services.peer_liveness_loop import start_peer_liveness
    start_peer_liveness(app)
    # Destroy public-interest submissions whose retention has run out. The
    # schedule is stored per row; without this nothing acts on it, and a
    # retention policy nothing enforces is a promise made to complainants on the
    # confirmation page and quietly broken. Leader-gated inside the loop.
    from services.report_retention_loop import start_report_retention
    start_report_retention(app)
    # Fold votes into NewsStory.score and rebuild the front-page rail. Both
    # functions existed and nothing called them, which is the kind of broken
    # where the code is right, the tests pass and the feature does not work: a
    # vote changed a row nobody read, and a rail emptied by a transient failure
    # had no repair path but its own TTL. Leader-gated inside the loop, and
    # deliberately NOT done in a request handler -- '/' is a cached render and
    # this codebase has been taken down once already by making it do work.
    from services.newsroom_loop import start_newsroom_recompute
    start_newsroom_recompute(app)
    # Re-mirror imported posts whose image failed the first time. Needed because
    # sync skips a quiet source entirely, so a transient media failure would
    # otherwise never be retried. Repairs go through the normal gates, NSFW
    # classifier included.
    from services.imported_media_repair import start_imported_media_repair
    start_imported_media_repair(app)
    # The folder->S3 media migration. Moved off the synchronous boot path (it
    # cost ~6m15s of downtime on every restart walking node_modules to conclude
    # there was nothing to migrate). See services/media_s3_migration.py.
    from services.media_s3_migration import start_media_s3_migration
    start_media_s3_migration(app)

    # NNTPChan (route-B) federation pull loop.
    from services.nntpchan.sync import start_background_sync as start_nntpchan_sync
    start_nntpchan_sync(app)
except Exception:
    app.logger.exception("Failed to start scraped-thread retirement")

try:
    from services.place_snapshot import start_place_snapshots
    start_place_snapshots(app)
except Exception:
    app.logger.exception("Failed to start graffiti-wall snapshots")

try:
    from services.video_offload import start_offload_controller
    start_offload_controller(app)
except Exception:
    app.logger.exception("Could not start video offload controller")

try:
    # Hourly emergency-cache snapshots. Off unless SNAPSHOT_TIMER_ENABLED, and
    # never without a publisher key: an unsigned snapshot is one no client will
    # serve, so scheduling them would render the whole site every hour to
    # produce something unusable.
    from services.snapshot_timer import start as start_snapshot_timer
    start_snapshot_timer()
except Exception:
    app.logger.exception("Could not start the snapshot timer")

try:
    from services.analytics.maintenance import start_analytics_maintenance
    start_analytics_maintenance(app)
except Exception:
    app.logger.exception("Could not start analytics maintenance")

try:
    from services.recommendations.training import start_recommendation_maintenance
    start_recommendation_maintenance(app)
except Exception:
    app.logger.exception("Could not start recommendation maintenance")

# Keeps the arcade's static content on the DHT: the school's courses, the
# vocabulary, the codeplay collections and any lab build context that has not
# been announced yet. The codeplay publisher had existed for a long time behind
# an admin button nobody pressed — 267 rows, 0 published — so the point of this
# is the schedule, not the publishing.
try:
    from services.arcade_publish_loop import start_arcade_publish
    start_arcade_publish(app)
except Exception:
    app.logger.exception("Could not start the arcade publish sweep")

# Stream recordings had the same shape of problem one layer over: they were
# written to a local-path volume on one node and served from there, so every
# archived broadcast existed exactly once while the rest of the site's media was
# already replicated on the DHT. This sweep moves them across and deletes the
# local copy.
try:
    from services.stream_archive_loop import start_stream_archive
    start_stream_archive(app)
except Exception:
    app.logger.exception("Could not start the stream archive sweep")

# The arcade compute queue had the same problem the publisher did: run_next()
# was correct and nothing ever called it, so /arcade/rent queued programs and
# ran none of them. One drainer per device, so a long GPU job does not hold up
# CPU work that could run beside it.
try:
    from services.compute_rental_worker import start_compute_rental_workers
    start_compute_rental_workers(app)
except Exception:
    app.logger.exception("Could not start the compute rental workers")

# Clusters get their own drainer. The one above is serial by design — one job
# per device at a time — and a cluster is N units that must run AT ONCE on N
# machines, which is the whole point of asking for a cluster. Draining them
# through the serial loop would turn "8 nodes for two minutes" into "one node
# for sixteen", which is not the thing that was bought.
#
# Imported inside the try rather than at module scope on purpose: this is the
# newest module in the boot path, and a site that will not start because one
# background drainer is missing is a far worse failure than a site that starts
# with clusters queued and nothing draining them.
try:
    from services.compute_cluster_worker import start_compute_cluster_workers
    start_compute_cluster_workers(app)
except Exception:
    app.logger.exception("Could not start the compute cluster workers")

try:
    from services.experiments import start_experiment_monitor
    start_experiment_monitor()
except Exception:
    app.logger.exception("Could not start experiment guardrail monitor")



@app.errorhandler(404)
def page_not_found(e):
    try:
        db.session.rollback()
    except Exception:
        pass
    return render_template("not-found.html"), 404


@app.errorhandler(500)
def internal_server_error(e):
    try:
        db.session.rollback()
    except Exception:
        pass
    app.logger.error(traceback.format_exc())
    return render_template("internal-error.html"), 500


@app.context_processor
def get_instance_name():
    def instance_name():
        return app.config["INSTANCE_NAME"]
    return dict(instance_name=instance_name)


@app.context_processor
def share_config():
    return dict(config=app.config)


@app.context_processor
def share_pooled_tips():
    """`tip_for(slip)` -> a tip-availability dict, or None (roadmap P15).

    Exposed as a global rather than passed by each route because pooled tipping
    appears on five unrelated surfaces — profile, forum post, article, byline,
    stream — and a route that forgot to pass it would silently show no button,
    which looks identical to "this person does not accept tips". A global is
    reachable from every template, so the answer is always the real one.

    It returns availability only. No amount, balance, aggregate or channel is
    computed here, and none could be: this server holds none of them.
    """
    from services.pooled_tips import tip_for

    return dict(tip_for=tip_for)


@app.context_processor
def share_static_integrity():
    """`integrity_for('js/x.js')` -> a Subresource Integrity value, or ''.

    The browser enforces SRI BEFORE running the script, which is the only way to
    protect the verifier from being modified — the manifest cannot do it, because
    checking the manifest is the verifier's own job and a tampered verifier will
    cheerfully declare itself valid.
    """
    def integrity_for(path):
        try:
            from services.static_manifest import cached_integrity
            return cached_integrity(path) or ""
        except Exception:
            return ""
    return dict(integrity_for=integrity_for)


@app.context_processor
def share_sysop_flag():
    """Expose sysop status to every template as `is_sysop`.

    A context processor rather than a per-render argument because several forms
    (board create, board admin, the admin dashboard's inline board form) share
    one template that needs to hide sysop-only controls — notably the NSFW filter
    toggle, which user-created boards must not be able to clear.
    """
    def _is_sysop():
        try:
            from model.Slip import slip_is_admin
            return bool(slip_is_admin())
        except Exception:
            return False
    return dict(is_sysop=_is_sysop())


@app.context_processor
def share_csrf():
    """`csrf_token()` and `csrf_input()` in every template.

    A context processor rather than a per-render argument because the forms that
    need it are spread across templates rendered by several different views, and
    a token that has to be passed explicitly is a token somebody forgets to pass
    -- which, since the check fails closed, presents as a broken admin page.

    Only templates that actually call one of these mint a token, so this does not
    put a session cookie on anonymous visitors who never see a protected form.
    """
    from services.csrf import current_token, token_input
    return dict(csrf_token=current_token, csrf_input=token_input)


@app.context_processor
def share_captcha():
    return get_template_context()


@app.route("/logo.png")
def site_logo():
    return send_from_directory("static", "logo.png", mimetype="image/png")


@app.route("/favicon.ico")
def favicon():
    # The small square favicon, not the full brand logo — see base.html.
    return send_from_directory("static", "favicon.png", mimetype="image/png")


@app.route("/health")
def health():
    return "OK", 200


@app.before_request
def _refuse_writes_during_a_cutover():
    """Read-only while the site is being moved to another server.

    A backup taken while posts are still landing is missing whatever arrived
    after it started, and nothing reports that — the loss only shows up later
    as posts that are simply absent. Freezing writes first is what makes the
    backup a complete record instead of a moving one.

    Admin stays open, always. A freeze that locks the operator out of the page
    that lifts it turns a planned cutover into a real outage.
    """
    from flask import jsonify, request

    try:
        from services.cutover import blocks, current, refusal

        if not blocks(request.method, request.path) or not current():
            return None
        payload = refusal()
    except Exception:
        # Never 500 over this. A broken freeze check that refused every write
        # would be a worse outage than the move it exists to protect.
        app.logger.debug("cutover freeze check failed", exc_info=True)
        return None

    response = jsonify(payload)
    response.status_code = 503
    response.headers["Retry-After"] = str(max(1, payload["retry_after_seconds"]))
    return response


@app.before_request
def _forward_to_the_current_domain():
    """A request on an old domain is handed forward, not 404'd.

    A name that still resolves and still answers should send people to where the
    site actually is. Anything else strands whoever has the old link — which,
    right after a move, is everyone.

    TEMPORARY, never permanent. A 301 is cached by browsers effectively forever,
    so moving back — the ordinary outcome of a registrar dispute being resolved
    — would leave readers pinned to a name the project no longer controls, with
    no way to reach them and say so.
    """
    from flask import redirect, request

    try:
        from services.network_directive import redirect_target

        target = redirect_target(
            request.host, request.path,
            request.query_string.decode("latin-1", "replace"),
            request.scheme or "https",
        )
    except Exception:
        # Never 500 a request over this. A broken directive check that took the
        # site down would be a worse outage than the domain change it exists to
        # smooth over.
        app.logger.debug("directive redirect check failed", exc_info=True)
        return None
    if target:
        return redirect(target, code=307)
    return None


@app.before_request
def _redirect_banned_visitors():
    """PERMANENTLY-banned IPs (no expiry) are forwarded to the sysop-configured
    "annoying" ban page. TIMED bans get a plain notice showing when they lift —
    the annoying treatment is reserved for permanent bans."""
    from flask import request, redirect, url_for, make_response
    path = request.path or "/"
    # Let the ban page, static/media assets and health checks through, so the
    # annoying page can load its content and there is no redirect loop.
    if (path.startswith("/static") or path.startswith("/upload")
            or path.startswith("/banned") or path == "/health"
            or path.startswith("/favicon")):
        return None
    try:
        import html
        from model.Ban import get_ban
        from services.client_ip import get_client_ip
        ip = get_client_ip()
        if not ip:
            return None
        ban = get_ban(ip)
        if ban is None:
            return None
        if ban.is_permanent:
            return redirect(url_for("main.banned"))
        # Timed ban: plain 403 notice with the lift time and reason, no popups.
        until = ban.expires_at.strftime("%Y-%m-%d %H:%M UTC")
        reason_html = ("<p>Reason: %s</p>" % html.escape(ban.reason)) if (ban.reason or "").strip() else ""
        body = (
            "<!doctype html><html><head><meta charset='utf-8'>"
            "<meta name='viewport' content='width=device-width,initial-scale=1'>"
            "<title>Temporarily banned</title></head>"
            "<body style='font:16px/1.6 -apple-system,BlinkMacSystemFont,sans-serif;"
            "max-width:34rem;margin:12vh auto;padding:0 1.2rem;color:#222'>"
            "<h1 style='font-size:1.4rem'>You are temporarily banned</h1>"
            "<p>Your access is suspended until <strong>%s</strong>.</p>%s"
            "<p style='color:#888;font-size:.9rem'>If you believe this is a mistake, contact a moderator.</p>"
            "</body></html>"
        ) % (until, reason_html)
        response = make_response(body, 403)
        response.headers["Content-Type"] = "text/html; charset=utf-8"
        return response
    except Exception:
        pass
    return None


@app.before_request
def _score_request_for_threat():
    """Score every request and record what WOULD have happened.

    Observe-only by design (roadmap/wall-of-shame.md phase 1). It returns None
    always — nothing here can block, challenge, or slow a response — because
    thresholds chosen before seeing real traffic are guesses, and a scorer
    shipped with guessed thresholds turns readers away before attackers.

    Wrapped whole in try/except and sampled: a security log that can 500 a
    request has become the outage it was meant to prevent.
    """
    try:
        from services.threat_watch import observe

        observe()
    except Exception:
        pass
    return None


@app.after_request
def _record_threat_outcome(response):
    """Persist the observation now that the status code exists.

    Separate from response signing on purpose: two unrelated concerns in one
    hook means a fault in either takes out both, and one of these is security
    logging while the other is what makes content verifiable.
    """
    try:
        from services.threat_watch import record_outcome

        record_outcome(response.status_code)
    except Exception:
        pass
    return response


@app.after_request
def _sign_response(response):
    """Attach an origin signature to the bytes about to be sent.

    Done here, once, rather than per blueprint: a signing scheme that covers
    some routes is a scheme a gateway can strip by choosing which route to
    attack, and "this response happens to be unsigned" is indistinguishable
    from "this response was tampered with" if only some are.

    The version is the object's cache generation where there is one, because
    that is already the number that changes exactly when the content does. The
    signature covers the key, the version and the body — see
    services/content_signing.py for why all three.

    Never raises. A response that could not be signed is still a response; the
    reader loses verification, not the page.
    """
    try:
        from services.content_signing import enabled, sign_object

        if not enabled() or response.direct_passthrough:
            return response
        # Only what a reader would verify. Redirects and errors carry no content
        # worth attesting to, and signing them would invite a client to treat a
        # 404 body as authoritative.
        if response.status_code != 200:
            return response
        content_type = (response.headers.get("Content-Type") or "").split(";")[0].strip()
        if content_type not in ("text/html", "application/json", "text/plain",
                                "text/css", "application/javascript"):
            return response

        body = response.get_data()
        if not body or len(body) > 4 * 1024 * 1024:
            # Signing a very large body costs a hash of it on every request for
            # a reader who is unlikely to be verifying inline anyway.
            return response

        from flask import request as _request

        key = _request.path
        version = _content_version(key)
        signed = sign_object(key, version, body)
        if signed is None:
            return response
        response.headers["X-Syndichan-Version"] = str(signed["version"])
        response.headers["X-Syndichan-Hash"] = signed["hash"]
        response.headers["X-Syndichan-Signature"] = signed["signature"]
        # So a client can find the key without knowing the convention.
        response.headers["X-Syndichan-Key"] = "/.well-known/syndichan/origin-key.json"
        # Who served this. The origin names itself "origin"; a volunteer gateway
        # overwrites this with its own key. Without it an observation has nothing
        # to attribute — and a gateway that strips it forfeits credit for honest
        # service, which is the incentive to leave it alone.
        response.headers.setdefault("X-Syndichan-Gateway", "origin")
    except Exception:
        from flask import request as _req
        app.logger.exception("response signing failed for %s", getattr(_req, "path", "?"))
    return response


def _content_version(key):
    """A monotonic version for an object.

    Content that goes through the render cache has a generation that already
    changes exactly when the content does, and that is the right number. For
    everything else the fallback is the process start time: it is monotonic
    across restarts, it does not go backwards, and it means a gateway cannot
    replay a body signed by an earlier deployment.

    It is deliberately NOT a wall-clock timestamp per request: two readers
    fetching the same unchanged page must get the same version, or every reader
    would think every page had changed.
    """
    try:
        import cache as _cache

        generation = _cache.cache.get("sig-gen:%s" % key)
        if generation is not None:
            return int(generation)
    except Exception:
        pass
    return _boot_epoch()


# Monotonic across restarts because it is the boot time, so a body signed by an
# older deployment cannot be replayed as current.
_CONTENT_EPOCH = None


def _boot_epoch():
    """Process start time, computed once, lazily.

    Deliberately NOT a module-level `int(time.time())`: `time` is not imported
    at this module's top level, so that would raise NameError during import and
    take the whole application down rather than degrading one header. This file
    has already been broken that way once today; the lazy form cannot do it.
    """
    global _CONTENT_EPOCH
    if _CONTENT_EPOCH is None:
        import time as _time

        _CONTENT_EPOCH = int(_time.time())
    return _CONTENT_EPOCH


@app.before_request
def _enforce_session_idle_timeout():
    """Per-account auto-logout: if the viewer's profile sets a session timeout,
    log them out once they've been idle longer than that. Idle time is tracked in
    the (permanent) session cookie; the limit is configured on the profile page."""
    from flask import request, session
    path = request.path or "/"
    if path.startswith("/static") or path.startswith("/upload") or path == "/health":
        return None
    if not session.get("session-id"):
        return None
    try:
        import time as _time
        from model.Slip import get_slip, clear_wallet_admin_session
        slip = get_slip()
        if slip is None:
            return None
        profile = getattr(slip, "profile", None)
        timeout_min = int(getattr(profile, "session_timeout_minutes", 0) or 0)
        if timeout_min <= 0:
            return None
        now = int(_time.time())
        last_active = session.get("la")
        if last_active and (now - int(last_active)) > timeout_min * 60:
            # Idle too long — end the session.
            sid = session.pop("session-id", None)
            session.pop("la", None)
            clear_wallet_admin_session()
            if sid:
                try:
                    from model.Session import Session as _Sess
                    db.session.query(_Sess).filter(_Sess.id == sid).delete(synchronize_session=False)
                    db.session.commit()
                except Exception:
                    db.session.rollback()
        else:
            # Only genuine navigation or the interaction keepalive counts as
            # activity. Background pollers (XHR/fetch on live pages) must NOT keep
            # the session alive, or auto-logout would never fire while a page is
            # left open. Real page loads send Sec-Fetch-Mode: navigate / Accept
            # text/html; the keepalive is fired by real user input (see base.html).
            accept = request.headers.get("Accept") or ""
            is_activity = (
                request.headers.get("Sec-Fetch-Mode") == "navigate"
                or "text/html" in accept
                or path == "/session/keepalive"
            )
            if is_activity:
                session["la"] = now
                session.permanent = True
    except Exception:
        try:
            db.session.rollback()
        except Exception:
            pass
    return None


@app.route("/static/<path:path>")
def serve_static(path):
    return send_from_directory("static", path)

sys.stderr.write("DEBUG: [app.py] FULLY LOADED\n")
sys.stderr.flush()
