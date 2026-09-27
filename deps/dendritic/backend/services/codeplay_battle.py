"""1v1 battles: matchmaking and live state.

WHY POLLING AND NOT SOCKET.IO
-----------------------------
Upstream used socket.io. This app is uWSGI + gevent, where every open
connection pins a gevent core -- and the last time long-lived streams and a
fast admin poll ran together they exhausted the pool and the site started
returning "async queue is full". Battles are short, bursty and rare compared to
page traffic, so they use Redis for state and a ~1s client poll: no held
connection per player, no new realtime dependency, and a battle that is
abandoned expires on its own via TTL rather than needing a disconnect event.

All battle state is in Redis with TTLs. Nothing here is worth a database table:
a battle is over in minutes, and only its OUTCOME (an attempt row and XP) is
durable.
"""
import json
import time
import uuid

import keystore

from shared import app

QUEUE_KEY = "arcade:battle:queue"
BATTLE_TTL = 30 * 60          # a battle record lives half an hour
QUEUE_TTL = 90                # a queue entry goes stale quickly
TURN_SECONDS = 300            # wall clock for a whole battle

_client = None


def _redis():
    global _client
    if _client is None:
        _client = keystore.make_redis()
    return _client


def _battle_key(battle_id):
    return "arcade:battle:%s" % battle_id


def _player_key(slip_id):
    return "arcade:battle:player:%s" % slip_id


def _load(battle_id):
    try:
        raw = _redis().get(_battle_key(battle_id))
    except Exception:
        app.logger.exception("battle: redis read failed")
        return None
    if not raw:
        return None
    try:
        return json.loads(raw)
    except (TypeError, ValueError):
        return None


def _save(battle):
    try:
        _redis().setex(_battle_key(battle["id"]), BATTLE_TTL, json.dumps(battle))
        for player in battle["players"]:
            _redis().setex(_player_key(player["slip_id"]), BATTLE_TTL, battle["id"])
    except Exception:
        app.logger.exception("battle: redis write failed")


def current_battle_id(slip):
    """The battle this slip is already in, if any."""
    if slip is None:
        return None
    try:
        value = _redis().get(_player_key(slip.id))
    except Exception:
        return None
    if isinstance(value, bytes):
        value = value.decode("utf-8", "replace")
    return value or None


def join_queue(slip, problem_picker):
    """Match with a waiting opponent, or wait.

    Returns (battle_id, waiting). The pop-then-check loop skips stale or
    self entries rather than trusting the queue's contents, because a player
    who closed the tab leaves their entry behind until it expires.
    """
    if slip is None:
        return None, False

    existing = current_battle_id(slip)
    if existing and _load(existing):
        return existing, False

    redis = _redis()
    try:
        while True:
            other = redis.lpop(QUEUE_KEY)
            if other is None:
                break
            if isinstance(other, bytes):
                other = other.decode("utf-8", "replace")
            try:
                waiting_id, queued_at = other.split(":", 1)
                waiting_id = int(waiting_id)
            except ValueError:
                continue
            if waiting_id == slip.id:
                continue                       # never match someone with themself
            if time.time() - float(queued_at) > QUEUE_TTL:
                continue                       # they gave up; drop the entry
            return _start(slip, waiting_id, problem_picker), False

        redis.rpush(QUEUE_KEY, "%d:%f" % (slip.id, time.time()))
        redis.expire(QUEUE_KEY, QUEUE_TTL * 4)
    except Exception:
        app.logger.exception("battle: matchmaking failed")
        return None, False
    return None, True


def leave_queue(slip):
    if slip is None:
        return
    try:
        redis = _redis()
        for entry in (redis.lrange(QUEUE_KEY, 0, -1) or []):
            text = entry.decode("utf-8", "replace") if isinstance(entry, bytes) else entry
            if text.startswith("%d:" % slip.id):
                redis.lrem(QUEUE_KEY, 0, entry)
    except Exception:
        app.logger.exception("battle: leaving queue failed")


def _name_for(slip_id):
    from model.Slip import Slip
    from shared import db
    row = db.session.query(Slip).filter(Slip.id == slip_id).one_or_none()
    return row.name if row else "player-%s" % slip_id


def _start(slip, opponent_id, problem_picker):
    problem = problem_picker()
    battle = {
        "id": uuid.uuid4().hex[:16],
        "started_at": time.time(),
        "ends_at": time.time() + TURN_SECONDS,
        "problem": problem,
        "players": [
            {"slip_id": opponent_id, "name": _name_for(opponent_id),
             "passed": 0, "total": 0, "finished": False, "finished_at": None},
            {"slip_id": slip.id, "name": slip.name,
             "passed": 0, "total": 0, "finished": False, "finished_at": None},
        ],
        "winner_slip_id": None,
        "over": False,
    }
    _save(battle)
    return battle["id"]


def state(battle_id, slip=None):
    """Battle state for rendering, with the clock resolved."""
    battle = _load(battle_id)
    if battle is None:
        return None
    if not battle["over"] and time.time() >= battle["ends_at"]:
        _finish(battle)
    battle["seconds_left"] = max(0, int(battle["ends_at"] - time.time()))
    if slip is not None:
        battle["you"] = next((p for p in battle["players"]
                              if p["slip_id"] == slip.id), None)
    return battle


def record_result(battle_id, slip, passed, total):
    """Store one player's judge result and decide the battle if it is settled."""
    battle = _load(battle_id)
    if battle is None or slip is None:
        return None
    for player in battle["players"]:
        if player["slip_id"] == slip.id:
            player["passed"] = passed
            player["total"] = total
            # Only a full pass ends someone's turn; a partial result is
            # recorded so the scoreboard moves, but they may keep trying.
            if total and passed == total and not player["finished"]:
                player["finished"] = True
                player["finished_at"] = time.time()
    if all(p["finished"] for p in battle["players"]) or \
            any(p["finished"] for p in battle["players"]) and battle["over"]:
        _finish(battle)
    elif any(p["finished"] for p in battle["players"]):
        # First to a full pass wins immediately; no reason to make the loser
        # sit out the clock.
        _finish(battle)
    else:
        _save(battle)
    return _load(battle_id)


def _finish(battle):
    """Decide a winner: most cases passed, earliest finish breaks a tie."""
    if battle.get("over"):
        return
    battle["over"] = True
    ranked = sorted(
        battle["players"],
        key=lambda p: (-p["passed"], p["finished_at"] or float("inf")),
    )
    best, second = ranked[0], ranked[1]
    if best["passed"] > 0 and (best["passed"] > second["passed"]
                               or (best["finished"] and not second["finished"])):
        battle["winner_slip_id"] = best["slip_id"]
    else:
        battle["winner_slip_id"] = None        # draw, including 0-0
    _save(battle)
    _award(battle)


def _award(battle):
    """Pay out XP once, when the battle ends."""
    from model.Slip import Slip
    from services import codeplay as game
    from shared import db

    problem = battle.get("problem") or {}
    for player in battle["players"]:
        won = battle["winner_slip_id"] == player["slip_id"]
        if not won and player["passed"] <= 0:
            continue
        slip = db.session.query(Slip).filter(Slip.id == player["slip_id"]).one_or_none()
        if slip is None:
            continue
        # Recorded under a battle-scoped item id so it never collides with the
        # same problem solved in single player, and so a rematch on the same
        # problem still counts.
        game.record_attempt(
            slip, "battle", "%s:%s" % (battle["id"], problem.get("id", "?")),
            correct=won, category=problem.get("category", ""),
            difficulty=problem.get("difficulty", "Medium"),
        )
    try:
        db.session.commit()
    except Exception:
        db.session.rollback()
        app.logger.exception("battle: could not record results")


def queue_depth():
    try:
        return int(_redis().llen(QUEUE_KEY) or 0)
    except Exception:
        return 0
