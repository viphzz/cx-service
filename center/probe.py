"""课程探测：用户填卡密 + 账号密码，agent 登录后把课程列表抓回来给他选。

为什么不放在兑换一步做完：
学习通有单点登录和风控，登录这件事只能在刷课机的真实浏览器里做。所以
「登录」必须变成一次独立的、派给 agent 的短任务，服务器只负责在中间传话。

这条链路的关键收益：探测定下来的 profile 会被正式刷课任务直接复用，
用户选完课提交时不用再登录一次，等于把风控暴露面减半。

为什么不扣配额：探测本身不产生任何学习记录，扣配额等于用户"看一眼课程
列表"就花掉一次购买。真正扣配额在选完课提交任务那一步。
但不扣配额就必须限制次数，否则一张卡可以无限登录不同账号——那等于
拿你的卡网当撞库工具。所以按卡密限制总探测次数。
"""
from datetime import datetime, timedelta, timezone

import crypto
import db
from config import PROBE_LIMIT_PER_CARD, PROBE_KEEP_MINUTES

LEASE_SECONDS = 600          # 探测任务租期，比刷课短得多，2 分钟登录不完就是有问题


def _now() -> str:
    return db.now()


def _iso(dt: datetime) -> str:
    return dt.isoformat(timespec="seconds")


def count_by_card(card_code: str) -> int:
    row = db.q1("""SELECT COUNT(*) AS n FROM probes
                   WHERE card_code=? AND status != 'canceled'""", (card_code,))
    return int(row["n"]) if row else 0


def create(card_code: str, username: str, password: str) -> dict:
    """建一个探测任务。返回 {ok, probe_id} 或 {ok: False, reason, code}。"""
    n = count_by_card(card_code)
    if n >= PROBE_LIMIT_PER_CARD:
        return {"ok": False, "code": "PROBE_LIMIT",
                "reason": f"这张卡密已探测 {n} 次，达到上限（{PROBE_LIMIT_PER_CARD} 次）。"
                          f"课程信息可以直接手填 courseid 提交"}

    ts = _now()
    pid = db.ex("""INSERT INTO probes(card_code, username_enc, username_hash,
                            password_enc, status, created_at, updated_at)
                   VALUES(?,?,?,?, 'queued', ?, ?)""",
                (card_code, crypto.encrypt(username), _hash(username),
                 crypto.encrypt(password), ts, ts))
    db.log(None, "info", f"课程探测创建 #{pid} 账号={crypto.mask(username)}")
    return {"ok": True, "probe_id": pid}


def _hash(username: str) -> str:
    import hashlib
    return hashlib.sha256((username or "").strip().encode("utf-8")).hexdigest()


def lease(agent_id: str) -> dict | None:
    """给 agent 派一个探测任务。一次只派一个，避免一台机器同时开一堆探测浏览器。"""
    ts = _now()
    until = _iso(datetime.now(timezone.utc) + timedelta(seconds=LEASE_SECONDS))

    with db.conn() as c:
        c.execute("BEGIN IMMEDIATE")
        row = c.execute(
            "SELECT * FROM probes WHERE status='queued' ORDER BY id LIMIT 1").fetchone()
        if not row:
            return None
        c.execute("""UPDATE probes SET status='leased', agent_id=?, lease_until=?,
                     updated_at=? WHERE id=? AND status='queued'""",
                  (agent_id, until, ts, row["id"]))
        probe_id = row["id"]
        username_enc = row["username_enc"]
        password_enc = row["password_enc"]

    return {
        "probe_id": probe_id,
        "account": {
            "username": crypto.decrypt(username_enc),
            "password": crypto.decrypt(password_enc),
        },
        "lease_seconds": LEASE_SECONDS,
    }


def report(probe_id: int, agent_id: str, status: str = "running",
           courses: list | None = None, message: str = "") -> dict:
    import json

    row = db.q1("SELECT * FROM probes WHERE id=?", (probe_id,))
    if not row:
        return {"ok": False, "code": "PROBE_GONE", "error": "探测任务不存在"}
    if row["agent_id"] != agent_id:
        return {"ok": False, "code": "PROBE_GONE", "error": "探测任务不属于该 agent"}
    if row["status"] == "canceled":
        return {"ok": False, "code": "PROBE_GONE", "error": "探测已取消"}

    ts = _now()
    patch = {"updated_at": ts, "lease_until":
             _iso(datetime.now(timezone.utc) + timedelta(seconds=LEASE_SECONDS))}

    if status in ("done", "failed"):
        patch["status"] = status
        patch["agent_id"] = None
        patch["lease_until"] = None
    else:
        patch["status"] = "running"

    if courses is not None:
        patch["courses"] = json.dumps(courses, ensure_ascii=False)
    if message:
        patch["message"] = message[:500]

    sets = ", ".join(f"{k}=?" for k in patch)
    db.ex(f"UPDATE probes SET {sets} WHERE id=?", tuple(patch.values()) + (probe_id,))

    if status == "done":
        n = len(courses or [])
        db.log(None, "info", f"课程探测 #{probe_id} 完成，抓到 {n} 门课", agent_id)
        return {"ok": True, "action": "stop", "count": n}
    if status == "failed":
        db.log(None, "error", f"课程探测 #{probe_id} 失败：{message[:200]}", agent_id)
        return {"ok": True, "action": "stop"}
    return {"ok": True, "action": "continue"}


def get(probe_id: int) -> dict | None:
    import json

    row = db.q1("SELECT * FROM probes WHERE id=?", (probe_id,))
    if not row:
        return None
    courses = None
    if row["courses"]:
        try:
            courses = json.loads(row["courses"])
        except Exception:
            courses = None
    return {
        "id": row["id"],
        "status": row["status"],
        "courses": courses,
        "message": row["message"],
        "updated_at": row["updated_at"],
    }


def reap_expired() -> int:
    """探测任务超时回收。登录失败/浏览器崩溃都会卡在 running。"""
    ts = _now()
    rows = db.q("""SELECT id FROM probes
                   WHERE status IN ('leased','running')
                     AND lease_until IS NOT NULL AND lease_until < ?""", (ts,))
    for r in rows:
        db.ex("""UPDATE probes SET status='failed', agent_id=NULL, lease_until=NULL,
                 message='探测超时（agent 未按时上报）', updated_at=? WHERE id=?""",
              (ts, r["id"]))
    return len(rows)


def purge_old() -> int:
    """清理过期的探测记录，它们只在用户选课时有用，没必要长期留着账号密码。"""
    cutoff = (datetime.now(timezone.utc)
              - timedelta(minutes=PROBE_KEEP_MINUTES)).isoformat(timespec="seconds")
    rows = db.q("SELECT id FROM probes WHERE created_at < ?", (cutoff,))
    for r in rows:
        db.ex("DELETE FROM probes WHERE id=?", (r["id"],))
    return len(rows)
