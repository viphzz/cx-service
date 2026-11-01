"""任务状态机（人工调度版）。

整个流程由管理员在面板上一步步推，agent 只负责登录和保活：

    submitted  用户已提交，排队中，等管理员点「开始登录」
        ↓ accept()
    queued     已批准，等 agent 领走
        ↓ lease()
    logging    agent 领到了，正在开浏览器登录
        ↓ agent 上报 ready
    ready      登录成功，浏览器挂着不动，等管理员点「开始刷课」
        ↓ begin()
    running    管理员已人工点进课程，脚本在刷
        ↓ finish()
    done       agent 收到后自动退出登录、关窗口、释放槽位

任何阶段都可能 failed / canceled。

为什么把判定「刷完了没有」整个删掉：学习通刷完就停在最后一章不动了，
管理员瞄一眼课表就知道。让机器去数 DOM 反而更不可靠——超星改一次版面
就得重写一次判据，而且判错了还要自动重刷，越滚越复杂。现在这套里没有
进度判定、没有被清空检测、没有守望复查、没有自动重刷，一个都没有。
"""
import json
from datetime import datetime, timedelta, timezone

import crypto
import db
from config import LEASE_SECONDS

# 这条任务还活着、占着刷课机槽位的状态
ACTIVE = ("logging", "ready", "running")

# 已经在用这个账号的状态。超星单点登录，同一账号同时登两处会互踢，
# 所以同账号的第二单在派发时必须跳过，等前面的结束了再说。
OCCUPYING = ("logging", "ready", "running")


def lease_seconds() -> int:
    """任务租期：系统设置（meta，运行时可调）优先，env 兜底。"""
    return db.setting_int("lease_seconds", LEASE_SECONDS)


def _now_dt() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.isoformat(timespec="seconds")


def create(card_code: str, account_id: int, course_name: str,
           note: str = "", course_id: str = "", rate: float = 1.0) -> int:
    """用户提交即建单，状态是 submitted（等你批准）。"""
    ts = db.now()
    tid = db.ex("""INSERT INTO tasks(card_code, account_id, course_id, course_name,
                              note, rate, status, created_at, updated_at)
                   VALUES(?,?,?,?,?,?,'submitted',?,?)""",
                (card_code, account_id, course_id or course_name, course_name,
                 note, rate, ts, ts))
    db.log(tid, "info", f"用户提交 课程={course_name}")
    return tid


def accept(task_id: int) -> dict:
    """管理员点「开始登录」：submitted -> queued，agent 就可以领了。

    这里刻意不检查账号是否被占用。同一账号的第二单也该被批准、正常排队，
    真正防顶号的地方在 lease()——它会把已经有任务占着这个账号的单往后放。
    如果在批准这一步就拦住，管理员就得盯着"哪个号现在空着"再点，
    队列的意义就没了。
    """
    task = db.q1("SELECT * FROM tasks WHERE id=?", (task_id,))
    if not task:
        return {"ok": False, "error": "任务不存在"}
    if task["status"] != "submitted":
        return {"ok": False, "error": f"任务当前是 {task['status']}，不能重复开始"}

    ts = db.now()
    db.ex("UPDATE tasks SET status='queued', updated_at=? WHERE id=? AND status='submitted'",
          (ts, task_id))
    db.log(task_id, "info", "管理员批准，进入派发队列")
    return {"ok": True, "status": "queued"}


def begin(task_id: int) -> dict:
    """管理员点「开始刷课」：ready -> running。只是改状态，给用户看进度用。"""
    task = db.q1("SELECT * FROM tasks WHERE id=?", (task_id,))
    if not task:
        return {"ok": False, "error": "任务不存在"}
    if task["status"] != "ready":
        return {"ok": False, "error": f"任务当前是 {task['status']}，还没登录好"}
    ts = db.now()
    db.ex("UPDATE tasks SET status='running', started_at=?, updated_at=? WHERE id=?",
          (ts, ts, task_id))
    db.log(task_id, "info", "管理员点了开始刷课")
    return {"ok": True, "status": "running"}


def finish(task_id: int) -> dict:
    """管理员点「标记完成」：running/ready -> done。

    agent 下一次保活上报会收到 action=stop，然后自己退登录、关窗口。
    """
    task = db.q1("SELECT * FROM tasks WHERE id=?", (task_id,))
    if not task:
        return {"ok": False, "error": "任务不存在"}
    if task["status"] not in ("running", "ready", "logging"):
        return {"ok": False, "error": f"任务当前是 {task['status']}，不能标记完成"}
    ts = db.now()
    db.ex("""UPDATE tasks SET status='done', finished_at=?, progress=1.0, updated_at=?
             WHERE id=?""", (ts, ts, task_id))
    db.log(task_id, "info", "管理员标记完成")
    return {"ok": True, "status": "done"}


def cancel(task_id: int, reason: str = "管理员取消") -> dict:
    task = db.q1("SELECT * FROM tasks WHERE id=?", (task_id,))
    if not task:
        return {"ok": False, "error": "任务不存在"}
    if task["status"] in ("done", "canceled"):
        return {"ok": False, "error": "任务已经结束了"}
    ts = db.now()
    db.ex("""UPDATE tasks SET status='canceled', agent_id=NULL, lease_until=NULL,
             message=?, updated_at=? WHERE id=?""", (reason[:500], ts, task_id))
    db.log(task_id, "warn", f"任务取消：{reason}")
    return {"ok": True, "status": "canceled"}


def lease(agent_id: str, slots: int) -> list[dict]:
    """给 agent 分配任务。只派 queued。

    查可领任务和标记已领放在同一个写事务里，用 BEGIN IMMEDIATE 抢写锁。
    SQLite 同一时刻只允许一个写者，所以两个 agent 同时来也拿不到同一条。

    还要排除「这个账号已经有任务在跑」——单点登录会互踢，
    派出去等于自己顶自己。
    """
    take = max(0, min(int(slots), 10))
    if take == 0:
        return []

    until = _iso(_now_dt() + timedelta(seconds=lease_seconds()))
    ts = db.now()
    picked: list[dict] = []

    with db.conn() as c:
        c.execute("BEGIN IMMEDIATE")
        busy_hashes = {
            r["username_hash"] for r in c.execute(f"""
                SELECT DISTINCT a.username_hash
                FROM accounts a JOIN tasks t ON t.account_id = a.id
                WHERE t.status IN {OCCUPYING} AND a.username_hash IS NOT NULL
            """).fetchall()
        }
        rows = c.execute(
            "SELECT * FROM tasks WHERE status='queued' ORDER BY id LIMIT ?",
            (take * 3,)).fetchall()
        for r in rows:
            if len(picked) >= take:
                break
            acc = c.execute("SELECT username_hash FROM accounts WHERE id=?",
                            (r["account_id"],)).fetchone()
            h = acc["username_hash"] if acc else None
            if h and h in busy_hashes:
                continue
            c.execute("""UPDATE tasks SET status='logging', agent_id=?, lease_until=?,
                         updated_at=? WHERE id=? AND status='queued'""",
                      (agent_id, until, ts, r["id"]))
            picked.append(dict(r))
            if h:
                busy_hashes.add(h)

    out = []
    for r in picked:
        acc = db.q1("SELECT * FROM accounts WHERE id=?", (r["account_id"],))
        if not acc:
            db.ex("UPDATE tasks SET status='failed', message='账号记录缺失' WHERE id=?",
                  (r["id"],))
            continue
        out.append({
            "task_id": r["id"],
            "account": {
                "username": crypto.decrypt(acc["username_enc"]),
                "password": crypto.decrypt(acc["password_enc"]),
            },
            "course": {
                "id": r["course_id"],
                "name": r["course_name"] or "",
                "note": r.get("note") or "",
            },
            "lease_seconds": lease_seconds(),
        })
        db.log(r["id"], "info", f"派给 {agent_id}")
    return out


def report(task_id: int, agent_id: str, status: str = "ready",
           message: str = "") -> dict:
    """处理 agent 上报。返回 action 告诉 agent 下一步做什么。

    agent 的用法：登录成功后每 30 秒报一次 ready，靠这个续约顺便问
    「我这单还要不要继续」。管理员点了完成，这里就回 action=stop，
    agent 收到后自己退登录、关窗口。

    action 含义：
      wait     继续挂着，别动页面
      running  管理员已经点了开始刷课，继续挂着
      stop     这单结束了，收工
    """
    task = db.q1("SELECT * FROM tasks WHERE id=?", (task_id,))
    if not task:
        return {"ok": False, "code": "TASK_GONE", "action": "stop", "error": "任务不存在"}
    if task["agent_id"] != agent_id:
        return {"ok": False, "code": "TASK_GONE", "action": "stop", "error": "任务不属于该 agent"}

    ts = db.now()

    # 管理员已经收尾（完成/取消），或者任务被判失败，agent 立刻收工
    if task["status"] in ("done", "canceled", "failed"):
        db.ex("UPDATE tasks SET agent_id=NULL, lease_until=NULL WHERE id=?", (task_id,))
        return {"ok": False, "code": "TASK_GONE", "action": "stop",
                "error": f"任务已{ {'done':'完成','canceled':'取消','failed':'失败'}[task['status']] }"}

    until = _iso(_now_dt() + timedelta(seconds=lease_seconds()))
    patch = {"updated_at": ts, "lease_until": until, "agent_id": agent_id}

    if status == "logging":
        if task["status"] in ("queued", "logging"):
            patch["status"] = "logging"
    elif status == "ready":
        # 已经在 running 的不要被打回 ready，否则用户那边的进度条会来回跳
        if task["status"] in ("logging", "ready"):
            patch["status"] = "ready"
    elif status == "failed":
        patch["status"] = "failed"
        patch["agent_id"] = None
        patch["lease_until"] = None
        if message:
            patch["message"] = message[:500]
    elif status == "paused":
        # agent 主动交还（进程退出、profile 被占用、登录失败）。退回 submitted，
        # 让管理员决定是重试还是取消，不自动重排——人工流程里自动重试只会添乱。
        patch["status"] = "submitted"
        patch["agent_id"] = None
        patch["lease_until"] = None
        if message:
            patch["message"] = message[:500]

    if message and status not in ("failed", "paused"):
        patch["message"] = message[:500]

    sets = ", ".join(f"{k}=?" for k in patch)
    db.ex(f"UPDATE tasks SET {sets} WHERE id=?", tuple(patch.values()) + (task_id,))

    if status == "failed":
        db.log(task_id, "error", f"agent 报失败：{message[:200]}", agent_id)
        return {"ok": True, "action": "stop", "server_time": ts}
    if status == "paused":
        db.log(task_id, "warn", f"agent 交还任务：{message[:200]}", agent_id)
        return {"ok": True, "action": "stop", "server_time": ts}

    now_status = db.q1("SELECT status FROM tasks WHERE id=?", (task_id,))
    st = (now_status or {}).get("status") or ""
    if st == "running":
        return {"ok": True, "action": "running", "server_time": ts}
    if st == "done":
        return {"ok": True, "action": "stop", "server_time": ts}
    return {"ok": True, "action": "wait", "server_time": ts}


def requeue(task_id: int, reason: str = "") -> bool:
    task = db.q1("SELECT * FROM tasks WHERE id=?", (task_id,))
    if not task or task["status"] in ("canceled", "done"):
        return False
    db.ex("""UPDATE tasks SET status='submitted', agent_id=NULL, lease_until=NULL,
             updated_at=?, message=? WHERE id=?""",
          (db.now(), reason[:500], task_id))
    db.log(task_id, "info", f"退回排队：{reason}")
    return True


def reap_expired() -> int:
    """回收租约超时的任务。

    agent 每 30 秒保活一次会刷新 lease_until，所以正常情况下不会超时。
    真超时了说明 agent 挂了或者断电了：
      logging 阶段 -> 退回 submitted，重新排队，管理员再点一次就行
      ready/running 阶段 -> 判 failed，因为浏览器已经没了，人工刷课也接不上了
    """
    ts = db.now()
    rows = db.q("""SELECT id, status, agent_id FROM tasks
                   WHERE status IN ('logging','ready','running')
                     AND lease_until IS NOT NULL AND lease_until < ?""", (ts,))
    for r in rows:
        if r["status"] == "logging":
            db.ex("""UPDATE tasks SET status='submitted', agent_id=NULL, lease_until=NULL,
                     message='登录超时，已退回排队', updated_at=? WHERE id=?""",
                  (ts, r["id"]))
            db.log(r["id"], "warn", f"登录超时回收（原 agent={r['agent_id']}）")
        else:
            db.ex("""UPDATE tasks SET status='failed', agent_id=NULL, lease_until=NULL,
                     message='刷课机失联，任务中断', updated_at=? WHERE id=?""",
                  (ts, r["id"]))
            db.log(r["id"], "error", f"刷课机失联（原 agent={r['agent_id']}），任务判失败")
    return len(rows)


def stats() -> dict:
    rows = db.q("SELECT status, COUNT(*) AS n FROM tasks GROUP BY status")
    by = {r["status"]: r["n"] for r in rows}
    out = {k: by.get(k, 0) for k in
           ("submitted", "queued", "logging", "ready", "running",
            "done", "failed", "canceled")}
    out["total"] = sum(by.values())
    return out


def queue_position(task_id: int) -> int:
    """排队名次（1 开始）。只数 submitted 里比它早的。"""
    row = db.q1("""SELECT COUNT(*) AS n FROM tasks
                   WHERE status='submitted' AND id < ?""", (task_id,))
    return int((row or {}).get("n") or 0) + 1
