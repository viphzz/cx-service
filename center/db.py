"""调度中心存储层（SQLite）。

选 SQLite 不是偷懒：这个业务的数据量是每天几十单、同时在跑几个任务，
PG 的运维成本远大于收益。真要做集群再换，届时只需重写这一层。

并发靠 WAL + 每次操作独立连接。FastAPI 是单进程多协程，
SQLite 的写锁在毫秒级，不会成为瓶颈。
"""
import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone

from config import DB_PATH

SCHEMA = """
CREATE TABLE IF NOT EXISTS cards (
    code         TEXT PRIMARY KEY,
    product      TEXT NOT NULL,
    quota        INTEGER NOT NULL DEFAULT 1,      -- 剩余次数
    quota_total  INTEGER,                         -- 初始次数（分组/展示用）
    status       TEXT NOT NULL DEFAULT 'unused',   -- unused/active/expired/revoked
    batch        TEXT,
    created_at   TEXT NOT NULL,
    activated_at TEXT,
    expires_at   TEXT
);

CREATE TABLE IF NOT EXISTS accounts (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    card_code     TEXT NOT NULL,
    username_enc  BLOB NOT NULL,
    username_hash TEXT,                            -- sha256(手机号)，用于跨记录去重
    password_enc  BLOB NOT NULL,
    school        TEXT,                            -- 学校名，用于判断是否本校
    profile       TEXT,                            -- 刷课机上的 profile 目录名
    created_at    TEXT NOT NULL,
    last_login_at TEXT
);

CREATE TABLE IF NOT EXISTS tasks (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    card_code     TEXT,
    account_id    INTEGER NOT NULL,
    course_id     TEXT NOT NULL,
    clazz_id      TEXT,
    cpi           TEXT,
    course_name   TEXT,
    sections      TEXT,                            -- JSON 数组；null 表示整门课
    rate          REAL DEFAULT 1.0,
    -- 状态机（全部由人工在管理面板推进，agent 只负责登录和保活）：
    --   submitted 用户已提交，排队中，等管理员点「开始登录」
    --   queued    已批准，等 agent 领走
    --   logging   agent 已领到，正在登录
    --   ready     登录成功，浏览器挂着，等管理员点「开始刷课」
    --   running   正在刷，管理员已人工点进课程
    --   done / failed / canceled
    status        TEXT NOT NULL DEFAULT 'submitted',
    done          INTEGER DEFAULT 0,               -- 剩余未完成任务点数，0=全部做完（不是已完成数）
    total         INTEGER DEFAULT 0,               -- 任务点总数
    best_done     INTEGER,                         -- 历史最小剩余值；NULL 表示还没上报过
    progress      REAL DEFAULT 0,
    current       TEXT,
    message       TEXT,
    note          TEXT,                            -- 用户填的备注（授课老师、班级等），管理员分辨课程用
    agent_id      TEXT,
    lease_until   TEXT,
    rebrush_round INTEGER DEFAULT 0,               -- 历史字段，保留兼容
    resume_count  INTEGER DEFAULT 0,               -- 历史字段，保留兼容
    check_only    INTEGER DEFAULT 0,               -- 历史字段，保留兼容
    watch_until   TEXT,                            -- 历史字段，保留兼容
    last_check_at TEXT,
    started_at    TEXT,                            -- 管理员点「开始刷课」的时间
    finished_at   TEXT,                            -- 管理员点「标记完成」的时间
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS agents (
    id          TEXT PRIMARY KEY,                  -- pc-01
    token       TEXT NOT NULL UNIQUE,              -- X-Agent-Token
    name        TEXT,
    capacity    INTEGER DEFAULT 4,
    running     INTEGER DEFAULT 0,
    version     TEXT,
    browser     TEXT,
    status      TEXT DEFAULT 'online',             -- online/offline/paused
    paused      INTEGER DEFAULT 0,                 -- 1=不领新任务（手上正在跑的不受影响）
    note        TEXT,
    last_seen   TEXT,
    created_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS events (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id INTEGER,
    agent_id TEXT,
    ts      TEXT NOT NULL,
    level   TEXT NOT NULL,
    msg     TEXT NOT NULL
);

-- 课程探测：用户填卡密 + 账号密码，agent 登录后把课程列表抓回来给用户选。
-- 它不扣卡密配额（真正扣配额在用户选完课提交任务时），但有次数上限，
-- 否则一张卡可以无限登录别人的账号。
CREATE TABLE IF NOT EXISTS probes (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    card_code     TEXT,
    username_enc  BLOB NOT NULL,
    username_hash TEXT,
    password_enc  BLOB NOT NULL,
    status        TEXT NOT NULL DEFAULT 'queued',  -- queued/leased/running/done/failed/canceled
    agent_id      TEXT,
    lease_until   TEXT,
    courses       TEXT,                            -- JSON 课程列表
    message       TEXT,
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT
);

-- 服务公告（后台管理，前台只读已发布）
CREATE TABLE IF NOT EXISTS announcements (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    title      TEXT NOT NULL,
    content    TEXT NOT NULL,
    is_pinned  INTEGER NOT NULL DEFAULT 0,
    published  INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

-- 帮助中心文章
CREATE TABLE IF NOT EXISTS help_articles (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    title      TEXT NOT NULL,
    content    TEXT NOT NULL,
    category   TEXT NOT NULL DEFAULT '常见问题',
    sort       INTEGER NOT NULL DEFAULT 0,
    published  INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

-- 用户反馈（回复内联，单轮回复足够当前业务；要多轮对话再拆表）
CREATE TABLE IF NOT EXISTS feedback (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    kind       TEXT NOT NULL,
    task_id    INTEGER,
    contact    TEXT,
    content    TEXT NOT NULL,
    status     TEXT NOT NULL DEFAULT 'pending',   -- pending/processing/resolved
    reply      TEXT,
    replied_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

-- 管理员操作审计（只记动作和对象，绝不记密码/token）
CREATE TABLE IF NOT EXISTS admin_audit (
    id     INTEGER PRIMARY KEY AUTOINCREMENT,
    action TEXT NOT NULL,
    object TEXT,
    detail TEXT,
    ip     TEXT,
    ts     TEXT NOT NULL
);

-- 前台用户账号（手机号 + PBKDF2 密码哈希）。用于登录后直接查询自己的订单。
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at    TEXT NOT NULL,
    last_login_at TEXT,
    status        TEXT NOT NULL DEFAULT 'active'
);

CREATE INDEX IF NOT EXISTS idx_tasks_status ON tasks(status);
CREATE INDEX IF NOT EXISTS idx_tasks_agent  ON tasks(agent_id);
CREATE INDEX IF NOT EXISTS idx_events_task  ON events(task_id);
CREATE INDEX IF NOT EXISTS idx_accounts_card ON accounts(card_code);
CREATE INDEX IF NOT EXISTS idx_probes_status ON probes(status);
CREATE INDEX IF NOT EXISTS idx_feedback_status ON feedback(status);
"""


def meta_get(key: str, default: str | None = None) -> str | None:
    row = q1("SELECT value FROM meta WHERE key=?", (key,))
    return row["value"] if row else default


def meta_set(key: str, value: str):
    ex("INSERT OR REPLACE INTO meta(key, value) VALUES(?,?)", (key, value))


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@contextmanager
def conn():
    c = sqlite3.connect(DB_PATH, timeout=30)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA journal_mode=WAL")
    c.execute("PRAGMA foreign_keys=ON")
    try:
        yield c
        c.commit()
    except Exception:
        c.rollback()
        raise
    finally:
        c.close()


def init():
    with conn() as c:
        c.executescript(SCHEMA)
    _migrate()


def _columns(table: str) -> list[str]:
    with conn() as c:
        return [r[1] for r in c.execute(f"PRAGMA table_info({table})")]


def _migrate():
    """老库补列。SQLite 没有 ADD COLUMN IF NOT EXISTS，只能自己判断。"""
    cols = _columns("accounts")
    with conn() as c:
        if "username_hash" not in cols:
            c.execute("ALTER TABLE accounts ADD COLUMN username_hash TEXT")
            c.execute("CREATE INDEX IF NOT EXISTS idx_accounts_hash "
                      "ON accounts(username_hash)")

    tcols = _columns("tasks")
    with conn() as c:
        if "resume_count" not in tcols:
            c.execute("ALTER TABLE tasks ADD COLUMN resume_count INTEGER DEFAULT 0")
        # 守望复查用：标记"这次派发只是去读一次进度，不是去刷课"
        if "check_only" not in tcols:
            c.execute("ALTER TABLE tasks ADD COLUMN check_only INTEGER DEFAULT 0")
        # 人工流程用：用户备注、开始刷课时间、完成时间
        if "note" not in tcols:
            c.execute("ALTER TABLE tasks ADD COLUMN note TEXT")
        if "started_at" not in tcols:
            c.execute("ALTER TABLE tasks ADD COLUMN started_at TEXT")
        if "finished_at" not in tcols:
            c.execute("ALTER TABLE tasks ADD COLUMN finished_at TEXT")
        # 前台用户绑定：登录后下单的记录归属，用于「我的订单」查询
        if "user_id" not in tcols:
            c.execute("ALTER TABLE tasks ADD COLUMN user_id INTEGER")

    ccols = _columns("cards")
    with conn() as c:
        if "quota_total" not in ccols:
            c.execute("ALTER TABLE cards ADD COLUMN quota_total INTEGER")
        # 老数据回填：原始次数 ≈ 当前剩余 + 已产生的订单数（幂等，只补空缺/异常值）
        c.execute(
            "UPDATE cards SET quota_total = quota + "
            "(SELECT COUNT(*) FROM tasks t WHERE t.card_code = cards.code) "
            "WHERE quota_total IS NULL OR quota_total < 1"
        )

    acols = _columns("agents")
    with conn() as c:
        if "paused" not in acols:
            c.execute("ALTER TABLE agents ADD COLUMN paused INTEGER DEFAULT 0")
        # 节点健康字段（agent 心跳可选上报，老行/老 agent 为 NULL，照常运行）
        for col, typ in (("cpu", "REAL"), ("memory", "REAL"), ("uptime", "TEXT")):
            if col not in acols:
                c.execute(f"ALTER TABLE agents ADD COLUMN {col} {typ}")

    # 老库里的 queued/leased/paused/verify_required 都是旧状态机的产物，
    # 新流程只认 submitted/queued/logging/ready/running/done/failed/canceled。
    # 未完成的旧任务统一退回 submitted，让管理员重新决定要不要开始。
    with conn() as c:
        c.execute("""UPDATE tasks SET status='submitted'
                     WHERE status IN ('leased','paused','verify_required')""")

    # 帮助中心从旧兑换页 FAQ 迁移真实内容（只在表为空时做一次，不算 Mock）
    with conn() as c:
        n = c.execute("SELECT COUNT(*) FROM help_articles").fetchone()[0]
        if n == 0:
            ts = now()
            seeds = [
                ("卡密使用", 1, "购买后如何兑换？",
                 "在店铺下单后获得兑换卡密，进入「服务兑换」输入卡密验证，"
                 "验证成功后填写服务信息并确认提交即可。"),
                ("服务提交", 2, "提交后多久开始处理？",
                 "订单按提交顺序排队，轮到后会自动开始，不需要你做任何操作。"
                 "高峰期可能需要等待，进度页会实时显示当前状态。"),
                ("服务进度", 3, "处理期间我能登录学习通吗？",
                 "不能。处理期间登录会把服务顶下线，导致本次失败且卡密不退。"
                 "请等订单显示「已完成」后再登录查看。"),
                ("常见问题", 4, "课程名称填错了怎么办？",
                 "提交后请立即联系客服说明情况，提供你的卡密和处理中的服务编号，"
                 "我们会帮你处理。"),
            ]
            for cat, sort, title, content in seeds:
                c.execute(
                    "INSERT INTO help_articles(title, content, category, sort, published, created_at, updated_at) "
                    "VALUES(?,?,?,?,1,?,?)", (title, content, cat, sort, ts, ts))


def log(task_id: int | None, level: str, msg: str, agent_id: str | None = None):
    with conn() as c:
        c.execute("INSERT INTO events(task_id, agent_id, ts, level, msg) VALUES(?,?,?,?,?)",
                  (task_id, agent_id, now(), level, msg[:4000]))


def audit(action: str, obj: str = "", detail: str = "", ip: str = ""):
    """管理员操作审计。只记动作、对象、说明和 IP——绝不记密码和 token。"""
    with conn() as c:
        c.execute("INSERT INTO admin_audit(action, object, detail, ip, ts) VALUES(?,?,?,?,?)",
                  (action[:64], (obj or "")[:128], (detail or "")[:400], (ip or "")[:64], now()))


def setting_int(key: str, default: int) -> int:
    """读运行时可调整数值（系统设置写入 meta），非法/缺失时回落 env 默认。"""
    row = q1("SELECT value FROM meta WHERE key=?", (key,))
    if row:
        try:
            return int(row["value"])
        except (TypeError, ValueError):
            pass
    return default


def setting_str(key: str, default: str = "") -> str:
    row = q1("SELECT value FROM meta WHERE key=?", (key,))
    return row["value"] if row and row["value"] is not None else default


def log(task_id: int | None, level: str, msg: str, agent_id: str | None = None):
    with conn() as c:
        c.execute("INSERT INTO events(task_id, agent_id, ts, level, msg) VALUES(?,?,?,?,?)",
                  (task_id, agent_id, now(), level, msg[:4000]))


def q(sql: str, args: tuple = ()) -> list[dict]:
    with conn() as c:
        return [dict(r) for r in c.execute(sql, args).fetchall()]


def q1(sql: str, args: tuple = ()) -> dict | None:
    with conn() as c:
        r = c.execute(sql, args).fetchone()
        return dict(r) if r else None


def ex(sql: str, args: tuple = ()) -> int:
    with conn() as c:
        cur = c.execute(sql, args)
        return cur.lastrowid or cur.rowcount


def jload(s, default=None):
    if not s:
        return default
    try:
        return json.loads(s)
    except Exception:
        return default


def prune_events(retention_days: int) -> int:
    """删除超过保留期的事件日志，返回删除条数。

    ts 统一由 now() 生成（UTC ISO 秒级），同格式字符串比较即可。
    由后台循环调用，不在请求路径里执行。
    """
    cutoff = (datetime.now(timezone.utc)
              - timedelta(days=retention_days)).isoformat(timespec="seconds")
    row = q1("SELECT COUNT(*) AS n FROM events WHERE ts < ?", (cutoff,))
    n = int((row or {}).get("n") or 0)
    if n:
        ex("DELETE FROM events WHERE ts < ?", (cutoff,))
    return n


def prune_shots(retention_days: int) -> int:
    """删除超过保留期的异常截图文件，返回删除张数。"""
    from config import DATA

    import time as _time
    cutoff = _time.time() - retention_days * 86400
    n = 0
    d = DATA / "shots"
    if not d.exists():
        return 0
    for f in d.iterdir():
        try:
            if f.is_file() and f.stat().st_mtime < cutoff:
                f.unlink()
                n += 1
        except OSError:
            continue
    return n


def is_quiet_hour(quiet: str = "0-7") -> bool:
    """判断当前是否在禁刷时段。

    超星对凌晨挂脚本很敏感，官方 FQA 也提到过类似风险，
    所以默认 0-7 点不派新任务（已在跑的任务不打断）。
    """
    if not quiet:
        return False
    try:
        start_s, end_s = quiet.split("-")
        start, end = int(start_s), int(end_s)
    except Exception:
        return False
    h = datetime.now().hour
    if start <= end:
        return start <= h < end
    return h >= start or h < end
