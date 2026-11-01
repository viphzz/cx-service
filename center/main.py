"""调度中心主服务。

三组接口：
  /api/agent/*  给刷课机 agent 调用，X-Agent-Token 认证，agent 主动轮询
  /api/*        给用户兑换页调用，凭卡密
  /admin/*      给你自己用，X-Admin-Token 认证

后台还有两个循环：
  reap    回收租约超时的任务，不让任务卡死在"运行中"
  watch   完成后定期复查，发现学习记录被清空就自动重排
"""
import asyncio
import hashlib
import hmac
import json
import secrets
import time
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from pydantic import BaseModel, Field

import accounts
import cards
import crypto
import db
import probe
import tasks
import config as C


# ---------------------------------------------------------------- 认证

def agent_auth(x_agent_token: str = Header(default="")) -> dict:
    if not x_agent_token:
        raise HTTPException(401, detail={"error": "缺少 token", "code": "TOKEN_INVALID"})
    row = db.q1("SELECT * FROM agents WHERE token=?", (x_agent_token,))
    if not row:
        raise HTTPException(401, detail={"error": "token 无效", "code": "TOKEN_INVALID"})
    db.ex("UPDATE agents SET last_seen=?, status='online' WHERE id=?", (db.now(), row["id"]))
    return row


# 管理面板会话。
# 不再把 token 印在 URL 上：地址栏会进书签、浏览历史、代理日志和截图，
# 而这个面板能看到所有用户的手机号、课程和密码密文。
ADMIN_COOKIE = "cx_admin"
_ADMIN_FAILS: dict = {}


def _admin_session_value(exp: int) -> str:
    """{exp_unix}.{HMAC}——cookie 值本身带过期时刻，服务端强制校验。

    旧版是固定 HMAC：浏览器 max_age 到期只是浏览器不再发送，值本身永久
    有效，任何拿到这个值的人都能无限期冒充管理员。现在把 unix 过期时刻
    一起签进去，过期、截短、改一个字符都直接 401。
    """
    sig = hmac.new(C.SECRET_KEY.encode("utf-8"),
                   f"admin-session-v2:{exp}".encode(), hashlib.sha256).hexdigest()[:32]
    return f"{exp}.{sig}"


def _admin_cookie_valid(tok: str) -> bool:
    exp_s, dot, sig = tok.partition(".")
    if not dot or not sig:
        return False
    try:
        exp = int(exp_s)
    except ValueError:
        return False
    if exp <= 0 or time.time() >= exp:
        return False
    expect = _admin_session_value(exp).split(".", 1)[1]
    return hmac.compare_digest(sig, expect)


def admin_auth(request: Request, x_admin_token: str = Header(default="")):
    """管理接口鉴权：浏览器面板走 cookie，命令行和脚本走 X-Admin-Token。"""
    tok = request.cookies.get(ADMIN_COOKIE) or ""
    if tok and _admin_cookie_valid(tok):
        return
    if x_admin_token and secrets.compare_digest(x_admin_token, C.ADMIN_TOKEN):
        return
    raise HTTPException(401, detail={"error": "未登录", "code": "UNAUTHORIZED"})


# ---------------------------------------------------------------- 前台用户会话

USER_COOKIE = "cx_user"
USER_SESSION_DAYS = 7


def _user_session_value(uid: int, exp: int) -> str:
    sig = hmac.new(C.SECRET_KEY.encode("utf-8"),
                   f"user-session-v1:{uid}:{exp}".encode(),
                   hashlib.sha256).hexdigest()[:32]
    return f"{uid}.{exp}.{sig}"


def current_user(request: Request) -> dict | None:
    """解析前台登录态。无效/过期一律当未登录，不抛错。"""
    tok = request.cookies.get(USER_COOKIE) or ""
    parts = tok.split(".")
    if len(parts) != 3:
        return None
    try:
        uid, exp = int(parts[0]), int(parts[1])
    except ValueError:
        return None
    if exp <= time.time():
        return None
    expect = _user_session_value(uid, exp).split(".", 2)[2]
    if not hmac.compare_digest(parts[2], expect):
        return None
    row = db.q1("SELECT id, username, created_at FROM users WHERE id=? AND status='active'",
                (uid,))
    return row


def view_token(obj_id: int, kind: str = "task") -> str:
    """查看凭证（任务进度页、课程探测结果页共用）。

    原来是 /s/{task_id} 直接拿自增 ID 当凭证——ID 是连续整数，任何人从 1
    往上撸就能看别人买了什么课、刷到第几章、用的哪个机器。这属于客户隐私，
    而且这类站点一定会被扫。

    这里不新增数据库列，直接用 SECRET_KEY 对 (类型, id) 做 HMAC 截断：
    确定性、不可枚举、换个 key 立刻全失效。kind 参与签名，所以任务 1 和
    探测 1 的凭证互不通用。
    """
    mac = hmac.new(C.SECRET_KEY.encode("utf-8"),
                   f"view:{kind}:{obj_id}".encode(), hashlib.sha256).hexdigest()
    return mac[:20]


def check_view_token(obj_id: int, t: str, kind: str = "task") -> bool:
    return bool(t) and secrets.compare_digest(t, view_token(obj_id, kind))


# ---------------------------------------------------------------- 模型

class HeartbeatIn(BaseModel):
    agent_id: str
    running: int = 0
    capacity: int = 4
    version: str = ""
    browser: str = ""
    note: str = ""
    # 节点健康（可选）：老 agent 不上报，中心照常运行，节点页显示 "—"
    cpu: float | None = None
    memory: float | None = None
    uptime: str = ""


class ReportIn(BaseModel):
    task_id: int
    status: str = "running"
    progress: float | None = None
    remaining: int | None = None      # 还剩几个任务点没做，0 = 完成
    total: int | None = None
    current: str = ""
    message: str = ""


class ShotIn(BaseModel):
    task_id: int
    image: str = Field(max_length=400_000)


class RedeemIn(BaseModel):
    card: str
    username: str
    password: str
    course_name: str
    note: str = ""
    school: str = ""


class ProbeIn(BaseModel):
    card: str
    username: str
    password: str


class ProbeReportIn(BaseModel):
    probe_id: int
    status: str = "running"          # running / done / failed
    courses: list[dict] | None = None
    message: str = ""


class ChooseIn(BaseModel):
    t: str
    course_id: str
    clazz_id: str = ""
    cpi: str = ""
    course_name: str = ""


# ---------------------------------------------------------------- 后台循环

STOP = None


async def _loop_reap():
    while True:
        try:
            n = tasks.reap_expired()
            if n:
                db.log(None, "warn", f"回收到期任务 {n} 个")
        except Exception as e:
            db.log(None, "error", f"回收循环异常 {e}")
        await asyncio.sleep(60)


async def _loop_probe_hk():
    """探测任务的回收与清理。

    登录失败、浏览器崩溃、agent 断电都会让探测卡在 running；探测记录里存着
    账号密码，也没必要长期留着，过期直接删。
    """
    while True:
        try:
            n = probe.reap_expired()
            if n:
                db.log(None, "warn", f"回收超时探测任务 {n} 个")
            probe.purge_old()
        except Exception as e:
            db.log(None, "error", f"探测回收循环异常 {e}")
        await asyncio.sleep(60)


async def _loop_janitor():
    """数据生命周期管理：事件日志和异常截图超期清理。

    每 6 小时跑一轮，只删超期数据，不影响在跑任务和近期排查材料；
    清理动作本身写入事件日志，可追溯。保留天数在 config 里可调。
    """
    while True:
        try:
            n_ev = db.prune_events(db.setting_int("event_days", C.EVENT_RETENTION_DAYS))
            n_sh = db.prune_shots(db.setting_int("shot_days", C.SHOT_RETENTION_DAYS))
            if n_ev or n_sh:
                db.log(None, "info", f"清理过期数据：事件 {n_ev} 条、截图 {n_sh} 张")
        except Exception as e:
            db.log(None, "error", f"清理循环异常 {e}")
        await asyncio.sleep(6 * 3600)


@asynccontextmanager
async def lifespan(app: FastAPI):
    db.init()
    t1 = asyncio.create_task(_loop_reap())
    t3 = asyncio.create_task(_loop_probe_hk())
    t4 = asyncio.create_task(_loop_janitor())
    db.log(None, "info", "调度中心启动")
    yield
    for t in (t1, t3, t4):
        t.cancel()


app = FastAPI(title="CX 调度中心", lifespan=lifespan)


# ---------------------------------------------------------------- agent 接口

@app.post("/api/agent/heartbeat")
async def heartbeat(body: HeartbeatIn, agent: dict = Depends(agent_auth)):
    db.ex("""UPDATE agents SET running=?, capacity=?, version=?, browser=?,
             note=?, cpu=?, memory=?, uptime=?, last_seen=?, status='online'
             WHERE id=?""",
          (body.running, body.capacity, body.version, body.browser,
           body.note[:200], body.cpu, body.memory, body.uptime[:64],
           db.now(), agent["id"]))
    pause_until = db.meta_get("pause_until")
    if pause_until and pause_until < db.now():
        pause_until = None
        db.meta_set("pause_until", "")
    return {"ok": True, "server_time": db.now(), "pause_until": pause_until or None}


@app.get("/api/agent/tasks")
async def pull_tasks(agent_id: str = "", slots: int = 1, agent: dict = Depends(agent_auth)):
    # 这台机器被管理员暂停了。只是不领新任务，手上正跑的不动——
    # 暂停通常是为了腾出机器或者临时下线，不该把别人正在刷的视频掐掉。
    if agent.get("paused"):
        return {"tasks": [], "reason": "agent_paused"}
    pause_until = db.meta_get("pause_until") or ""
    if pause_until and pause_until > db.now():
        return {"tasks": [], "reason": "paused"}
    if db.is_quiet_hour(C.QUIET_HOURS):
        return {"tasks": [], "reason": "quiet_hours"}
    got = tasks.lease(agent["id"], slots)
    return {"tasks": got, "count": len(got)}


@app.post("/api/agent/report")
async def report(body: ReportIn, agent: dict = Depends(agent_auth)):
    """agent 上报。现在只关心状态和消息——进度判定整块删了。

    ready 状态会被反复上报（每 30 秒一次保活），顺带刷新租约，
    并从这里拿回 action：wait 继续挂、running 管理员已开始、stop 收工。
    """
    r = tasks.report(body.task_id, agent["id"], body.status, body.message or "")
    if not r.get("ok"):
        return JSONResponse(r, status_code=409)
    return r


@app.post("/api/agent/shot")
async def shot(body: ShotIn, agent: dict = Depends(agent_auth)):
    path = C.DATA / "shots" / f"task{body.task_id}_{int(asyncio.get_event_loop().time())}.jpg"
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = body.image.split(",", 1)[-1]
    import base64
    try:
        path.write_bytes(base64.b64decode(raw))
    except Exception as e:
        raise HTTPException(400, detail={"error": f"图片解码失败 {e}", "code": "BAD_REQUEST"})
    db.log(body.task_id, "info", f"截图 {path.name}", agent["id"])
    return {"ok": True, "name": path.name}


# ---------------------------------------------------------------- 外网代理

@app.post("/api/proxy/tk")
async def proxy_tk(request: Request, agent: dict = Depends(agent_auth)):
    """题库代理：刷课机没外网时，由中心代它去查言溪题库。

    刷课机常部署在受限网络里，连不上 tk.enncy.cn，OCS 就会报「题库连接失败」。
    中心有出网能力，帮着转发一次即可。

    只固定转发到这一个上游，不接受任意 URL 参数，否则就成了公开代理。
    """
    body = await request.body()
    if not body:
        raise HTTPException(400, detail={"error": "请求体为空", "code": "BAD_REQUEST"})
    if len(body) > 64 * 1024:
        raise HTTPException(400, detail={"error": "请求体过大", "code": "BAD_REQUEST"})

    import httpx
    try:
        async with httpx.AsyncClient(timeout=25.0) as c:
            r = await c.post("https://tk.enncy.cn/query", content=body,
                             headers={"Content-Type": "application/json"})
    except Exception as e:
        db.log(None, "warn", f"题库代理失败 {type(e).__name__}: {e}",
               agent.get("id") or "")
        raise HTTPException(502, detail={"error": f"题库不可达：{e}",
                                         "code": "BAD_GATEWAY"})

    return Response(content=r.content, media_type="application/json",
                    headers={"access-control-allow-origin": "*"})


# ---------------------------------------------------------------- 限流

_RATE: dict[str, list[float]] = {}


def _rate_ok(key: str, limit: int = 12, window: int = 60) -> bool:
    """按来源 IP 做滑动窗口限流。

    兑换口是整套系统唯一不需要任何口令的写接口，卡密校验位只有一位，
    允许无限次尝试等于把库房钥匙挂在门上让人慢慢试。正常用户一分钟提交
    一次都算多，12 次/分钟足够宽松。
    """
    now = time.monotonic()
    lst = _RATE.setdefault(key, [])
    lst[:] = [x for x in lst if now - x < window]
    if len(lst) >= limit:
        return False
    lst.append(now)
    return True


# ---------------------------------------------------------------- 用户兑换

class _NoQuota(Exception):
    """卡密配额不足。事务内抛出以中断并整体回滚。"""


def _make_task(code: str, username: str, password: str, course_name: str,
               note: str = "", school: str = "", course_id: str = "",
               user_id: int | None = None) -> dict:
    """建账号 + 建任务 + 扣配额，三步在同一个 BEGIN IMMEDIATE 事务里：
    任一步失败整体回滚，不再留下 canceled 状态的脏任务或孤立的账号记录。

    同账号提交第二门课不拦，正常排到队尾。真正防顶号的地方在派发那一步
    （tasks.lease 会跳过已经有任务占着这个账号的单），所以排队期间不会有
    两个浏览器同时登同一个号。

    卡密扣减本身也是原子条件更新（quota>=1 才生效），双重保证并发下
    一张一次性卡密不会被两个请求同时用掉。

    返回 {"ok": True, task_id, status_url, remaining, queue} 或 {"ok": False, error, code}。
    """
    ts = db.now()
    tid = None
    try:
        with db.conn() as c:
            c.execute("BEGIN IMMEDIATE")
            aid = c.execute(
                """INSERT INTO accounts(card_code, username_enc, username_hash,
                                        password_enc, school, profile, created_at)
                   VALUES(?,?,?,?,?,?,?)""",
                (code, crypto.encrypt(username), accounts.hash_username(username),
                 crypto.encrypt(password), school, None, ts)).lastrowid
            c.execute("UPDATE accounts SET profile=? WHERE id=?",
                      (accounts.profile_name(aid, username), aid))
            tid = c.execute(
                """INSERT INTO tasks(card_code, account_id, course_id, course_name,
                                     note, rate, status, user_id, created_at, updated_at)
                   VALUES(?,?,?,?,?,?,'submitted',?,?,?)""",
                (code, aid, course_id or course_name, course_name,
                 note, 1.0, user_id, ts, ts)).lastrowid
            cur = c.execute(
                "UPDATE cards SET quota=quota-1 WHERE code=? AND quota>=1", (code,))
            if cur.rowcount == 0:
                raise _NoQuota()
    except _NoQuota:
        return {"ok": False, "code": "NO_QUOTA", "error": "卡密次数不足"}

    db.log(tid, "info", f"用户兑换 账号={crypto.mask(username)}")
    return {"ok": True, "task_id": tid,
            "status_url": f"{C.PUBLIC_URL}/s/{tid}?t={view_token(tid)}",
            "remaining": cards.remaining(code),
            "queue": tasks.queue_position(tid)}


@app.post("/api/redeem")
async def redeem(body: RedeemIn, request: Request):
    ip = (request.client.host if request.client else "?") or "?"
    if not _rate_ok(ip):
        return JSONResponse({"ok": False, "error": "提交太频繁，请稍后再试",
                             "code": "RATE_LIMITED"}, status_code=429)

    if not body.username.strip() or not body.password:
        return JSONResponse({"ok": False, "error": "账号和密码都要填",
                             "code": "BAD_REQUEST"}, status_code=400)
    if not body.course_name.strip():
        return JSONResponse({"ok": False, "code": "BAD_REQUEST",
                             "error": "课程名称要填，照抄课表上的完整名字"}, status_code=400)

    chk = cards.activate(body.card)
    if not chk["ok"]:
        return JSONResponse({"ok": False, "error": chk["reason"],
                             "code": chk["code"]}, status_code=400)

    u = current_user(request)
    r = _make_task(chk["code"], body.username.strip(), body.password,
                   body.course_name.strip(), body.note.strip(), body.school,
                   user_id=u["id"] if u else None)
    if not r.get("ok"):
        return JSONResponse(r, status_code=400)
    return r


class MultiCourseIn(BaseModel):
    card: str
    username: str
    password: str
    courses: list[dict] = []


@app.post("/api/redeem_multi")
async def redeem_multi(body: MultiCourseIn, request: Request):
    """多次卡：一次提交多门课程（同一学习通账号）。配额与建单在同一事务里，
    不够 N 次就整体拒绝，不会出现半张订单。"""
    ip = (request.client.host if request.client else "?") or "?"
    if not _rate_ok(f"multi:{ip}", limit=8, window=60):
        return JSONResponse({"ok": False, "error": "提交太频繁，请稍后再试",
                             "code": "RATE_LIMITED"}, status_code=429)

    username = (body.username or "").strip()
    if not username or not body.password:
        return JSONResponse({"ok": False, "error": "账号和密码都要填",
                             "code": "BAD_REQUEST"}, status_code=400)
    courses = []
    for c in (body.courses or [])[:10]:
        name = str((c or {}).get("course_name") or "").strip()
        if not name:
            continue
        courses.append({"name": name[:120],
                        "note": str((c or {}).get("note") or "").strip()[:120]})
    if not courses:
        return JSONResponse({"ok": False, "error": "至少填一门课程",
                             "code": "BAD_REQUEST"}, status_code=400)

    chk = cards.activate(body.card)
    if not chk["ok"]:
        return JSONResponse({"ok": False, "error": chk["reason"],
                             "code": chk["code"]}, status_code=400)
    need = len(courses)
    if chk["quota"] < need:
        return JSONResponse({"ok": False, "code": "NO_QUOTA",
                             "error": f"这张卡剩余 {chk['quota']} 次，不够提交 {need} 门课"},
                            status_code=400)

    code = chk["code"]
    u = current_user(request)
    uid = u["id"] if u else None
    ts = db.now()
    tids = []
    try:
        with db.conn() as c:
            c.execute("BEGIN IMMEDIATE")
            aid = c.execute(
                """INSERT INTO accounts(card_code, username_enc, username_hash,
                                        password_enc, school, profile, created_at)
                   VALUES(?,?,?,?,?,?,?)""",
                (code, crypto.encrypt(username), accounts.hash_username(username),
                 crypto.encrypt(body.password), "", None, ts)).lastrowid
            c.execute("UPDATE accounts SET profile=? WHERE id=?",
                      (accounts.profile_name(aid, username), aid))
            for cs in courses:
                tids.append(c.execute(
                    """INSERT INTO tasks(card_code, account_id, course_id, course_name,
                                         note, rate, status, user_id, created_at, updated_at)
                       VALUES(?,?,?,?,?,?,'submitted',?,?,?)""",
                    (code, aid, cs["name"], cs["name"], cs["note"],
                     1.0, uid, ts, ts)).lastrowid)
            cur = c.execute("UPDATE cards SET quota=quota-? WHERE code=? AND quota>=?",
                            (need, code, need))
            if cur.rowcount == 0:
                raise _NoQuota()
    except _NoQuota:
        return JSONResponse({"ok": False, "code": "NO_QUOTA",
                             "error": "卡密次数不足"}, status_code=400)

    for tid in tids:
        db.log(tid, "info", f"用户兑换（多次卡） 账号={crypto.mask(username)}")
    first = tids[0]
    return {"ok": True, "task_ids": tids, "task_id": first,
            "status_url": f"{C.PUBLIC_URL}/s/{first}?t={view_token(first)}",
            "status_urls": [f"{C.PUBLIC_URL}/s/{t}?t={view_token(t)}" for t in tids],
            "remaining": cards.remaining(code),
            "queue": tasks.queue_position(first)}


# ---------------------------------------------------------------- 课程探测

class CardCheckIn(BaseModel):
    card: str


@app.post("/api/card/check")
async def api_card_check(body: CardCheckIn, request: Request):
    """校验卡密。前端拿它做「验过了才让往下填」的那道门。

    不激活、不扣额度——用户可能只是想确认卡密对不对。
    """
    ip = (request.client.host if request.client else "?") or "?"
    # 卡密是 31 字符字母表，暴力空间够大，但这里必须限流：
    # 这个接口是唯一能不消耗就试探卡密的地方。
    if not _rate_ok(f"cardchk:{ip}", limit=10, window=60):
        return JSONResponse({"ok": False, "error": "校验太频繁，请稍后再试",
                             "code": "RATE_LIMITED"}, status_code=429)

    r = cards.check(body.card)
    if not r.get("ok"):
        return JSONResponse(r, status_code=400)
    return {"ok": True, "remaining": r["quota"], "product": r["product"]}


@app.post("/api/probe")
async def api_probe(body: ProbeIn, request: Request):
    """用户填卡密 + 账号密码，派一台刷课机去登录并把课程列表抓回来。

    不扣卡密配额（"看一眼课表"不该算一次购买），真正扣配额是选完课提交任务
    的时候。但按卡密限次，否则一张卡能无限登录不同手机号。
    """
    ip = (request.client.host if request.client else "?") or "?"
    if not _rate_ok(f"probe:{ip}", limit=8, window=60):
        return JSONResponse({"ok": False, "error": "提交太频繁，请稍后再试",
                             "code": "RATE_LIMITED"}, status_code=429)

    if not body.username.strip() or not body.password:
        return JSONResponse({"ok": False, "error": "账号和密码都要填",
                             "code": "BAD_REQUEST"}, status_code=400)

    chk = cards.activate(body.card)
    if not chk["ok"]:
        return JSONResponse({"ok": False, "error": chk["reason"], "code": chk["code"]},
                            status_code=400)

    r = probe.create(chk["code"], body.username.strip(), body.password)
    if not r.get("ok"):
        return JSONResponse({"ok": False, "error": r["reason"], "code": r["code"]},
                            status_code=400)

    pid = r["probe_id"]
    return {"ok": True, "probe_id": pid,
            "poll_url": f"{C.PUBLIC_URL}/p/{pid}?t={view_token(pid, 'probe')}"}


@app.get("/api/probe/{probe_id}")
async def api_probe_get(probe_id: int, t: str = ""):
    if not check_view_token(probe_id, t, "probe"):
        raise HTTPException(403, detail={"error": "链接无效", "code": "FORBIDDEN"})
    d = probe.get(probe_id)
    if not d:
        raise HTTPException(404, detail={"error": "探测任务不存在", "code": "NOT_FOUND"})
    return {"ok": True, "probe": d}


@app.post("/api/probe/{probe_id}/choose")
async def api_probe_choose(probe_id: int, body: ChooseIn, request: Request):
    """用户在课程列表里选完一门，直接建任务。账号密码从探测记录里取，不用再输一遍。"""
    ip = (request.client.host if request.client else "?") or "?"
    if not _rate_ok(f"choose:{ip}", limit=12, window=60):
        return JSONResponse({"ok": False, "error": "提交太频繁", "code": "RATE_LIMITED"},
                            status_code=429)

    if not check_view_token(probe_id, body.t, "probe"):
        raise HTTPException(403, detail={"error": "链接无效", "code": "FORBIDDEN"})

    row = db.q1("SELECT * FROM probes WHERE id=?", (probe_id,))
    if not row:
        raise HTTPException(404, detail={"error": "探测任务不存在", "code": "NOT_FOUND"})
    if row["status"] not in ("done",):
        return JSONResponse({"ok": False, "code": "PROBE_NOT_READY",
                             "error": "课程列表还没读出来，请稍等"}, status_code=400)
    if not body.course_id.strip():
        return JSONResponse({"ok": False, "code": "BAD_REQUEST",
                             "error": "先选一门课"}, status_code=400)

    chk = cards.activate(row["card_code"])
    if not chk["ok"]:
        return JSONResponse({"ok": False, "error": chk["reason"], "code": chk["code"]},
                            status_code=400)

    r = _make_task(chk["code"],
                   crypto.decrypt(row["username_enc"]),
                   crypto.decrypt(row["password_enc"]),
                   body.course_name or f"课程 {body.course_id}",
                   "", "", body.course_id.strip())
    if not r.get("ok"):
        return JSONResponse(r, status_code=400)

    # 探测记录用完即焚：账号密码没有长期留存的理由，任务里已经另存了一份加密的
    db.ex("UPDATE probes SET status='canceled', updated_at=? WHERE id=?",
          (db.now(), probe_id))
    return r


@app.get("/api/agent/probes")
async def agent_pull_probe(agent: dict = Depends(agent_auth)):
    pause_until = db.meta_get("pause_until") or ""
    if pause_until and pause_until > db.now():
        return {"probe": None, "reason": "paused"}
    return {"probe": probe.lease(agent["id"])}


@app.post("/api/agent/probe_report")
async def agent_probe_report(body: ProbeReportIn, agent: dict = Depends(agent_auth)):
    r = probe.report(body.probe_id, agent["id"], body.status,
                     body.courses, body.message)
    if not r.get("ok"):
        return JSONResponse(r, status_code=409)
    return r


@app.get("/api/task/{task_id}")
async def task_status(task_id: int, t: str = ""):
    if not check_view_token(task_id, t):
        raise HTTPException(403, detail={"error": "查看链接无效，请用兑换时返回的完整链接",
                                         "code": "FORBIDDEN"})
    t_row = db.q1("""SELECT id, status, message, course_name, note,
                            created_at, updated_at, started_at, finished_at
                     FROM tasks WHERE id=?""", (task_id,))
    if not t_row:
        raise HTTPException(404, detail={"error": "任务不存在", "code": "NOT_FOUND"})
    # 排队名次只对还没开始的单有意义，其它状态前端不会用到
    if t_row.get("status") == "submitted":
        t_row["queue"] = tasks.queue_position(task_id)
    return {"ok": True, "task": t_row}


# ---------------------------------------------------------------- 管理

class LoginIn(BaseModel):
    username: str = "admin"
    password: str = ""


@app.post("/admin/login")
async def admin_login(body: LoginIn, request: Request, response: Response):
    """管理面板登录：账号 + 密码。口令对了就下发一个 12 小时有效的 cookie。

    账号/密码存 meta（admin_user / admin_password_hash）；尚未改过密码时
    回落环境变量 CX_ADMIN_PASSWORD，老口令继续可用。
    """
    ip = (request.client.host if request.client else "?") or "?"
    now = time.time()
    fails = [t for t in _ADMIN_FAILS.get(ip, []) if now - t < 900]
    if len(fails) >= 5:
        raise HTTPException(429, detail={"error": "尝试太多次，15 分钟后再试",
                                         "code": "LOCKED"})
    want_user = db.setting_str("admin_user", "admin") or "admin"
    stored_hash = db.setting_str("admin_password_hash", "")
    user_ok = secrets.compare_digest((body.username or "admin").strip(), want_user)
    if stored_hash:
        pwd_ok = crypto.verify_password(body.password or "", stored_hash)
    else:
        pwd_ok = bool(C.ADMIN_PASSWORD) and secrets.compare_digest(
            body.password or "", C.ADMIN_PASSWORD)
    if not (user_ok and pwd_ok):
        fails.append(now)
        _ADMIN_FAILS[ip] = fails
        db.log(None, "warn", f"管理登录失败 {ip}（第 {len(fails)} 次）")
        raise HTTPException(401, detail={"error": "账号或密码错误", "code": "BAD_PASSWORD"})

    _ADMIN_FAILS.pop(ip, None)
    db.audit("admin.login", "", "", ip)
    exp = int(time.time()) + C.SESSION_HOURS * 3600
    response.set_cookie(ADMIN_COOKIE, _admin_session_value(exp),
                        max_age=C.SESSION_HOURS * 3600,
                        httponly=True, secure=True, samesite="lax", path="/")
    db.log(None, "info", f"管理面板登录 {ip}")
    return {"ok": True}


@app.post("/admin/account")
async def admin_account_change(request: Request, _=Depends(admin_auth)):
    """修改管理员账号 / 密码。密码留空表示不改；改完写审计。"""
    body = await request.json()
    if not isinstance(body, dict):
        raise HTTPException(400, detail={"error": "请求体必须是 JSON 对象",
                                         "code": "BAD_REQUEST"})
    changed = []
    user = str(body.get("username") or "").strip()
    if user:
        if len(user) < 3 or len(user) > 32:
            raise HTTPException(400, detail={"error": "账号长度 3~32 位",
                                             "code": "BAD_REQUEST"})
        db.meta_set("admin_user", user)
        changed.append("用户名")
    pwd = str(body.get("password") or "")
    if pwd:
        if len(pwd) < 8:
            raise HTTPException(400, detail={"error": "密码至少 8 位",
                                             "code": "BAD_REQUEST"})
        db.meta_set("admin_password_hash", crypto.hash_password(pwd))
        changed.append("密码")
    if changed:
        db.audit("admin.account", "", "修改" + "、".join(changed),
                 request.client.host if request.client else "")
    return {"ok": True, "changed": changed}


@app.post("/admin/logout")
async def admin_logout(response: Response):
    response.delete_cookie(ADMIN_COOKIE, path="/")
    return {"ok": True}


@app.get("/admin/stats")
async def admin_stats(_=Depends(admin_auth)):
    agents = db.q("SELECT id, name, running, capacity, status, last_seen, browser FROM agents")
    return {"ok": True, "tasks": tasks.stats(), "agents": agents}


@app.post("/admin/cards")
async def admin_gen_cards(n: int = 10, quota: int = 1, product: str = "cx-1course",
                          _=Depends(admin_auth)):
    codes = cards.generate(n=n, quota=quota, product=product)
    db.audit("cards.generate", f"{len(codes)}张", product)
    return {"ok": True, "count": len(codes), "codes": codes,
            "import_text": cards.export_import_list(codes)}


@app.get("/admin/cards/export", response_class=PlainTextResponse)
async def admin_export(codes: str = "", _=Depends(admin_auth)):
    """codes 用逗号分隔，返回一行一个的纯文本，直接粘进独角数卡后台。"""
    lst = [c.strip() for c in codes.split(",") if c.strip()]
    return cards.export_import_list(lst)


_AGENT_SCRIPT = r'''@echo off
chcp 65001 >nul
cd /d "%~dp0"

if not exist "venv\Scripts\python.exe" (
    echo Not installed yet. Double-click install.bat first.
    pause
    exit /b 1
)

REM ===== Agent identity: __AGENT_ID__ =====
set "AGENT_CENTER=https://example.com/cx"
set "AGENT_ID=__AGENT_ID__"
set "AGENT_TOKEN=__TOKEN__"
set "AGENT_CAPACITY=__CAPACITY__"

REM ===== Runtime options =====
set "AGENT_PROFILE_TEMPLATE="
if exist "D:\cx-template\Default\Extensions" set "AGENT_PROFILE_TEMPLATE=D:\cx-template"
set "AGENT_DATA_DIR=%~dp0data"
set "AGENT_OCS_MODE=auto"
set "AGENT_KEEPALIVE=30"
set "AGENT_KEEP_ON_VERIFY=0"
set "PYTHONIOENCODING=utf-8"

echo ========================================
echo   Agent ID : %AGENT_ID%
echo   Center   : %AGENT_CENTER%
echo   Capacity : %AGENT_CAPACITY%
echo ========================================
echo   Keep this window open.
echo   Keep this PC awake (no sleep).
echo.

venv\Scripts\python.exe agent\main.py

echo.
echo Agent stopped.
pause
'''


def _agent_script(agent_id: str, token: str, capacity: int = 4) -> str:
    """生成这台刷课机的启动脚本。

    三个刻意的选择：

    一、出 .bat 不出 .ps1。Windows 默认禁止运行 PowerShell 脚本，有些机器
        （域策略、受控环境）连 Set-ExecutionPolicy 都改不动，
        -ExecutionPolicy Bypass 也盖不过组策略。cmd 批处理没这问题。

    二、文件里一个中文都不写。cmd 按系统 ANSI（GBK）逐行解析 bat，
        UTF-8 的中文会变成乱码并把整行拆断，set 语句直接失效。要中文
        就留给 python 输出——chcp 65001 + PYTHONIOENCODING 之后那边正常。

    三、%~dp0 取脚本自身所在目录，这样整包挪到哪儿都能跑。
    """
    return (_AGENT_SCRIPT
            .replace("__AGENT_ID__", agent_id)
            .replace("__TOKEN__", token)
            .replace("__CAPACITY__", str(capacity)))


@app.get("/admin/agents")
async def admin_agents(_=Depends(admin_auth)):
    """刷课机列表。token 不在这里下发，要单独调 /admin/agents/{id}/token。

    在线状态按心跳时间算，不看数据库那个 status 列——那一列只在心跳时被
    写成 online，机器一关机就再也没人把它改回来，会永远显示"在线"，
    看着像活着其实早就断了。
    """
    from datetime import datetime, timezone

    rows = db.q("""SELECT id, name, capacity, running, status, paused, last_seen,
                          version, browser, note, cpu, memory, uptime, created_at
                   FROM agents ORDER BY id""")
    now = datetime.now(timezone.utc)
    for r in rows:
        alive = False
        if r.get("last_seen"):
            try:
                seen = datetime.fromisoformat(r["last_seen"])
                alive = (now - seen).total_seconds() <= db.setting_int("online_threshold", C.ONLINE_THRESHOLD)
            except Exception:
                alive = False
        r["status"] = "online" if alive else "offline"
        r["tasks"] = [x["id"] for x in db.q(
            """SELECT id FROM tasks WHERE agent_id=?
               AND status IN ('logging','ready','running') ORDER BY id""", (r["id"],))]
    return {"ok": True, "agents": rows}


@app.get("/admin/agents/{agent_id}/token")
async def admin_agent_token(agent_id: str, _=Depends(admin_auth)):
    row = db.q1("SELECT token, capacity FROM agents WHERE id=?", (agent_id,))
    if not row:
        raise HTTPException(404, detail={"error": "没有这台机器", "code": "NOT_FOUND"})
    return {"ok": True, "token": row["token"],
            "script": _agent_script(agent_id, row["token"], row["capacity"] or 4)}


@app.delete("/admin/agents/{agent_id}")
async def admin_del_agent(agent_id: str, _=Depends(admin_auth)):
    busy = db.q1("""SELECT id FROM tasks WHERE agent_id=?
                     AND status IN ('logging','ready','running') LIMIT 1""", (agent_id,))
    if busy:
        raise HTTPException(400, detail={
            "error": f"任务 #{busy['id']} 还在这台机器上跑，先处理它", "code": "BUSY"})
    db.ex("DELETE FROM agents WHERE id=?", (agent_id,))
    db.log(None, "warn", f"删除刷课机 {agent_id}")
    db.audit("agent.del", agent_id, "")
    return {"ok": True}


@app.post("/admin/agents/{agent_id}/pause")
async def admin_agent_pause(agent_id: str, _=Depends(admin_auth)):
    """暂停这台机器：它不再领新任务。

    手上正在跑的（ready/running）不受影响——暂停通常是为了腾机器或者临时
    下线，不该把别人正在刷的视频掐掉。要停那些任务就逐单取消。
    """
    if not db.q1("SELECT id FROM agents WHERE id=?", (agent_id,)):
        raise HTTPException(404, detail={"error": "没有这台机器", "code": "NOT_FOUND"})
    db.ex("UPDATE agents SET paused=1 WHERE id=?", (agent_id,))
    db.log(None, "warn", f"暂停刷课机 {agent_id}，不再派新任务")
    return {"ok": True, "agent_id": agent_id, "paused": True}


@app.post("/admin/agents/{agent_id}/resume")
async def admin_agent_resume(agent_id: str, _=Depends(admin_auth)):
    if not db.q1("SELECT id FROM agents WHERE id=?", (agent_id,)):
        raise HTTPException(404, detail={"error": "没有这台机器", "code": "NOT_FOUND"})
    db.ex("UPDATE agents SET paused=0 WHERE id=?", (agent_id,))
    db.log(None, "info", f"恢复刷课机 {agent_id}")
    return {"ok": True, "agent_id": agent_id, "paused": False}


@app.post("/admin/agents/{agent_id}/capacity")
async def admin_agent_capacity(agent_id: str, capacity: int = 4,
                               _=Depends(admin_auth)):
    if capacity < 1 or capacity > 12:
        raise HTTPException(400, detail={"error": "容量只能是 1~12", "code": "BAD_REQUEST"})
    if not db.q1("SELECT id FROM agents WHERE id=?", (agent_id,)):
        raise HTTPException(404, detail={"error": "没有这台机器", "code": "NOT_FOUND"})
    db.ex("UPDATE agents SET capacity=? WHERE id=?", (capacity, agent_id))
    db.log(None, "info", f"{agent_id} 容量改为 {capacity}")
    return {"ok": True}


@app.post("/admin/agents")
async def admin_add_agent(agent_id: str, name: str = "", capacity: int = 4,
                          _=Depends(admin_auth)):
    """新增（或重新注册）一台刷课机。返回 token 和现成的启动脚本。"""
    agent_id = (agent_id or "").strip()
    if not agent_id or not agent_id.replace("-", "").isalnum():
        raise HTTPException(400, detail={"error": "机器 ID 只能用字母数字和短横线",
                                         "code": "BAD_REQUEST"})
    if capacity < 1 or capacity > 12:
        raise HTTPException(400, detail={"error": "容量只能是 1~12", "code": "BAD_REQUEST"})

    token = secrets.token_urlsafe(32)
    db.ex("""INSERT OR REPLACE INTO agents(id, token, name, capacity, status, created_at)
             VALUES(?,?,?,?, 'offline', ?)""",
          (agent_id, token, name or agent_id.upper(), capacity, db.now()))
    db.log(None, "info", f"注册刷课机 {agent_id}，容量 {capacity}")
    db.audit("agent.add", agent_id, f"capacity={capacity}")
    return {"ok": True, "agent_id": agent_id, "token": token, "capacity": capacity,
            "script": _agent_script(agent_id, token, capacity)}


@app.post("/admin/pause")
async def admin_pause(hours: int = 1, _=Depends(admin_auth)):
    from datetime import datetime, timedelta, timezone
    until = (datetime.now(timezone.utc) + timedelta(hours=hours)).isoformat(timespec="seconds")
    db.meta_set("pause_until", until)
    db.log(None, "warn", f"管理员暂停派单至 {until}")
    db.audit("dispatch.pause", "", f"{hours}h", "")
    return {"ok": True, "pause_until": until}


@app.post("/admin/resume")
async def admin_resume(request: Request, _=Depends(admin_auth)):
    db.meta_set("pause_until", "")
    db.audit("dispatch.resume", "", "", request.client.host if request.client else "")
    return {"ok": True}


class AdminTaskIn(BaseModel):
    username: str
    password: str
    course_name: str
    note: str = ""
    card: str = ""


@app.post("/admin/task")
async def admin_create_task(body: AdminTaskIn, _=Depends(admin_auth)):
    """手工补单。不填卡密就自动生成一张，保证配额账目对得上。"""
    code = body.card.strip()
    if not code:
        gen = cards.generate(n=1, quota=1, product="manual")
        code = gen[0] if gen else ""
    r = _make_task(code, body.username.strip(), body.password,
                   body.course_name.strip(), body.note.strip())
    if not r.get("ok"):
        raise HTTPException(400, detail={"error": r.get("error"), "code": r.get("code")})
    return r


@app.get("/admin/cards/export-filter", response_class=PlainTextResponse)
async def admin_cards_export_filter(quota: int = 0, status: str = "", batch: str = "",
                                    _=Depends(admin_auth)):
    """按条件导出卡密纯文本（一行一张）：配额次数 / 状态 / 批次，可组合。"""
    where, args = [], []
    if quota > 0:
        where.append("quota=?")
        args.append(quota)
    if status in ("unused", "active", "revoked", "expired"):
        where.append("status=?")
        args.append(status)
    if batch:
        where.append("batch=?")
        args.append(batch)
    w = ("WHERE " + " AND ".join(where)) if where else ""
    rows = db.q(f"SELECT code FROM cards {w} ORDER BY rowid", tuple(args))
    return "\n".join(r["code"] for r in rows)


@app.get("/admin/cards/export-all", response_class=PlainTextResponse)
async def admin_export_all(_=Depends(admin_auth)):
    """全部卡密，一行一张。直接粘进独角数卡后台。"""
    rows = db.q("SELECT code FROM cards ORDER BY rowid")
    return "\n".join(r["code"] for r in rows)


@app.post("/admin/task/{task_id}/accept")
async def admin_accept(task_id: int, request: Request, _=Depends(admin_auth)):
    """「开始登录」：批准这一单，让刷课机去开浏览器登录。"""
    db.audit("task.accept", f"#{task_id}", "", request.client.host if request.client else "")
    r = tasks.accept(task_id)
    if not r.get("ok"):
        raise HTTPException(400, detail={"error": r.get("error"), "code": "BAD_STATE"})
    return r


@app.post("/admin/task/{task_id}/begin")
async def admin_begin(task_id: int, request: Request, _=Depends(admin_auth)):
    """「开始刷课」：你已经人工点进课程了，把状态推到 running 给用户看。"""
    db.audit("task.begin", f"#{task_id}", "", request.client.host if request.client else "")
    r = tasks.begin(task_id)
    if not r.get("ok"):
        raise HTTPException(400, detail={"error": r.get("error"), "code": "BAD_STATE"})
    return r


@app.post("/admin/task/{task_id}/finish")
async def admin_finish(task_id: int, request: Request, _=Depends(admin_auth)):
    """「标记完成」：刷课机收到后会自己退出登录、关窗口、让出槽位。"""
    db.audit("task.finish", f"#{task_id}", "", request.client.host if request.client else "")
    r = tasks.finish(task_id)
    if not r.get("ok"):
        raise HTTPException(400, detail={"error": r.get("error"), "code": "BAD_STATE"})
    return r


@app.post("/admin/task/{task_id}/cancel")
async def admin_cancel(task_id: int, request: Request, reason: str = "管理员取消", _=Depends(admin_auth)):
    db.audit("task.cancel", f"#{task_id}", reason[:80], request.client.host if request.client else "")
    r = tasks.cancel(task_id, reason)
    if not r.get("ok"):
        raise HTTPException(400, detail={"error": r.get("error"), "code": "BAD_STATE"})
    return r


@app.post("/admin/task/{task_id}/refund")
async def admin_refund(task_id: int, _=Depends(admin_auth)):
    """人工补单：把这次任务消耗的配额还给卡密，并把任务标记取消。

    不做自动退还，理由很实际：agent 报 failed 的原因未必可信（网络抖动、
    目标站点抽风、本机杀毒拦了浏览器都能报 failed），自动退等于给白嫖
    留口子。但用户确实付了钱、任务又真的没跑成，运营手上必须有补救手段，
    所以做成人手动触发，每一步都落在事件日志里。
    """
    t_row = db.q1("SELECT * FROM tasks WHERE id=?", (task_id,))
    if not t_row:
        raise HTTPException(404, detail={"error": "任务不存在", "code": "NOT_FOUND"})
    code = t_row["card_code"]
    if code:
        db.ex("UPDATE cards SET quota=quota+1 WHERE code=?", (code,))
    db.ex("""UPDATE tasks SET status='canceled', message=?, updated_at=? WHERE id=?""",
          ("管理员补单，配额已退还", db.now(), task_id))
    db.log(task_id, "warn", f"管理员补单，卡密 {code or '(无)'} 配额 +1")
    db.audit("task.refund", f"#{task_id}", f"card={code}")
    return {"ok": True, "card": code, "remaining": cards.remaining(code) if code else 0}


@app.post("/admin/task/{task_id}/requeue")
async def admin_requeue(task_id: int, request: Request, _=Depends(admin_auth)):
    """异常任务重新排队：failed 等状态退回 submitted，由管理员重新决定。"""
    if not tasks.requeue(task_id, "管理员重新排队"):
        raise HTTPException(400, detail={"error": "任务不存在或已结束，不能重排",
                                         "code": "BAD_STATE"})
    db.audit("task.requeue", f"#{task_id}", "", request.client.host if request.client else "")
    return {"ok": True, "status": "submitted"}


@app.get("/admin/tasks")
async def admin_tasks(limit: int = 60, status: str = "", q: str = "",
                      page: int = 1, size: int = 0, _=Depends(admin_auth)):
    """任务列表。旧调用（只传 limit）行为不变；新参数支持状态筛选、
    搜索（课程名/备注/任务 ID）和分页（page+size），筛选下推到 SQL。
    """
    where, args = [], []
    if status:
        where.append("t.status=?")
        args.append(status)
    if q:
        where.append("(t.course_name LIKE ? OR t.note LIKE ? OR CAST(t.id AS TEXT)=?)")
        like = f"%{q}%"
        args += [like, like, q.strip()]
    w = ("WHERE " + " AND ".join(where)) if where else ""
    base = f"""FROM tasks t LEFT JOIN accounts a ON a.id = t.account_id {w}"""
    sel = """SELECT t.id, t.status, t.course_name, t.note,
                    t.agent_id, t.message, t.created_at,
                    t.started_at, t.finished_at, t.updated_at,
                    a.username_enc,
                    (SELECT COUNT(*) FROM tasks x
                      WHERE x.status='submitted' AND x.id < t.id) AS ahead"""
    pagination = None
    if size and size > 0:
        page = max(1, page)
        total = db.q1(f"SELECT COUNT(*) AS n {base}", tuple(args))["n"]
        rows = db.q(f"""{sel} {base}
                        ORDER BY t.id DESC LIMIT ? OFFSET ?""",
                    tuple(args) + (size, (page - 1) * size))
        pagination = {"page": page, "size": size, "total": int(total)}
    else:
        rows = db.q(f"{sel} {base} ORDER BY t.id DESC LIMIT ?", tuple(args) + (limit,))
    for r in rows:
        # 只给脱敏手机号，明文密码/账号不下发到浏览器
        try:
            r["username"] = crypto.mask(crypto.decrypt(r.pop("username_enc")))
        except Exception:
            r["username"] = "-"
            r.pop("username_enc", None)
    return {"ok": True, "tasks": rows, "pagination": pagination}


@app.get("/admin/task/{task_id}")
async def admin_task_detail(task_id: int, _=Depends(admin_auth)):
    """任务详情：任务行 + 脱敏账号 + 所属节点实时状态 + 该任务的事件历史。"""
    from datetime import datetime, timezone

    t = db.q1("""SELECT t.*, a.username_enc FROM tasks t
                 LEFT JOIN accounts a ON a.id = t.account_id WHERE t.id=?""",
              (task_id,))
    if not t:
        raise HTTPException(404, detail={"error": "任务不存在", "code": "NOT_FOUND"})
    try:
        t["username"] = crypto.mask(crypto.decrypt(t.pop("username_enc")))
    except Exception:
        t.pop("username_enc", None)
        t["username"] = "-"

    ag = None
    if t.get("agent_id"):
        row = db.q1("""SELECT id, name, capacity, running, paused, last_seen,
                              version, browser, note
                       FROM agents WHERE id=?""", (t["agent_id"],))
        if row:
            alive = False
            if row.get("last_seen"):
                try:
                    seen = datetime.fromisoformat(row["last_seen"])
                    alive = (datetime.now(timezone.utc) - seen).total_seconds() \
                        <= db.setting_int("online_threshold", C.ONLINE_THRESHOLD)
                except Exception:
                    alive = False
            row["status"] = "online" if alive else "offline"
            ag = row

    ev = db.q("""SELECT id, ts, level, msg, agent_id FROM events
                 WHERE task_id=? ORDER BY id DESC LIMIT 50""", (task_id,))
    return {"ok": True, "task": t, "agent": ag, "events": ev}


def _agents_with_status() -> list:
    """节点列表，status 按 last_seen 实时算（status 列只在心跳时写 online，不可信）。"""
    from datetime import datetime, timezone

    rows = db.q("""SELECT id, name, capacity, running, status, paused, last_seen,
                          version, browser, note, cpu, memory, uptime, created_at
                   FROM agents ORDER BY id""")
    now = datetime.now(timezone.utc)
    for r in rows:
        alive = False
        if r.get("last_seen"):
            try:
                seen = datetime.fromisoformat(r["last_seen"])
                alive = (now - seen).total_seconds() <= db.setting_int("online_threshold", C.ONLINE_THRESHOLD)
            except Exception:
                alive = False
        r["status"] = "online" if alive else "offline"
        r["tasks"] = [x["id"] for x in db.q(
            """SELECT id FROM tasks WHERE agent_id=?
               AND status IN ('logging','ready','running') ORDER BY id""",
            (r["id"],))]
    return rows


@app.get("/admin/agents/{agent_id}")
async def admin_agent_detail(agent_id: str, _=Depends(admin_auth)):
    """节点详情：基础信息 + 实时在线状态 + 当前任务 + 最近结束的任务 + 节点事件。"""
    rows = [a for a in _agents_with_status() if a["id"] == agent_id]
    if not rows:
        raise HTTPException(404, detail={"error": "没有这台机器", "code": "NOT_FOUND"})
    row = rows[0]
    row["recent_tasks"] = db.q(
        """SELECT id, status, course_name, created_at, finished_at
           FROM tasks WHERE agent_id=? AND status IN ('done','failed','canceled')
           ORDER BY id DESC LIMIT 10""", (agent_id,))
    row["events"] = db.q(
        """SELECT id, ts, level, msg, task_id FROM events
           WHERE agent_id=? ORDER BY id DESC LIMIT 30""", (agent_id,))
    return {"ok": True, "agent": row}


@app.get("/admin/overview")
async def admin_overview(_=Depends(admin_auth)):
    """运营总览：核心指标 + 近 7 天趋势 + 节点状态 + 调度状态。全部真实 SQL。"""
    from datetime import datetime, timedelta, timezone

    now = datetime.now().astimezone()
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0) \
        .astimezone(timezone.utc).isoformat(timespec="seconds")
    s = tasks.stats()
    agents = _agents_with_status()
    agents_online = sum(1 for a in agents if a["status"] == "online")

    trend = []
    for i in range(6, -1, -1):
        d = (now - timedelta(days=i)).replace(hour=0, minute=0, second=0,
                                              microsecond=0)
        d_end = d + timedelta(days=1)
        start = d.astimezone(timezone.utc).isoformat(timespec="seconds")
        end = d_end.astimezone(timezone.utc).isoformat(timespec="seconds")
        created = db.q1("SELECT COUNT(*) AS n FROM tasks WHERE created_at>=? AND created_at<?",
                        (start, end))
        done = db.q1("SELECT COUNT(*) AS n FROM tasks WHERE finished_at>=? AND finished_at<?",
                     (start, end))
        trend.append({"date": d.strftime("%m-%d"),
                      "created": int(created["n"]), "done": int(done["n"])})

    pause_until = db.meta_get("pause_until") or ""
    today_created = db.q1(
        "SELECT COUNT(*) AS n FROM tasks WHERE created_at>=?", (today_start,))
    today_done = db.q1(
        "SELECT COUNT(*) AS n FROM tasks WHERE finished_at>=?", (today_start,))
    return {"ok": True,
            "today": {"created": int(today_created["n"]), "done": int(today_done["n"])},
            "pending": (s.get("submitted") or 0) + (s.get("queued") or 0),
            "active": (s.get("logging") or 0) + (s.get("ready") or 0)
                      + (s.get("running") or 0),
            "stats": s,
            "agents": agents,
            "agents_online": agents_online,
            "trend": trend,
            "dispatch": {
                "paused": bool(pause_until and pause_until > db.now()),
                "pause_until": pause_until or None,
                "quiet_hours": C.QUIET_HOURS,
                "online_threshold": db.setting_int("online_threshold", C.ONLINE_THRESHOLD),
            }}


@app.get("/admin/dispatch")
async def admin_dispatch(_=Depends(admin_auth)):
    """调度控制中心：全局暂停状态、禁刷时段、各节点接单开关。"""
    pause_until = db.meta_get("pause_until") or ""
    return {"ok": True,
            "paused": bool(pause_until and pause_until > db.now()),
            "pause_until": pause_until or None,
            "quiet_hours": C.QUIET_HOURS,
            "online_threshold": db.setting_int("online_threshold", C.ONLINE_THRESHOLD),
            "agents": _agents_with_status()}


@app.get("/admin/events")
async def admin_events(limit: int = 80, level: str = "", q: str = "",
                       task_id: int = 0, _=Depends(admin_auth)):
    where, args = [], []
    if level in ("info", "warn", "error"):
        where.append("level=?")
        args.append(level)
    if q:
        where.append("msg LIKE ?")
        args.append(f"%{q}%")
    if task_id:
        where.append("task_id=?")
        args.append(task_id)
    w = ("WHERE " + " AND ".join(where)) if where else ""
    return {"ok": True,
            "events": db.q(f"""SELECT id, task_id, agent_id, ts, level, msg
                               FROM events {w} ORDER BY id DESC LIMIT ?""",
                           tuple(args) + (limit,))}


@app.get("/admin/cards/all")
async def admin_cards_all(limit: int = 5000, _=Depends(admin_auth)):
    # cards 表主键是 code，没有 id 列，也没有 used 列（用 status 表示是否已用）。
    # 之前这里写了 used 和 ORDER BY id，接口一调就 500，面板上导出卡密是坏的。
    rows = db.q("""SELECT rowid AS no, code, quota, COALESCE(quota_total, quota) AS quota_total, status, product, batch,
                          created_at, activated_at, expires_at
                   FROM cards ORDER BY rowid DESC LIMIT ?""", (limit,))
    return {"ok": True, "count": len(rows),
            "codes": [r["code"] for r in rows],
            "detail": rows}


@app.post("/admin/cards/{code}/revoke")
async def admin_card_revoke(code: str, _=Depends(admin_auth)):
    """禁用卡密（复用 schema 已有的 revoked 状态）。"""
    r = cards.revoke(code)
    if not r.get("ok"):
        raise HTTPException(400, detail={"error": r.get("error"),
                                         "code": r.get("code", "BAD_REQUEST")})
    return r


# ---------------------------------------------------------------- 前台用户账号

class UserAuthIn(BaseModel):
    username: str = ""
    password: str = ""


def _norm_user(s: str) -> str:
    return (s or "").strip()


@app.post("/api/register")
async def api_register(body: UserAuthIn, request: Request, response: Response):
    ip = (request.client.host if request.client else "?") or "?"
    if not _rate_ok(f"reg:{ip}", limit=5, window=60):
        return JSONResponse({"ok": False, "error": "操作太频繁，请稍后再试",
                             "code": "RATE_LIMITED"}, status_code=429)
    u = _norm_user(body.username)
    p = body.password or ""
    if len(u) < 5 or len(u) > 32:
        return JSONResponse({"ok": False, "error": "账号至少 5 位（建议用手机号）",
                             "code": "BAD_REQUEST"}, status_code=400)
    if len(p) < 6:
        return JSONResponse({"ok": False, "error": "密码至少 6 位",
                             "code": "BAD_REQUEST"}, status_code=400)
    if db.q1("SELECT id FROM users WHERE username=?", (u,)):
        return JSONResponse({"ok": False, "error": "这个账号已经注册过了，请直接登录",
                             "code": "EXISTS"}, status_code=409)
    uid = db.ex("INSERT INTO users(username, password_hash, created_at, last_login_at) "
                "VALUES(?,?,?,?)",
                (u, crypto.hash_password(p), db.now(), db.now()))
    exp = int(time.time()) + USER_SESSION_DAYS * 86400
    response.set_cookie(USER_COOKIE, _user_session_value(uid, exp),
                        max_age=USER_SESSION_DAYS * 86400, httponly=True,
                        secure=True, samesite="lax", path="/")
    db.log(None, "info", f"用户注册 {crypto.mask(u)}")
    return {"ok": True, "user": {"id": uid, "username": u}}


@app.post("/api/login")
async def api_user_login(body: UserAuthIn, request: Request, response: Response):
    ip = (request.client.host if request.client else "?") or "?"
    if not _rate_ok(f"ulogin:{ip}", limit=10, window=60):
        return JSONResponse({"ok": False, "error": "登录太频繁，请稍后再试",
                             "code": "RATE_LIMITED"}, status_code=429)
    u = _norm_user(body.username)
    row = db.q1("SELECT * FROM users WHERE username=? AND status='active'", (u,))
    if not row or not crypto.verify_password(body.password or "", row["password_hash"]):
        return JSONResponse({"ok": False, "error": "账号或密码不正确",
                             "code": "BAD_CREDENTIALS"}, status_code=401)
    db.ex("UPDATE users SET last_login_at=? WHERE id=?", (db.now(), row["id"]))
    exp = int(time.time()) + USER_SESSION_DAYS * 86400
    response.set_cookie(USER_COOKIE, _user_session_value(row["id"], exp),
                        max_age=USER_SESSION_DAYS * 86400, httponly=True,
                        secure=True, samesite="lax", path="/")
    return {"ok": True, "user": {"id": row["id"], "username": row["username"]}}


@app.post("/api/logout")
async def api_user_logout(response: Response):
    response.delete_cookie(USER_COOKIE, path="/")
    return {"ok": True}


@app.get("/api/me")
async def api_me(request: Request):
    u = current_user(request)
    return {"ok": True, "user": ({"id": u["id"], "username": u["username"]} if u else None)}


@app.get("/api/site")
async def api_site():
    """站点公开信息（系统设置里的站名/副标题/客服联系方式）。"""
    return {"ok": True,
            "site_name": db.setting_str("site_name", "CX 服务中心"),
            "site_subtitle": db.setting_str("site_subtitle",
                                            "快捷提交服务需求，实时查看处理进度"),
            "contact": db.setting_str("contact", "")}


def _task_brief_rows_from(rows: list) -> list:
    out = []
    for r in rows:
        try:
            uu = crypto.mask(crypto.decrypt(r.pop("username_enc")))
        except Exception:
            r.pop("username_enc", None)
            uu = "-"
        out.append({"id": r["id"], "status": r["status"],
                    "course_name": r["course_name"], "username": uu,
                    "created_at": r["created_at"], "updated_at": r["updated_at"],
                    "status_url": f"{C.PUBLIC_URL}/s/{r['id']}?t={view_token(r['id'])}"})
    return out


@app.get("/api/my/tasks")
async def api_my_tasks(request: Request):
    """登录用户的订单列表（前台「查询进度」用）。"""
    u = current_user(request)
    if not u:
        raise HTTPException(401, detail={"error": "请先登录", "code": "UNAUTHORIZED"})
    rows = db.q("""SELECT t.id, t.status, t.course_name, t.created_at, t.updated_at,
                          a.username_enc
                   FROM tasks t LEFT JOIN accounts a ON a.id=t.account_id
                   WHERE t.user_id=? ORDER BY t.id DESC LIMIT 50""", (u["id"],))
    return {"ok": True, "tasks": _task_brief_rows_from(rows)}


class CardQueryIn(BaseModel):
    card: str = ""


@app.post("/api/query/by-card")
async def api_query_by_card(body: CardQueryIn, request: Request):
    """未登录用户凭卡密查询自己名下的订单。卡密本身即凭证。"""
    ip = (request.client.host if request.client else "?") or "?"
    if not _rate_ok(f"qc:{ip}", limit=8, window=60):
        return JSONResponse({"ok": False, "error": "查询太频繁，请稍后再试",
                             "code": "RATE_LIMITED"}, status_code=429)
    code = cards.normalize(body.card or "")
    if not cards.verify_format(code):
        return JSONResponse({"ok": False, "error": "卡密格式不正确",
                             "code": "BAD_FORMAT"}, status_code=400)
    rows = db.q("""SELECT t.id, t.status, t.course_name, t.created_at, t.updated_at,
                          a.username_enc
                   FROM tasks t LEFT JOIN accounts a ON a.id=t.account_id
                   WHERE t.card_code=? ORDER BY t.id DESC LIMIT 50""", (code,))
    return {"ok": True, "tasks": _task_brief_rows_from(rows),
            "message": "" if rows else "这张卡密下还没有订单记录"}


# ---------------------------------------------------------------- 对外：状态统计与公告

@app.get("/api/status")
async def api_status():
    """平台公开状态。只输出布尔/计数：不暴露节点 ID、IP、负载、数据库信息。"""
    from datetime import datetime, timezone

    now = datetime.now(timezone.utc)
    online = 0
    total = 0
    for r in db.q("SELECT last_seen FROM agents"):
        total += 1
        if r.get("last_seen"):
            try:
                if (now - datetime.fromisoformat(r["last_seen"])).total_seconds() \
                        <= db.setting_int("online_threshold", C.ONLINE_THRESHOLD):
                    online += 1
            except Exception:
                pass
    pause_until = db.meta_get("pause_until") or ""
    paused = bool(pause_until and pause_until > db.now())
    return {"ok": True, "service": "cx", "version": "0.5.0",
            "normal": True, "accepting": not paused,
            "nodes_online": online, "nodes_total": total}


# ---------------------------------------------------------------- 公开：公告 / 帮助 / 反馈

@app.get("/api/announcements")
async def api_announcements(limit: int = 10):
    rows = db.q("""SELECT id, title, is_pinned, created_at FROM announcements
                   WHERE published=1
                   ORDER BY is_pinned DESC, id DESC LIMIT ?""", (max(1, min(limit, 50)),))
    return {"ok": True, "announcements": rows}


@app.get("/api/announcements/{aid}")
async def api_announcement_detail(aid: int):
    row = db.q1("""SELECT id, title, content, is_pinned, created_at
                   FROM announcements WHERE id=? AND published=1""", (aid,))
    if not row:
        raise HTTPException(404, detail={"error": "公告不存在", "code": "NOT_FOUND"})
    return {"ok": True, "announcement": row}


@app.get("/api/help")
async def api_help():
    rows = db.q("""SELECT id, title, content, category FROM help_articles
                   WHERE published=1 ORDER BY category, sort, id""")
    cats: dict[str, list] = {}
    for r in rows:
        cats.setdefault(r["category"], []).append(
            {"id": r["id"], "title": r["title"], "content": r["content"]})
    return {"ok": True,
            "categories": [{"category": k, "articles": v} for k, v in cats.items()]}


class FeedbackIn(BaseModel):
    kind: str = "其他问题"
    task_id: int = 0
    contact: str = ""
    content: str = ""


FEEDBACK_KINDS = ("卡密问题", "服务提交", "服务进度", "账号问题", "其他问题")


@app.post("/api/feedback")
async def api_feedback(body: FeedbackIn, request: Request):
    ip = (request.client.host if request.client else "?") or "?"
    if not _rate_ok(f"fb:{ip}", limit=3, window=60):
        return JSONResponse({"ok": False, "error": "提交太频繁，请稍后再试",
                             "code": "RATE_LIMITED"}, status_code=429)
    content = (body.content or "").strip()
    if len(content) < 5:
        return JSONResponse({"ok": False, "error": "请描述一下遇到的问题（至少 5 个字）",
                             "code": "BAD_REQUEST"}, status_code=400)
    if len(content) > 1000:
        content = content[:1000]
    kind = body.kind if body.kind in FEEDBACK_KINDS else "其他问题"
    tid = body.task_id or None
    if tid and not db.q1("SELECT id FROM tasks WHERE id=?", (tid,)):
        tid = None
    ts = db.now()
    fid = db.ex("""INSERT INTO feedback(kind, task_id, contact, content, status, created_at, updated_at)
                   VALUES(?,?,?,?, 'pending', ?, ?)""",
                (kind, tid, (body.contact or "").strip()[:100], content, ts, ts))
    db.log(None, "info", f"收到用户反馈 #{fid}（{kind}）")
    return {"ok": True, "feedback_id": fid}


# ---------------------------------------------------------------- 管理：数据分析 / 异常任务

@app.get("/admin/analytics")
async def admin_analytics(days: int = 7, _=Depends(admin_auth)):
    """数据分析：任务趋势（新增/完成/失败）、卡密统计、成功率。全部 SQL 聚合。"""
    from datetime import datetime, timedelta, timezone

    days = max(1, min(days, 90))
    now = datetime.now().astimezone()
    start_day = (now - timedelta(days=days - 1)).replace(hour=0, minute=0, second=0,
                                                         microsecond=0)
    start_utc = start_day.astimezone(timezone.utc).isoformat(timespec="seconds")
    end_utc = (now + timedelta(days=1)).replace(hour=0, minute=0, second=0,
                                                microsecond=0) \
        .astimezone(timezone.utc).isoformat(timespec="seconds")

    trend = []
    for i in range(days):
        d = start_day + timedelta(days=i)
        d_end = d + timedelta(days=1)
        ds = d.astimezone(timezone.utc).isoformat(timespec="seconds")
        de = d_end.astimezone(timezone.utc).isoformat(timespec="seconds")
        created = db.q1("SELECT COUNT(*) AS n FROM tasks WHERE created_at>=? AND created_at<?",
                        (ds, de))
        done = db.q1("SELECT COUNT(*) AS n FROM tasks WHERE finished_at>=? AND finished_at<?",
                     (ds, de))
        failed = db.q1("""SELECT COUNT(*) AS n FROM tasks
                          WHERE status='failed' AND updated_at>=? AND updated_at<?""",
                       (ds, de))
        trend.append({"date": d.strftime("%m-%d"), "created": int(created["n"]),
                      "done": int(done["n"]), "failed": int(failed["n"])})

    cards = db.q1("""SELECT COUNT(*) AS total,
                     SUM(CASE WHEN status='active' THEN 1 ELSE 0 END) AS used,
                     SUM(CASE WHEN status='unused' THEN 1 ELSE 0 END) AS unused,
                     SUM(CASE WHEN status='revoked' THEN 1 ELSE 0 END) AS revoked
                     FROM cards""")
    total = int(cards["total"] or 0)
    used = int(cards["used"] or 0)
    finish = db.q1("""SELECT
                      SUM(CASE WHEN status='done' THEN 1 ELSE 0 END) AS done,
                      SUM(CASE WHEN status='failed' THEN 1 ELSE 0 END) AS failed,
                      SUM(CASE WHEN status='canceled' THEN 1 ELSE 0 END) AS canceled
                      FROM tasks WHERE created_at>=?""", (start_utc,))
    d_ = int(finish["done"] or 0)
    f_ = int(finish["failed"] or 0)
    c_ = int(finish["canceled"] or 0)
    denom = d_ + f_
    return {"ok": True, "days": days,
            "trend": trend,
            "cards": {"total": total, "used": used,
                      "unused": int(cards["unused"] or 0),
                      "revoked": int(cards["revoked"] or 0),
                      "usage_rate": round(used / total, 4) if total else 0},
            "outcome": {"done": d_, "failed": f_, "canceled": c_,
                        "success_rate": round(d_ / denom, 4) if denom else 0}}


@app.get("/admin/abnormal")
async def admin_abnormal(_=Depends(admin_auth)):
    """异常任务：failed 任务 + 长时间无状态更新的在跑任务（agent 保活每 30s
    刷新 updated_at，静默超过 30 分钟视为卡住）。"""
    from datetime import datetime, timedelta, timezone

    stale_before = (datetime.now(timezone.utc) - timedelta(minutes=30)) \
        .isoformat(timespec="seconds")

    def _rows(sql, args):
        out = []
        for r in db.q(sql, args):
            try:
                r["username"] = crypto.mask(crypto.decrypt(r.pop("username_enc")))
            except Exception:
                r.pop("username_enc", None)
                r["username"] = "-"
            out.append(r)
        return out

    failed = _rows(
        """SELECT t.id, t.status, t.course_name, t.agent_id, t.message,
                  t.updated_at, a.username_enc
           FROM tasks t LEFT JOIN accounts a ON a.id=t.account_id
           WHERE t.status='failed' ORDER BY t.updated_at DESC LIMIT 50""", ())
    stale = _rows(
        """SELECT t.id, t.status, t.course_name, t.agent_id, t.message,
                  t.updated_at, a.username_enc
           FROM tasks t LEFT JOIN accounts a ON a.id=t.account_id
           WHERE t.status IN ('logging','ready','running') AND t.updated_at < ?
           ORDER BY t.updated_at LIMIT 50""", (stale_before,))
    return {"ok": True, "failed": failed, "stale": stale}


# ---------------------------------------------------------------- 管理：任务截图

@app.get("/admin/task/{task_id}/shots")
async def admin_task_shots(task_id: int, _=Depends(admin_auth)):
    """列出该任务的异常截图文件名。"""
    names = sorted((C.DATA / "shots").glob(f"task{task_id}_*.jpg")) \
        if (C.DATA / "shots").exists() else []
    return {"ok": True, "task_id": task_id,
            "shots": [n.name for n in names][-20:]}


@app.get("/admin/shots/{name}")
async def admin_shot_file(name: str, _=Depends(admin_auth)):
    """查看截图。文件名白名单校验，杜绝目录穿越；不公开暴露目录。"""
    import re
    from fastapi.responses import FileResponse

    if not re.fullmatch(r"task\d+_[\d.]+\.jpg", name or ""):
        raise HTTPException(400, detail={"error": "文件名不合法", "code": "BAD_REQUEST"})
    path = C.DATA / "shots" / name
    if not path.exists():
        raise HTTPException(404, detail={"error": "截图不存在", "code": "NOT_FOUND"})
    return FileResponse(path, media_type="image/jpeg")


# ---------------------------------------------------------------- 管理：公告 / 帮助 CRUD

class AnnouncementIn(BaseModel):
    title: str = ""
    content: str = ""
    is_pinned: bool = False
    published: bool = True


@app.get("/admin/announcements")
async def admin_announcements(_=Depends(admin_auth)):
    return {"ok": True,
            "announcements": db.q("""SELECT * FROM announcements
                                     ORDER BY is_pinned DESC, id DESC LIMIT 200""")}


@app.post("/admin/announcements")
async def admin_announcement_add(body: AnnouncementIn, request: Request,
                                 _=Depends(admin_auth)):
    title = (body.title or "").strip()
    content = (body.content or "").strip()
    if not title or not content:
        raise HTTPException(400, detail={"error": "标题和内容都要填", "code": "BAD_REQUEST"})
    ts = db.now()
    aid = db.ex("""INSERT INTO announcements(title, content, is_pinned, published, created_at, updated_at)
                   VALUES(?,?,?,?,?,?)""",
                (title[:200], content, 1 if body.is_pinned else 0,
                 1 if body.published else 0, ts, ts))
    db.audit("announcement.add", f"#{aid}", title[:80], request.client.host if request.client else "")
    return {"ok": True, "id": aid}


@app.put("/admin/announcements/{aid}")
async def admin_announcement_edit(aid: int, body: AnnouncementIn, request: Request,
                                  _=Depends(admin_auth)):
    if not db.q1("SELECT id FROM announcements WHERE id=?", (aid,)):
        raise HTTPException(404, detail={"error": "公告不存在", "code": "NOT_FOUND"})
    title = (body.title or "").strip()
    content = (body.content or "").strip()
    if not title or not content:
        raise HTTPException(400, detail={"error": "标题和内容都要填", "code": "BAD_REQUEST"})
    db.ex("""UPDATE announcements SET title=?, content=?, is_pinned=?, published=?,
             updated_at=? WHERE id=?""",
          (title[:200], content, 1 if body.is_pinned else 0,
           1 if body.published else 0, db.now(), aid))
    db.audit("announcement.edit", f"#{aid}", title[:80], request.client.host if request.client else "")
    return {"ok": True}


@app.delete("/admin/announcements/{aid}")
async def admin_announcement_del(aid: int, request: Request, _=Depends(admin_auth)):
    if not db.q1("SELECT id FROM announcements WHERE id=?", (aid,)):
        raise HTTPException(404, detail={"error": "公告不存在", "code": "NOT_FOUND"})
    db.ex("DELETE FROM announcements WHERE id=?", (aid,))
    db.audit("announcement.del", f"#{aid}", "", request.client.host if request.client else "")
    return {"ok": True}


class HelpIn(BaseModel):
    title: str = ""
    content: str = ""
    category: str = "常见问题"
    sort: int = 0
    published: bool = True


@app.get("/admin/help")
async def admin_help(_=Depends(admin_auth)):
    return {"ok": True,
            "articles": db.q("SELECT * FROM help_articles ORDER BY category, sort, id")}


@app.post("/admin/help")
async def admin_help_add(body: HelpIn, request: Request, _=Depends(admin_auth)):
    title = (body.title or "").strip()
    content = (body.content or "").strip()
    if not title or not content:
        raise HTTPException(400, detail={"error": "标题和内容都要填", "code": "BAD_REQUEST"})
    ts = db.now()
    hid = db.ex("""INSERT INTO help_articles(title, content, category, sort, published, created_at, updated_at)
                   VALUES(?,?,?,?,?,?,?)""",
                (title[:200], content, (body.category or "常见问题")[:32],
                 int(body.sort), 1 if body.published else 0, ts, ts))
    db.audit("help.add", f"#{hid}", title[:80], request.client.host if request.client else "")
    return {"ok": True, "id": hid}


@app.put("/admin/help/{hid}")
async def admin_help_edit(hid: int, body: HelpIn, request: Request, _=Depends(admin_auth)):
    if not db.q1("SELECT id FROM help_articles WHERE id=?", (hid,)):
        raise HTTPException(404, detail={"error": "文章不存在", "code": "NOT_FOUND"})
    title = (body.title or "").strip()
    content = (body.content or "").strip()
    if not title or not content:
        raise HTTPException(400, detail={"error": "标题和内容都要填", "code": "BAD_REQUEST"})
    db.ex("""UPDATE help_articles SET title=?, content=?, category=?, sort=?, published=?,
             updated_at=? WHERE id=?""",
          (title[:200], content, (body.category or "常见问题")[:32],
           int(body.sort), 1 if body.published else 0, db.now(), hid))
    db.audit("help.edit", f"#{hid}", title[:80], request.client.host if request.client else "")
    return {"ok": True}


@app.delete("/admin/help/{hid}")
async def admin_help_del(hid: int, request: Request, _=Depends(admin_auth)):
    if not db.q1("SELECT id FROM help_articles WHERE id=?", (hid,)):
        raise HTTPException(404, detail={"error": "文章不存在", "code": "NOT_FOUND"})
    db.ex("DELETE FROM help_articles WHERE id=?", (hid,))
    db.audit("help.del", f"#{hid}", "", request.client.host if request.client else "")
    return {"ok": True}


# ---------------------------------------------------------------- 管理：用户反馈

@app.get("/admin/feedback")
async def admin_feedback(status: str = "", _=Depends(admin_auth)):
    where, args = [], []
    if status in ("pending", "processing", "resolved"):
        where.append("status=?")
        args.append(status)
    w = ("WHERE " + " AND ".join(where)) if where else ""
    return {"ok": True,
            "feedback": db.q(f"""SELECT * FROM feedback {w}
                                 ORDER BY CASE status WHEN 'pending' THEN 0
                                                      WHEN 'processing' THEN 1
                                                      ELSE 2 END, id DESC
                                 LIMIT 200""", tuple(args))}


class ReplyIn(BaseModel):
    reply: str = ""
    status: str = ""


@app.post("/admin/feedback/{fid}/reply")
async def admin_feedback_reply(fid: int, body: ReplyIn, request: Request,
                               _=Depends(admin_auth)):
    row = db.q1("SELECT id FROM feedback WHERE id=?", (fid,))
    if not row:
        raise HTTPException(404, detail={"error": "反馈不存在", "code": "NOT_FOUND"})
    reply = (body.reply or "").strip()
    if not reply:
        raise HTTPException(400, detail={"error": "回复内容不能为空", "code": "BAD_REQUEST"})
    patch = {"reply": reply[:1000], "replied_at": db.now(), "updated_at": db.now()}
    if body.status in ("pending", "processing", "resolved"):
        patch["status"] = body.status
    sets = ", ".join(f"{k}=?" for k in patch)
    db.ex(f"UPDATE feedback SET {sets} WHERE id=?", tuple(patch.values()) + (fid,))
    db.audit("feedback.reply", f"#{fid}", "", request.client.host if request.client else "")
    return {"ok": True}


# ---------------------------------------------------------------- 管理：操作审计 / 系统设置

@app.get("/admin/audit")
async def admin_audit_list(limit: int = 100, _=Depends(admin_auth)):
    return {"ok": True,
            "audit": db.q("SELECT * FROM admin_audit ORDER BY id DESC LIMIT ?",
                          (max(1, min(limit, 500)),))}


SETTINGS_SCHEMA = {
    # key: (中文名, 类型 int/str, 最小, 最大)
    "site_name": ("网站名称", "str", 0, 40),
    "site_subtitle": ("网站副标题", "str", 0, 80),
    "contact": ("客服联系方式", "str", 0, 100),
    "lease_seconds": ("任务租约时长（秒）", "int", 300, 86400),
    "online_threshold": ("节点在线判定（秒）", "int", 10, 600),
    "event_days": ("事件日志保留（天）", "int", 7, 365),
    "shot_days": ("截图保留（天）", "int", 3, 180),
}


@app.get("/admin/settings")
async def admin_settings_get(_=Depends(admin_auth)):
    out = {}
    for k, (label, typ, lo, hi) in SETTINGS_SCHEMA.items():
        if typ == "int":
            default = {"lease_seconds": C.LEASE_SECONDS,
                       "online_threshold": C.ONLINE_THRESHOLD,
                       "event_days": C.EVENT_RETENTION_DAYS,
                       "shot_days": C.SHOT_RETENTION_DAYS}.get(k, 0)
            out[k] = {"label": label, "value": db.setting_int(k, default),
                      "min": lo, "max": hi, "type": "int"}
        else:
            out[k] = {"label": label, "value": db.setting_str(k), "type": "str"}
    return {"ok": True, "settings": out}


@app.post("/admin/settings")
async def admin_settings_set(request: Request, _=Depends(admin_auth)):
    body = await request.json()
    if not isinstance(body, dict):
        raise HTTPException(400, detail={"error": "请求体必须是 JSON 对象",
                                         "code": "BAD_REQUEST"})
    changed = []
    for k, v in body.items():
        if k not in SETTINGS_SCHEMA:
            continue
        label, typ, lo, hi = SETTINGS_SCHEMA[k]
        if typ == "int":
            try:
                n = int(v)
            except (TypeError, ValueError):
                raise HTTPException(400, detail={"error": f"{label}必须是数字",
                                                 "code": "BAD_REQUEST"})
            if not (lo <= n <= hi):
                raise HTTPException(400, detail={
                    "error": f"{label}必须在 {lo}~{hi} 之间", "code": "BAD_REQUEST"})
            db.meta_set(k, str(n))
        else:
            db.meta_set(k, str(v)[:hi])
        changed.append(k)
    if changed:
        db.audit("settings.set", ",".join(changed), "",
                 request.client.host if request.client else "")
    return {"ok": True, "changed": changed}


@app.get("/admin", response_class=HTMLResponse)
async def admin_page(token: str = ""):
    """管理面板。

    页面本身不含敏感数据，真正的数据要靠 X-Admin-Token 才能取，
    所以这里只校验一个形式上的 token 是否存在，具体验证在 API 层做。
    """
    path = C.DATA.parent / "center" / "static" / "admin.html"
    if not path.exists():
        path = __import__("pathlib").Path(__file__).parent / "static" / "admin.html"
    try:
        return path.read_text(encoding="utf-8")
    except Exception as e:
        return HTMLResponse(f"<h1>管理面板丢失</h1><p>{e}</p><p>期望位置 {path}</p>",
                            status_code=500)


@app.get("/", response_class=HTMLResponse)
async def index():
    return INDEX_HTML


INDEX_HTML = """<!doctype html><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>CX 服务中心</title>
<style>
:root{--bg:#f4f6fb;--panel:#fff;--line:#e5e9f2;--ink:#17233f;--sub:#64748b;--faint:#9aa7bd;
  --pri:#3b6fd1;--pri2:#4C8DFF;--ok:#1f9d66;--warn:#c47d12;
  --shadow:0 1px 2px rgba(23,35,63,.05),0 10px 30px -14px rgba(23,35,63,.14)}
*{box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{margin:0;background:var(--bg);color:var(--ink);
  font:15px/1.7 -apple-system,BlinkMacSystemFont,"Segoe UI","Microsoft YaHei",sans-serif}
a{color:var(--pri);text-decoration:none}
.nav{position:sticky;top:0;z-index:50;background:rgba(255,255,255,.92);
  backdrop-filter:blur(10px);border-bottom:1px solid var(--line)}
.nav-in{max-width:1040px;margin:0 auto;padding:0 20px;height:58px;display:flex;align-items:center;gap:22px}
.brand{display:flex;align-items:center;gap:9px;font-weight:800;font-size:16px;color:var(--ink);flex:none}
.brand .bi{width:32px;height:32px;border-radius:9px;color:#fff;
  background:linear-gradient(135deg,var(--pri2),var(--pri));display:flex;align-items:center;justify-content:center}
.nav-links{display:flex;gap:4px}
.nav-links a{padding:7px 13px;border-radius:9px;color:var(--sub);font-size:14px;font-weight:500}
.nav-links a:hover{color:var(--ink);background:#f1f4fa}
.nav-links a.on{color:var(--pri);background:#eef3fe;font-weight:600}
.nav-cta{margin-left:auto;display:flex;gap:9px;align-items:center}
.nav-cta a.nt{font-size:13.5px;color:var(--sub);padding:6px 10px;border-radius:8px}
.nav-cta a.nt:hover{background:#f1f4fa;color:var(--ink)}
.btn{display:inline-flex;align-items:center;justify-content:center;gap:8px;
  background:linear-gradient(135deg,var(--pri2),var(--pri));color:#fff;border:0;border-radius:11px;
  padding:10px 20px;font-size:14px;font-weight:600;cursor:pointer;font-family:inherit;transition:.18s;
  box-shadow:0 8px 20px -8px rgba(59,111,209,.5)}
.btn:hover{transform:translateY(-1px);filter:brightness(1.06)}
.btn.ghost{background:#fff;color:var(--ink);border:1px solid var(--line);box-shadow:none}
.btn.ghost:hover{background:#f7f9fd}
#navToggle{display:none;background:none;border:0;font-size:22px;color:var(--ink);cursor:pointer}
.wrap{max-width:1040px;margin:0 auto;padding:0 20px}

.hero{margin:30px 0 0;background:linear-gradient(135deg,#16337e,#2456c9 60%,#3b6fd1);
  border-radius:24px;padding:46px 40px;color:#fff;position:relative;overflow:hidden;
  box-shadow:0 20px 50px -22px rgba(36,86,201,.55)}
.hero::after{content:"";position:absolute;right:-70px;top:-80px;width:260px;height:260px;
  border-radius:50%;background:rgba(255,255,255,.07)}
.hero h1{font-size:29px;margin:0 0 10px;letter-spacing:.5px}
.hero p{color:rgba(255,255,255,.84);font-size:15px;margin:0 0 24px;max-width:520px}
.hero .btns{display:flex;gap:12px;flex-wrap:wrap;position:relative}
.hero .btn.ghost{background:rgba(255,255,255,.15);color:#fff;border-color:rgba(255,255,255,.3)}
.hero .btn.ghost:hover{background:rgba(255,255,255,.24)}

.sect{margin-top:26px}
.sect h2{font-size:17px;margin:0 0 14px;display:flex;align-items:center;gap:9px}
.sect h2::before{content:"";width:4px;height:16px;border-radius:2px;
  background:linear-gradient(180deg,var(--pri2),var(--pri))}
.sect h2 .r{margin-left:auto;font-size:13px;font-weight:400}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:16px;
  padding:18px 20px;box-shadow:var(--shadow)}
.ann{display:block;background:var(--panel);border:1px solid var(--line);border-radius:13px;
  padding:14px 17px;margin-bottom:9px;color:var(--ink);transition:.15s;box-shadow:var(--shadow)}
.ann:hover{transform:translateY(-1px);border-color:#cfd8e8}
.ann .t{font-weight:600;font-size:14px;display:flex;align-items:center;gap:8px}
.ann .d{color:var(--faint);font-size:12px;margin-top:3px}
.pin{background:#fff4e0;color:var(--warn);border:1px solid #f5d9a8;border-radius:999px;
  padding:1px 9px;font-size:11px;font-weight:700;flex:none}
.strow{display:flex;align-items:center;gap:11px;font-size:14px}
.strow .dot{width:9px;height:9px;border-radius:50%;flex:none}
.dot.on{background:#22c58b;box-shadow:0 0 0 3.5px rgba(34,197,139,.18)}
.dot.off{background:#cbd5e1}
.strow span{color:var(--sub);font-size:12.5px;margin-left:auto}
.empty{color:var(--faint);text-align:center;padding:22px 16px;font-size:13.5px}
.grid2{display:grid;grid-template-columns:1.4fr 1fr;gap:14px}
.foot{margin:40px 0 30px;text-align:center;color:var(--faint);font-size:12.5px}
@media (max-width:760px){
  .nav-links{display:none;position:absolute;top:58px;left:0;right:0;background:#fff;
    flex-direction:column;padding:10px 16px;border-bottom:1px solid var(--line);gap:2px}
  .nav-links.open{display:flex}
  .nav-links a{padding:11px 13px}
  #navToggle{display:block}
  .nav-cta .nt{display:none}
  .hero{padding:34px 24px}
  .hero h1{font-size:23px}
  .grid2{grid-template-columns:1fr}
}
</style>

<header class="nav">
  <div class="nav-in">
    <a class="brand" href="./">
      <span class="bi"><svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 10L12 5 2 10l10 5 10-5z"/><path d="M6 12.5V17c0 1.66 2.69 3 6 3s6-1.34 6-3v-4.5"/></svg></span>
      <span id="siteName">CX 服务中心</span></a>
    <nav class="nav-links" id="navLinks">
      <a href="./" class="on">首页</a>
      <a href="./track">查询进度</a>
      <a href="./help">帮助中心</a>
    </nav>
    <div class="nav-cta">
      <a class="nt" href="./announcements">公告</a>
      <span id="userArea"></span>
      <a class="btn" href="https://example.com/" target="_blank" rel="noopener"
         style="padding:8px 16px;font-size:13.5px">获取卡密</a>
    </div>
    <button id="navToggle" aria-label="菜单">☰</button>
  </div>
</header>

<div class="wrap">
  <div class="hero">
    <h1 id="heroTitle">CX 服务中心</h1>
    <p id="heroSub">快捷提交服务需求，实时查看处理进度</p>
    <div class="btns">
      <a class="btn" href="./redeem">🎫 立即兑换</a>
      <a class="btn ghost" href="./track">🔍 查询进度</a>
    </div>
  </div>

  <div class="sect">
    <h2>服务公告<span class="r"><a href="./announcements">全部公告 →</a></span></h2>
    <div id="annBox"><div class="empty">加载中…</div></div>
  </div>

  <div class="sect" style="margin-top:22px">
    <h2>系统状态</h2>
    <div class="panel" id="statusBox"><div class="strow"><span class="dot on"></span><b>检测中…</b></div></div>
  </div>
</div>

<div class="foot" id="siteFoot">CX 服务中心 · 订单信息加密存储 · 处理进度以学习通课表为准</div>

<script>
document.getElementById('navToggle').onclick = function () {
  document.getElementById('navLinks').classList.toggle('open');
};
const esc = s => String(s == null ? '' : s).replace(/[&<>"']/g,
  c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));

async function loadSite() {
  try {
    const d = await (await fetch('api/site')).json();
    if (d.site_name) {
      document.title = d.site_name;
      document.getElementById('siteName').textContent = d.site_name;
      document.getElementById('heroTitle').textContent = d.site_name;
    }
    if (d.site_subtitle) {
      document.getElementById('heroSub').textContent = d.site_subtitle;
    }
    document.getElementById('siteFoot').textContent =
      (d.site_name || 'CX 服务中心') +
      (d.contact ? ' · 客服联系：' + d.contact : '') +
      ' · 订单信息加密存储';
  } catch (e) {}
}

async function loadUser() {
  try {
    const d = await (await fetch('api/me')).json();
    const box = document.getElementById('userArea');
    if (d.user) {
      box.innerHTML = '<a class="nt" href="./track">' + esc(d.user.username) +
        '</a><a class="nt" href="javascript:logout()">退出</a>';
    } else {
      box.innerHTML = '<a class="nt" href="./account">登录 / 注册</a>';
    }
  } catch (e) {}
}

async function logout() {
  await fetch('api/logout', {method: 'POST'});
  location.reload();
}

async function loadStatus() {
  try {
    const d = await (await fetch('api/status')).json();
    const on = d.nodes_online > 0;
    document.getElementById('statusBox').innerHTML =
      '<div class="strow"><span class="dot ' + (on ? 'on' : 'off') + '"></span>' +
      '<b>服务节点' + (on ? '正常' : '离线') + '</b>' +
      '<span>' + d.nodes_online + ' / ' + d.nodes_total + ' 在线</span></div>';
  } catch (e) {
    document.getElementById('statusBox').innerHTML =
      '<div class="strow"><span class="dot off"></span><b>服务节点状态获取失败</b></div>';
  }
}

async function loadAnn() {
  try {
    const d = await (await fetch('api/announcements?limit=3')).json();
    const list = d.announcements || [];
    document.getElementById('annBox').innerHTML = list.length ? list.map(a =>
      '<a class="ann" href="./announcements?id=' + a.id + '">' +
      '<div class="t">' + (a.is_pinned ? '<span class="pin">置顶</span>' : '') +
      '<span>' + esc(a.title) + '</span></div>' +
      '<div class="d">' + a.created_at.slice(0, 16).replace('T', ' ') + '</div></a>'
    ).join('') : '<div class="empty">暂无公告</div>';
  } catch (e) {}
}

loadSite(); loadUser(); loadStatus(); loadAnn();
setInterval(loadStatus, 30000);
</script>
"""



REDEEM_HTML = """<!doctype html><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>服务兑换 · CX 服务中心</title>
<style>
:root{--bg:#f4f6fb;--panel:#fff;--line:#e5e9f2;--ink:#17233f;--sub:#64748b;--faint:#9aa7bd;
  --pri:#3b6fd1;--pri2:#4C8DFF;--ok:#1f9d66;--warn:#c47d12;--err:#d33f4e;
  --shadow:0 1px 2px rgba(23,35,63,.05),0 10px 30px -14px rgba(23,35,63,.14)}
*{box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{margin:0;background:var(--bg);color:var(--ink);
  font:15px/1.7 -apple-system,BlinkMacSystemFont,"Segoe UI","Microsoft YaHei",sans-serif}
a{color:var(--pri);text-decoration:none}
.nav{position:sticky;top:0;z-index:50;background:rgba(255,255,255,.92);backdrop-filter:blur(10px);border-bottom:1px solid var(--line)}
.nav-in{max-width:1040px;margin:0 auto;padding:0 20px;height:58px;display:flex;align-items:center;gap:22px}
.brand{display:flex;align-items:center;gap:9px;font-weight:800;font-size:16px;color:var(--ink);flex:none}
.brand .bi{width:32px;height:32px;border-radius:9px;color:#fff;background:linear-gradient(135deg,var(--pri2),var(--pri));display:flex;align-items:center;justify-content:center}
.nav-links{display:flex;gap:4px}
.nav-links a{padding:7px 13px;border-radius:9px;color:var(--sub);font-size:14px;font-weight:500}
.nav-links a:hover{color:var(--ink);background:#f1f4fa}
.nav-cta{margin-left:auto;display:flex;gap:9px;align-items:center}
.nav-cta a.nt{font-size:13.5px;color:var(--sub);padding:6px 10px;border-radius:8px}
.btn{display:inline-flex;align-items:center;justify-content:center;gap:8px;background:linear-gradient(135deg,var(--pri2),var(--pri));
  color:#fff;border:0;border-radius:11px;padding:10px 20px;font-size:14px;font-weight:600;
  cursor:pointer;font-family:inherit;transition:.18s;box-shadow:0 8px 20px -8px rgba(59,111,209,.5)}
.btn:hover{transform:translateY(-1px)}
#navToggle{display:none;background:none;border:0;font-size:22px;color:var(--ink);cursor:pointer}
.wrap{max-width:600px;margin:0 auto;padding:28px 18px 50px}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:18px;padding:24px 22px;box-shadow:var(--shadow)}
.steps{display:flex;align-items:center;margin-bottom:22px}
.step{display:flex;align-items:center;gap:8px;flex:none}
.step .num{width:25px;height:25px;border-radius:50%;background:#edf1f8;color:var(--faint);font-size:12px;
  font-weight:700;display:flex;align-items:center;justify-content:center;transition:.25s}
.step .t{font-size:13px;font-weight:600;color:var(--faint);transition:.25s}
.step.on .num{background:linear-gradient(135deg,var(--pri2),var(--pri));color:#fff;box-shadow:0 0 0 4px rgba(76,141,255,.16)}
.step.on .t{color:var(--ink)}
.step.done .num{background:#e3f6ee;color:var(--ok)}
.step.done .t{color:var(--ok)}
.bar{flex:1;height:2px;background:#e5e9f2;border-radius:2px;margin:0 10px;min-width:14px;transition:.35s}
.bar.on{background:var(--pri)}
.sec{display:flex;align-items:center;gap:9px;margin:20px 0 6px;font-size:13px;font-weight:700;
  color:var(--pri);letter-spacing:.4px}
.sec::after{content:"";flex:1;height:1px;background:var(--line)}
label{display:block;margin:13px 0 6px;font-size:13px;color:var(--sub);font-weight:500}
.field{position:relative}
.field>svg{position:absolute;left:13px;top:50%;transform:translateY(-50%);color:var(--faint);pointer-events:none;transition:.18s}
.field:focus-within>svg{color:var(--pri)}
input{width:100%;padding:11.5px 12px 11.5px 41px;border:1px solid var(--line);border-radius:11px;
  font-size:15px;background:#fbfcfe;transition:.18s;font-family:inherit;color:var(--ink)}
input:focus{outline:none;border-color:var(--pri);background:#fff;box-shadow:0 0 0 3.5px rgba(76,141,255,.14)}
input:disabled{background:#f1f4f9;color:var(--faint)}
input::placeholder{color:#b3bdd0}
#card{font-family:ui-monospace,Consolas,monospace;letter-spacing:.5px;text-transform:uppercase;font-weight:600}
.pwbox input{padding-right:48px}
.pw-eye{position:absolute;right:7px;top:50%;transform:translateY(-50%);width:34px;height:34px;margin:0;padding:0;
  border:0;border-radius:9px;background:none;color:var(--faint);cursor:pointer;
  display:flex;align-items:center;justify-content:center}
.pw-eye:hover{background:#f1f4f9}
.btn.block{display:block;width:100%;margin-top:16px;padding:13.5px;font-size:15px}
.btn.ghost{background:#fff;color:var(--ink);border:1px solid var(--line);box-shadow:none}
.btn.ghost:hover{background:#f7f9fd}
.hidden{display:none !important}
.hint{color:var(--faint);font-size:12.5px;margin-top:6px;line-height:1.6}
.badge{display:inline-flex;align-items:center;background:#e3f6ee;color:var(--ok);
  border:1px solid #bfe8d6;border-radius:999px;padding:2px 10px;font-size:12px;font-weight:700}
.notice{margin-top:16px;border-radius:12px;padding:12px 14px;font-size:13px;line-height:1.7;
  background:#fff8ec;border:1px solid #f5e0b8;color:#92610c;display:flex;gap:9px}
.notice svg{flex:none;margin-top:2px;color:var(--warn)}
#msg{margin-top:16px;font-size:14px;min-height:20px}
.ok{color:var(--ok)}.err{color:var(--err)}
.kv{display:grid;grid-template-columns:96px 1fr;gap:9px 14px;font-size:14px;background:#fbfcfe;
  border:1px solid var(--line);border-radius:12px;padding:15px 17px;margin-top:6px}
.kv dt{color:var(--faint)}
.kv dd{margin:0;word-break:break-all}
.kv .mono{font-family:ui-monospace,Consolas,monospace;font-size:13px}
.course-block{border:1px dashed #cfd8e8;border-radius:13px;padding:12px 14px;margin-top:12px;position:relative}
.course-block .rm{position:absolute;right:8px;top:8px;border:0;background:none;color:var(--faint);
  cursor:pointer;font-size:15px;padding:2px 6px;border-radius:6px}
.course-block .rm:hover{background:#fdecee;color:var(--err)}
.course-block .ttl{font-size:12.5px;font-weight:700;color:var(--pri);margin-bottom:2px}
@media (max-width:760px){
  .nav-links{display:none;position:absolute;top:58px;left:0;right:0;background:#fff;flex-direction:column;padding:10px 16px;border-bottom:1px solid var(--line);gap:2px}
  .nav-links.open{display:flex}
  .nav-links a{padding:11px 13px}
  #navToggle{display:block}
  .nav-cta .nt{display:none}
}
</style>
<header class="nav">
  <div class="nav-in">
    <a class="brand" href="./"><span class="bi"><svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 10L12 5 2 10l10 5 10-5z"/><path d="M6 12.5V17c0 1.66 2.69 3 6 3s6-1.34 6-3v-4.5"/></svg></span><span id="siteName">CX 服务中心</span></a>
    <nav class="nav-links" id="navLinks">
      <a href="./">首页</a>
      <a href="./track">查询进度</a>
      <a href="./help">帮助中心</a>
    </nav>
    <div class="nav-cta">
      <a class="nt" href="./announcements">公告</a>
      <a class="btn" href="https://example.com/" target="_blank" rel="noopener" style="padding:8px 16px;font-size:13.5px">获取卡密</a>
    </div>
    <button id="navToggle" aria-label="菜单">☰</button>
  </div>
</header>

<div class="wrap">
  <div class="panel">
    <div class="steps">
      <div class="step on" id="s1"><div class="num">1</div><div class="t">验证卡密</div></div>
      <div class="bar" id="stepBar"></div>
      <div class="step" id="s2"><div class="num">2</div><div class="t">服务信息</div></div>
      <div class="bar" id="stepBar2"></div>
      <div class="step" id="s3"><div class="num">3</div><div class="t">确认提交</div></div>
    </div>

    <div class="field">
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="5" width="20" height="14" rx="2"/><path d="M2 10h20"/></svg>
      <input id="card" placeholder="CX-XXXXX-XXXXX-XXXXX" autocomplete="one-time-code" data-lpignore="true" data-1p-ignore>
    </div>
    <button class="btn block" id="goCard">验证卡密</button>
    <div id="lock2" class="hint" style="margin-top:12px">请先验证卡密（只验证、不扣次数）。还没有卡密？<a href="https://example.com/" target="_blank" rel="noopener">点此获取</a></div>

    <div id="p2" class="hidden">
      <div class="sec">服务信息 <span class="badge" id="quota"></span></div>
      <label>学习通手机号</label>
      <div class="field">
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="7" y="2" width="10" height="20" rx="2"/><path d="M11 18h2"/></svg>
        <input id="username" inputmode="numeric" autocomplete="off" data-lpignore="true" data-1p-ignore>
      </div>
      <label>密码</label>
      <div class="field pwbox">
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="4" y="11" width="16" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/></svg>
        <input id="password" type="password" autocomplete="new-password" data-lpignore="true" data-1p-ignore>
        <button type="button" id="pwEye" class="pw-eye" aria-label="显示密码" title="显示/隐藏密码">
          <svg id="eyeOpen" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
          <svg id="eyeOff" width="20" height="20" viewBox="0 0 24 24" fill="none" style="display:none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg>
        </button>
      </div>

      <div class="sec" style="margin-top:20px">课程 <span id="courseHint" class="hint" style="margin:0"></span></div>
      <div id="courses"></div>
      <button class="btn ghost block" id="addCourse" style="display:none">＋ 添加另一门课程（这张卡剩余多次）</button>

      <button class="btn block" id="goNext">下一步：确认信息</button>
      <div class="notice">
        <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
        <span>订单处理期间请<b>不要登录学习通</b>。你在别处登录会把处理顶下线，本次服务会失败，卡密不退。</span>
      </div>
    </div>

    <div id="p3" class="hidden">
      <div class="sec">确认订单信息</div>
      <dl class="kv">
        <dt>服务类型</dt><dd>课程服务</dd>
        <dt>兑换卡</dt><dd class="mono" id="cCard"></dd>
        <dt>账号</dt><dd id="cUser"></dd>
        <dt>密码</dt><dd id="cPwd"></dd>
        <dt>课程数</dt><dd id="cCount"></dd>
      </dl>
      <div id="cCourses" style="margin-top:10px"></div>
      <button class="btn block" id="go">确认提交</button>
      <button class="btn ghost block" id="goBack">返回修改</button>
    </div>
  </div>
  <div id="msg"></div>
</div>

<script>
document.getElementById('navToggle').onclick = function () {
  document.getElementById('navLinks').classList.toggle('open');
};
const $ = id => document.getElementById(id);
const msg = $('msg');
let CARD = '', QUOTA = 1;

function fail(t) { msg.className = 'err'; msg.textContent = t; }
function maskPhone(s) {
  s = String(s || '');
  return s.length >= 7 ? s.slice(0, 3) + '****' + s.slice(-4) : '****';
}
function esc(s) {
  return String(s == null ? '' : s).replace(/[&<>"']/g,
    c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}

/* 课程块：每块一门课（课程名 + 授课老师） */
let CIDX = 0;
function addCourseBlock(name, note) {
  CIDX += 1;
  const id = CIDX;
  const div = document.createElement('div');
  div.className = 'course-block';
  div.id = 'cb' + id;
  div.innerHTML =
    '<div class="ttl">课程 ' + document.querySelectorAll('.course-block').length + 1 + '</div>' +
    (document.querySelectorAll('.course-block').length ? '<button class="rm" data-rm="' + id + '" title="删除这门课">✕</button>' : '') +
    '<label>课程名称</label>' +
    '<div class="field"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 19.5A2.5 2.5 0 0 1 6.5 17H20"/><path d="M6.5 2H20v20H6.5A2.5 2.5 0 0 1 4 19.5v-15A2.5 2.5 0 0 1 6.5 2z"/></svg>' +
    '<input class="c-name" placeholder="照抄课表上的完整课程名" autocomplete="off" value="' + esc(name || '') + '"></div>' +
    '<label>授课老师（选填）</label>' +
    '<div class="field"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>' +
    '<input class="c-note" placeholder="课程重名时填写，方便区分" autocomplete="off" value="' + esc(note || '') + '"></div>';
  $('courses').appendChild(div);
  div.querySelectorAll('.rm').forEach(b => b.onclick = () => {
    div.remove();
    renumber();
  });
  renumber();
  refreshAddBtn();
}

function renumber() {
  const blocks = document.querySelectorAll('.course-block');
  blocks.forEach((b, i) => { b.querySelector('.ttl').textContent = '课程 ' + (i + 1); });
}

function refreshAddBtn() {
  const n = document.querySelectorAll('.course-block').length;
  $('addCourse').style.display = (QUOTA > 1 && n < Math.min(QUOTA, 6)) ? 'block' : 'none';
  $('courseHint').textContent = QUOTA > 1 ? '（这张卡可提交 ' + QUOTA + ' 次，可一次填多门课）' : '';
}

$('addCourse').onclick = () => {
  if (document.querySelectorAll('.course-block').length >= Math.min(QUOTA, 6)) return;
  addCourseBlock();
};

$('goCard').onclick = async () => {
  const card = $('card').value.trim();
  if (!card) { fail('先填卡密'); return; }
  const btn = $('goCard');
  btn.disabled = true; msg.className = ''; msg.textContent = '校验中…';
  try {
    const r = await fetch('api/card/check', {
      method: 'POST', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({ card })
    });
    const d = await r.json();
    if (d.ok) {
      CARD = card; QUOTA = d.remaining || 1;
      msg.innerHTML = '<span class="ok">✓ 兑换卡验证成功，剩余 ' + d.remaining + ' 次。请继续填写服务信息。</span>';
      $('quota').textContent = '剩余 ' + d.remaining + ' 次';
      $('p2').classList.remove('hidden');
      $('lock2').classList.add('hidden');
      $('s1').className = 'step done';
      $('s2').className = 'step on';
      $('stepBar').classList.add('on');
      $('card').disabled = true;
      btn.textContent = '卡密已验证';
      if (!document.querySelectorAll('.course-block').length) addCourseBlock();
      refreshAddBtn();
      $('username').focus();
    } else {
      fail(d.error || (d.detail && d.detail.error) || '卡密不正确');
      btn.disabled = false;
    }
  } catch (e) { fail('网络错误：' + e.message); btn.disabled = false; }
};

function readForm() {
  const courses = Array.from(document.querySelectorAll('.course-block')).map(b => ({
    course_name: b.querySelector('.c-name').value.trim(),
    note: b.querySelector('.c-note').value.trim()
  }));
  return { u: $('username').value.trim(), p: $('password').value, courses: courses };
}

$('goNext').onclick = () => {
  const f = readForm();
  if (!f.u) { fail('先填学习通手机号'); return; }
  if (!f.p) { fail('先填密码'); return; }
  const names = f.courses.map(c => c.course_name).filter(Boolean);
  if (!names.length) { fail('先填课程名称'); return; }
  if (names.length < f.courses.length) { fail('有课程名称没填，请补齐或删除那一门'); return; }
  if (f.courses.length > QUOTA) { fail('这门卡只剩 ' + QUOTA + ' 次，最多提交 ' + QUOTA + ' 门课'); return; }
  msg.textContent = '';
  $('cCard').textContent = CARD;
  $('cUser').textContent = maskPhone(f.u);
  $('cPwd').textContent = '********';
  $('cCount').textContent = f.courses.length + ' 门';
  $('cCourses').innerHTML = f.courses.map((c, i) =>
    '<div class="kv" style="grid-template-columns:70px 1fr"><dt>课程 ' + (i + 1) + '</dt><dd>' +
    esc(c.course_name) + (c.note ? ' <span style="color:#9aa7bd">· ' + esc(c.note) + '</span>' : '') +
    '</dd></div>').join('');
  $('p2').classList.add('hidden');
  $('p3').classList.remove('hidden');
  $('s2').className = 'step done';
  $('s3').className = 'step on';
  $('stepBar2').classList.add('on');
};

$('goBack').onclick = () => {
  $('p3').classList.add('hidden');
  $('p2').classList.remove('hidden');
  $('s2').className = 'step on';
  $('s3').className = 'step';
  $('stepBar2').classList.remove('on');
};

$('go').onclick = async () => {
  const f = readForm();
  const btn = $('go');
  btn.disabled = true; msg.className = ''; msg.textContent = '正在提交…';
  try {
    let url = 'api/redeem';
    let payload = { card: CARD, username: f.u, password: f.p,
                    course_name: (f.courses[0] || {}).course_name || '',
                    note: (f.courses[0] || {}).note || '' };
    if (f.courses.length > 1) {
      url = 'api/redeem_multi';
      payload = { card: CARD, username: f.u, password: f.p, courses: f.courses };
    }
    const r = await fetch(url, {
      method: 'POST', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify(payload)
    });
    const d = await r.json();
    if (d.ok) { location.href = d.status_url; }
    else { fail(d.error || (d.detail && d.detail.error) || '提交失败'); btn.disabled = false; }
  } catch (e) { fail('网络错误：' + e.message); btn.disabled = false; }
};

$('card').addEventListener('keydown', e => { if (e.key === 'Enter') $('goCard').click(); });
$('password').addEventListener('keydown', e => { if (e.key === 'Enter') $('goNext').click(); });

$('pwEye').onclick = () => {
  const ip = $('password');
  const show = ip.type === 'password';
  ip.type = show ? 'text' : 'password';
  $('eyeOpen').style.display = show ? 'none' : '';
  $('eyeOff').style.display = show ? '' : 'none';
};

(async () => {
  try {
    const d = await (await fetch('api/site')).json();
    if (d.site_name) { document.title = '服务兑换 · ' + d.site_name; $('siteName').textContent = d.site_name; }
  } catch (e) {}
  try {
    const me = await (await fetch('api/me')).json();
    if (me.user) {
      document.querySelector('.nav-cta').insertAdjacentHTML('afterbegin',
        '<a class="nt" href="./track">' + esc(me.user.username) + '</a>');
    } else {
      document.querySelector('.nav-cta').insertAdjacentHTML('afterbegin',
        '<a class="nt" href="./account">登录 / 注册</a>');
    }
  } catch (e) {}
})();
</script>
"""


ACCOUNT_HTML = """<!doctype html><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>登录注册 · CX 服务中心</title>
<style>
:root{--bg:#f4f6fb;--panel:#fff;--line:#e5e9f2;--ink:#17233f;--sub:#64748b;--faint:#9aa7bd;
  --pri:#3b6fd1;--pri2:#4C8DFF;--ok:#1f9d66;--err:#d33f4e;--shadow:0 1px 2px rgba(23,35,63,.05),0 10px 30px -14px rgba(23,35,63,.14)}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);
  font:15px/1.7 -apple-system,BlinkMacSystemFont,"Segoe UI","Microsoft YaHei",sans-serif;
  min-height:100vh}
a{color:var(--pri);text-decoration:none}
.wrap{max-width:420px;margin:0 auto;padding:56px 18px 50px}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:20px;
  padding:32px 28px;box-shadow:var(--shadow)}
.brand{display:flex;align-items:center;gap:10px;justify-content:center;margin-bottom:18px;
  font-weight:800;font-size:17px}
.brand .bi{width:36px;height:36px;border-radius:10px;color:#fff;
  background:linear-gradient(135deg,var(--pri2),var(--pri));display:flex;align-items:center;justify-content:center}
h1{font-size:18px;text-align:center;margin:0 0 4px}
.sub{color:var(--faint);font-size:12.5px;text-align:center;margin-bottom:22px}
.tabs{display:flex;background:#f1f4fa;border-radius:11px;padding:3px;margin-bottom:20px}
.tabs button{flex:1;border:0;background:none;padding:9px;border-radius:9px;font-size:14px;
  font-weight:600;color:var(--sub);cursor:pointer;font-family:inherit;transition:.15s}
.tabs button.on{background:#fff;color:var(--ink);box-shadow:0 1px 3px rgba(23,35,63,.1)}
label{display:block;margin:13px 0 6px;font-size:13px;color:var(--sub);font-weight:500}
input{width:100%;padding:11.5px 13px;border:1px solid var(--line);border-radius:11px;font-size:15px;
  background:#fbfcfe;font-family:inherit;color:var(--ink);transition:.18s}
input:focus{outline:none;border-color:var(--pri);background:#fff;box-shadow:0 0 0 3.5px rgba(76,141,255,.14)}
input::placeholder{color:#b3bdd0}
.btn{display:block;width:100%;margin-top:18px;padding:13px;border:0;border-radius:12px;
  background:linear-gradient(135deg,var(--pri2),var(--pri));color:#fff;font-size:15px;font-weight:600;
  cursor:pointer;font-family:inherit;transition:.2s;box-shadow:0 10px 24px -10px rgba(59,111,209,.5)}
.btn:hover:not(:disabled){transform:translateY(-1px)}
.btn:disabled{background:#c3cede;cursor:not-allowed;box-shadow:none}
#msg{margin-top:13px;font-size:13.5px;min-height:18px;text-align:center}
.err{color:var(--err)}.ok{color:var(--ok)}
.hint{color:var(--faint);font-size:12px;margin-top:14px;text-align:center;line-height:1.8}
.hint a{color:var(--pri)}
</style>
<div class="wrap">
  <div class="panel">
    <div class="brand">
      <span class="bi"><svg width="19" height="19" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 10L12 5 2 10l10 5 10-5z"/><path d="M6 12.5V17c0 1.66 2.69 3 6 3s6-1.34 6-3v-4.5"/></svg></span>
      <span id="siteName">CX 服务中心</span>
    </div>
    <h1 id="title">登录</h1>
    <div class="sub" id="subtitle">登录后可直接查看你的全部订单进度</div>
    <div class="tabs">
      <button id="tabLogin" class="on">登录</button>
      <button id="tabReg">注册</button>
    </div>
    <label>账号（手机号）</label>
    <input id="u" inputmode="numeric" placeholder="常用手机号，用于登录" autocomplete="username">
    <label>密码</label>
    <input id="p" type="password" placeholder="至少 6 位" autocomplete="current-password">
    <button class="btn" id="go">登录</button>
    <div id="msg"></div>
    <div class="hint">注册即表示同意我们仅将信息用于本次服务处理。<br>
      不登录也可以 <a href="./redeem">直接兑换</a> ·
      <a href="./track">凭卡密查询</a></div>
  </div>
</div>
<script>
const $ = id => document.getElementById(id);
let MODE = 'login';

async function loadSite() {
  try {
    const d = await (await fetch('api/site')).json();
    if (d.site_name) { document.title = '登录注册 · ' + d.site_name; $('siteName').textContent = d.site_name; }
  } catch (e) {}
}

function setMode(m) {
  MODE = m;
  $('tabLogin').classList.toggle('on', m === 'login');
  $('tabReg').classList.toggle('on', m === 'reg');
  $('title').textContent = m === 'login' ? '登录' : '注册';
  $('subtitle').textContent = m === 'login'
    ? '登录后可直接查看你的全部订单进度'
    : '注册一个账号，之后可直接查询自己的订单';
  $('go').textContent = m === 'login' ? '登录' : '注册并登录';
  $('p').setAttribute('autocomplete', m === 'login' ? 'current-password' : 'new-password');
  $('msg').textContent = '';
}
$('tabLogin').onclick = () => setMode('login');
$('tabReg').onclick = () => setMode('reg');

$('go').onclick = async () => {
  const u = $('u').value.trim(), p = $('p').value;
  const msg = $('msg');
  if (!u) { msg.className = 'err'; msg.textContent = '请填写账号'; return; }
  if (p.length < 6) { msg.className = 'err'; msg.textContent = '密码至少 6 位'; return; }
  $('go').disabled = true;
  msg.className = ''; msg.textContent = MODE === 'login' ? '登录中…' : '注册中…';
  try {
    const r = await fetch(MODE === 'login' ? 'api/login' : 'api/register', {
      method: 'POST', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({username: u, password: p})
    });
    const d = await r.json();
    if (d.ok) {
      msg.className = 'ok'; msg.textContent = '成功，正在跳转…';
      location.href = './track';
    } else {
      msg.className = 'err';
      msg.textContent = d.error || (d.detail && d.detail.error) || '操作失败';
      $('go').disabled = false;
    }
  } catch (e) {
    msg.className = 'err'; msg.textContent = '网络错误，请重试';
    $('go').disabled = false;
  }
};
['u', 'p'].forEach(id => $(id).addEventListener('keydown', e => { if (e.key === 'Enter') $('go').click(); }));
loadSite();
</script>
"""

ANN_HTML = """<!doctype html><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>服务公告 · CX 服务中心</title>
<style>
:root{--bg:#f4f6fb;--panel:#fff;--line:#e5e9f2;--ink:#17233f;--sub:#64748b;--faint:#9aa7bd;
  --pri:#3b6fd1;--pri2:#4C8DFF;--warn:#c47d12;--shadow:0 1px 2px rgba(23,35,63,.05),0 10px 30px -14px rgba(23,35,63,.14)}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);
  font:15px/1.7 -apple-system,BlinkMacSystemFont,"Segoe UI","Microsoft YaHei",sans-serif}
a{color:var(--pri);text-decoration:none}
.nav{position:sticky;top:0;z-index:50;background:rgba(255,255,255,.9);backdrop-filter:blur(10px);border-bottom:1px solid var(--line)}
.nav-in{max-width:1040px;margin:0 auto;padding:0 20px;height:58px;display:flex;align-items:center;gap:26px}
.brand{display:flex;align-items:center;gap:9px;font-weight:800;font-size:16px;color:var(--ink)}
.brand .bi{width:32px;height:32px;border-radius:9px;color:#fff;background:linear-gradient(135deg,var(--pri2),var(--pri));display:flex;align-items:center;justify-content:center}
.nav-links{display:flex;gap:4px;margin-left:8px}
.nav-links a{padding:7px 13px;border-radius:9px;color:var(--sub);font-size:14px;font-weight:500}
.nav-links a:hover{color:var(--ink);background:#f1f4fa}
.nav-links a.on{color:var(--pri);background:#eef3fe;font-weight:600}
.nav-cta{margin-left:auto}
#navToggle{display:none;background:none;border:0;font-size:22px;color:var(--ink);cursor:pointer}
.wrap{max-width:720px;margin:0 auto;padding:30px 20px 50px}
h1{font-size:22px;margin:0 0 18px}
.ann{display:block;background:var(--panel);border:1px solid var(--line);border-radius:14px;
  padding:16px 19px;margin-bottom:11px;color:var(--ink);transition:.15s;box-shadow:var(--shadow);cursor:pointer}
.ann:hover{transform:translateY(-1px);border-color:#cfd8e8}
.ann .t{font-weight:600;font-size:14.5px;display:flex;align-items:center;gap:8px}
.ann .d{color:var(--faint);font-size:12px;margin-top:4px}
.pin{background:#fff4e0;color:var(--warn);border:1px solid #f5d9a8;border-radius:999px;
  padding:1px 9px;font-size:11px;font-weight:700;flex:none}
.detail{background:var(--panel);border:1px solid var(--line);border-radius:16px;padding:26px;box-shadow:var(--shadow)}
.detail h2{margin:0 0 4px;font-size:19px;display:flex;align-items:center;gap:9px}
.detail .d{color:var(--faint);font-size:12.5px;margin-bottom:16px}
.detail .c{font-size:14.5px;line-height:1.9;color:#33415e;white-space:pre-wrap;word-break:break-word}
.back{display:inline-flex;align-items:center;gap:6px;font-size:13.5px;color:var(--sub);cursor:pointer;
  margin-bottom:14px;border:0;background:none;font-family:inherit;padding:0}
.back:hover{color:var(--pri)}
.empty{color:var(--faint);text-align:center;padding:30px 16px;font-size:13.5px}
@media (max-width:760px){
  .nav-links{display:none;position:absolute;top:58px;left:0;right:0;background:#fff;flex-direction:column;padding:10px 16px;border-bottom:1px solid var(--line);gap:2px}
  .nav-links.open{display:flex}
  .nav-links a{padding:11px 13px}
  #navToggle{display:block;margin-left:auto}
  .nav-cta{display:none}
}
</style>
<header class="nav">
  <div class="nav-in">
    <a class="brand" href="./"><span class="bi"><svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 10L12 5 2 10l10 5 10-5z"/><path d="M6 12.5V17c0 1.66 2.69 3 6 3s6-1.34 6-3v-4.5"/></svg></span>CX 服务中心</a>
    <nav class="nav-links" id="navLinks">
      <a href="./">首页</a>
      <a href="./track">查询进度</a>
      <a href="./track">服务进度</a>
      <a href="./help">帮助中心</a>
    </nav>
    <div class="nav-cta"><a class="btn" href="https://example.com/" target="_blank" rel="noopener" style="display:inline-flex;background:linear-gradient(135deg,var(--pri2),var(--pri));color:#fff;border-radius:11px;padding:8px 18px;font-size:13.5px;font-weight:600">获取卡密</a></div>
    <button id="navToggle" aria-label="菜单">☰</button>
  </div>
</header>
<div class="wrap">
  <div id="listBox">
    <h1>服务公告</h1>
    <div id="annList"><div class="empty">加载中…</div></div>
  </div>
  <div id="detailBox" class="hidden">
    <button class="back" id="backBtn">← 返回公告列表</button>
    <div class="detail">
      <h2 id="dTitle"></h2>
      <div class="d" id="dTime"></div>
      <div class="c" id="dContent"></div>
    </div>
  </div>
</div>
<script>
document.getElementById('navToggle').onclick=function(){document.getElementById('navLinks').classList.toggle('open')};
const esc = s => String(s == null ? '' : s).replace(/[&<>"']/g,
  c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));

async function loadList() {
  try {
    const r = await fetch('api/announcements?limit=50');
    const d = await r.json();
    const list = d.announcements || [];
    document.getElementById('annList').innerHTML = list.length ? list.map(a =>
      '<div class="ann" data-id="' + a.id + '">' +
      '<div class="t">' + (a.is_pinned ? '<span class="pin">置顶</span>' : '') +
      '<span>' + esc(a.title) + '</span></div>' +
      '<div class="d">' + a.created_at.slice(0, 16).replace('T', ' ') + '</div></div>'
    ).join('') : '<div class="empty">暂无公告</div>';
    document.querySelectorAll('.ann').forEach(el => el.onclick = () => showDetail(el.dataset.id));
  } catch (e) {
    document.getElementById('annList').innerHTML = '<div class="empty">加载失败，请刷新</div>';
  }
}

async function showDetail(id) {
  try {
    const r = await fetch('api/announcements/' + id);
    const d = await r.json();
    if (!d.ok) return;
    const a = d.announcement;
    document.getElementById('dTitle').innerHTML = (a.is_pinned ? '<span class="pin">置顶</span>' : '') + esc(a.title);
    document.getElementById('dTime').textContent = a.created_at.slice(0, 16).replace('T', ' ');
    document.getElementById('dContent').textContent = a.content;
    document.getElementById('listBox').classList.add('hidden');
    document.getElementById('detailBox').classList.remove('hidden');
    window.scrollTo(0, 0);
  } catch (e) {}
}

document.getElementById('backBtn').onclick = () => {
  document.getElementById('detailBox').classList.add('hidden');
  document.getElementById('listBox').classList.remove('hidden');
};

const qid = new URLSearchParams(location.search).get('id');
if (qid) showDetail(qid); else loadList();
</script>

"""

HELP_HTML = """<!doctype html><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>帮助中心 · CX 服务中心</title>
<style>
:root{--bg:#f4f6fb;--panel:#fff;--line:#e5e9f2;--ink:#17233f;--sub:#64748b;--faint:#9aa7bd;
  --pri:#3b6fd1;--pri2:#4C8DFF;--shadow:0 1px 2px rgba(23,35,63,.05),0 10px 30px -14px rgba(23,35,63,.14)}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);
  font:15px/1.7 -apple-system,BlinkMacSystemFont,"Segoe UI","Microsoft YaHei",sans-serif}
a{color:var(--pri);text-decoration:none}
.nav{position:sticky;top:0;z-index:50;background:rgba(255,255,255,.9);backdrop-filter:blur(10px);border-bottom:1px solid var(--line)}
.nav-in{max-width:1040px;margin:0 auto;padding:0 20px;height:58px;display:flex;align-items:center;gap:26px}
.brand{display:flex;align-items:center;gap:9px;font-weight:800;font-size:16px;color:var(--ink)}
.brand .bi{width:32px;height:32px;border-radius:9px;color:#fff;background:linear-gradient(135deg,var(--pri2),var(--pri));display:flex;align-items:center;justify-content:center}
.nav-links{display:flex;gap:4px;margin-left:8px}
.nav-links a{padding:7px 13px;border-radius:9px;color:var(--sub);font-size:14px;font-weight:500}
.nav-links a:hover{color:var(--ink);background:#f1f4fa}
.nav-links a.on{color:var(--pri);background:#eef3fe;font-weight:600}
.nav-cta{margin-left:auto}
#navToggle{display:none;background:none;border:0;font-size:22px;color:var(--ink);cursor:pointer}
.wrap{max-width:720px;margin:0 auto;padding:30px 20px 50px}
h1{font-size:22px;margin:0 0 6px}
.sub{color:var(--sub);font-size:14px;margin:0 0 22px}
.cat{margin-bottom:22px}
.cat h2{font-size:15px;margin:0 0 10px;display:flex;align-items:center;gap:8px}
.cat h2::before{content:"";width:3px;height:15px;border-radius:2px;background:linear-gradient(180deg,var(--pri2),var(--pri))}
details{background:var(--panel);border:1px solid var(--line);border-radius:13px;margin-bottom:9px;box-shadow:var(--shadow)}
summary{cursor:pointer;padding:14px 17px;font-size:14px;font-weight:600;list-style:none;
  display:flex;align-items:center;gap:9px}
summary::-webkit-details-marker{display:none}
summary::before{content:"+";color:var(--pri);font-weight:700;font-size:16px;flex:none}
details[open] summary::before{content:"–"}
details .a{padding:0 17px 15px;color:var(--sub);font-size:13.5px;line-height:1.85}
.fb-cta{margin-top:26px;background:linear-gradient(135deg,#eef3fe,#f6f9ff);border:1px solid #d8e4fa;
  border-radius:16px;padding:22px;text-align:center}
.fb-cta b{display:block;font-size:15px;margin-bottom:6px}
.fb-cta span{color:var(--sub);font-size:13px;display:block;margin-bottom:14px}
.btn{display:inline-flex;align-items:center;justify-content:center;gap:8px;
  background:linear-gradient(135deg,var(--pri2),var(--pri));color:#fff;border:0;border-radius:11px;
  padding:11px 26px;font-size:14px;font-weight:600;cursor:pointer;font-family:inherit;
  box-shadow:0 8px 20px -8px rgba(59,111,209,.5)}
.empty{color:var(--faint);text-align:center;padding:30px 16px;font-size:13.5px}
@media (max-width:760px){
  .nav-links{display:none;position:absolute;top:58px;left:0;right:0;background:#fff;flex-direction:column;padding:10px 16px;border-bottom:1px solid var(--line);gap:2px}
  .nav-links.open{display:flex}
  .nav-links a{padding:11px 13px}
  #navToggle{display:block;margin-left:auto}
  .nav-cta{display:none}
}
</style>
<header class="nav">
  <div class="nav-in">
    <a class="brand" href="./"><span class="bi"><svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 10L12 5 2 10l10 5 10-5z"/><path d="M6 12.5V17c0 1.66 2.69 3 6 3s6-1.34 6-3v-4.5"/></svg></span>CX 服务中心</a>
    <nav class="nav-links" id="navLinks">
      <a href="./">首页</a>
      <a href="./track">查询进度</a>
      <a href="./track">服务进度</a>
      <a href="./help" class="on">帮助中心</a>
    </nav>
    <div class="nav-cta"><a class="btn" href="./redeem" style="padding:8px 18px;font-size:13.5px">立即兑换</a></div>
    <button id="navToggle" aria-label="菜单">☰</button>
  </div>
</header>
<div class="wrap">
  <h1>帮助中心</h1>
  <p class="sub">常见问题与使用说明</p>
  <div id="helpBox"><div class="empty">加载中…</div></div>
  <div class="fb-cta"><b>没找到你要的答案？</b><span>请联系客服，或在「查询进度」页用卡密查看订单状态</span></div>
</div>
<script>
document.getElementById('navToggle').onclick=function(){document.getElementById('navLinks').classList.toggle('open')};
const esc = s => String(s == null ? '' : s).replace(/[&<>"']/g,
  c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
async function load() {
  try {
    const r = await fetch('api/help');
    const d = await r.json();
    const cats = d.categories || [];
    document.getElementById('helpBox').innerHTML = cats.length ? cats.map(c =>
      '<div class="cat"><h2>' + esc(c.category) + '</h2>' +
      c.articles.map(a =>
        '<details><summary>' + esc(a.title) + '</summary><div class="a">' +
        esc(a.content) + '</div></details>').join('') + '</div>'
    ).join('') : '<div class="empty">暂无内容</div>';
  } catch (e) {
    document.getElementById('helpBox').innerHTML = '<div class="empty">加载失败，请刷新</div>';
  }
}
load();
</script>

"""

TRACK_HTML = """<!doctype html><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>查询进度 · CX 服务中心</title>
<style>
:root{--bg:#f4f6fb;--panel:#fff;--line:#e5e9f2;--ink:#17233f;--sub:#64748b;--faint:#9aa7bd;
  --pri:#3b6fd1;--pri2:#4C8DFF;--ok:#1f9d66;--err:#d33f4e;--shadow:0 1px 2px rgba(23,35,63,.05),0 10px 30px -14px rgba(23,35,63,.14)}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);
  font:15px/1.7 -apple-system,BlinkMacSystemFont,"Segoe UI","Microsoft YaHei",sans-serif}
a{color:var(--pri);text-decoration:none}
.nav{position:sticky;top:0;z-index:50;background:rgba(255,255,255,.92);backdrop-filter:blur(10px);border-bottom:1px solid var(--line)}
.nav-in{max-width:1040px;margin:0 auto;padding:0 20px;height:58px;display:flex;align-items:center;gap:22px}
.brand{display:flex;align-items:center;gap:9px;font-weight:800;font-size:16px;color:var(--ink);flex:none}
.brand .bi{width:32px;height:32px;border-radius:9px;color:#fff;background:linear-gradient(135deg,var(--pri2),var(--pri));display:flex;align-items:center;justify-content:center}
.nav-links{display:flex;gap:4px}
.nav-links a{padding:7px 13px;border-radius:9px;color:var(--sub);font-size:14px;font-weight:500}
.nav-links a:hover{color:var(--ink);background:#f1f4fa}
.nav-links a.on{color:var(--pri);background:#eef3fe;font-weight:600}
.nav-cta{margin-left:auto;display:flex;gap:9px;align-items:center}
.nav-cta a.nt{font-size:13.5px;color:var(--sub);padding:6px 10px;border-radius:8px}
.nav-cta a.nt:hover{background:#f1f4fa;color:var(--ink)}
.btn{display:inline-flex;align-items:center;justify-content:center;gap:8px;background:linear-gradient(135deg,var(--pri2),var(--pri));
  color:#fff;border:0;border-radius:11px;padding:10px 20px;font-size:14px;font-weight:600;cursor:pointer;
  font-family:inherit;transition:.18s;box-shadow:0 8px 20px -8px rgba(59,111,209,.5)}
.btn:hover{transform:translateY(-1px)}
.btn.ghost{background:#fff;color:var(--ink);border:1px solid var(--line);box-shadow:none}
#navToggle{display:none;background:none;border:0;font-size:22px;color:var(--ink);cursor:pointer}
.wrap{max-width:760px;margin:0 auto;padding:30px 18px 50px}
h1{font-size:21px;margin:0 0 6px}
.sub{color:var(--sub);font-size:13.5px;margin:0 0 18px}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:16px;padding:20px;
  box-shadow:var(--shadow);margin-bottom:14px}
label{display:block;margin:0 0 6px;font-size:13px;color:var(--sub);font-weight:500}
input{width:100%;padding:11px 13px;border:1px solid var(--line);border-radius:11px;font-size:15px;
  background:#fbfcfe;font-family:inherit;color:var(--ink);text-transform:uppercase;
  font-family:ui-monospace,Consolas,monospace;letter-spacing:.5px}
input:focus{outline:none;border-color:var(--pri);background:#fff;box-shadow:0 0 0 3.5px rgba(76,141,255,.14)}
input::placeholder{color:#b3bdd0;font-family:-apple-system,sans-serif;letter-spacing:0}
.row{display:flex;gap:10px;margin-top:14px}
.row .btn{flex:none;padding:11px 22px}
.msg{margin-top:12px;font-size:13.5px;min-height:18px}
.err{color:var(--err)}.ok{color:var(--ok)}
.tbl{width:100%;border-collapse:collapse;font-size:13.5px}
.tbl th{text-align:left;color:var(--faint);font-weight:600;font-size:12px;padding:8px 10px;border-bottom:1px solid var(--line)}
.tbl td{padding:11px 10px;border-bottom:1px solid #f1f4f9}
.tbl tr:last-child td{border-bottom:0}
.tag{display:inline-flex;align-items:center;gap:5px;padding:2px 9px;border-radius:20px;font-size:11.5px;font-weight:600}
.tag i{width:6px;height:6px;border-radius:50%;background:currentColor}
.t-submitted,.t-ready{background:#fff4e0;color:#a2620e}
.t-queued{background:#eef3fe;color:#2f5bb7}
.t-logging,.t-running{background:#e8f7f0;color:#14815a}
.t-done{background:#e3f6ee;color:#147a51}
.t-failed,.t-canceled{background:#fdecee;color:#b3313f}
.empty{color:var(--faint);text-align:center;padding:26px 16px;font-size:13.5px}
.tip{color:var(--sub);font-size:12.5px;line-height:1.8;margin-top:12px}
.tip b{color:var(--ink)}
@media (max-width:760px){
  .nav-links{display:none;position:absolute;top:58px;left:0;right:0;background:#fff;flex-direction:column;padding:10px 16px;border-bottom:1px solid var(--line);gap:2px}
  .nav-links.open{display:flex}
  .nav-links a{padding:11px 13px}
  #navToggle{display:block}
  .nav-cta .nt{display:none}
  .row{flex-direction:column}
  .row .btn{width:100%}
}
</style>
<header class="nav">
  <div class="nav-in">
    <a class="brand" href="./"><span class="bi"><svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 10L12 5 2 10l10 5 10-5z"/><path d="M6 12.5V17c0 1.66 2.69 3 6 3s6-1.34 6-3v-4.5"/></svg></span><span id="siteName">CX 服务中心</span></a>
    <nav class="nav-links" id="navLinks">
      <a href="./">首页</a>
      <a href="./track" class="on">查询进度</a>
      <a href="./help">帮助中心</a>
    </nav>
    <div class="nav-cta">
      <a class="nt" href="./announcements">公告</a>
      <span id="userArea"></span>
      <a class="btn" href="https://example.com/" target="_blank" rel="noopener" style="padding:8px 16px;font-size:13.5px">获取卡密</a>
    </div>
    <button id="navToggle" aria-label="菜单">☰</button>
  </div>
</header>
<div class="wrap">
  <h1>查询服务进度</h1>
  <div class="sub" id="pageSub">登录后可直接查看你的全部订单；未登录可凭卡密查询</div>

  <div class="panel" id="loginBox" style="display:none">
    <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap">
      <b>登录后可直接查看全部订单进度</b>
      <a class="btn" href="./account" style="margin-left:auto;padding:8px 18px;font-size:13.5px">登录 / 注册</a>
    </div>
  </div>

  <div class="panel">
    <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap">
      <b id="listTitle">我的订单</b>
      <button class="btn ghost" id="refreshBtn" style="margin-left:auto;padding:7px 16px;font-size:13px">刷新</button>
    </div>
    <div id="taskBox" style="margin-top:10px"><div class="empty">加载中…</div></div>
  </div>

  <div class="panel" id="cardBox" style="display:none">
    <label>输入卡密查询该卡下的订单</label>
    <div class="row">
      <input id="qCard" placeholder="CX-XXXXX-XXXXX-XXXXX" autocomplete="off">
      <button class="btn" id="qGo">查询</button>
    </div>
    <div class="msg" id="qMsg"></div>
    <div class="tip">卡密是你购买时获得的兑换码。同卡密下的所有订单都会列出；
      <b>点击「查看进度」</b>可打开完整进度页（链接请自行保存）。</div>
  </div>
</div>
<script>
document.getElementById('navToggle').onclick = function () {
  document.getElementById('navLinks').classList.toggle('open');
};
const $ = id => document.getElementById(id);
const esc = s => String(s == null ? '' : s).replace(/[&<>"']/g,
  c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const LABEL = {submitted: '已提交', queued: '等待处理', logging: '登录中',
  ready: '准备就绪', running: '处理中', done: '已完成', failed: '处理失败', canceled: '已取消'};

function renderList(list, emptyText) {
  if (!list.length) { $('taskBox').innerHTML = '<div class="empty">' + (emptyText || '暂无订单') + '</div>'; return; }
  $('taskBox').innerHTML = '<div style="overflow:auto"><table class="tbl"><thead><tr>' +
    '<th>编号</th><th>课程</th><th>状态</th><th>提交时间</th><th></th></tr></thead><tbody>' +
    list.map(t => '<tr><td class="mono">#' + t.id + '</td>' +
      '<td>' + esc(t.course_name || '-') + '</td>' +
      '<td><span class="tag t-' + t.status + '"><i></i>' + (LABEL[t.status] || t.status) + '</span></td>' +
      '<td style="color:#9aa7bd">' + (t.created_at || '').slice(5, 16).replace('T', ' ') + '</td>' +
      '<td style="text-align:right"><a class="btn ghost" href="' + t.status_url +
      '" style="padding:5px 12px;font-size:12.5px">查看进度</a></td></tr>').join('') +
    '</tbody></table></div>';
}

async function init() {
  try {
    const me = await (await fetch('api/me')).json();
    const site = await (await fetch('api/site')).json();
    if (site.site_name) { document.title = '查询进度 · ' + site.site_name; $('siteName').textContent = site.site_name; }
    if (me.user) {
      $('userArea').innerHTML = '<a class="nt" href="javascript:logout()">' + esc(me.user.username) + ' · 退出</a>';
      $('listTitle').textContent = '我的订单';
      $('pageSub').textContent = '已登录：' + me.user.username + '，以下是你提交的全部订单';
      $('cardBox').style.display = 'block';
      loadMine();
    } else {
      $('userArea').innerHTML = '<a class="nt" href="./account">登录 / 注册</a>';
      $('loginBox').style.display = 'block';
      $('listTitle').textContent = '凭卡密查询';
      $('cardBox').style.display = 'block';
      $('taskBox').innerHTML = '<div class="empty">未登录。输入卡密后可查询该卡下的订单</div>';
    }
  } catch (e) {
    $('taskBox').innerHTML = '<div class="empty">加载失败，请刷新</div>';
  }
}

async function loadMine() {
  try {
    const r = await fetch('api/my/tasks');
    if (r.status === 401) { $('taskBox').innerHTML = '<div class="empty">请先登录</div>'; return; }
    const d = await r.json();
    renderList(d.tasks || [], '你还没有提交过订单');
  } catch (e) { $('taskBox').innerHTML = '<div class="empty">加载失败，请刷新</div>'; }
}

$('qGo').onclick = async () => {
  const card = $('qCard').value.trim();
  if (!card) { $('qMsg').className = 'err'; $('qMsg').textContent = '先输入卡密'; return; }
  $('qMsg').className = ''; $('qMsg').textContent = '查询中…';
  try {
    const r = await fetch('api/query/by-card', {
      method: 'POST', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({card: card})
    });
    const d = await r.json();
    if (!d.ok) { $('qMsg').className = 'err'; $('qMsg').textContent = d.error || '查询失败'; return; }
    $('qMsg').className = d.tasks.length ? 'ok' : '';
    $('qMsg').textContent = d.tasks.length ? ('查到 ' + d.tasks.length + ' 个订单') : (d.message || '没有查到订单');
    renderList(d.tasks || [], d.message || '这张卡密下还没有订单记录');
  } catch (e) {
    $('qMsg').className = 'err'; $('qMsg').textContent = '网络错误';
  }
};
$('refreshBtn').onclick = () => { if ($('userArea').textContent.indexOf('退出') >= 0) loadMine(); else $('qGo').click(); };
async function logout() { await fetch('api/logout', {method: 'POST'}); location.reload(); }
init();
</script>
"""



@app.get("/redeem", response_class=HTMLResponse)
async def redeem_page():
    return REDEEM_HTML


@app.get("/account", response_class=HTMLResponse)
async def account_page():
    return ACCOUNT_HTML


@app.get("/announcements", response_class=HTMLResponse)
async def announcements_page():
    return ANN_HTML


@app.get("/help", response_class=HTMLResponse)
async def help_page():
    return HELP_HTML


@app.get("/track", response_class=HTMLResponse)
async def track_page():
    return TRACK_HTML

@app.get("/s/{task_id}", response_class=HTMLResponse)
async def status_page(task_id: int, t: str = ""):
    if not check_view_token(task_id, t):
        return HTMLResponse(NOLINK_HTML, status_code=403)
    return STATUS_HTML.replace("__TID__", str(task_id)).replace("__VT__", t)


STATUS_HTML = """<!doctype html>
<html lang="zh-CN"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>服务进度</title>
<style>
:root{
  --bg:#f4f6fb;--panel:#fff;--line:#e5e9f2;--ink:#17233f;--sub:#64748b;--faint:#9aa7bd;
  --pri:#3b6fd1;--ok:#1f9d66;--warn:#c47d12;--err:#d33f4e;
  --shadow:0 1px 2px rgba(23,35,63,.05),0 10px 30px -14px rgba(23,35,63,.14);
}
*{box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{margin:0;color:var(--ink);
  font:15px/1.7 -apple-system,BlinkMacSystemFont,"Segoe UI","Microsoft YaHei",sans-serif;
  background:var(--bg)}
.wrap{max-width:540px;margin:0 auto;padding:30px 18px 60px}

.crumb{display:flex;align-items:center;gap:8px;font-size:13px;color:var(--faint);margin-bottom:14px}
.crumb a{color:var(--pri);text-decoration:none}

.panel{background:var(--panel);border:1px solid var(--line);border-radius:18px;
  padding:28px 24px 24px;text-align:center;--sc:var(--sub);
  box-shadow:var(--shadow);transition:.25s}
.panel.warnc{--sc:var(--warn)}
.panel.infoc{--sc:var(--pri)}
.panel.ok{--sc:var(--ok)}
.panel.errc{--sc:var(--err)}

.tl{display:flex;margin-bottom:26px}
.nd{flex:1;position:relative}
.nd i{display:block;width:9px;height:9px;border-radius:50%;background:#e2e8f2;
  margin:0 auto 7px;transition:.3s}
.nd::before{content:"";position:absolute;top:3.5px;left:-50%;width:100%;height:2px;
  background:#e2e8f2;transition:.3s}
.nd:first-child::before{display:none}
.nd em{font-style:normal;font-size:10.5px;color:var(--faint);white-space:nowrap}
.nd.past i,.nd.now i{background:var(--sc)}
.nd.past::before,.nd.now::before{background:var(--sc)}
.nd.past em{color:var(--sub)}
.nd.now em{color:var(--ink);font-weight:700}

.dot{width:13px;height:13px;border-radius:50%;display:inline-block;
  margin-right:9px;vertical-align:-1px;background:var(--sc);position:relative}
.panel.busy .dot::after{content:"";position:absolute;inset:-2px;border-radius:50%;
  border:2px solid var(--sc);animation:ring 1.8s ease-out infinite}
@keyframes ring{0%{transform:scale(1);opacity:.75}100%{transform:scale(2.3);opacity:0}}
.st{font-size:20px;font-weight:700;color:var(--sc);margin-bottom:10px}
.desc{color:var(--sub);font-size:13.5px;line-height:1.8;text-align:left;
  background:#f8fafd;border:1px solid var(--line);border-radius:12px;
  padding:14px 16px;margin-top:14px}
.meta{color:var(--faint);font-size:12px;margin-top:12px;line-height:1.8}
.warn{margin-top:16px;border-radius:12px;padding:13px 15px;font-size:13px;
  background:#fff8ec;border:1px solid #f5e0b8;color:#92610c;line-height:1.7}
.warn b{color:#7a4f06}
.prog{height:6px;background:#e2e8f2;border-radius:4px;overflow:hidden;margin-top:18px}
.prog i{display:block;height:100%;width:34%;border-radius:4px;
  background:linear-gradient(90deg,#4C8DFF,#34c98b);
  animation:slide 1.5s ease-in-out infinite}
@keyframes slide{0%{transform:translateX(-110%)}100%{transform:translateX(340%)}}
</style>
<div class="wrap">
<div class="crumb"><a href="../">← 返回 CX 服务中心</a></div>
  <div class="panel" id="panel">
    <div class="st"><span class="dot"></span>加载中</div>
  </div>
  <div class="meta" id="sub"></div>
  <div id="tip"></div>
</div>
<script>
const TID = __TID__, VT = "__VT__";
const panel = document.getElementById('panel');
const tip = document.getElementById('tip');
const sub = document.getElementById('sub');

const M = {
  submitted: ['warnc', '已提交',
    '您的服务信息已经成功提交，正在排队。轮到你会自动开始，不需要你做任何操作。'],
  queued: ['warnc', '等待处理',
    '当前任务正在等待系统处理，马上安排登录你的账号。'],
  logging: ['infoc', '登录中',
    '系统正在处理必要的服务验证，大约需要 1 分钟。'],
  ready: ['infoc', '准备就绪',
    '已登录成功，正在安排开始。这个阶段可能要等一会儿，请耐心等待。'],
  running: ['ok', '处理中',
    '服务正在进行，请耐心等待。进度以学习通课表为准。'],
  done: ['ok', '已完成',
    '您的服务已经完成，可以登录学习通查看学习记录了。'],
  failed: ['errc', '处理失败', '当前服务处理出现异常，请联系客服处理。'],
  canceled: ['errc', '已取消', '订单已取消。如需重新下单，请联系客服。']
};

const BUSY = ['submitted','queued','logging','ready','running'];
const STAGES = ['已提交', '登录中', '处理中', '已完成'];

function stageIdx(st) {
  if (st === 'submitted' || st === 'queued') return 0;
  if (st === 'logging') return 1;
  if (st === 'ready' || st === 'running') return 2;
  if (st === 'done') return 3;
  return -1;
}

function render(x) {
  const m = M[x.status] || ['warnc', x.status, ''];
  const busy = BUSY.indexOf(x.status) >= 0;
  panel.className = 'panel ' + m[0] + (busy ? ' busy' : '');

  sub.textContent = '服务编号 #' + x.id
    + (x.created_at ? ' · 提交于 ' + x.created_at.slice(0, 16).replace('T', ' ') : '')
    + (x.updated_at ? ' · 更新于 ' + x.updated_at.slice(5, 16).replace('T', ' ') : '');

  let html = '';
  const si = stageIdx(x.status);
  if (si >= 0) {
    html += '<div class="tl">' + STAGES.map(function (s, i) {
      const c = i < si ? 'past' : (i === si ? 'now' : '');
      return '<div class="nd ' + c + '"><i></i><em>' + s + '</em></div>';
    }).join('') + '</div>';
  }

  html += '<div class="st"><span class="dot"></span>' + m[1] + '</div>';
  let desc = m[2];
  if (x.status === 'submitted' && x.queue) {
    desc = '队列第 ' + x.queue + ' 位。轮到你会自动开始，请勿登录学习通。';
  }
  html += '<div class="desc">' + desc + '</div>';
  if (busy) {
    html += '<div class="prog"><i></i></div>';
  }
  panel.innerHTML = html;

  if (busy) {
    tip.innerHTML = '<div class="warn"><b>重要：整个过程请不要登录学习通。</b>' +
      '你在手机或电脑上登录，会把处理进程顶下线，本次服务直接失败，卡密不退。</div>';
  } else {
    tip.innerHTML = '';
  }
}

async function tick() {
  try {
    // 页面在 /s/{id} 或 /cx/s/{id}，必须用 ../api/ 而不是 api/：
    // 相对路径会多拼一层 s，后端直接 404。
    const r = await fetch('../api/task/' + TID + '?t=' + encodeURIComponent(VT));
    const d = await r.json();
    if (!d.ok) {
      panel.className = 'panel errc';
      panel.innerHTML = '<div class="st"><span class="dot"></span>链接无效</div>' +
        '<div class="desc">请用兑换成功时返回的完整链接打开。</div>';
      return;
    }
    render(d.task);
  } catch (e) {}
}
tick(); setInterval(tick, 5000);
</script>
</html>

"""

NOLINK_HTML = """<!doctype html><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>链接无效</title>
<style>
:root{--bg:#071126;--panel:#0D1B38;--line:rgba(158,175,210,.14);
  --ink:#F4F7FF;--sub:#9EAFD2;--err:#FF5B6E}
*{box-sizing:border-box}
body{margin:0;font:15px/1.8 -apple-system,BlinkMacSystemFont,"Segoe UI","Microsoft YaHei",sans-serif;
  color:var(--ink);min-height:100vh;display:flex;align-items:center;justify-content:center;
  background:var(--bg);
  background-image:radial-gradient(900px 460px at 85% -10%,rgba(76,141,255,.12),transparent 60%)}
.card{background:var(--panel);border:1px solid var(--line);border-radius:20px;
  max-width:440px;margin:20px;padding:36px 30px;text-align:center;
  box-shadow:0 1px 2px rgba(0,0,0,.3),0 12px 34px -16px rgba(0,0,0,.6)}
.ic{width:56px;height:56px;border-radius:50%;margin:0 auto 16px;
  background:rgba(255,91,110,.12);color:var(--err);
  display:flex;align-items:center;justify-content:center}
h1{font-size:19px;margin:0 0 10px}
p{color:var(--sub);font-size:14px;margin:0 0 6px;line-height:1.8}
code{background:#0a1830;border:1px solid var(--line);border-radius:5px;
  padding:1px 7px;font-size:13px}
</style>
<div class="card">
  <div class="ic">
    <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor"
      stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
      <circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/>
      <line x1="9" y1="9" x2="15" y2="15"/>
    </svg>
  </div>
  <h1>链接无效</h1>
  <p>请使用兑换成功时返回的完整链接查看进度（链接末尾带 <code>?t=</code> 参数）。</p>
  <p>找不到就把卡密发给客服，我们帮你查。</p>
</div>

"""


PROBE_HTML = """<!doctype html>
<html lang="zh-CN"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>选择课程</title>
<style>
:root{
  --bg:#f4f6fb;--panel:#fff;--line:#e5e9f2;--ink:#17233f;--sub:#64748b;--faint:#9aa7bd;
  --pri:#3b6fd1;--pri2:#4C8DFF;--ok:#1f9d66;--err:#d33f4e;
  --shadow:0 1px 2px rgba(23,35,63,.05),0 10px 30px -14px rgba(23,35,63,.14);
}
*{box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{margin:0;color:var(--ink);
  font:15px/1.65 -apple-system,BlinkMacSystemFont,"Segoe UI","Microsoft YaHei",sans-serif;
  background:var(--bg)}
.wrap{max-width:640px;margin:0 auto;padding:30px 18px 60px}
.crumb{display:flex;align-items:center;gap:8px;font-size:13px;color:var(--faint);margin-bottom:14px}
.crumb a{color:var(--pri);text-decoration:none}

.panel{background:var(--panel);border:1px solid var(--line);border-radius:18px;
  padding:24px 22px;box-shadow:var(--shadow)}

.state{text-align:center;padding:30px 0 26px;color:var(--sub)}
.state b{display:block;color:var(--ink);font-size:16px;margin-bottom:7px}
.state .big-ic{width:58px;height:58px;border-radius:50%;margin:0 auto 16px;
  display:flex;align-items:center;justify-content:center}
.big-ic.ok{background:linear-gradient(135deg,#34c98b,#1f9d66);color:#fff;
  box-shadow:0 12px 28px -10px rgba(31,157,102,.45)}
.big-ic.err{background:#fdebec;color:var(--err)}
.spin{width:30px;height:30px;border:3px solid #e2e8f2;border-radius:50%;
  margin:0 auto 16px;position:relative;overflow:hidden}
.spin::before{content:"";position:absolute;inset:-3px;border-radius:50%;
  border:3px solid transparent;border-top-color:var(--pri);border-right-color:var(--pri);
  animation:r .85s linear infinite}
@keyframes r{to{transform:rotate(360deg)}}

.course{border:1px solid var(--line);border-radius:14px;padding:15px 17px;
  margin-bottom:10px;cursor:pointer;transition:.18s;display:flex;gap:13px;
  align-items:flex-start;background:#fbfcfe}
.course:hover{border-color:#b9c8e2;transform:translateY(-1px);
  box-shadow:0 6px 16px -10px rgba(23,35,63,.2)}
.course.on{border-color:var(--pri);background:#f0f5ff;
  box-shadow:0 0 0 3px rgba(76,141,255,.15)}
.course .dot{width:18px;height:18px;border-radius:50%;border:2px solid #cbd5e1;
  flex:none;margin-top:2px;transition:.18s;background:#fff}
.course.on .dot{border-color:var(--pri);background:var(--pri);
  box-shadow:inset 0 0 0 3.5px #fff}
.course .nm{font-weight:600;font-size:14.5px;line-height:1.5}
.course .meta{color:var(--faint);font-size:12px;margin-top:4px}

button{font:inherit;border:0;border-radius:12px;padding:13.5px;width:100%;
  background:linear-gradient(135deg,var(--pri2),var(--pri));color:#fff;font-weight:600;
  cursor:pointer;transition:.2s;box-shadow:0 10px 24px -10px rgba(59,111,209,.5)}
button:hover:not(:disabled){transform:translateY(-1px)}
button:disabled{background:#c3cede;cursor:not-allowed;box-shadow:none}
.msg{margin-top:14px;font-size:13.5px;min-height:20px}
.ok{color:var(--ok)}.err{color:var(--err)}.warn{color:#c47d12}
a{color:var(--pri)}
.lk{display:inline-block;margin-top:16px;padding:11px 28px;border-radius:12px;
  background:linear-gradient(135deg,var(--pri2),var(--pri));color:#fff;font-weight:600;
  font-size:14px;text-decoration:none;box-shadow:0 10px 24px -10px rgba(59,111,209,.5);
  transition:.2s}
.lk:hover{transform:translateY(-1px)}
</style>
<div class="wrap">
<div class="crumb"><a href="../">← 返回 CX 服务中心</a></div>
  <div class="panel">
    <div id="box"></div>
  </div>
  <div class="msg" id="msg"></div>
</div>
<script>
const PID = __PID__, VT = "__VT__";
let courses = [], picked = -1, timer = null;

const box = document.getElementById('box');
const msg = document.getElementById('msg');

function el(tag, cls, txt) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (txt != null) e.textContent = txt;
  return e;
}

function showWaiting() {
  box.innerHTML = '';
  const s = el('div', 'state');
  s.appendChild(el('div', 'spin'));
  s.appendChild(el('b', null, '正在登录并读取课程列表'));
  s.appendChild(el('div', null, '第一次登录可能需要 30 到 90 秒，请不要关闭页面'));
  box.appendChild(s);
}

function showFail(text) {
  if (timer) clearInterval(timer);
  box.innerHTML = '';
  const ic = el('div', 'big-ic err');
  ic.innerHTML = '<svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>';
  box.appendChild(ic);
  const s = el('div', 'state');
  s.appendChild(el('b', null, '没能读到课程列表'));
  s.appendChild(el('div', null, text || '请稍后重试，或联系客服'));
  box.appendChild(s);
}

function showCourses(list) {
  if (timer) clearInterval(timer);
  if (!list.length) { showFail('这个账号下没有找到课程'); return; }
  box.innerHTML = '';
  const tip = el('div', 'sub', '共找到 ' + list.length + ' 门课，选一门开始');
  tip.style.cssText = 'color:#64748b;font-size:13px;margin-bottom:14px';
  box.appendChild(tip);

  list.forEach(function (c, i) {
    const d = el('div', 'course');
    d.appendChild(el('div', 'dot'));
    const body = el('div');
    body.appendChild(el('div', 'nm', c.name || ('课程 ' + c.id)));
    const meta = [];
    if (c.teacher) meta.push(c.teacher);
    if (c.clazz_name) meta.push(c.clazz_name);
    if (c.id) meta.push('ID ' + c.id);
    if (meta.length) body.appendChild(el('div', 'meta', meta.join(' · ')));
    d.appendChild(body);
    d.onclick = function () {
      picked = i;
      Array.prototype.forEach.call(box.querySelectorAll('.course'), function (x) {
        x.classList.remove('on');
      });
      d.classList.add('on');
      go.disabled = false;
    };
    box.appendChild(d);
  });

  const go = el('button', null, '开始处理这门课');
  go.disabled = true;
  go.style.marginTop = '18px';
  go.onclick = function () { submit(go, list[picked]); };
  box.appendChild(go);
}

async function submit(btn, c) {
  btn.disabled = true;
  msg.className = '';
  msg.textContent = '正在提交…';
  try {
    const r = await fetch('../api/probe/' + PID + '/choose', {
      method: 'POST', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({
        t: VT, course_id: String(c.id),
        clazz_id: c.clazz_id || '', cpi: c.cpi || '', course_name: c.name || ''
      })
    });
    const d = await r.json();
    if (d.ok) {
      msg.className = 'ok';
      msg.textContent = '已经排上队了，服务编号 ' + d.task_id;
      box.innerHTML = '';
      const ic = el('div', 'big-ic ok');
      ic.innerHTML = '<svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M20 6L9 17l-5-5"/></svg>';
      box.appendChild(ic);
      const s = el('div', 'state');
      s.appendChild(el('b', null, '提交成功'));
      s.appendChild(el('div', null, '处理进程领到任务后会自动开始，点下面的按钮随时看进度'));
      const lk = el('a', 'lk', '查看服务进度');
      lk.href = d.status_url;
      s.appendChild(lk);
      box.appendChild(s);
    } else {
      msg.className = 'err';
      msg.textContent = d.error || d.detail && d.detail.error || '提交失败';
      btn.disabled = false;
    }
  } catch (e) {
    msg.className = 'err';
    msg.textContent = '网络错误：' + e.message;
    btn.disabled = false;
  }
}

async function poll() {
  try {
    const r = await fetch('../api/probe/' + PID + '?t=' + encodeURIComponent(VT));
    const d = await r.json();
    if (!d.ok) { showFail(d.detail && d.detail.error); return; }
    const p = d.probe;
    if (p.status === 'done') showCourses(p.courses || []);
    else if (p.status === 'failed') showFail(p.message);
  } catch (e) {}
}

showWaiting();
poll();
timer = setInterval(poll, 3000);
</script>
</html>

"""


@app.get("/p/{probe_id}", response_class=HTMLResponse)
async def probe_page(probe_id: int, t: str = ""):
    if not check_view_token(probe_id, t, "probe"):
        return HTMLResponse(NOLINK_HTML, status_code=403)
    return PROBE_HTML.replace("__PID__", str(probe_id)).replace("__VT__", t)


@app.get("/api/version")
async def api_version():
    """健康检查。部署文档里用它探活，之前代码里没有这个路由，运维第一步就撞 404。"""
    return {"ok": True, "service": "cx-center", "version": "0.5.0",
            "server_time": db.now()}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host=C.HOST, port=C.PORT)
