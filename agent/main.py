"""刷课机 agent 主程序。

职责边界很清楚：agent 只负责把浏览器开起来、登录、导航到目标课程，
然后把页面交给脚本猫里的 OCS，之后只做观察和上报。

不实现任何刷课逻辑。理由是 OCS 已经把那部分做得很好（视频心跳、
跳章节、答题、字体解密都是它自己的），我们再插一手只会互相打架——
前面在沙盒里就撞过这个：OCS 后台一跳转，我正在操作的 frame 就 detach 了。

所以 agent 的价值是：
  - 多账号隔离（profile）
  - 无人值守（自动登录、自动领任务）
  - 可观测（进度、截图、异常上报）
  - 可回收（租约、超时、断电后自恢复）
"""
import asyncio
import base64
import hashlib
import json
import signal
import sys
import time
from contextlib import suppress

import httpx

import browser as bm
import config as C
import login as lg

STOP = asyncio.Event()
SEM: asyncio.Semaphore | None = None
RUNNING: dict[int, asyncio.Task] = {}

# 槽位必须显式分配，不能靠 (CAPACITY - free + i) 推导。
# 推导式的问题：任务结束放开的是"中间的"槽位时，下一次领取算出来的
# 仍是同一个数字，于是两个实例抢同一个 CDP 端口，第二个浏览器直接起不来。
# 这里维护一个可用槽位池，领走就删、结束才还，天然不重复。
SLOT_FREE: set[int] = set()
RUNNING_SLOT: dict[int, int] = {}

# 课程探测任务（登录 + 读课表）单独记，不和刷课任务混在一个字典里：
# 两者的 id 空间独立，混用会导致 "if tid in RUNNING" 误判。
PROBES: dict[int, asyncio.Task] = {}
PROBE_SLOT: dict[int, int] = {}


def _take_slot() -> int | None:
    if not SLOT_FREE:
        return None
    s = min(SLOT_FREE)
    SLOT_FREE.discard(s)
    return s


def _free_slot(slot: int | None):
    if slot is not None:
        SLOT_FREE.add(slot)


# ---------------------------------------------------------------- HTTP

def _client() -> httpx.AsyncClient:
    return httpx.AsyncClient(
        base_url=C.CENTER_URL,
        headers={"X-Agent-Token": C.AGENT_TOKEN},
        timeout=60.0,
    )


async def heartbeat(client: httpx.AsyncClient):
    try:
        r = await client.post("/api/agent/heartbeat", json={
            "agent_id": C.AGENT_ID,
            "running": len(RUNNING) + len(PROBES),
            "capacity": C.CAPACITY,
            "version": "0.1.0",
            "browser": C.BROWSER_CHANNEL,
            "note": "",
        })
        if r.status_code == 200:
            return r.json()
    except Exception as e:
        log(f"心跳失败 {e}")
    return None


async def pull(client: httpx.AsyncClient, slots: int) -> list[dict]:
    try:
        r = await client.get("/api/agent/tasks",
                             params={"agent_id": C.AGENT_ID, "slots": slots})
        if r.status_code == 200:
            d = r.json()
            return d.get("tasks") or []
        log(f"领任务失败 {r.status_code} {r.text[:200]}")
    except Exception as e:
        log(f"领任务异常 {e}")
    return []


async def report(client: httpx.AsyncClient, task_id: int, status: str = "running",
                 remaining=None, total=None, progress=None, current="", message=""):
    try:
        r = await client.post("/api/agent/report", json={
            "task_id": task_id, "status": status, "remaining": remaining,
            "total": total, "progress": progress, "current": current,
            "message": message,
        })
        if r.status_code == 200:
            return r.json()
        if r.status_code == 409:
            d = r.json()
            log(f"任务 {task_id} 被服务端拒绝: {d.get('code')}")
            return {"ok": False, "action": "stop", "code": d.get("code")}
    except Exception as e:
        log(f"上报异常 {e}")
    return {"ok": False, "action": "continue"}


async def upload_shot(client: httpx.AsyncClient, task_id: int, img: bytes):
    try:
        await client.post("/api/agent/shot", json={
            "task_id": task_id,
            "image": "data:image/jpeg;base64," + base64.b64encode(img).decode(),
        })
    except Exception:
        pass


async def pull_probe(client: httpx.AsyncClient) -> dict | None:
    """领一个「登录并把课表读回来」的探测任务。"""
    try:
        r = await client.get("/api/agent/probes")
        if r.status_code == 200:
            return r.json().get("probe")
    except Exception as e:
        log(f"领探测任务异常 {e}")
    return None


async def report_probe(client: httpx.AsyncClient, probe_id: int, status: str = "running",
                       courses: list | None = None, message: str = "") -> dict:
    try:
        r = await client.post("/api/agent/probe_report", json={
            "probe_id": probe_id, "status": status,
            "courses": courses, "message": message,
        })
        if r.status_code == 200:
            return r.json()
        if r.status_code == 409:
            d = r.json()
            log(f"探测 {probe_id} 被服务端拒绝: {d.get('code')}")
            return {"ok": False, "action": "stop"}
    except Exception as e:
        log(f"探测上报异常 {e}")
    return {"ok": False, "action": "continue"}


# ---------------------------------------------------------------- 任务执行

def _profile_name(username: str) -> str:
    """profile 目录名按「账号」走，不按「任务」走。

    早先用 acc{task_id}_{尾号}，同一个手机号只要换一张卡重新下单就是新的
    任务号，于是每次都开一个全新的空 profile——登录态没了，只能重新走一遍
    密码登录。超星对同账号反复密码登录、尤其换设备登录盯得很紧，这等于白送
    风控特征，而且用户第二次下单必然要多等一次登录。

    改成按手机号哈希命名：一个账号一个 profile，终身复用登录态，第二次起
    直接免密进站。
    """
    u = (username or "").strip()
    h = hashlib.sha256(u.encode("utf-8")).hexdigest()[:10]
    return f"u{h}_{u[-4:]}" if len(u) >= 4 else f"u{h}"


# 课程列表抓取。
# 超星的课程页没有稳定接口，只能从链接和 onclick 里抠 courseid/clazzid。
# 三个来源都试：a[href]、带 onclick 的卡片、以及内嵌的 iframe。
COURSE_JS = r"""
() => {
  const out = [];
  const seen = new Set();

  const put = (a) => {
    const href = a.getAttribute('href') || '';
    const m = href.match(/[?&](courseid|courseId)=(\d+)/i);

    // 课程卡片的 <li> 上直接挂着 courseid / clazzid / personid，
    // 比从 href 里抠参数稳得多，href 里的参数顺序是会变的。
    const li = a.closest('li[courseid], li.course, .course-item, [courseid]');

    const cid = (li && li.getAttribute('courseid')) || (m && m[2]) || '';
    if (!cid || seen.has(cid)) return;
    seen.add(cid);

    let clazz = (li && li.getAttribute('clazzid')) || '';
    let cpi = (li && li.getAttribute('personid')) || '';
    const mc = href.match(/[?&](clazzid|clazzId)=([^&]*)/i);
    if (!clazz && mc) clazz = decodeURIComponent(mc[2]);
    const mp = href.match(/[?&]cpi=([^&]*)/i);
    if (!cpi && mp) cpi = decodeURIComponent(mp[2]);

    // 课程名在 .course-name 上，title 属性是完整名，文本会被 CSS 截断
    let name = '';
    if (li) {
      const el = li.querySelector('.course-name, [title]');
      if (el) name = el.getAttribute('title') || el.textContent || '';
    }
    name = (name || '').replace(/\s+/g, ' ').trim();

    // 卡片里除课程名之外的部分（学校、教师、学期），当副标题显示
    let extra = '';
    if (li) {
      extra = (li.innerText || '').replace(/\s+/g, ' ').trim();
      if (name && extra.indexOf(name) === 0) extra = extra.slice(name.length);
      extra = extra.replace(/^[\s·—|,-]+/, '').slice(0, 40);
    }

    out.push({ id: cid, clazz_id: clazz, cpi: cpi, name: name, teacher: extra });
  };

  document.querySelectorAll('a[href*="courseid"], a[href*="courseId"]').forEach(put);

  // 兜底：没有 <a> 但 <li> 带 courseid 的布局
  document.querySelectorAll('[courseid]').forEach(li => {
    const cid = li.getAttribute('courseid');
    if (!cid || seen.has(cid)) return;
    seen.add(cid);
    const el = li.querySelector('.course-name, [title]');
    out.push({
      id: cid,
      clazz_id: li.getAttribute('clazzid') || '',
      cpi: li.getAttribute('personid') || '',
      name: (el ? (el.getAttribute('title') || el.textContent || '') : '')
        .replace(/\s+/g, ' ').trim(),
      teacher: ''
    });
  });

  return JSON.stringify(out);
}
"""


async def _collect_courses(page) -> list[dict]:
    """从课程列表页抓课程。主文档和所有 iframe 都扫一遍，按 courseid 去重。"""
    seen: dict[str, dict] = {}
    for t in [page.main_frame] + list(page.frames):
        try:
            raw = await t.evaluate(COURSE_JS)
            for c in json.loads(raw or "[]"):
                cid = c.get("id")
                if not cid or cid in seen:
                    continue
                if not c.get("name"):
                    c["name"] = f"课程 {cid}"
                seen[cid] = c
        except Exception:
            continue
    return list(seen.values())


async def run_probe(client: httpx.AsyncClient, task: dict, slot: int):
    """登录一次，把课表读回来给用户选。

    这条任务不产生任何学习记录，价值在于：这次登录留下的 profile 会被后面
    的正式刷课任务直接复用，用户选完课提交时不用再登录第二次。
    """
    pid = task["probe_id"]
    acc = task["account"]
    profile = _profile_name(acc["username"])
    br = bm.Browser(profile, C.CDP_PORT_BASE + slot)

    try:
        log(f"[探测{pid}] 启动浏览器 profile={profile}")
        await br.open()
        page = await br.alive_page()
        if not page:
            await report_probe(client, pid, "failed", message="没有可用标签页")
            return

        try:
            how = await lg.ensure_login(page, acc["username"], acc["password"])
            log(f"[探测{pid}] 登录态 {how}")
        except lg.NeedHuman as e:
            log(f"[探测{pid}] 登录需人工：{e}")
            await report_probe(
                client, pid, "failed",
                message=f"登录被验证码/风控拦住（{e}），"
                        f"请先自己用手机正常登录一次这个账号，再回来重试")
            return

        await report_probe(client, pid, "running", message="正在读取课程列表")
        await page.goto(C.CX_HOME, wait_until="domcontentloaded", timeout=60000)
        await asyncio.sleep(4)

        courses = await _collect_courses(page)
        log(f"[探测{pid}] 读到 {len(courses)} 门课")
        if not courses:
            await report_probe(
                client, pid, "failed",
                message="没读到课程。可能这个账号下暂时没有课，或者页面结构变了")
            return

        await report_probe(client, pid, "done", courses=courses)
    except Exception as e:
        log(f"[探测{pid}] 异常 {e}")
        with suppress(Exception):
            await report_probe(client, pid, "failed", message=str(e)[:300])
    finally:
        with suppress(Exception):
            await br.close()


async def _logout_and_close(br):
    """收工时先退出学习通，再关窗口。

    为什么不直接关：买家刷完会自己登学习通看结果。如果只是关窗口，
    cookie 还留在 profile 里、超星那边的 session 也没失效，他再登录就是
    一次多终端登录，容易触发风控。主动退出等于把场地打扫干净。

    退出失败也无所谓，关窗口本身已经释放了槽位。
    """
    try:
        page = await br.alive_page()
        if page:
            log("退出学习通登录")
            await page.goto("https://passport2.chaoxing.com/logout",
                            wait_until="domcontentloaded", timeout=30000)
            await asyncio.sleep(3)
    except Exception as e:
        log(f"退出登录失败（不影响关窗）{type(e).__name__}")
    await br.close()


async def run_task(client: httpx.AsyncClient, task: dict, slot: int):
    """一条任务的完整生命周期：开浏览器 -> 登录 -> 挂着等人 -> 收工。

    刻意不做的事：不进课程、不进章节、不读进度、不判断刷完没刷完。
    这几件事都交给管理员——他瞄一眼学习通课表就知道刷到哪了，比机器数
    DOM 可靠得多，而且超星改一次版面不用改代码。

    agent 唯一的职责就是：把号登进去，然后把浏览器开着别动，直到管理面板
    点了「标记完成」。这中间它会每 30 秒问一次服务器「我这单还要不要继续」，
    顺便续租。
    """
    tid = task["task_id"]
    acc = task["account"]
    profile = _profile_name(acc["username"])

    br = bm.Browser(profile, C.CDP_PORT_BASE + slot)
    deadline = time.time() + C.TASK_TIMEOUT_HOURS * 3600

    try:
        log(f"[{tid}] 启动浏览器 profile={profile}")
        await br.open()

        if br.injected:
            log(f"[{tid}] OCS 以注入方式加载（不依赖扩展）")
        else:
            ids = br.extension_ids()
            if not ids:
                await report(client, tid, "failed",
                             message="profile 里没加载到任何扩展，OCS 无法运行")
                log(f"[{tid}] 扩展为 0，放弃")
                return
            log(f"[{tid}] profile 里有 {len(ids)} 个扩展 {ids}")
            if await br.wait_extension():
                log(f"[{tid}] 脚本猫已加载")
            else:
                log(f"[{tid}] 警告：没等到扩展的 service worker")

        page = await br.alive_page()
        if not page:
            await report(client, tid, "failed", message="浏览器起来但拿不到标签页")
            return

        # ---- 登录 ----
        try:
            how = await lg.ensure_login(page, acc["username"], acc["password"])
            log(f"[{tid}] 登录态 {how}")
        except lg.NeedHuman as e:
            log(f"[{tid}] 登录被拦住：{e}")
            if e.shot:
                await upload_shot(client, tid, e.shot)
            await report(client, tid, "failed",
                         message=f"登录需要人工验证：{e}"[:300])
            return
        except Exception as e:
            log(f"[{tid}] 登录异常 {type(e).__name__}: {e}")
            img = None
            with suppress(Exception):
                p = br.page()
                if p:
                    img = await _shot(p)
            if img:
                await upload_shot(client, tid, img)
            await report(client, tid, "failed", message=f"登录失败：{type(e).__name__}: {e}"[:300])
            return

        # 登录流程常把原标签页关掉，重新取一次
        page = await br.alive_page()
        if not page:
            await report(client, tid, "failed", message="登录后没有可用标签页")
            return

        log(f"[{tid}] 已登录，浏览器留着等人工点进课程")
        r = await report(client, tid, "ready", message=f"已登录({how})，等待人工点课")

        # ---- 保活 ----
        # 这里什么都不做。不碰页面、不读进度、不判断完成。
        # 唯一的事情是定时上报，让服务器知道这单还活着，同时接收收工指令。
        marked_running = False
        while not STOP.is_set():
            if time.time() > deadline:
                await report(client, tid, "failed", message="超过任务时限，自动收工")
                log(f"[{tid}] 超时，收工")
                return

            await asyncio.sleep(C.KEEPALIVE_SECONDS)

            r = await report(client, tid, "ready")
            if r.get("code") == "TASK_GONE" or r.get("action") == "stop":
                log(f"[{tid}] 服务端要求收工")
                return
            if r.get("action") == "running" and not marked_running:
                marked_running = True
                log(f"[{tid}] 管理员已开始刷课")

    except bm.ProfileBusy as e:
        log(f"[{tid}] {e}")
        await report(client, tid, "paused", message=str(e))
    except Exception as e:
        log(f"[{tid}] 异常 {type(e).__name__}: {e}")
        img = None
        with suppress(Exception):
            p = br.page()
            if p:
                img = await _shot(p)
        if img:
            await upload_shot(client, tid, img)
        await report(client, tid, "failed", message=f"{type(e).__name__}: {e}"[:400])
    finally:
        await _logout_and_close(br)
        log(f"[{tid}] 浏览器已关闭")


async def wait_stable(page, timeout: int = 45, quiet: int = 4):
    """等页面跳转停止，返回（新的 page 对象, 是否仍然可用）。

    为什么必须这么做：超星进入课程会连续跳好几次——
      stucoursemiddle → 302 → studentcourse → studentstudy
      →（OCS 补 mooc2=1）→ studentstudy?...&mooc2=1
    每一次整页跳转都会销毁旧 document，Playwright 手里的 page 就指向
    一个已经不存在的页面了。这时候任何 evaluate 都会失败，表现就是
    "跳到新版然后任务断了"。

    这里连续观察 URL，稳定 quiet 秒才算停。返回时用 ``page.context``
    重新取一个活页面，避免继续用失效的旧对象。
    """
    last = None
    steady = 0
    elapsed = 0
    while elapsed < timeout:
        await asyncio.sleep(1)
        elapsed += 1
        try:
            cur = page.url
        except Exception:
            cur = None
        if cur is None:
            # page 已经废了，从 context 里换一个
            try:
                nxt = [p for p in page.context.pages if not p.is_closed()]
                if not nxt:
                    return page, False
                page = nxt[-1]
                last = None
                steady = 0
                continue
            except Exception:
                return page, False
        if cur == last:
            steady += 1
            if steady >= quiet:
                break
        else:
            last = cur
            steady = 0
    return page, True


async def _shot(page):
    try:
        return await page.screenshot(type="jpeg", quality=55, full_page=False)
    except Exception:
        return None


# ---------------------------------------------------------------- 主循环

def log(msg: str):
    print(time.strftime("[%H:%M:%S]"), msg, flush=True)


async def main():
    global SEM

    if not C.AGENT_TOKEN:
        log("缺少 AGENT_TOKEN，先在调度中心执行：")
        log(f"  POST /admin/agents?agent_id={C.AGENT_ID}")
        log("把返回的 token 写进环境变量 AGENT_TOKEN")
        return 1

    SEM = asyncio.Semaphore(C.CAPACITY)
    SLOT_FREE.clear()
    SLOT_FREE.update(range(C.CAPACITY))
    log(f"agent {C.AGENT_ID} 启动，容量 {C.CAPACITY} -> {C.CENTER_URL}")

    async with _client() as client:
        hb = await heartbeat(client)
        if not hb:
            log("连不上调度中心，检查 CENTER_URL 和网络")
            return 1
        log(f"调度中心在线 {hb.get('server_time')}")

        last_hb = 0.0
        while not STOP.is_set():
            now = time.time()
            if now - last_hb >= C.HEARTBEAT_INTERVAL:
                await heartbeat(client)
                last_hb = now

            free = C.CAPACITY - len(RUNNING) - len(PROBES)
            if free > 0:
                # 探测优先派：用户正卡在选课页面上等着，晚一分钟他就以为坏了。
                # 而且探测只登录 + 读一次列表，几十秒就结束，不会长期占坑。
                pr = await pull_probe(client)
                if pr and (C.CAPACITY - len(RUNNING) - len(PROBES)) > 0:
                    slot = _take_slot()
                    if slot is not None:
                        await SEM.acquire()
                        pid = pr["probe_id"]
                        PROBE_SLOT[pid] = slot
                        t = asyncio.create_task(_guard_probe(client, pr, slot))
                        PROBES[pid] = t
                        t.add_done_callback(lambda _, k=pid: _probe_done(k))
                        log(f"领取探测任务 {pid} -> slot {slot}")

            free = C.CAPACITY - len(RUNNING) - len(PROBES)
            if free > 0:
                got = await pull(client, free)
                for t in got:
                    tid = t["task_id"]
                    if tid in RUNNING:
                        continue
                    slot = _take_slot()
                    if slot is None:
                        break
                    await SEM.acquire()
                    RUNNING_SLOT[tid] = slot
                    task = asyncio.create_task(_guard(client, t, slot))
                    RUNNING[tid] = task
                    task.add_done_callback(lambda _, k=tid: _done(k))
                    log(f"领取任务 {tid} -> slot {slot}")

            await asyncio.sleep(C.POLL_INTERVAL)

        # 退出前把所有在跑的任务交还队列。不做这一步的话，任务会一直被
        # 挂在"运行中"直到租约超时（默认 2 小时），这期间调度中心认为
        # 有人在做，不会重新派发，看起来就像队列空了、agent 卡住了。
        if RUNNING:
            log(f"退出前交还 {len(RUNNING)} 个任务")
            for tid in list(RUNNING.keys()):
                try:
                    await report(client, tid, "paused", message="agent 停止，任务交还队列")
                except Exception as e:
                    log(f"交还任务 {tid} 失败 {e}")
            await asyncio.sleep(1)

        for t in list(RUNNING.values()) + list(PROBES.values()):
            t.cancel()
        with suppress(Exception):
            await asyncio.gather(*RUNNING.values(), *PROBES.values(),
                                 return_exceptions=True)
    return 0


async def _guard(client, task, slot):
    try:
        await run_task(client, task, slot)
    except asyncio.CancelledError:
        raise
    except Exception as e:
        log(f"任务守护异常 {e}")
    finally:
        if SEM:
            SEM.release()


async def _guard_probe(client, probe_task, slot):
    try:
        await run_probe(client, probe_task, slot)
    except asyncio.CancelledError:
        raise
    except Exception as e:
        log(f"探测守护异常 {e}")
    finally:
        if SEM:
            SEM.release()


def _probe_done(pid):
    PROBES.pop(pid, None)
    _free_slot(PROBE_SLOT.pop(pid, None))
    log(f"探测 {pid} 结束")


def _done(tid):
    RUNNING.pop(tid, None)
    _free_slot(RUNNING_SLOT.pop(tid, None))
    log(f"任务 {tid} 结束，当前在跑 {len(RUNNING)}")


def _sig(*_):
    log("收到停止信号")
    STOP.set()


if __name__ == "__main__":
    signal.signal(signal.SIGINT, _sig)
    with suppress(AttributeError):
        signal.signal(signal.SIGTERM, _sig)
    sys.exit(asyncio.run(main()) or 0)
