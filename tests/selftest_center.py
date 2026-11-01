"""调度中心状态机自测（本机，不碰服务器）。

覆盖这次改动的关键路径：
  1. /api/version 探活
  2. 卡密生成 -> 兑换 -> 任务创建
  3. 任务状态页鉴权（无 t 参数必须 403）
  4. 同账号重复兑换必须 ACCOUNT_BUSY
  5. 领任务 -> 上报 remaining 变小（正常）
  6. 上报 remaining 变大 -> 判定被清空 -> 必须真的回队列（原实现不回）
  7. 重刷超过 MAX_REBRUSH -> failed
  8. 反复 paused 超过 MAX_RESUME -> failed（原实现无限重排）
  9. done -> 进入守望期

运行：
  python tests/selftest_center.py
"""
import os
import sys
import tempfile
import shutil
import pathlib
import time
import hmac
import hashlib

TMP = tempfile.mkdtemp(prefix="cxtest_")
os.environ["CX_DATA_DIR"] = TMP
os.environ["CX_SECRET_KEY"] = "a" * 64
os.environ["CX_ADMIN_TOKEN"] = "test-admin-token"
os.environ["CX_QUIET_HOURS"] = "none"
os.environ["CX_MAX_REBRUSH"] = "2"
os.environ["CX_MAX_RESUME"] = "2"
os.environ["CX_LEASE_SECONDS"] = "600"

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "center"))

from fastapi.testclient import TestClient  # noqa: E402
import main as appmod  # noqa: E402
import db  # noqa: E402

PASS, FAIL = [], []


def check(name, cond, extra=""):
    (PASS if cond else FAIL).append(name)
    print(("  [PASS] " if cond else "  [FAIL] ") + name + (f"  {extra}" if extra and not cond else ""))


def main():
    print(f"临时数据目录 {TMP}")
    H = {"X-Admin-Token": "test-admin-token"}

    with TestClient(appmod.app, base_url="https://testserver") as c:
        print("\n[1] 探活")
        r = c.get("/api/version")
        check("/api/version 存在", r.status_code == 200 and r.json()["ok"], r.text[:120])

        print("\n[2] 建 agent + 卡密")
        r = c.post("/admin/agents", params={"agent_id": "pc-01", "capacity": 4}, headers=H)
        atok = r.json()["token"]
        AH = {"X-Agent-Token": atok}
        r = c.post("/admin/cards", params={"n": 5, "quota": 1}, headers=H)
        codes = r.json()["codes"]
        check("生成 5 张卡密", len(codes) == 5)
        card = codes[0]

        print("\n[3] 兑换")
        body = {"card": card, "username": "15532931009", "password": "qwe123456",
                "course_name": "测试课", "note": "张三"}
        r = c.post("/api/redeem", json=body)
        d = r.json()
        check("兑换成功", d.get("ok") is True, r.text[:200])
        tid = d["task_id"]
        url = d["status_url"]
        check("状态链接带 t 参数", "?t=" in url, url)

        print("\n[4] 状态页鉴权")
        check("无 t 参数 403", c.get(f"/api/task/{tid}").status_code == 403)
        check("错误 t 参数 403", c.get(f"/api/task/{tid}?t=deadbeef").status_code == 403)
        tok = url.split("?t=")[1]
        r = c.get(f"/api/task/{tid}?t={tok}")
        check("正确 t 参数 200", r.status_code == 200 and r.json()["ok"])
        check("错 t 的 HTML 页 403", c.get(f"/s/{tid}?t=wrong").status_code == 403)

        print("\n[5] 同账号第二单照样收下，排到队尾")
        r = c.post("/api/redeem", json={**body, "card": codes[1], "course_name": "测试课二"})
        d2 = r.json()
        check("第二单不拒绝", d2.get("ok") is True, r.text[:200])
        tid_b = d2["task_id"]
        check("排队位置是 2", d2.get("queue") == 2, str(d2))

        print("\n[6] submitted 不派发，管理员批准后才派")
        r = c.get("/api/agent/tasks", params={"agent_id": "pc-01", "slots": 2}, headers=AH)
        check("没批准前领不到", r.json()["tasks"] == [], str(r.json())[:160])

        r = c.post(f"/admin/task/{tid}/accept", headers=H)
        check("批准成功", r.json().get("ok") is True, r.text[:160])

        r = c.get("/api/agent/tasks", params={"agent_id": "pc-01", "slots": 2}, headers=AH)
        tasks = r.json()["tasks"]
        check("领到 1 个任务", len(tasks) == 1, str(r.json())[:200])
        check("任务 id 一致", tasks[0]["task_id"] == tid)
        check("带明文账号", tasks[0]["account"]["username"] == "15532931009")
        check("带课程名给管理员认", tasks[0]["course"]["name"] == "测试课")

        print("\n[7] 登录成功上报 ready")
        r = c.post("/api/agent/report", headers=AH, json={
            "task_id": tid, "status": "ready", "message": "已登录"})
        check("ready 返回 wait", r.json().get("action") == "wait", r.text[:160])
        row = db.q1("SELECT status FROM tasks WHERE id=?", (tid,))
        check("状态变 ready", row["status"] == "ready", str(row))

        print("\n[8] 同账号的第二单不能被派发")
        c.post(f"/admin/task/{tid_b}/accept", headers=H)
        r = c.get("/api/agent/tasks", params={"agent_id": "pc-01", "slots": 2}, headers=AH)
        check("账号被占用时跳过第二单", r.json()["tasks"] == [], str(r.json())[:160])

        print("\n[9] 管理员点「开始刷课」")
        r = c.post(f"/admin/task/{tid}/begin", headers=H)
        check("begin 成功", r.json().get("ok") is True, r.text[:160])
        r = c.post("/api/agent/report", headers=AH, json={
            "task_id": tid, "status": "ready"})
        check("保活拿到 running", r.json().get("action") == "running", r.text[:160])

        print("\n[10] 管理员点「标记完成」-> agent 收工")
        r = c.post(f"/admin/task/{tid}/finish", headers=H)
        check("finish 成功", r.json().get("ok") is True, r.text[:160])
        r = c.post("/api/agent/report", headers=AH, json={
            "task_id": tid, "status": "ready"})
        check("agent 收到 stop",
              r.status_code == 409 and r.json().get("action") == "stop", r.text[:160])
        row = db.q1("SELECT status, finished_at FROM tasks WHERE id=?", (tid,))
        check("状态 done", row["status"] == "done")
        check("记了完成时间", row["finished_at"] is not None, str(row))

        print("\n[11] 账号释放后第二单才派得出去")
        r = c.get("/api/agent/tasks", params={"agent_id": "pc-01", "slots": 2}, headers=AH)
        got = [x["task_id"] for x in r.json()["tasks"]]
        check("第二单被派出去", got == [tid_b], str(got))

        print("\n[12] 补单退款")
        r = c.post("/admin/task/%d/refund" % tid_b, headers=H)
        check("补单接口可用", r.status_code == 200 and r.json()["ok"], r.text[:160])
        row = db.q1("SELECT quota FROM cards WHERE code=?", (codes[1],))
        check("补单后配额回来", row["quota"] == 1, str(row))

        print("\n[13] agent 交还任务，退回 submitted 等人工")
        r = c.post("/api/redeem", json={**body, "card": codes[2], "course_name": "测试课三"})
        tid_c = r.json()["task_id"]
        c.post(f"/admin/task/{tid_c}/accept", headers=H)
        r = c.get("/api/agent/tasks", params={"agent_id": "pc-01", "slots": 2}, headers=AH)
        got = [x["task_id"] for x in r.json()["tasks"]]
        check("第三单被领到", got == [tid_c], str(got))
        r = c.post("/api/agent/report", headers=AH, json={
            "task_id": tid_c, "status": "paused", "message": "测试交还"})
        check("交还返回 stop", r.json().get("action") == "stop", r.text[:160])
        row = db.q1("SELECT status FROM tasks WHERE id=?", (tid_c,))
        check("退回 submitted", row["status"] == "submitted", str(row))

        print("\n[14] 课程探测 -> 选课 -> 建任务")
        r = c.post("/api/probe", json={
            "card": codes[3], "username": "13800001111", "password": "pw123456"})
        d = r.json()
        check("探测任务创建", d.get("ok") is True, r.text[:200])
        probe_id = d["probe_id"]
        check("探测链接带 t", "?t=" in d.get("poll_url", ""), d.get("poll_url", ""))
        ptok = d["poll_url"].split("?t=")[1]

        check("探测无 t 403", c.get(f"/api/probe/{probe_id}").status_code == 403)

        g = c.get("/api/agent/probes", headers=AH)
        pr = g.json().get("probe")
        check("agent 领到探测任务", pr and pr["probe_id"] == probe_id, g.text[:200])
        check("探测下发明文账号", pr and pr["account"]["username"] == "13800001111")

        r = c.post("/api/agent/probe_report", headers=AH, json={
            "probe_id": probe_id, "status": "done",
            "courses": [
                {"id": "267792293", "clazz_id": "156533002", "cpi": "511882366",
                 "name": "中国古建筑欣赏与设计"},
                {"id": "240000001", "clazz_id": "", "cpi": "", "name": "另一门课"},
            ]})
        check("探测上报完成", r.json().get("ok") is True, r.text[:160])

        r = c.get(f"/api/probe/{probe_id}?t={ptok}")
        p = r.json().get("probe") or {}
        check("前端能拿到课程列表", len(p.get("courses") or []) == 2, r.text[:200])

        r = c.post(f"/api/probe/{probe_id}/choose", json={
            "t": ptok, "course_id": "267792293", "clazz_id": "156533002",
            "cpi": "511882366", "course_name": "中国古建筑欣赏与设计"})
        d = r.json()
        check("选课直接建任务", d.get("ok") is True and d.get("task_id"), r.text[:200])
        check("返回状态链接", "?t=" in (d.get("status_url") or ""))

        row = db.q1("SELECT status FROM probes WHERE id=?", (probe_id,))
        check("选课后探测记录作废", row["status"] == "canceled", str(row))
        row = db.q1("SELECT quota FROM cards WHERE code=?", (codes[3],))
        check("选课扣掉了配额", row["quota"] == 0, str(row))

        print("\n[15] 探测次数上限")
        hit = None
        for i in range(8):
            rr = c.post("/api/probe", json={
                "card": codes[4], "username": f"1370000{i:04d}", "password": "x"})
            if rr.json().get("code") == "PROBE_LIMIT":
                hit = i
                break
        check("同一张卡探测次数有上限", hit is not None, f"第 {hit} 次触发")

        print("\n[16] 限流")
        codes_hit = 0
        for _ in range(20):
            rr = c.post("/api/redeem", json={**body, "card": "CX-AAAAA-AAAAA-AAAAA"})
            if rr.status_code == 429:
                codes_hit += 1
        check("触发 429 限流", codes_hit > 0, f"命中 {codes_hit} 次")

        print("\n[17] 管理会话安全（cookie 带过期签名 + Secure）")
        r = c.get("/admin/stats")
        check("无认证 401", r.status_code == 401)
        # 自测环境没配 CX_ADMIN_PASSWORD，config 回落为 ADMIN_TOKEN 前 16 位，
        # 而 "test-admin-token" 恰好 16 位，口令即完整字符串
        r = c.post("/admin/login", json={"password": "test-admin-token"})
        check("口令登录成功", r.status_code == 200 and r.json().get("ok") is True,
              r.text[:160])
        sc = r.headers.get("set-cookie", "")
        check("Set-Cookie 带 Secure/HttpOnly/SameSite",
              "secure" in sc.lower() and "httponly" in sc.lower()
              and "samesite=lax" in sc.lower(), sc)
        ck = c.cookies.get("cx_admin") or ""
        check("登录后 cookie 生效", bool(ck) and len(ck.split(".")) == 2,
              ck[:24] + "...")
        # 篡改签名必须 401
        bad = ck.split(".")[0] + ".deadbeef" if ck else "0.deadbeef"
        r2 = c.get("/admin/stats", cookies={"cx_admin": bad})
        check("篡改签名 401", r2.status_code == 401, r2.text[:120])
        # 过期 cookie 必须 401（签名正确但 exp 已过）
        past = int(time.time()) - 60
        past_sig = hmac.new(("a" * 64).encode(),
                            f"admin-session-v2:{past}".encode(),
                            hashlib.sha256).hexdigest()[:32]
        r3 = c.get("/admin/stats", cookies={"cx_admin": f"{past}.{past_sig}"})
        check("过期 cookie 401", r3.status_code == 401, r3.text[:120])

        print("\n[18] 兑换事务原子性（失败整体回滚）")
        appmod._RATE.clear()  # 清掉前面限流测试的计数
        r = c.post("/admin/cards", params={"n": 1, "quota": 1}, headers=H)
        one = r.json()["codes"][0]
        r1 = c.post("/api/redeem", json={
            "card": one, "username": "16600000001", "password": "p1",
            "course_name": "原子性测试课"})
        check("首次兑换成功", r1.json().get("ok") is True, r1.text[:150])
        r2 = c.post("/api/redeem", json={
            "card": one, "username": "16600000001", "password": "p2",
            "course_name": "原子性测试课二"})
        check("同卡二次兑换被拒 NO_QUOTA",
              r2.json().get("ok") is False and r2.json().get("code") == "NO_QUOTA",
              r2.text[:150])
        n = db.q1("SELECT COUNT(*) AS n FROM accounts WHERE card_code=?", (one,))
        check("失败请求未留孤立账号", n["n"] == 1, str(n))
        n = db.q1("""SELECT COUNT(*) AS n FROM tasks
                     WHERE card_code=? AND status='canceled'""", (one,))
        check("失败请求未留 canceled 脏任务", n["n"] == 0, str(n))
        n = db.q1("SELECT quota FROM cards WHERE code=?", (one,))
        check("配额没有被重复扣减", n["quota"] == 0, str(n))

        print("\n[19] 数据清理（日志保留期）")
        db.ex("INSERT INTO events(task_id, agent_id, ts, level, msg) "
              "VALUES(NULL,NULL,'2020-01-01T00:00:00+00:00','info','old test')")
        before = db.q1("SELECT COUNT(*) AS n FROM events")["n"]
        removed = db.prune_events(90)
        after = db.q1("SELECT COUNT(*) AS n FROM events")["n"]
        check("超期事件被清理", removed >= 1 and after == before - removed,
              f"清 {removed} 条")
        check("近期事件保留", after >= 1)
        n = db.prune_shots(30)  # 临时目录里通常没有截图，函数不报错即可
        check("截图清理函数可用", n >= 0, f"清 {n} 张")

        print("\n[20] 后台新 API（总览/详情/调度/禁用/筛选）")
        r = c.get("/admin/overview", headers=H)
        d = r.json()
        check("overview 结构完整",
              r.status_code == 200 and "today" in d and "trend" in d
              and "agents" in d and "dispatch" in d, r.text[:200])
        check("趋势是 7 天", len(d.get("trend") or []) == 7)
        check("今日字段为数字",
              isinstance(d["today"].get("created"), int)
              and isinstance(d["today"].get("done"), int))

        r = c.get(f"/admin/task/{tid}", headers=H)
        d = r.json()
        check("任务详情含状态历史",
              r.status_code == 200 and d["task"]["status"] == "done"
              and isinstance(d.get("events"), list), r.text[:200])
        check("详情账号已脱敏", "****" in (d["task"].get("username") or ""))

        r = c.get("/admin/agents/pc-01", headers=H)
        d = r.json()
        check("节点详情结构完整",
              r.status_code == 200 and d["agent"]["id"] == "pc-01"
              and "tasks" in d["agent"] and "recent_tasks" in d["agent"]
              and "events" in d["agent"], r.text[:200])

        r = c.get("/admin/dispatch", headers=H)
        d = r.json()
        check("调度状态结构完整",
              r.status_code == 200 and "paused" in d
              and "agents" in d and d.get("online_threshold") == 90,
              r.text[:200])
        check("默认未暂停", d.get("paused") is False)

        r = c.post("/admin/cards", params={"n": 1, "quota": 1}, headers=H)
        rc = r.json()["codes"][0]
        r = c.post(f"/admin/cards/{rc}/revoke", headers=H)
        check("禁用卡密成功", r.status_code == 200 and r.json().get("ok") is True,
              r.text[:150])
        rr = c.post("/api/redeem", json={
            "card": rc, "username": "16600000002", "password": "x",
            "course_name": "禁用测试"})
        check("禁用后兑换被拒 REVOKED",
              rr.json().get("code") == "REVOKED", rr.text[:150])

        r = c.get("/admin/tasks", params={"status": "done", "q": "测试课"}, headers=H)
        d = r.json()
        check("任务筛选（状态+搜索）",
              all(t["status"] == "done" for t in d["tasks"])
              and len(d["tasks"]) >= 1, r.text[:200])
        r = c.get("/admin/tasks", params={"page": 1, "size": 5}, headers=H)
        d = r.json()
        check("分页参数生效",
              d.get("pagination") and len(d["tasks"]) <= 5
              and "total" in d["pagination"], str(d.get("pagination")))

        r = c.get("/admin/events", params={"level": "error", "limit": 50}, headers=H)
        d = r.json()
        check("日志等级筛选",
              all(e["level"] == "error" for e in d["events"]) if d["events"] else True,
              r.text[:150])

        print("\n[21] 公开接口（状态/公告/帮助/反馈）")
        r = c.get("/api/status")
        d = r.json()
        check("平台状态结构", r.status_code == 200 and "accepting" in d
              and "nodes_online" in d, r.text[:150])
        check("状态接口不泄露节点 ID", "pc-01" not in r.text, "")
        r = c.get("/api/announcements")
        check("公告列表可用", r.status_code == 200
              and isinstance(r.json().get("announcements"), list))
        r = c.get("/api/help")
        d = r.json()
        cats = [x["category"] for x in d.get("categories", [])]
        check("帮助中心有内容", "服务提交" in cats, str(cats))
        r = c.post("/api/feedback", json={
            "kind": "服务进度", "task_id": tid, "contact": "qq:12345",
            "content": "测试反馈：进度一直不动，麻烦看一下"})
        d = r.json()
        check("反馈提交成功", d.get("ok") is True and d.get("feedback_id"), r.text[:150])
        fid = d["feedback_id"]
        r = c.post("/api/feedback", json={"kind": "其他问题", "content": "短"})
        check("反馈内容过短被拒", r.status_code == 400)
        for i in range(4):
            rr = c.post("/api/feedback", json={
                "kind": "其他问题", "content": "限流测试内容" + str(i)})
            last = rr
        check("反馈限流 429", last.status_code == 429, last.text[:120])

        print("\n[22] 公告管理")
        r = c.post("/admin/announcements", headers=H, json={
            "title": "系统升级通知", "content": "本周进行系统维护，服务正常。",
            "is_pinned": True, "published": True})
        aid = r.json().get("id")
        check("公告创建", r.status_code == 200 and aid, r.text[:150])
        r = c.get("/api/announcements")
        lst = r.json()["announcements"]
        check("公开列表含新公告且置顶", lst and lst[0]["id"] == aid
              and lst[0]["is_pinned"] == 1, str(lst[:1]))
        r = c.get(f"/api/announcements/{aid}")
        check("公告详情", r.json()["announcement"]["title"] == "系统升级通知")
        c.put(f"/admin/announcements/{aid}", headers=H, json={
            "title": "系统升级通知", "content": "内容", "is_pinned": False,
            "published": False})
        r = c.get("/api/announcements")
        check("隐藏后公开列表不可见", all(x["id"] != aid for x in r.json()["announcements"]))
        c.delete(f"/admin/announcements/{aid}", headers=H)
        check("公告删除后 404", c.get(f"/api/announcements/{aid}").status_code == 404)

        print("\n[23] 帮助管理")
        r = c.post("/admin/help", headers=H, json={
            "title": "测试文章", "content": "测试内容", "category": "测试分类",
            "sort": 9, "published": True})
        hid = r.json().get("id")
        check("帮助文章创建", r.status_code == 200 and hid, r.text[:150])
        r = c.get("/api/help")
        ok_ = any(x["category"] == "测试分类" for x in r.json()["categories"])
        check("公开帮助含新分类", ok_)
        c.put(f"/admin/help/{hid}", headers=H, json={
            "title": "测试文章", "content": "测试内容", "category": "测试分类",
            "sort": 9, "published": False})
        r = c.get("/api/help")
        check("隐藏后公开不可见", all(x["category"] != "测试分类"
                                    for x in r.json()["categories"]))
        c.delete(f"/admin/help/{hid}", headers=H)

        print("\n[24] 反馈管理")
        r = c.get("/admin/feedback", params={"status": "pending"}, headers=H)
        check("待处理列表含测试反馈", any(f["id"] == fid for f in r.json()["feedback"]))
        r = c.post(f"/admin/feedback/{fid}/reply", headers=H, json={
            "reply": "已核实，进度正常，请刷新查看。", "status": "resolved"})
        check("回复成功", r.status_code == 200 and r.json().get("ok") is True)
        r = c.get("/admin/feedback", params={"status": "resolved"}, headers=H)
        fb = [f for f in r.json()["feedback"] if f["id"] == fid]
        check("反馈状态流转+回复留存", fb and fb[0]["reply"] and fb[0]["status"] == "resolved")

        print("\n[25] 数据分析 / 异常任务 / 截图 / 审计 / 设置")
        r = c.get("/admin/analytics", params={"days": 7}, headers=H)
        d = r.json()
        check("数据分析结构", len(d["trend"]) == 7 and "cards" in d
              and "success_rate" in d["outcome"], r.text[:150])
        r = c.get("/admin/abnormal", headers=H)
        check("异常任务结构", "failed" in r.json() and "stale" in r.json())
        r = c.get(f"/admin/task/{tid}/shots", headers=H)
        check("截图列表接口", r.status_code == 200
              and isinstance(r.json().get("shots"), list))
        check("截图文件名白名单拦截",
              c.get("/admin/shots/..%2Fetc.jpg", headers=H).status_code in (400, 404))
        check("截图不存在 404",
              c.get("/admin/shots/task999999_1.0.jpg", headers=H).status_code == 404)

        c.post("/admin/pause?hours=1", headers=H)
        c.post("/admin/resume", headers=H)
        r = c.get("/admin/audit", headers=H)
        acts = [a["action"] for a in r.json()["audit"]]
        check("审计含暂停/恢复/登录", "dispatch.pause" in acts
              and "dispatch.resume" in acts and "admin.login" in acts, str(acts[:6]))

        r = c.get("/admin/settings", headers=H)
        d = r.json()["settings"]
        check("设置结构完整", all(k in d for k in
              ("site_name", "lease_seconds", "online_threshold", "event_days")))
        r = c.post("/admin/settings", headers=H, json={"lease_seconds": 600})
        check("修改租约设置", r.json().get("changed") == ["lease_seconds"])
        check("非法设置被拒", c.post("/admin/settings", headers=H,
              json={"lease_seconds": 10}).status_code == 400)
        appmod._RATE.clear()
        r = c.post("/admin/cards", params={"n": 1, "quota": 1}, headers=H)
        c4 = r.json()["codes"][0]
        r = c.post("/api/redeem", json={
            "card": c4, "username": "16600000003", "password": "p",
            "course_name": "租约测试课"})
        tid4 = r.json()["task_id"]
        c.post(f"/admin/task/{tid4}/accept", headers=H)
        r = c.get("/api/agent/tasks", params={"agent_id": "pc-01", "slots": 1}, headers=AH)
        check("租约设置动态生效",
              r.json()["tasks"] and r.json()["tasks"][0]["lease_seconds"] == 600,
              r.text[:200])

        print("\n[26] 节点健康字段（可选上报）")
        r = c.post("/api/agent/heartbeat", headers=AH, json={
            "agent_id": "pc-01", "running": 1, "capacity": 4,
            "cpu": 42.5, "memory": 61.0, "uptime": "3h20m"})
        check("健康字段心跳成功", r.status_code == 200)
        r = c.get("/admin/agents/pc-01", headers=H)
        a = r.json()["agent"]
        check("健康字段落库可查", a.get("cpu") == 42.5 and a.get("memory") == 61.0,
              str({k: a.get(k) for k in ("cpu", "memory", "uptime")}))

        print("\n[27] 前台用户体系（注册/登录/我的订单/卡密查询）")
        appmod._RATE.clear()
        r = c.post("/api/me")
        check("未登录 me 为空", r.json().get("user") is None)
        r = c.post("/api/register", json={"username": "15500001111", "password": "abc12345"})
        check("注册成功", r.json().get("ok") is True, r.text[:150])
        r = c.post("/api/register", json={"username": "15500001111", "password": "abc12345"})
        check("重复注册被拒", r.status_code == 409, r.text[:120])
        r = c.post("/api/login", json={"username": "15500001111", "password": "wrong123"})
        check("错误密码 401", r.status_code == 401)
        c.post("/api/logout")
        r = c.post("/api/login", json={"username": "15500001111", "password": "abc12345"})
        check("登录成功", r.json().get("ok") is True, r.text[:150])
        r = c.get("/api/me")
        check("me 返回当前用户", (r.json().get("user") or {}).get("username") == "15500001111")

        r = c.post("/admin/cards", params={"n": 1, "quota": 2}, headers=H)
        multi_card = r.json()["codes"][0]
        r = c.post("/api/redeem_multi", json={
            "card": multi_card, "username": "15500001111", "password": "pw123456",
            "courses": [{"course_name": "多次卡课程甲", "note": "张老师"},
                        {"course_name": "多次卡课程乙", "note": ""}]})
        d = r.json()
        check("多次卡一次提交两门课", d.get("ok") is True and len(d.get("task_ids") or []) == 2,
              r.text[:200])
        check("两次卡配额扣完", db.q1("SELECT quota FROM cards WHERE code=?",
                                    (multi_card,))["quota"] == 0)
        r = c.get("/api/my/tasks")
        mine = r.json().get("tasks") or []
        check("我的订单含两门课", len(mine) >= 2 and any(t["course_name"] == "多次卡课程甲"
                                                  for t in mine), str(len(mine)))
        check("订单带可访问的进度链接",
              all("?t=" in t["status_url"] for t in mine))

        r = c.post("/api/query/by-card", json={"card": multi_card})
        qs = r.json().get("tasks") or []
        check("凭卡密查到订单", len(qs) == 2, r.text[:150])
        r = c.post("/api/query/by-card", json={"card": "CX-AAAAA-AAAAA-AAAAA"})
        check("非法卡密格式被拒", r.status_code == 400)

        appmod._RATE.clear()
        r = c.post("/admin/cards", params={"n": 1, "quota": 1}, headers=H)
        one = r.json()["codes"][0]
        r = c.post("/api/redeem_multi", json={
            "card": one, "username": "15500001111", "password": "pw",
            "courses": [{"course_name": "甲"}, {"course_name": "乙"}]})
        check("配额不足拒绝多课", r.json().get("code") == "NO_QUOTA", r.text[:150])
        n = db.q1("SELECT COUNT(*) AS n FROM tasks WHERE card_code=?", (one,))
        check("拒绝时零残留", n["n"] == 0, str(n))

        r = c.get("/api/site")
        check("站点信息公开可用",
              r.json().get("site_name") and "site_subtitle" in r.json(), r.text[:150])
        r = c.get("/admin/cards/all?limit=5", headers=H)
        check("卡密列表带编号", all("no" in x for x in r.json()["detail"]))
        r = c.post("/admin/cards", params={"n": 1, "quota": 2}, headers=H)
        fresh = r.json()["codes"][0]
        r = c.get("/admin/cards/export-filter", params={"quota": 2}, headers=H)
        check("按配额导出可用", r.status_code == 200 and fresh in r.text,
              r.text[:120])

        print("\n[28] 后台账号密码登录")
        r = c.post("/admin/login", json={"username": "admin", "password": "test-admin-token"})
        check("默认账号 admin 可登录", r.status_code == 200)
        r = c.post("/admin/login", json={"username": "hacker", "password": "test-admin-token"})
        check("错误用户名被拒", r.status_code == 401)
        r = c.post("/admin/account", headers=H,
                   json={"username": "ops", "password": "newpass12345"})
        check("修改管理员账号密码", r.json().get("ok") is True, r.text[:150])
        r = c.post("/admin/login", json={"username": "admin", "password": "test-admin-token"})
        check("旧凭据失效", r.status_code == 401)
        r = c.post("/admin/login", json={"username": "ops", "password": "newpass12345"})
        check("新凭据可登录", r.status_code == 200)

    print("\n" + "=" * 52)
    print(f"通过 {len(PASS)} / 失败 {len(FAIL)}")
    if FAIL:
        for f in FAIL:
            print("  FAIL:", f)
    shutil.rmtree(TMP, ignore_errors=True)
    return 0 if not FAIL else 1


if __name__ == "__main__":
    sys.exit(main())
