"""浏览器实例管理。

关键约束：脚本猫是浏览器扩展，Playwright 默认启动的是一个干净实例，
不带任何扩展。所以不能用 `chromium.launch()`，必须用
`launch_persistent_context()` 指向一个已经装好脚本猫 + OCS 的
持久化 profile 目录。

流程：
  1. 每个账号一个 profile 目录（profiles/acc1_1009 这种）
  2. 首次执行时从模板 profile 整体复制一份，扩展、OCS 配置、字体表缓存全都带过来
  3. 之后这个 profile 自己长（cookie、登录态、OCS 的 localStorage）

一个 profile 同一时刻只能被一个实例占用。浏览器自己会检测
"user data directory is already in use"，但报错信息很难看，
所以这里先用一个锁文件把它拦在前面。
"""
import asyncio
import json
import shutil
from pathlib import Path

import config as C


class ProfileBusy(RuntimeError):
    pass


class Browser:
    """一个账号对应的浏览器实例。"""

    def __init__(self, profile_name: str, cdp_port: int):
        self.profile_name = profile_name
        self.profile_dir = C.PROFILES / profile_name
        self.cdp_port = cdp_port
        self._ctx = None
        self._pw = None
        self._lockfile = C.PROFILES / f"{profile_name}.lock"
        # OCS 是通过注入加载的（而不是靠扩展），run_task 里要据此决定
        # 要不要等扩展的 service worker
        self.injected = False

    # ---------------------------------------------------------------- profile

    def prepare(self):
        """确保 profile 存在而且可用。

        这里有两套判定，必须分开，否则会互相打架：

        1. 有模板（扩展模式）：判定标准是"能不能真的加载到扩展"。
           只看目录存不存在是不够的。之前踩过这个坑：目录建出来了，但
           Default/Extensions 是空的，agent 以为准备好了，实际没有任何扩展
           可用——OCS 不启动，页面不动，而日志只打一行"0 个扩展"就继续跑。

        2. 没模板（注入模式）：判定标准只是"目录存在"。
           OCS 由 add_init_script 注入，profile 里本来就不该有扩展。
           早先的实现统一要求"必须加载到扩展"，结果是注入模式下每次启动
           都判定 profile 不完整、整个删掉重建——cookie 和登录态全丢，
           每个账号每次都要重新走一遍密码登录，白白增加超星的风控暴露面。
           这是必须区分开的，否则注入模式永远无法免密复用登录态。
        """
        has_tpl = bool(C.PROFILE_TEMPLATE) and Path(C.PROFILE_TEMPLATE).exists()

        # 注入模式：只要目录在就是可用，绝不因为"没有扩展"而删除
        if not has_tpl:
            if not self.profile_dir.exists():
                self.profile_dir.mkdir(parents=True, exist_ok=True)
            return

        # 扩展模式：已经完整就直接用
        if self.profile_dir.exists() and self.extension_args():
            return

        # 走到这里说明是扩展模式且 profile 不完整，删掉重来
        if self.profile_dir.exists():
            shutil.rmtree(self.profile_dir, ignore_errors=True)

        tpl = C.PROFILE_TEMPLATE
        if not has_tpl:
            self.profile_dir.mkdir(parents=True, exist_ok=True)
            return

        last_err = None
        for attempt in range(3):
            try:
                shutil.copytree(
                    tpl, self.profile_dir,
                    ignore=shutil.ignore_patterns(
                        "Cache", "Code Cache", "GPUCache", "ShaderCache",
                        "GrShaderCache", "Crashpad", "*.lock", "LOCK"),
                )
                last_err = None
                break
            except Exception as e:
                last_err = e
                shutil.rmtree(self.profile_dir, ignore_errors=True)
                if attempt < 2:
                    __import__("time").sleep(2)

        if last_err is not None:
            raise RuntimeError(
                f"复制模板 profile 失败（模板可能正被 Edge 占用，"
                f"先关掉所有 msedge 进程）：{last_err}")

        if not self.extension_args():
            raise RuntimeError(
                f"profile 复制完成但没有加载到任何扩展。"
                f"检查模板 {tpl}\\Default\\Extensions 里是否有扩展目录，"
                f"以及每个扩展目录下是否有带 manifest.json 的版本目录。")

    def _acquire(self):
        if self._lockfile.exists():
            try:
                pid = int(self._lockfile.read_text().strip())
            except Exception:
                pid = 0
            if pid and _pid_alive(pid):
                raise ProfileBusy(f"profile {self.profile_name} 正被进程 {pid} 占用")
        self._lockfile.write_text(str(__import__("os").getpid()))

    def _release(self):
        try:
            self._lockfile.unlink()
        except Exception:
            pass

    # ---------------------------------------------------------------- 扩展

    def extension_args(self) -> list[str]:
        """让 Chromium 真的把 profile 里的扩展加载起来。

        这是整条链路的前提，也是之前一直没跑通的根因：
        Playwright 启动 Chromium 时默认带 --disable-extensions，
        所以即使 profile 里明明装着脚本猫，扩展也不会运行。扩展不动，
        OCS 就不会注入，页面自然什么都不做——看起来像"进不去课程"、
        "读不到进度"，实际是脚本根本没上场。

        覆盖办法是显式给出 --load-extension 并配合
        --disable-extensions-except，后者会取代默认的 --disable-extensions。

        传的是 Default/Extensions 下每个扩展里版本号最高的那个目录，
        因为同一扩展可能有多个历史版本残留在磁盘上，加载错版本会报
        manifest 错误。
        """
        root = self.profile_dir / "Default" / "Extensions"
        if not root.exists():
            return []

        paths: list[str] = []
        for ext_id in sorted(root.iterdir()):
            if not ext_id.is_dir():
                continue
            vers = [v for v in ext_id.iterdir()
                    if v.is_dir() and (v / "manifest.json").exists()]
            if not vers:
                continue
            # 版本号目录名形如 1.5.0_0，按字符串倒序够用（主版本号位数一致）
            vers.sort(key=lambda p: p.name, reverse=True)
            paths.append(str(vers[0]))

        if not paths:
            return []

        joined = ",".join(paths)
        return [f"--disable-extensions-except={joined}",
                f"--load-extension={joined}"]

    def extension_ids(self) -> list[str]:
        """profile 里装了哪些扩展，仅用于打日志。"""
        root = self.profile_dir / "Default" / "Extensions"
        if not root.exists():
            return []
        return [d.name for d in root.iterdir() if d.is_dir()]

    # ---------------------------------------------------------------- 生命周期

    # ---------------------------------------------------------------- OCS 注入

    def _want_inject(self) -> bool:
        """要不要用注入方式加载 OCS。

        inject  : 强制注入
        extension: 强制走扩展
        auto    : profile 里有扩展就用扩展，没有就注入

        auto 是默认值，用意是：刷课机上如果已经把脚本猫配好了，就走扩展，
        那是官方支持的方式；如果没配（或者配坏了），自动降级到注入，
        不至于整台机器白等。注入这条路实测能让 OCS 完整跑起来。
        """
        mode = (C.OCS_MODE or "auto").lower()
        if mode == "inject":
            return True
        if mode == "extension":
            return False
        return not bool(self.extension_args())

    async def _install_ocs(self):
        """把 shim 和 OCS 脚本注入到每个 frame 的 document-start。

        OCS 的入口有一道硬性环境检测：12 个 GM API 缺一个就 confirm + return，
        业务逻辑一步都不跑。所以 shim 必须先于 OCS 注入，而且 unsafeWindow
        必须在里面——它是那 12 个里唯一不带 GM_ 前缀的。

        跨域：OCS 会拉 cdn.ocsjs.com 的字体表来识别题目里的加密字体，
        页面里 fetch 会被同源策略拦。这里用 context.route 代发，并且手动补
        access-control-allow-origin，否则响应回来照样被浏览器拒掉。
        """
        shim_path = C.VENDOR / "gm_shim.js"
        ocs_path = C.VENDOR / "ocs.user.js"
        if not shim_path.exists() or not ocs_path.exists():
            raise RuntimeError(
                f"缺少注入脚本：{shim_path} / {ocs_path}。"
                f"这两个文件必须和 agent 一起分发。")

        shim = shim_path.read_text(encoding="utf-8")
        ocs = ocs_path.read_text(encoding="utf-8")
        await self._ctx.add_init_script(shim)

        # 题库配置必须在 OCS 读 store 之前落地，所以夹在 shim 和 ocs 中间。
        # OCS 把配置存在 GM_store 里，而 shim 把 GM_store 映射成了
        # localStorage['__ocs_v_<namespace>.<key>']，所以直接写这个键即可。
        # namespace=common.settings，key=answererWrappers（见 ocs.user.js:10571/10580）。
        tiku_js = self._tiku_script()
        if tiku_js:
            await self._ctx.add_init_script(tiku_js)

        await self._ctx.add_init_script(ocs)

        # 繁体字库。OCS 会去 cdn.ocsjs.com 拉 resources/font/table.json，
        # 刷课机经常没有外网，所以必须在 route 里就地喂给它，不能让它真去请求。
        #
        # font_body 一定要先初始化再进 if：下面 handler 用了 nonlocal font_body，
        # 如果缓存文件不存在、这个变量压根没被赋值，handler 一进来就 NameError，
        # route 没接管，请求落到真实网络，页面报 "Failed to fetch"。
        # 顺序：data 下用户自己放的最新，其次包里自带的 vendor/font_table.json。
        font_body = None
        for _p in (C.FONT_CACHE, C.ROOT / "vendor" / "font_table.json"):
            try:
                if _p.exists():
                    font_body = _p.read_text(encoding="utf-8")
                    break
            except Exception:
                pass

        async def handler(route):
            u = route.request.url
            if "ocs-version.json" in u:
                await route.fulfill(
                    status=200, body='{"version":"4.13.16"}',
                    headers={"access-control-allow-origin": "*",
                             "content-type": "application/json"})
                return
            if "font/table.json" in u:
                nonlocal font_body
                if font_body is None:
                    try:
                        resp = await self._ctx.request.fetch(route.request)
                        raw = await resp.body()
                        font_body = raw.decode("utf-8", "replace")
                        C.FONT_CACHE.write_text(font_body, encoding="utf-8")
                    except Exception:
                        font_body = "{}"
                await route.fulfill(
                    status=200, body=font_body,
                    headers={"access-control-allow-origin": "*",
                             "content-type": "application/json"})
                return
            if "tk.enncy.cn" in u:
                # 题库查询。刷课机所在的网络常常到不了外网，转给中心代查。
                # 跨域 POST + JSON 会先发 OPTIONS 预检，这里直接放行，
                # 否则预检失败，真正的 POST 根本不会发出来。
                if route.request.method == "OPTIONS":
                    await route.fulfill(status=204, headers={
                        "access-control-allow-origin": "*",
                        "access-control-allow-headers": "*",
                        "access-control-allow-methods": "GET, POST, OPTIONS",
                    })
                    return
                try:
                    # post_data 是属性（str）；post_data_buffer 是 async 方法，
                    # 别写成 route.request.post_data_buffer，那样拿到的是函数对象。
                    pd = route.request.post_data
                    body = pd.encode("utf-8") if pd else b""
                    resp = await self._ctx.request.post(
                        f"{C.CENTER_URL}/api/proxy/tk",
                        data=body,
                        headers={"Content-Type": "application/json",
                                 "X-Agent-Token": C.AGENT_TOKEN},
                        timeout=15000,
                    )
                    await route.fulfill(
                        status=resp.status,
                        body=await resp.body(),
                        headers={"access-control-allow-origin": "*",
                                 "access-control-allow-headers": "*",
                                 "content-type": "application/json"})
                except Exception as e:
                    print(f"[browser] 题库代理失败 {e}")
                    await route.fulfill(
                        status=502,
                        body=json.dumps({"code": -1, "message": f"题库代理失败 {e}"},
                                        ensure_ascii=False).encode("utf-8"),
                        headers={"access-control-allow-origin": "*",
                                 "content-type": "application/json"})
                return
            await route.continue_()

        await self._ctx.route("**/*", handler)

    def _tiku_script(self) -> str | None:
        """把题库配置包成一段 init script，让每个 frame 自己写进 localStorage。

        为什么不只写一次：OCS 在学习页的 iframe 里初始化，而那个 iframe 的
        origin 可能是 mooc2-ans.chaoxing.com，和 mooc1 的 localStorage 不互通。
        所以每个 frame 都得往自己 origin 里写一份，跨域的写会抛，吞掉就行。

        键名是 shim 的映射结果：GM_setValue(k) -> localStorage['__ocs_v_' + k]，
        而 OCS 的 namespaceKey 是 namespace + '.' + key，也就是
        common.settings.answererWrappers。
        """
        p = C.TIKU_CONFIG
        if not p.exists():
            print(f"[browser] 没找到题库配置 {p}，OCS 自动答题将不可用")
            return None

        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except Exception as e:
            print(f"[browser] 题库配置解析失败：{e}")
            return None

        if not data:
            return None

        payload = json.dumps(data, ensure_ascii=False)
        return (
            "(function(){\n"
            "  try {\n"
            "    localStorage.setItem('__ocs_v_common.settings.answererWrappers',\n"
            f"      {json.dumps(payload)});\n"
            "  } catch (e) {}\n"
            "})();"
        )

    async def open(self):
        from playwright.async_api import async_playwright

        self.prepare()
        self._acquire()

        self._pw = await async_playwright().start()
        ext = self.extension_args()
        args = [
            f"--remote-debugging-port={self.cdp_port}",
            "--disable-blink-features=AutomationControlled",
            # 关掉后台节流，否则窗口不在前台时视频进度不动
            "--disable-background-timer-throttling",
            "--disable-backgrounding-occluded-windows",
            "--disable-renderer-backgrounding",
            "--no-first-run",
            "--no-default-browser-check",
        ] + ext

        self._ctx = await self._pw.chromium.launch_persistent_context(
            user_data_dir=str(self.profile_dir),
            channel=C.BROWSER_CHANNEL,
            headless=C.HEADLESS,
            args=args,
            viewport={"width": C.VIEWPORT_W, "height": C.VIEWPORT_H},
            locale="zh-CN",
            timezone_id="Asia/Shanghai",
        )

        if self._want_inject():
            await self._install_ocs()
            self.injected = True
        else:
            self.injected = False
        return self._ctx

    async def alive_page(self):
        """拿一个还活着的标签页。

        为什么需要它：登录成功后超星常常把原来那个标签页关掉（或者自己
        window.close），之后再在旧 page 对象上 goto 就是 TargetClosedError。
        每个阶段之间都该重新取一次，而不是一路拿着最初的 page 不放。
        """
        if not self._ctx:
            return None
        for p in self._ctx.pages:
            try:
                if not p.is_closed():
                    return p
            except Exception:
                continue
        try:
            return await self._ctx.new_page()
        except Exception:
            return None

    async def wait_extension(self, timeout: float = 25.0) -> bool:
        """等扩展的 service worker 起来。

        判据必须是 chrome-extension:// 前缀。之前用 "service_worker"
        子串判断，Edge 自己的内置 worker 也会命中，导致扩展明明没加载
        却报"已加载"，把真正的错误掩盖掉了。
        """
        import asyncio

        deadline = timeout
        while deadline > 0:
            try:
                for w in self._ctx.service_workers:
                    if (w.url or "").startswith("chrome-extension://"):
                        return True
            except Exception:
                pass
            await asyncio.sleep(1.0)
            deadline -= 1.0
        return False

    async def close(self):
        try:
            if self._ctx:
                await self._ctx.close()
        except Exception:
            pass
        try:
            if self._pw:
                await self._pw.stop()
        except Exception:
            pass
        self._release()

    @property
    def context(self):
        return self._ctx

    def page(self):
        """拿一个已存在的标签页，没有就新建。

        launch_persistent_context 默认会开一个 about:blank，
        复用它比每次 new_page 更接近真人行为。
        """
        pages = [p for p in self._ctx.pages if p.url != "about:blank"]
        if pages:
            return pages[0]
        if self._ctx.pages:
            return self._ctx.pages[0]
        return None

    async def new_page(self):
        return await self._ctx.new_page()


def _pid_alive(pid: int) -> bool:
    import os
    try:
        os.kill(pid, 0)
        return True
    except (OSError, ProcessLookupError):
        return False
    except Exception:
        return False


async def detect_login(page) -> bool:
    """判断当前是否已登录学习通。

    判据是访问课程列表页后，页面上有没有出现用户信息或课程卡片。
    这里不去读 cookie——cookie 名字会变，而"页面能不能看到课程"骗不了人。
    """
    try:
        await page.goto(C.CX_HOME, wait_until="domcontentloaded", timeout=45000)
    except Exception:
        return False
    await asyncio.sleep(2)
    try:
        return await page.evaluate(r"""
        () => {
          const hasCourse = document.querySelectorAll(
            '.course-item, .courseItem, li.course, .course-list li').length > 0;
          const hasUser = !!document.querySelector(
            '.user-info, .userInfo, .avatar, #personal, .personal');
          const isLoginPage = location.href.indexOf('passport') >= 0 ||
                              !!document.querySelector('#phone, input[name="uname"]');
          return !isLoginPage && (hasCourse || hasUser);
        }
        """)
    except Exception:
        return False
