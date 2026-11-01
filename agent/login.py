"""学习通登录。

两种路径：
  1. profile 里已有登录态 → 直接过
  2. 没有 → 填手机号密码，点登录

密码登录这条链超星挂了风控（滑块、图形验证码、异地提醒），
所以这里的原则是：能自动就自动，一旦出现人机校验立刻停下等你处理，
绝不硬试。硬试的后果不是登录失败，是账号被标记。
"""
import asyncio

import config as C


class NeedHuman(RuntimeError):
    """需要人工介入。带一个原因，agent 会把窗口留着并上报 verify_required。"""

    def __init__(self, reason: str, shot: bytes | None = None):
        super().__init__(reason)
        self.shot = shot


async def is_logged_in(page) -> bool:
    from browser import detect_login
    return await detect_login(page)


async def login(page, username: str, password: str) -> bool:
    """登录。成功返回 True，需要人工则抛 NeedHuman。"""
    await page.goto(C.CX_LOGIN, wait_until="domcontentloaded", timeout=60000)
    await asyncio.sleep(2)

    # 有的入口会先跳到"选择登录方式"
    if "passport" not in page.url:
        await page.goto(C.CX_LOGIN, wait_until="domcontentloaded", timeout=60000)
        await asyncio.sleep(2)

    filled = await page.evaluate(r"""
    (cred) => {
      const setVal = (el, v) => {
        if (!el) return false;
        el.focus();
        el.value = v;
        el.dispatchEvent(new Event('input', {bubbles: true}));
        el.dispatchEvent(new Event('change', {bubbles: true}));
        return true;
      };
      const phone = document.querySelector(
        '#phone, input[name="uname"], input[placeholder*="手机"], input[placeholder*="账号"]');
      const pwd = document.querySelector(
        '#pwd, input[name="password"], input[type="password"]');
      const a = setVal(phone, cred.u);
      const b = setVal(pwd, cred.p);
      return JSON.stringify({phone: !!phone, pwd: !!pwd, filled: a && b});
    }
    """, {"u": username, "p": password})

    import json
    info = json.loads(filled or "{}")
    if not info.get("filled"):
        shot = await _shot(page)
        raise NeedHuman(f"登录页结构不匹配（手机号框={info.get('phone')}，"
                        f"密码框={info.get('pwd')}），需要人工确认页面", shot)

    # 滑块是常见的第二道。先看有没有出现，出现就交给人。
    if await _has_slider(page):
        shot = await _shot(page)
        raise NeedHuman("出现滑块验证，请在刷课机上手动完成", shot)

    clicked = await page.evaluate(r"""
    () => {
      const btn = document.querySelector(
        '#loginBtn, .login-btn, button[type="submit"], a.pointer');
      if (!btn) return false;
      btn.click();
      return true;
    }
    """)
    if not clicked:
        shot = await _shot(page)
        raise NeedHuman("找不到登录按钮", shot)

    # 等跳转或出错
    for _ in range(C.LOGIN_TIMEOUT // 2):
        await asyncio.sleep(2)
        if await _has_slider(page):
            shot = await _shot(page)
            raise NeedHuman("点登录后弹出了滑块，请手动完成", shot)
        url = page.url
        if "passport" not in url:
            await asyncio.sleep(2)
            return await is_logged_in(page)

    shot = await _shot(page)
    raise NeedHuman("登录超时，页面停在登录页", shot)


async def has_slider(page) -> bool:
    return await _has_slider(page)


async def _has_slider(page) -> bool:
    try:
        return await page.evaluate(r"""
        () => {
          const sels = ['#nc_1_wrapper', '.nc-container', '.yidun',
                        '#aliyunCaptcha', '.captcha', '#verifyCode'];
          for (const s of sels) {
            const el = document.querySelector(s);
            if (el) {
              const r = el.getBoundingClientRect();
              if (r.width > 0 && r.height > 0) return true;
            }
          }
          return false;
        }
        """)
    except Exception:
        return False


async def _shot(page) -> bytes | None:
    try:
        return await page.screenshot(type="jpeg", quality=60)
    except Exception:
        return None


async def ensure_login(page, username: str, password: str) -> str:
    """保证登录态可用。返回 'reused' 或 'fresh'。"""
    if await is_logged_in(page):
        return "reused"
    await login(page, username, password)
    return "fresh"
