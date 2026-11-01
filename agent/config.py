"""刷课机 agent 配置。

跑在刷课机上，只做三件事：开浏览器、登录、盯着进度上报。
不开放任何入站端口，全部由它主动往调度中心发起请求。
"""
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DATA = Path(os.getenv("AGENT_DATA_DIR", str(ROOT / "data")))
DATA.mkdir(parents=True, exist_ok=True)

# ---- 调度中心 ----
CENTER_URL = os.getenv("AGENT_CENTER", "http://127.0.0.1:8080").rstrip("/")
AGENT_ID = os.getenv("AGENT_ID", "pc-01")
AGENT_TOKEN = os.getenv("AGENT_TOKEN", "")

# ---- 浏览器 ----
# Edge 的可执行文件。留空则由 Playwright 自己找。
BROWSER_CHANNEL = os.getenv("AGENT_BROWSER", "msedge")

# 必须有头。OCS 的悬浮窗、视频播放、超星的行为检测都需要真实渲染，
# headless 下视频会被判定为未观看，而且容易被识别。
HEADLESS = os.getenv("AGENT_HEADLESS", "0") == "1"

# 本机允许同时开几个浏览器实例。16G 内存建议 4，别按 CPU 算——
# 每个实例吃 300-500MB，还要留余量给系统和 OCS 的脚本运行。
CAPACITY = int(os.getenv("AGENT_CAPACITY", "4"))

# 窗口尺寸。别用默认的 800x600，超星的页面在这个尺寸下会进移动版布局。
VIEWPORT_W = int(os.getenv("AGENT_VIEW_W", "1400"))
VIEWPORT_H = int(os.getenv("AGENT_VIEW_H", "900"))

# 实例之间的调试端口起始值，每个实例 +1
CDP_PORT_BASE = int(os.getenv("AGENT_CDP_BASE", "9222"))

# ---- profile ----
PROFILES = DATA / "profiles"
PROFILES.mkdir(parents=True, exist_ok=True)

# ---- 题库 ----
# OCS 的题库配置（answererWrappers）。agent 启动时把它写进页面的 localStorage，
# 否则 OCS 遇到测验题只会干等，整个"自动答题"是废的。
# 放 data/tiku.json 优先，方便每台机器单独配；没有就回落到 agent 目录下那份。
def _pick_tiku() -> Path:
    for p in (DATA / "tiku.json", ROOT / "tiku.json"):
        if p.exists():
            return p
    return ROOT / "tiku.json"


TIKU_CONFIG = _pick_tiku()

# 模板 profile：你手动配置好的那一个，装了脚本猫和 OCS、登录过学习通。
# 新账号首次执行时从这个目录整体复制一份，这样不用每次手动装扩展。
# 留空则不复制，直接用空 profile（需要人工先配一次）。
PROFILE_TEMPLATE = os.getenv("AGENT_PROFILE_TEMPLATE", "")

# ---- OCS 加载方式 ----
# inject: 不用扩展，直接往页面注入 OCS 脚本（需要 agent/vendor 下有 ocs.user.js
#         和 gm_shim.js）。实测可用，而且省掉装扩展这一步——刷课机只要装了
#         Edge 就能跑，不用手工去商店装脚本猫。
# extension: 依赖 profile 里的脚本猫扩展，OCS 由扩展加载。
# auto: 先看 profile 有没有扩展，有就用扩展，没有就注入。
OCS_MODE = os.getenv("AGENT_OCS_MODE", "auto").strip().lower()

# vendor 目录，放 ocs.user.js 和 gm_shim.js
VENDOR = ROOT / "vendor"

# 字体表本地缓存。OCS 会去 cdn.ocsjs.com 拉识字字体表，页面里 fetch 会被
# CORS 拦，所以由 agent 侧代发这个请求并把结果塞回页面。
FONT_CACHE = DATA / "font_table.json"

# ---- 轮询 ----
POLL_INTERVAL = int(os.getenv("AGENT_POLL_INTERVAL", "15"))   # 秒
HEARTBEAT_INTERVAL = int(os.getenv("AGENT_HB_INTERVAL", "60"))

# 读一次进度并上报的间隔（秒）。
# 每次读进度都要另开一个标签页加载整个课程目录，代价不小；而"记录被清空"
# 这种事延迟 30 秒还是 3 分钟发现，业务上没有区别。所以放宽到 180 秒，
# 顺带把租约续约频率也降到同量级（租期 7200 秒，完全够）。
KEEPALIVE_SECONDS = int(os.getenv("AGENT_KEEPALIVE", "30"))

# 历史参数：进度上报间隔。新流程不读进度了，保留只为兼容旧环境变量。
REPORT_INTERVAL = int(os.getenv("AGENT_REPORT_INTERVAL", "180"))

# ---- 行为 ----
# 单个任务最长跑多久，超了就放弃并上报 failed。防止卡住的任务永远占着实例。
TASK_TIMEOUT_HOURS = float(os.getenv("AGENT_TASK_TIMEOUT", "12"))

# 登录页等多久算超时（秒）
LOGIN_TIMEOUT = int(os.getenv("AGENT_LOGIN_TIMEOUT", "180"))

# 遇到图形验证码/人脸时，是否保留窗口等人工处理
KEEP_ON_VERIFY = os.getenv("AGENT_KEEP_ON_VERIFY", "1") == "1"

# 保留窗口等人工处理的最长时间（分钟）。超时就把任务交还队列，
# 避免一个没人管的验证码把槽位永久占住。
VERIFY_WAIT_MINUTES = int(os.getenv("AGENT_VERIFY_WAIT", "30"))

# ---- 超星地址 ----
# 课程列表页。用新版入口，旧的 /visit/interaction 会重定向。
CX_HOME = "https://mooc1.chaoxing.com/visit/interaction"
CX_LOGIN = "https://passport2.chaoxing.com/login"
