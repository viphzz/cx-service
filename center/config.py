"""调度中心配置。

全部走环境变量，部署时用 systemd 的 Environment= 或 .env 注入，
不把密钥写进代码。
"""
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DATA = Path(os.getenv("CX_DATA_DIR", str(ROOT / "data")))
DATA.mkdir(parents=True, exist_ok=True)

DB_PATH = str(DATA / "center.db")

# ---- 服务 ----
HOST = os.getenv("CX_HOST", "0.0.0.0")
PORT = int(os.getenv("CX_PORT", "8080"))

# 对外访问地址，兑换页里生成二维码/链接要用
PUBLIC_URL = os.getenv("CX_PUBLIC_URL", "http://127.0.0.1:8080").rstrip("/")

# ---- 安全 ----
# 管理员口令：进后台看任务、生成卡密、暂停 agent。
# 现在管理面板走「口令登录换 cookie」，这个值同时还是脚本用的 X-Admin-Token。
ADMIN_TOKEN = os.getenv("CX_ADMIN_TOKEN", "")
if not ADMIN_TOKEN:
    # 没配就用随机值并打印，避免默认口令上线
    import secrets
    ADMIN_TOKEN = secrets.token_urlsafe(24)
    print(f"[warn] CX_ADMIN_TOKEN 未配置，本次使用随机值：{ADMIN_TOKEN}")

# 管理面板的登录口令。和 ADMIN_TOKEN 分开：前者是给人手输的短口令，
# 后者是给脚本用的长 token，混用会让"口令太长记不住、token 太短不安全"。
ADMIN_PASSWORD = os.getenv("CX_ADMIN_PASSWORD", "")
if not ADMIN_PASSWORD:
    ADMIN_PASSWORD = ADMIN_TOKEN[:16]
    print("[warn] CX_ADMIN_PASSWORD 未配置，暂时沿用 ADMIN_TOKEN 前 16 位")

# 账号密码落库用的对称密钥。丢了就解不开历史账号，务必固定保存。
SECRET_KEY = os.getenv("CX_SECRET_KEY", "")
if not SECRET_KEY:
    import secrets
    SECRET_KEY = secrets.token_hex(32)
    print(f"[warn] CX_SECRET_KEY 未配置，本次使用随机值：{SECRET_KEY}")
    print("[warn] 重启后历史账号将无法解密，请立刻把它写进环境变量")

# 管理面板会话时长（小时）。cookie 值里带 exp 签名，服务端强制过期，
# 不只是浏览器到期——旧版 cookie 值永久有效，泄露即长期失守。
SESSION_HOURS = int(os.getenv("CX_SESSION_HOURS", "12"))

# 节点在线判定阈值（秒）：last_seen 距今在此范围内算在线。
# 管理面板展示和调度判断统一读这一个值，不要在多处写死 90。
ONLINE_THRESHOLD = int(os.getenv("CX_ONLINE_THRESHOLD", "90"))

# 数据保留天数：事件日志和异常截图超过期限由后台循环清理，
# 清理动作本身会写入事件日志。
EVENT_RETENTION_DAYS = int(os.getenv("CX_EVENT_DAYS", "90"))
SHOT_RETENTION_DAYS = int(os.getenv("CX_SHOT_DAYS", "30"))

# ---- 业务参数 ----
# 禁刷时段，超星凌晨挂脚本容易被判异常并清空记录
QUIET_HOURS = os.getenv("CX_QUIET_HOURS", "0-7")

# 任务租期。agent 超过这个时间没续报，任务回队。
LEASE_SECONDS = int(os.getenv("CX_LEASE_SECONDS", "7200"))

# agent 上报的最小间隔，防止刷屏写库
REPORT_MIN_INTERVAL = int(os.getenv("CX_REPORT_MIN_INTERVAL", "20"))

# 完成后守望多久（分钟），期间定期比对进度是否被清空
WATCH_MINUTES = int(os.getenv("CX_WATCH_MINUTES", "1440"))
WATCH_INTERVAL = int(os.getenv("CX_WATCH_INTERVAL", "60"))

# 被清空后自动重刷的最大轮数
MAX_REBRUSH = int(os.getenv("CX_MAX_REBRUSH", "3"))

# 任务被 agent 交还的最大次数。交还（paused）和"被清空重刷"是两回事：
# 前者通常是登录失败、验证码超时、agent 退出，反复发生说明这个任务根本
# 跑不下去，必须有上限，否则会变成永久摇奖，卡密一直被占着。
MAX_RESUME = int(os.getenv("CX_MAX_RESUME", "8"))

# 单卡默认可提交几次任务
DEFAULT_QUOTA = int(os.getenv("CX_DEFAULT_QUOTA", "1"))

# ---- 课程探测 ----
# 同一张卡密最多探几次课程列表。探测不扣配额（用户"看一眼课表"不该花钱），
# 但必须限次：不限的话一张卡可以无限登录不同手机号，等于把站点变成撞库工具。
PROBE_LIMIT_PER_CARD = int(os.getenv("CX_PROBE_LIMIT", "5"))

# 探测记录保留多久（分钟）。过期即删，账号密码没有长期留存的必要。
PROBE_KEEP_MINUTES = int(os.getenv("CX_PROBE_KEEP", "120"))

# 卡密有效期天数
CARD_DAYS = int(os.getenv("CX_CARD_DAYS", "365"))

# ---- 通知 ----
# 企业微信/钉钉/飞书机器人，或自建的 webhook
WEBHOOK_URL = os.getenv("CX_WEBHOOK_URL", "")
