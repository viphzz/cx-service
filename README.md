# 学习通刷课系统

自建的**超星学习通刷课系统**。用户用一次性卡密在网页上提交账号和课程，管理员在面板上派单，刷课机（Windows + Edge）领取任务、自动登录、把浏览器交给页面内的刷课脚本执行，管理员确认完成后收工。

不依赖 Redis / MQ / Docker，单进程 FastAPI + SQLite。刷课机全部出站长轮询，**不需要公网 IP，不开任何入站端口**。

> ⚠️ **使用须知**：本项目为技术实现参考，仅用于自建自动化平台与工程学习。使用者需自行确保使用方式符合目标平台的服务条款与所在地法律；作者不对任何违规使用、账号风险或由此产生的后果负责。

---

## 主链路

```
用户                        管理面板                     刷课机
 │                            │                          │
 ├─ 卡密 + 账号 + 课程 ──────▶ 任务(submitted)            │
 │                            ├─ 点「开始登录」─▶ queued   │
 │                            │                          ├─ 轮询领单 → logging
 │                            │                          ├─ 登录学习通
 │                            │  ◀──────── ready ─────────┤ 浏览器挂起等指令
 │                            ├─ 点「开始刷课」─▶ running  │
 │                            │      （管理员点进课程，    │
 │                            │        脚本接管刷课）      │
 │                            ├─ 点「标记完成」─▶ done     ├─ 退出登录、关窗、释放槽位
```

**关键点：机器只负责登录、开窗口、保活；「刷完没有」由管理员看课表判断。** 不做自动进度判定——目标平台改一次版面就会连环失效，维护成本远超收益。

## 目录

```
center/                 调度中心（服务端）
├── main.py             全部路由 + 用户侧页面（内嵌 HTML）
├── tasks.py            状态机、队列、租约、同账号占号
├── cards.py            卡密生成（带校验位）/ 原子扣减 / 禁用
├── accounts.py         账号密码 AES-GCM 存取
├── crypto.py           加解密 + 日志脱敏
├── probe.py            课程探测（先登录读课表，用户选课）
├── db.py               SQLite schema / 迁移 / 日志与截图清理
├── config.py           全部环境变量
└── static/admin.html   管理面板（单文件 SPA，零外部依赖）

agent/                  刷课机
├── main.py             主循环：轮询、槽位池、心跳、上报
├── browser.py          Playwright 封装（持久化 profile、扩展加载、脚本注入）
├── login.py            学习通登录 + 人机校验检测
├── config.py           环境变量
├── tiku.example.json   题库配置示例（脚本答题用）
└── vendor/gm_shim.js   GM API 垫片（把油猴 API 映射到 localStorage）

tests/selftest_center.py   端到端自测（TestClient，百条断言）
```

## 任务状态机

```
submitted ──管理员派单──▶ queued ──刷课机领取──▶ logging ──登录成功──▶ ready
                                                                      │
                                                          管理员「开始刷课」
                                                                      ▼
                                                                   running
                                                                      │
                                                          管理员「标记完成」
                                                                      ▼
                                                                   done
任意状态 → failed / canceled
```

状态值写死在库里，只允许改 UI 文案，不允许改取值。

## 刷课机怎么接任务

刷课机不监听端口，靠**主动轮询**拿活：

| 接口 | 频率 | 作用 |
|---|---|---|
| `POST /api/agent/heartbeat` | 60s | 报存活、容量、版本 |
| `GET /api/agent/tasks` | 15s | 领任务（一次领空闲槽位数） |
| `POST /api/agent/report` | 30s | 保活 + 上报状态，响应里带 `action: wait/running/stop` |
| `POST /api/agent/shot` | 异常时 | 上传失败截图 |

派单在 `BEGIN IMMEDIATE` 事务里完成"选任务 + 写租约 + 推状态"，两台刷课机不会抢到同一单。租约默认 7200 秒，机器断电到期自动回收，不会永久占坑。

**同账号占用**：同一手机号的第二单在派发时跳过，避免多终端登录互踢。

## 快速开始

### 调度中心

```bash
cd center
python -m venv venv && venv/bin/pip install -r requirements.txt

export CX_SECRET_KEY="$(python -c 'import secrets;print(secrets.token_hex(32))')"  # 务必固定保存
export CX_ADMIN_TOKEN="$(python -c 'import secrets;print(secrets.token_urlsafe(32))')"
export CX_ADMIN_PASSWORD="你的管理口令"
export CX_PUBLIC_URL="https://your-domain.example"

venv/bin/uvicorn main:app --host 127.0.0.1 --port 8080
```

`/` 用户兑换页，`/admin` 管理面板，`/api/version` 自检。

### 刷课机

```bat
cd agent
pip install -r requirements.txt
playwright install msedge

set "AGENT_CENTER=https://your-domain.example"
set "AGENT_ID=pc-01"
set "AGENT_TOKEN=<面板里新增节点后拿到的 token>"
set "AGENT_CAPACITY=4"
set "AGENT_PROFILE_TEMPLATE=D:\cx-template"
set "AGENT_OCS_MODE=auto"
python main.py
```

`AGENT_PROFILE_TEMPLATE` 指向一个已经配好脚本管理器（脚本猫）和刷课脚本的 Edge profile 目录。首次执行某账号时从这里整体复制，扩展和登录态随之带过来；后续该账号复用自己那份 profile，不必重复密码登录。

## 配置项

调度中心（详见 `center/config.py`）：

| 变量 | 说明 | 默认 |
|---|---|---|
| `CX_SECRET_KEY` | 加密与签名密钥，**丢失则历史账号不可解** | 随机（仅调试） |
| `CX_ADMIN_TOKEN` | 脚本调用管理接口的令牌 | 空 |
| `CX_ADMIN_PASSWORD` | 管理面板口令 | 空 |
| `CX_PUBLIC_URL` | 对外地址，用于生成进度查询链接 | 127.0.0.1 |
| `CX_ONLINE_THRESHOLD` | 刷课机在线判定阈值（秒） | 90 |
| `CX_LEASE_SECONDS` | 任务租约（秒） | 7200 |
| `CX_EVENT_DAYS` / `CX_SHOT_DAYS` | 事件日志 / 异常截图保留天数 | 90 / 30 |

刷课机（详见 `agent/config.py`）：`AGENT_CENTER`、`AGENT_ID`、`AGENT_TOKEN`、`AGENT_CAPACITY`、`AGENT_PROFILE_TEMPLATE`、`AGENT_OCS_MODE`（`auto` / `inject` / `extension`）、`AGENT_KEEPALIVE`、`AGENT_KEEP_ON_VERIFY`。

## 安全设计

- **账号密码**：AES-GCM 加密落库，接口只下发脱敏手机号，明文永不出库
- **管理会话**：Cookie 值为 `{exp}.{HMAC(SECRET_KEY, "admin-session-v2:"+exp)}`，服务端验签 + 验过期双重校验，配 `HttpOnly` / `Secure` / `SameSite=Lax`
- **登录限流**：同 IP 5 次失败锁 15 分钟，失败写日志但不记密码
- **公开进度页**：链接带 HMAC 签名，只展示脱敏信息，不含密码、刷课机内部字段、后台备注
- **卡密并发**：条件更新 `UPDATE ... WHERE quota >= 1`，同一张单次卡并发兑换只会成功一次

## 自测

```bash
cd center
PYTHONPATH=. venv/bin/python ../tests/selftest_center.py
```

覆盖卡密并发、兑换事务、状态机流转、租约回收、鉴权、日志清理等。

## 部署

systemd 管单进程，Nginx 反代，SQLite 放独立数据目录。

```ini
[Service]
WorkingDirectory=/opt/cx/center
EnvironmentFile=/opt/cx.env
ExecStart=/opt/cx/center/venv/bin/uvicorn main:app --host 127.0.0.1 --port 8080
Restart=always
```

刷课机侧建议：固定机器、关休眠、保持有线或稳定网络。

## 未包含

- 刷课脚本本体（第三方油猴脚本，体积大、更新频繁，请自行获取并按 `agent/vendor/` 或脚本管理器方式安装）
- 数据库备份、监控告警等运维配套

## License

MIT，见 [LICENSE](LICENSE)。
