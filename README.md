# CX 服务调度中心

一个自托管的**任务调度 + 浏览器自动化执行**系统。用户用一次性卡密提交服务请求，调度中心排队、派单，执行机以真实浏览器登录目标站点并把会话交给页面内的自动化脚本，管理员在控制台人工确认完成。

不依赖 Redis / MQ / Docker，单进程 FastAPI + SQLite，执行机全部出站长轮询（不需要公网 IP、不开入站端口）。

> ⚠️ **使用须知**：本项目是通用「任务调度 + 浏览器自动化」工程实现，仅用于学习与自建自动化平台的参考。使用者需自行确保用途符合目标网站的服务条款与所在地法律；作者不对任何违规使用负责。请勿用于侵犯他人账号、破坏平台规则或违反学术诚信的场景。

---

## 架构

```
用户前台 ──提交卡密+账号──▶ 调度中心 (FastAPI + SQLite)
                                │  排队 / 人工批准 / 租约派单
                                ▼
                          执行机 Agent (Windows + Edge + Playwright)
                                │  出站长轮询，无入站端口
                                ▼
                          目标站点（登录后交给页面内脚本）
```

三端职责：

| 端 | 职责 |
|---|---|
| **调度中心** `center/` | 卡密、账号加密存储、任务状态机、队列与租约、后台 API、管理面板（单文件 SPA） |
| **执行机** `agent/` | 轮询领任务、开浏览器、登录、保活、上报；不判断业务结果 |
| **页面脚本** | 登录成功后由执行机注入或扩展加载，负责页面内的具体操作 |

## 目录

```
center/                 调度中心
├── main.py             全部路由 + 4 个用户侧页面（内嵌 HTML）
├── tasks.py            状态机、队列、租约、占号
├── cards.py            卡密生成（带校验位）/ 扣减 / 禁用
├── accounts.py         账号密码 AES-GCM 存取
├── crypto.py           加解密 + 日志脱敏
├── probe.py            课程探测（先登录读列表，用户选课）
├── db.py               SQLite schema / 迁移 / 日志与截图清理
├── config.py           全部环境变量
└── static/admin.html   管理面板（单文件，零外部依赖）

agent/                  执行机
├── main.py             主循环：轮询、槽位池、心跳、上报
├── browser.py          Playwright 封装（持久化 profile、扩展加载、脚本注入）
├── login.py            登录 + 人机校验检测
├── config.py           环境变量
├── tiku.example.json   题库配置示例（答题用，按需填写）
└── vendor/gm_shim.js   GM API 垫片（把 user script 的 GM_* 映射到 localStorage）

tests/selftest_center.py   端到端自测（TestClient，百条断言）
```

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

访问 `/` 是用户兑换页，`/admin` 是管理面板，`/api/version` 自检。

### 执行机

```bash
cd agent
pip install -r requirements.txt
playwright install msedge

set AGENT_CENTER=https://your-domain.example
set AGENT_ID=pc-01
set AGENT_TOKEN=<在管理面板「服务节点」新增后拿到的 token>
set AGENT_CAPACITY=4
set AGENT_OCS_MODE=auto
python main.py
```

## 关键设计

**状态机**（只改 UI 文案，不改取值）
```
submitted → queued → logging → ready → running → done
                                   ↘ failed / canceled
```
`ready` 是核心：登录成功但不下判断，等管理员点「开始刷课」；执行机每 30 秒保活询问服务端该继续还是收工。

**租约**：派单即写 `lease_until`（默认 7200 秒）。执行机断电后租约到期自动回收，不会永久占坑。

**同账号占用**：同一账号的第二单在派发时跳过，避免多地登录互踢。

**卡密原子扣减**：`UPDATE ... WHERE quota >= 1` 条件更新，同一张卡并发兑换只会成功一次。

**数据加密**：账号密码 AES-GCM 落库，密钥来自 `CX_SECRET_KEY`，接口只下发脱敏手机号。

## 配置项

调度中心（详见 `center/config.py`）：

| 变量 | 说明 | 默认 |
|---|---|---|
| `CX_SECRET_KEY` | 加密与签名密钥，**丢失则历史数据不可解** | 随机（仅调试） |
| `CX_ADMIN_TOKEN` | 脚本调用管理接口的令牌 | 空 |
| `CX_ADMIN_PASSWORD` | 管理面板口令 | 空 |
| `CX_PUBLIC_URL` | 对外地址，用于生成查询链接 | 127.0.0.1 |
| `CX_ONLINE_THRESHOLD` | 执行机在线判定阈值（秒） | 90 |
| `CX_LEASE_SECONDS` | 任务租约（秒） | 7200 |
| `CX_EVENT_DAYS` / `CX_SHOT_DAYS` | 事件日志 / 异常截图保留天数 | 90 / 30 |

执行机（详见 `agent/config.py`）：`AGENT_CENTER`、`AGENT_ID`、`AGENT_TOKEN`、`AGENT_CAPACITY`、`AGENT_PROFILE_TEMPLATE`、`AGENT_OCS_MODE`（`auto`/`inject`/`extension`）、`AGENT_KEEPALIVE`。

## 自测

```bash
cd center
PYTHONPATH=. venv/bin/python ../tests/selftest_center.py
```

覆盖卡密并发、兑换事务、状态机流转、租约回收、鉴权、清理任务等。

## 部署

systemd 管理单进程，Nginx 反代，SQLite 文件放在独立数据目录。

```ini
[Service]
WorkingDirectory=/opt/cx/center
EnvironmentFile=/opt/cx.env
ExecStart=/opt/cx/center/venv/bin/uvicorn main:app --host 127.0.0.1 --port 8080
Restart=always
```

更新面板前建议现网备份，改完硬刷新浏览器。

## 未包含

- 第三方网课脚本本体（体积大、更新频繁，请自行获取并在 `agent/vendor/` 或浏览器扩展中安装）
- 数据库备份、监控、告警等运维配套

## License

MIT，见 [LICENSE](LICENSE)。
