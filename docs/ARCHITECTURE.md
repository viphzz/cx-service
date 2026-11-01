# 架构说明

## 1. 通信模型

执行机（Agent）**不开放任何入站端口**，全部请求由它主动发起。好处是刷课机可以待在 NAT/家宽后面，不需要公网 IP、不需要端口映射，也不需要在防火墙上开口子。

```
Agent ──GET  /api/agent/tasks──────▶ 中心   领任务（带 X-Agent-Token）
Agent ──POST /api/agent/heartbeat──▶ 中心   心跳（60s）
Agent ──POST /api/agent/report─────▶ 中心   状态/保活（30s），响应里带 action
Agent ──POST /api/agent/shot───────▶ 中心   异常截图
```

中心不主动推任何东西，所以「暂停派单」「标记完成」这类操作都是**下一次轮询才生效**，最长延迟一个轮询周期（默认 15–30 秒）。这是有意的取舍：换来的是零入站攻击面。

## 2. 任务状态机

```
submitted ──管理员批准──▶ queued ──Agent 领取──▶ logging ──登录成功──▶ ready
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

约束：

- 状态值写死在数据库里，`submitted/queued/logging/ready/running/done/failed/canceled` 八个值不可变更，只允许改 UI 文案。
- `ready` 是刻意保留的中间态：签入成功 ≠ 任务开始。Agent 只负责把号登进去，什么时候算"开始刷"由人决定。
- Agent 上报时只带 `status`，服务端决定是否接受（状态机不匹配返回 409 + `action: stop`）。

## 3. 派单与租约

派单在一个 `BEGIN IMMEDIATE` 事务里完成三件事：选任务、写 `agent_id` 与 `lease_until`、把状态推到 `logging`。SQLite 的写锁保证两个 Agent 不会领到同一条。

```
UPDATE tasks SET agent_id=?, lease_until=now+7200, status='logging'
WHERE id=? AND status='queued'
```

租约到期未续（Agent 断电、进程被杀）由一个后台循环回收：

- `logging` 阶段超时 → 退回 `queued`，可以重新派
- `ready` / `running` 超时 → 判 `failed`（浏览器已经没了，续不上）

**同账号占用**：派单时跳过 `logging/ready/running` 状态里已经占着同一 `username_hash` 的任务。目标站点普遍是单点登录，两个地方同时登会互踢，宁可排队。

## 4. 卡密

- 格式 `CX-XXXXX-XXXXX-XXXXX`，末位是校验位，防手抄错。
- 兑换是**单事务**：建账号 → 建任务 → 扣配额，任一步失败整体回滚，不留脏数据。
- 扣减用条件更新：`UPDATE cards SET quota=quota-1 WHERE code=? AND quota>=1`，影响行数为 0 就是配额不足。并发下同一张单次卡只会成功一次。

## 5. 数据表

| 表 | 用途 | 关键点 |
|---|---|---|
| `cards` | 卡密 | `quota` 剩余次数、`quota_total` 初始次数（分组用）、`status` |
| `accounts` | 账号 | 密码 AES-GCM 存 `password_enc`，另有 `username_hash` 供占用判断 |
| `tasks` | 任务（同时也是订单） | 状态机 + 租约字段 + `course_id` / `course_name` / `note` |
| `agents` | 执行机 | `token`、`capacity`、`paused`、`last_seen`、健康字段 |
| `events` | 事件日志 | 按天清理（默认 90 天） |
| `probes` | 课程探测 | 短期数据，过期焚毁（存着账号密码，不宜久留） |
| `meta` | 键值 | 暂停派单截止时间、系统设置 |

## 6. 安全设计

- **账号密码**：AES-GCM 加密落库，密钥来自 `CX_SECRET_KEY`。接口只下发脱敏手机号，明文密码永不出库。
- **管理会话**：Cookie 值是 `{exp}.{HMAC(SECRET_KEY, "admin-session-v2:"+exp)}`，服务端验签 + 验过期双重校验，配 `HttpOnly` / `Secure` / `SameSite=Lax`。不是简单设个 `max_age`。
- **登录限流**：同 IP 5 次失败锁 15 分钟，失败写日志（不记密码）。
- **公开页面**：进度页链接带 HMAC 签名，只展示脱敏信息，不含密码、执行机内部字段、后台备注。
- **执行机鉴权**：`X-Agent-Token` 与 `agents.token` 比对；管理接口另用 `X-Admin-Token` 或面板 Cookie。

## 7. 执行机一侧

- **持久化 profile**：每个账号一个 `user_data_dir`，登录态复用，避免反复密码登录触发风控。
- **profile 模板**：首次执行时从模板目录整体复制，扩展和脚本配置随之一并带过来。
- **槽位池**：显式分配 CDP 端口与 profile 锁，防止同一 profile 被两个实例同时打开。
- **登录失败处理**：遇到滑块/验证码不硬试，直接上报需要人工，保留窗口等人处理。
- **脚本加载**：两种方式——浏览器扩展（脚本管理器）或直接 `add_init_script` 注入；`auto` 模式按 profile 里有没有扩展自动选择。

## 8. 后台

`static/admin.html` 是单文件 SPA（hash 路由、零外部依赖），轮询后台 API 刷新。菜单：运营总览 / 任务管理 / 服务节点 / 卡密管理 / 调度中心 / 事件日志 / 手动补单 / 数据分析 / 异常任务 / 公告 / 帮助 / 审计 / 设置。

## 9. 取舍

明确不做的事：

- **不做自动进度判定**。目标站点改一次版面就会连环失效，维护成本远超收益；改为人工确认。
- **不引入 Redis / MQ**。这个量级用不上，SQLite 的写锁足够。
- **不做多机主从**。单进程够用，横向扩展的收益低于复杂度。
