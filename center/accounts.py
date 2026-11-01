"""账号管理。

账号密码加密存储，主密钥在环境变量里。这里只负责存取，
不负责校验——校验由刷课机上的真实登录完成，登录失败了会通过任务上报回来。

username_hash 是手机号的 SHA256。为什么需要它：密码要加密，加密后
同一个手机号每次加密结果都不同（nonce 随机），没法直接 WHERE 查。
但业务上必须能判断"这个手机号是不是已经有任务在跑"——超星单点登录，
同账号两处同时登录会互踢，而且会被判成多终端刷课。所以额外存一份哈希
专门供查重用，哈希不可逆，泄露了也还原不出手机号。

profile 字段记录该账号在刷课机上的浏览器数据目录名。它不是账号的一部分，
而是"这个账号上次在哪个 profile 里登录成功过"，有了它下次直接用同一个
profile，免密进站，省掉重复走密码登录那条风控链。
"""
import hashlib

import crypto
import db


def hash_username(username: str) -> str:
    return hashlib.sha256((username or "").strip().encode("utf-8")).hexdigest()


def find_active_by_username(username: str) -> dict | None:
    """查同手机号是否有未结束的任务。

    返回 account 行（含活跃任务信息）或 None。
    """
    h = hash_username(username)
    return db.q1("""SELECT a.*, t.id AS active_task, t.status AS active_status
                    FROM accounts a
                    JOIN tasks t ON t.account_id = a.id
                    WHERE a.username_hash = ?
                      AND t.status IN ('queued','leased','running','paused','verify_required')
                    ORDER BY t.id DESC LIMIT 1""", (h,))


def create(card_code: str, username: str, password: str,
           school: str = "", profile: str = "") -> int:
    return db.ex("""INSERT INTO accounts(card_code, username_enc, username_hash,
                            password_enc, school, profile, created_at)
                    VALUES(?,?,?,?,?,?,?)""",
                 (card_code, crypto.encrypt(username), hash_username(username),
                  crypto.encrypt(password), school, profile or None, db.now()))


def get(account_id: int) -> dict | None:
    row = db.q1("SELECT * FROM accounts WHERE id=?", (account_id,))
    if not row:
        return None
    return {
        "id": row["id"],
        "card_code": row["card_code"],
        "username": crypto.decrypt(row["username_enc"]),
        "school": row["school"],
        "profile": row["profile"],
        "last_login_at": row["last_login_at"],
    }


def set_profile(account_id: int, profile: str):
    db.ex("UPDATE accounts SET profile=?, last_login_at=? WHERE id=?",
          (profile, db.now(), account_id))


def by_card(card_code: str) -> list[dict]:
    rows = db.q("SELECT * FROM accounts WHERE card_code=? ORDER BY id DESC", (card_code,))
    return [{
        "id": r["id"],
        "username": crypto.mask(crypto.decrypt(r["username_enc"])),
        "school": r["school"],
        "profile": r["profile"],
        "created_at": r["created_at"],
        "last_login_at": r["last_login_at"],
    } for r in rows]


def profile_name(account_id: int, username: str) -> str:
    """给账号分配一个稳定的 profile 目录名。

    用账号 id + 手机号后四位，既能一眼看出是谁，又不会因为手机号
    明文出现在磁盘路径上而泄露。
    """
    tail = (username or "")[-4:]
    return f"acc{account_id}_{tail}" if tail else f"acc{account_id}"
