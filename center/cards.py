"""卡密生成与核销。

设计要点：卡网（独角数卡）只负责卖和发码，核销逻辑完全在这里。
所以卡密必须自带校验位——用户手输错一位，本地就能判定"格式不对"，
不用查库，也不会把用户引导到"卡密不存在"这种更容易引起纠纷的提示。

格式: CX-XXXXX-XXXXX-XXXXX
字母表剔除了 0/O/1/I/L 等易混字符，31 个字符。
最后一段末位是校验位。
"""
import secrets
from datetime import datetime, timedelta, timezone

import db
from config import CARD_DAYS

ALPHABET = "23456789ABCDEFGHJKMNPQRSTUVWXYZ"   # 31 个字符
GROUP = 5
GROUPS = 3
PREFIX = "CX"


def _checksum(body: str) -> str:
    total = sum(ALPHABET.index(ch) * (i + 1) for i, ch in enumerate(body))
    return ALPHABET[total % len(ALPHABET)]


def generate(n: int = 1, product: str = "cx-1course", quota: int = 1,
             days: int | None = None, batch: str | None = None) -> list[str]:
    """批量生成并入库，返回本次新增的卡密。"""
    days = CARD_DAYS if days is None else days
    created = []
    ts = db.now()
    exp = (datetime.now(timezone.utc) + timedelta(days=days)).isoformat(timespec="seconds")
    tag = batch or datetime.now().strftime("%Y%m%d")

    for _ in range(n):
        for _try in range(8):
            body = "".join(secrets.choice(ALPHABET) for _ in range(GROUP * GROUPS - 1))
            full = body + _checksum(body)
            code = f"{PREFIX}-" + "-".join(
                full[i:i + GROUP] for i in range(0, len(full), GROUP))
            if not db.q1("SELECT 1 FROM cards WHERE code=?", (code,)):
                break
        else:
            raise RuntimeError("卡密碰撞过多，检查随机源")

        db.ex("""INSERT INTO cards(code, product, quota, quota_total, status, batch,
                                    created_at, expires_at)
                 VALUES(?,?,?,?,'unused',?,?,?)""",
              (code, product, quota, quota, tag, ts, exp))
        created.append(code)
    return created


def normalize(raw: str) -> str:
    return (raw or "").strip().upper().replace(" ", "").replace("—", "-").replace("_", "-")


def verify_format(code: str) -> bool:
    parts = code.split("-")
    if len(parts) != GROUPS + 1 or parts[0] != PREFIX:
        return False
    body = "".join(parts[1:])
    if len(body) != GROUP * GROUPS:
        return False
    if any(ch not in ALPHABET for ch in body):
        return False
    return _checksum(body[:-1]) == body[-1]


def check(raw: str) -> dict:
    """只校验，不激活状态、不扣额度。

    给前端做「先输卡密、验过了才让填账号密码」这一步用。和 activate 的区别
    只有一个：不动 status。用户可能只是想看看卡密对不对，这时候把它标成
    已激活没有意义，反而让后台分不清"真用过"和"只是试了一下"。
    """
    code = normalize(raw)
    if not verify_format(code):
        return {"ok": False, "reason": "卡密格式不正确，请检查是否输错", "code": "BAD_FORMAT"}

    row = db.q1("SELECT * FROM cards WHERE code=?", (code,))
    if not row:
        return {"ok": False, "reason": "卡密不存在", "code": "NOT_FOUND"}
    if row["status"] == "revoked":
        return {"ok": False, "reason": "卡密已被禁用", "code": "REVOKED"}
    if row["status"] == "expired":
        return {"ok": False, "reason": "卡密已过期", "code": "EXPIRED"}
    if row["expires_at"] and row["expires_at"] < db.now():
        return {"ok": False, "reason": "卡密已过期", "code": "EXPIRED"}
    if row["quota"] <= 0:
        return {"ok": False, "reason": "这张卡密的次数已经用完了", "code": "NO_QUOTA"}

    return {"ok": True, "code": code, "quota": row["quota"], "product": row["product"]}


def activate(raw: str) -> dict:
    """核销前检查。返回 {ok, code, quota, product} 或 {ok:False, reason}。

    注意这里是"检查 + 首次激活"，不扣配额。真正扣配额在成功建任务之后，
    避免用户填了信息但任务没建成却把次数吃掉。
    """
    code = normalize(raw)
    if not verify_format(code):
        return {"ok": False, "reason": "卡密格式不正确，请检查是否输错", "code": "BAD_FORMAT"}

    row = db.q1("SELECT * FROM cards WHERE code=?", (code,))
    if not row:
        return {"ok": False, "reason": "卡密不存在", "code": "NOT_FOUND"}
    if row["status"] == "revoked":
        return {"ok": False, "reason": "卡密已被禁用", "code": "REVOKED"}
    if row["status"] == "expired":
        return {"ok": False, "reason": "卡密已过期", "code": "EXPIRED"}
    if row["expires_at"] and row["expires_at"] < db.now():
        db.ex("UPDATE cards SET status='expired' WHERE code=?", (code,))
        return {"ok": False, "reason": "卡密已过期", "code": "EXPIRED"}
    if row["quota"] <= 0:
        return {"ok": False, "reason": "卡密次数已用完", "code": "NO_QUOTA"}

    if row["status"] == "unused":
        db.ex("UPDATE cards SET status='active', activated_at=? WHERE code=?",
              (db.now(), code))
        db.log(None, "info", f"卡密首次激活 {code}")

    return {"ok": True, "code": code, "quota": row["quota"], "product": row["product"]}


def consume(code: str, n: int = 1) -> bool:
    """扣减配额。每建成一个任务扣 1。

    用条件更新保证并发安全：quota 不够时 rowcount 为 0，直接返回 False。
    """
    with db.conn() as c:
        cur = c.execute("UPDATE cards SET quota=quota-? WHERE code=? AND quota>=?",
                        (n, code, n))
        return cur.rowcount > 0


def remaining(code: str) -> int:
    row = db.q1("SELECT quota FROM cards WHERE code=?", (code,))
    return row["quota"] if row else 0


def revoke(raw: str) -> dict:
    """禁用卡密。复用 schema 已有的 revoked 状态，已禁用/核销都不受影响。"""
    code = normalize(raw)
    if not verify_format(code):
        return {"ok": False, "error": "卡密格式不正确", "code": "BAD_FORMAT"}
    if not db.q1("SELECT code FROM cards WHERE code=?", (code,)):
        return {"ok": False, "error": "卡密不存在", "code": "NOT_FOUND"}
    db.ex("UPDATE cards SET status='revoked' WHERE code=?", (code,))
    db.log(None, "warn", f"卡密被禁用 {code}")
    return {"ok": True, "code": code}


def export_import_list(codes: list[str]) -> str:
    """导出成独角数卡后台可批量粘贴的格式：一行一个，不要多余字符。

    独角数卡导入卡密时按行切分，带空格或逗号都会变成卡密的一部分。
    """
    return "\n".join(codes)
