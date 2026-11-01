"""账号密码的对称加密。

和 chaoxing-runner 里的实现同源（AESGCM，nonce 前置），差别只在密钥来源：
那边读本地 master.key 文件，这边必须读环境变量——调度中心部署在云服务器，
容器重建、换机器、备份恢复都可能让本地文件消失，密钥一丢历史账号全解不开。

密钥是 64 位 hex（32 字节）。生成方法：
    python -c "import secrets; print(secrets.token_hex(32))"
"""
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from config import SECRET_KEY

_NONCE_LEN = 12


def _key() -> bytes:
    raw = bytes.fromhex(SECRET_KEY)
    if len(raw) != 32:
        raise RuntimeError(f"CX_SECRET_KEY 长度异常: {len(raw)} 字节，应为 32")
    return raw


def encrypt(plain: str) -> bytes:
    if plain is None:
        plain = ""
    nonce = os.urandom(_NONCE_LEN)
    return nonce + AESGCM(_key()).encrypt(nonce, plain.encode("utf-8"), None)


def decrypt(blob: bytes) -> str:
    if not blob:
        return ""
    return AESGCM(_key()).decrypt(blob[:_NONCE_LEN], blob[_NONCE_LEN:], None).decode("utf-8")


def mask(s: str) -> str:
    """日志脱敏。手机号显示成 155****1009 这种，前后都留够位数方便人认。"""
    if not s:
        return ""
    if len(s) <= 4:
        return "*" * len(s)
    if len(s) >= 11:
        return s[:3] + "****" + s[-4:]
    return s[:2] + "*" * (len(s) - 4) + s[-2:]


def hash_password(pwd: str) -> str:
    """PBKDF2-SHA256（20 万轮）存密码，格式 salt$hex。不用 bcrypt 是为了零新增依赖。"""
    import hashlib
    import os

    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", (pwd or "").encode("utf-8"), salt, 200_000)
    return salt.hex() + "$" + dk.hex()


def verify_password(pwd: str, stored: str) -> bool:
    import hashlib
    import hmac

    try:
        salt_hex, want = (stored or "").split("$", 1)
        salt = bytes.fromhex(salt_hex)
    except (ValueError, AttributeError):
        return False
    dk = hashlib.pbkdf2_hmac("sha256", (pwd or "").encode("utf-8"), salt, 200_000)
    return hmac.compare_digest(dk.hex(), want)
