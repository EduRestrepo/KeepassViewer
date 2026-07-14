import json
import os
import threading
import uuid
import base64
import secrets
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

from ldap3 import (
    Server as LDAPServer,
    Connection as LDAPConnection,
    ALL as LDAP_ALL,
    NTLM as LDAP_NTLM,
    SIMPLE as LDAP_SIMPLE,
    SUBTREE,
)
from jose import JWTError, jwt
from cryptography.fernet import Fernet
import requests

try:
    from passlib.context import CryptContext
    pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")
except Exception:  # pragma: no cover - argon2 backend should be installed
    pwd_context = None

try:
    import msal
except ImportError:
    msal = None

logger = logging.getLogger("kpv.auth")

CONFIG_PATH = os.path.join(os.path.dirname(__file__), "config.json")
CONFIG_LOCK = threading.Lock()

# Secret keys that must never be used in production. If found, they are rotated.
WEAK_SECRETS = {
    "",
    "secret",
    "change-me",
    "your-secret-key-change-me",
    "default-secret-key-32-chars-long!!",
}

JWT_ALGORITHM = "HS256"
TOKEN_TTL_MINUTES = int(os.environ.get("KPV_TOKEN_TTL_MINUTES", "120"))  # 2h default


# --------------------------------------------------------------------------- #
# Config persistence
# --------------------------------------------------------------------------- #
def load_config() -> dict:
    if os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}


def save_config(config: dict) -> None:
    with CONFIG_LOCK:
        with open(CONFIG_PATH, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=4)


# --------------------------------------------------------------------------- #
# Secret key handling
# --------------------------------------------------------------------------- #
def get_secret_key(config: Optional[dict] = None) -> str:
    """Resolve the active signing/encryption secret.

    Priority: environment variable > config file. Never falls back to a
    well-known default; callers should have run ensure_security() at startup.
    """
    env_key = os.environ.get("KPV_SECRET_KEY")
    if env_key:
        return env_key
    if config is None:
        config = load_config()
    return config.get("secret_key", "")


def _fernet_for(secret: str) -> Fernet:
    key = secret.encode()
    key_32 = (key + b"0" * 32)[:32]
    return Fernet(base64.urlsafe_b64encode(key_32))


def get_fernet(secret: Optional[str] = None) -> Fernet:
    return _fernet_for(secret if secret is not None else get_secret_key())


def encrypt_value(value: str, secret: Optional[str] = None) -> str:
    if not value:
        return ""
    return get_fernet(secret).encrypt(value.encode()).decode()


def decrypt_value(value: str, secret: Optional[str] = None) -> str:
    """Decrypt a stored secret. Returns "" on failure (never the ciphertext)."""
    if not value:
        return ""
    try:
        return get_fernet(secret).decrypt(value.encode()).decode()
    except Exception:
        logger.warning("decrypt_value: could not decrypt a stored secret")
        return ""


# --------------------------------------------------------------------------- #
# Password hashing (local admin)
# --------------------------------------------------------------------------- #
def hash_password(plain: str) -> str:
    if pwd_context is None:
        return plain
    return pwd_context.hash(plain)


def verify_password(plain: str, stored: str) -> bool:
    if not stored:
        return False
    if pwd_context is not None and stored.startswith("$argon2"):
        try:
            return pwd_context.verify(plain, stored)
        except Exception:
            return False
    # Legacy plaintext comparison (pre-migration safety net)
    return secrets.compare_digest(plain, stored)


# --------------------------------------------------------------------------- #
# One-time security migration: run at startup
# --------------------------------------------------------------------------- #
def ensure_security() -> None:
    """Rotate weak secret keys and hash plaintext admin passwords.

    Re-encrypts any stored secrets with the new key so existing data keeps
    working after rotation. Safe to run on every boot (idempotent).
    """
    config = load_config()
    changed = False

    # If a secret is provided via env, that always wins and we don't persist it.
    env_key = os.environ.get("KPV_SECRET_KEY")
    old_key = config.get("secret_key", "")

    if env_key:
        active_key = env_key
        # Re-encrypt config secrets under the env key if they were stored under old_key
        if old_key and old_key != env_key:
            _rotate_encrypted_values(config, old_key, env_key)
            changed = True
    elif old_key in WEAK_SECRETS:
        active_key = secrets.token_urlsafe(48)
        _rotate_encrypted_values(config, old_key, active_key)
        config["secret_key"] = active_key
        changed = True
        logger.warning("ensure_security: rotated weak secret_key to a random value")
    else:
        active_key = old_key

    # Hash plaintext admin password
    admin_pass = config.get("admin_pass", "")
    if admin_pass and not admin_pass.startswith("$argon2"):
        # admin_pass historically stored encrypted OR plaintext. Try to decrypt
        # under the active key first; if that fails treat it as plaintext.
        candidate = decrypt_value(admin_pass, active_key) or admin_pass
        config["admin_pass"] = hash_password(candidate)
        changed = True
        logger.warning("ensure_security: hashed local admin password with argon2")

    if changed:
        save_config(config)


def _rotate_encrypted_values(config: dict, old_key: str, new_key: str) -> None:
    for field in ("keepass_password", "azure_client_secret"):
        val = config.get(field)
        if val:
            plain = decrypt_value(val, old_key)
            if plain:
                config[field] = encrypt_value(plain, new_key)


# --------------------------------------------------------------------------- #
# JWT
# --------------------------------------------------------------------------- #
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    secret_key = get_secret_key()
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (
        expires_delta or timedelta(minutes=TOKEN_TTL_MINUTES)
    )
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, secret_key, algorithm=JWT_ALGORITHM)


def verify_token(token: str):
    secret_key = get_secret_key()
    try:
        payload = jwt.decode(token, secret_key, algorithms=[JWT_ALGORITHM])
        if payload.get("sub") is None:
            return None
        return payload
    except JWTError:
        return None


# --------------------------------------------------------------------------- #
# Authentication
# --------------------------------------------------------------------------- #
def _parse_ldap_host(ad_server: str):
    import re
    host = re.sub(r"^ldaps?://", "", ad_server.strip())
    port = 636 if ad_server.strip().lower().startswith("ldaps") else 389
    if ":" in host:
        parts = host.split(":")
        host = parts[0]
        try:
            port = int(parts[1])
        except ValueError:
            pass
    return host, port


def _authenticate_local(username, password, config):
    admin_u = config.get("admin_user", "")
    admin_hash = config.get("admin_pass", "")
    if admin_u and username.lower() == admin_u.lower() and verify_password(password, admin_hash):
        return {"username": username, "role": "admin"}
    return None


def _authenticate_ad(username, password, config):
    ad_server = config.get("ad_server")
    ad_domain = config.get("ad_domain")
    if not ad_server or not ad_domain:
        return None

    admin_u = config.get("admin_user", "")
    required_group = config.get("ad_group")

    def role_for(user):
        return "admin" if admin_u and user.lower() == admin_u.lower() else "user"

    # 1) Host Auth Bridge (for GPO-restricted domain admins)
    try:
        bridge_res = requests.post(
            "http://host.docker.internal:8888/auth",
            json={"username": username, "password": password},
            timeout=5,
        )
        if bridge_res.status_code == 200:
            result = bridge_res.json()
            if result.get("valid"):
                if required_group:
                    groups = result.get("groups", [])
                    if not any(required_group.lower() in g.lower() for g in groups):
                        logger.info("AD bridge: %s not in required group", username)
                        return None
                return {"username": username, "role": role_for(username)}
            return None  # bridge reachable and rejected credentials
    except requests.exceptions.RequestException:
        logger.debug("AD bridge unavailable, falling back to direct LDAP")

    # 2) Direct LDAP via service account DN lookup
    host, port = _parse_ldap_host(ad_server)
    service_pass = decrypt_value(config.get("admin_pass_ldap", "")) or config.get("ldap_service_pass", "")
    if service_pass:
        service_user = admin_u
    else:
        service_user = username
        service_pass = password
    # Backwards compatibility: original design reused admin creds. We now keep a
    # dedicated optional field but degrade gracefully.
    try:
        server = LDAPServer(host, port=port, get_info=LDAP_ALL)
        bind_user = service_user if "@" in service_user else f"{service_user}@{ad_domain.strip()}"
        conn = LDAPConnection(server, user=bind_user, password=service_pass,
                              authentication=LDAP_SIMPLE, receive_timeout=10, auto_referrals=False)
        if not conn.bind():
            conn = LDAPConnection(server, user=f"{ad_domain.strip()}\\{service_user}",
                                  password=service_pass, authentication=LDAP_NTLM,
                                  receive_timeout=10, auto_referrals=False)
            if not conn.bind():
                logger.info("AD service bind failed: %s", conn.result)
                return None

        search_base = ",".join(f"DC={p}" for p in ad_domain.strip().split("."))
        conn.search(search_base=search_base,
                    search_filter=f"(sAMAccountName={username.strip()})",
                    search_scope=SUBTREE,
                    attributes=["distinguishedName", "memberOf"])
        if not conn.entries:
            return None

        user_entry = conn.entries[0]
        user_dn = user_entry.entry_dn

        # Verify password by binding as the user's DN (bypasses 52f restriction)
        user_conn = LDAPConnection(server, user=user_dn, password=password,
                                   authentication=LDAP_SIMPLE, receive_timeout=10, auto_referrals=False)
        if not user_conn.bind():
            return None

        if required_group:
            user_groups = user_entry.memberOf.value if hasattr(user_entry, "memberOf") else []
            if isinstance(user_groups, str):
                user_groups = [user_groups]
            if not any(required_group.lower() in g.lower() for g in (user_groups or [])):
                return None

        return {"username": username, "role": role_for(username)}
    except Exception as e:
        logger.error("AD authentication error: %s", e)
        return None


def _authenticate_entra(username, password, config):
    tenant_id = config.get("azure_tenant_id")
    client_id = config.get("azure_client_id")
    if not (msal and tenant_id and client_id):
        return None

    client_secret = decrypt_value(config.get("azure_client_secret", ""))
    group_id = config.get("azure_group_id")
    try:
        authority = f"https://login.microsoftonline.com/{tenant_id}"
        if client_secret:
            app = msal.ConfidentialClientApplication(client_id, client_credential=client_secret, authority=authority)
        else:
            app = msal.PublicClientApplication(client_id, authority=authority)

        full_username = username
        if "@" not in username and config.get("ad_domain"):
            full_username = f"{username}@{config.get('ad_domain')}"

        result = app.acquire_token_by_username_password(full_username, password, scopes=["User.Read"])
        if "access_token" not in result:
            logger.info("Entra auth failed: %s", result.get("error_description"))
            return None

        if group_id:
            headers = {"Authorization": f"Bearer {result['access_token']}"}
            graph_res = requests.get("https://graph.microsoft.com/v1.0/me/memberOf", headers=headers, timeout=10)
            if graph_res.ok:
                groups = graph_res.json().get("value", [])
                is_member = any(
                    g.get("id") == group_id
                    or g.get("displayName") == group_id
                    or g.get("displayName") == config.get("ad_group")
                    for g in groups
                )
                if not is_member:
                    return None
        return {"username": username, "role": "user"}
    except Exception as e:
        logger.error("Entra ID auth exception: %s", e)
        return None


def authenticate_user(username, password):
    """Try providers in order: local admin, Active Directory, Entra ID."""
    config = load_config()

    # Local admin always available as a break-glass account.
    local = _authenticate_local(username, password, config)
    if local:
        return local

    ad = _authenticate_ad(username, password, config)
    if ad:
        return ad

    entra = _authenticate_entra(username, password, config)
    if entra:
        return entra

    return None
