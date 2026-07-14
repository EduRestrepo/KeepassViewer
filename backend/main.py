import os
import time
import logging
from datetime import datetime, timezone
from typing import Optional

from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel
import socketio

from keepass_manager import KeePassManager
from auth import (
    authenticate_user, load_config, save_config, create_access_token,
    verify_token, encrypt_value, decrypt_value, ensure_security,
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("kpv.main")

# Rotate weak secrets / hash admin password before serving anything.
ensure_security()

app = FastAPI(title="KeePass Web Viewer")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="api/login", auto_error=False)

# --------------------------------------------------------------------------- #
# CORS — restricted. The frontend is served same-origin, so CORS is only
# needed for explicitly allowed external origins.
# --------------------------------------------------------------------------- #
_origins_env = os.environ.get("KPV_ALLOWED_ORIGINS", "")
ALLOWED_ORIGINS = [o.strip() for o in _origins_env.split(",") if o.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=bool(ALLOWED_ORIGINS),
    allow_methods=["*"],
    allow_headers=["*"],
)

sio = socketio.AsyncServer(
    async_mode="asgi",
    cors_allowed_origins=ALLOWED_ORIGINS or [],
)
socket_app = socketio.ASGIApp(sio, app)

# --------------------------------------------------------------------------- #
# Audit log
# --------------------------------------------------------------------------- #
AUDIT_PATH = os.path.join(os.path.dirname(__file__), "audit.log")


def audit(user: str, action: str, detail: str = ""):
    line = f"{datetime.now(timezone.utc).isoformat()}\t{user}\t{action}\t{detail}\n"
    try:
        with open(AUDIT_PATH, "a", encoding="utf-8") as f:
            f.write(line)
    except Exception as e:
        logger.warning("Could not write audit log: %s", e)


# --------------------------------------------------------------------------- #
# Login rate limiting (in-memory)
# --------------------------------------------------------------------------- #
_FAILED = {}  # key -> [timestamps]
MAX_ATTEMPTS = 5
WINDOW_SECONDS = 300


def _rate_key(request: Request, username: str) -> str:
    ip = request.client.host if request.client else "unknown"
    return f"{ip}:{username.lower()}"


def check_rate_limit(key: str):
    now = time.time()
    attempts = [t for t in _FAILED.get(key, []) if now - t < WINDOW_SECONDS]
    _FAILED[key] = attempts
    if len(attempts) >= MAX_ATTEMPTS:
        raise HTTPException(status_code=429, detail="Demasiados intentos. Espera unos minutos.")


def record_failure(key: str):
    _FAILED.setdefault(key, []).append(time.time())


def clear_failures(key: str):
    _FAILED.pop(key, None)


# --------------------------------------------------------------------------- #
# State
# --------------------------------------------------------------------------- #
kp_manager: Optional[KeePassManager] = None
kp_master_password: Optional[str] = None


async def get_current_user(request: Request, token: Optional[str] = Depends(oauth2_scheme)):
    final_token = token or request.query_params.get("token")
    if not final_token:
        raise HTTPException(status_code=401, detail="Missing token")
    payload = verify_token(final_token)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    return payload


async def require_admin(current_user: dict = Depends(get_current_user)):
    if current_user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Permisos insuficientes")
    return current_user


def require_db():
    if not kp_manager or not kp_manager.is_open:
        raise HTTPException(status_code=400, detail="Base de datos bloqueada")
    return kp_manager


# --------------------------------------------------------------------------- #
# Models
# --------------------------------------------------------------------------- #
class LoginRequest(BaseModel):
    username: str
    password: str


class KeePassOpenRequest(BaseModel):
    password: Optional[str] = ""


class EntryRequest(BaseModel):
    uuid: Optional[str] = None
    title: str
    username: str
    password: Optional[str] = ""
    url: Optional[str] = ""
    notes: Optional[str] = ""
    group_uuid: Optional[str] = None


class GroupRequest(BaseModel):
    name: str
    parent_uuid: Optional[str] = None


# --------------------------------------------------------------------------- #
# Auth
# --------------------------------------------------------------------------- #
@app.post("/api/login")
async def login(req: LoginRequest, request: Request):
    clean_user = req.username.strip()
    key = _rate_key(request, clean_user)
    check_rate_limit(key)

    user = authenticate_user(clean_user, req.password.strip())
    if not user:
        record_failure(key)
        audit(clean_user, "login_failed", request.client.host if request.client else "")
        raise HTTPException(status_code=401, detail="Invalid credentials")

    clear_failures(key)
    audit(user["username"], "login_ok", f"role={user['role']}")
    access_token = create_access_token(data={"sub": user["username"], "role": user["role"]})
    return {"user": user, "access_token": access_token, "token_type": "bearer"}


# --------------------------------------------------------------------------- #
# KeePass open / lock
# --------------------------------------------------------------------------- #
@app.post("/api/keepass/open")
async def open_keepass(req: KeePassOpenRequest, current_user: dict = Depends(get_current_user)):
    global kp_manager, kp_master_password
    config = load_config()
    file_path = config.get("keepass_file_path")

    if not file_path or not os.path.exists(file_path):
        raise HTTPException(status_code=400, detail=f"Archivo no encontrado en {file_path}")

    req_password = req.password
    if not req_password:
        is_saved = config.get("save_keepass_password") in [True, "true", "True", 1, "1"]
        if is_saved and config.get("keepass_password"):
            req_password = decrypt_value(config.get("keepass_password"))

    if not req_password:
        raise HTTPException(status_code=401, detail="Contraseña maestra requerida")

    if kp_manager and kp_manager.is_open and req_password == kp_master_password:
        return {"status": "success", "message": "Database already open"}

    kp_manager = KeePassManager(file_path)
    if kp_manager.open(req_password):
        kp_master_password = req_password
        audit(current_user["sub"], "db_unlocked")
        return {"status": "success"}
    raise HTTPException(status_code=401, detail="Contraseña maestra incorrecta")


@app.post("/api/keepass/lock")
async def lock_keepass(current_user: dict = Depends(get_current_user)):
    global kp_manager, kp_master_password
    if kp_manager:
        kp_manager.close()
    kp_master_password = None
    audit(current_user["sub"], "db_locked")
    return {"status": "locked"}


# --------------------------------------------------------------------------- #
# Entries (passwords never sent in bulk)
# --------------------------------------------------------------------------- #
@app.get("/api/keepass/entries")
async def get_entries(current_user: dict = Depends(get_current_user)):
    return require_db().get_entries(include_secrets=False)


@app.get("/api/keepass/entries/{uuid}/password")
async def reveal_password(uuid: str, current_user: dict = Depends(get_current_user)):
    pwd = require_db().get_password(uuid)
    if pwd is None:
        raise HTTPException(status_code=404, detail="Entry not found")
    audit(current_user["sub"], "password_revealed", uuid)
    return {"password": pwd}


@app.get("/api/keepass/groups")
async def get_groups(current_user: dict = Depends(get_current_user)):
    return require_db().get_groups()


@app.post("/api/keepass/groups")
async def add_group(group: GroupRequest, current_user: dict = Depends(get_current_user)):
    if require_db().add_group(group.name, group.parent_uuid):
        audit(current_user["sub"], "group_added", group.name)
        return {"status": "success"}
    raise HTTPException(status_code=500, detail="Failed to add group")


@app.delete("/api/keepass/groups/{uuid}")
async def delete_group(uuid: str, current_user: dict = Depends(get_current_user)):
    if require_db().delete_group(uuid):
        await sio.emit("entry_change", {"action": "group_delete", "user": current_user["sub"]})
        audit(current_user["sub"], "group_deleted", uuid)
        return {"status": "success"}
    raise HTTPException(status_code=400, detail="No se pudo eliminar el grupo")


@app.post("/api/keepass/entries")
async def add_entry(entry: EntryRequest, current_user: dict = Depends(get_current_user)):
    db = require_db()
    if db.add_entry(entry.group_uuid, entry.title, entry.username, entry.password, entry.url, entry.notes):
        await sio.emit("entry_change", {"action": "add", "user": current_user["sub"]})
        audit(current_user["sub"], "entry_added", entry.title)
        return {"status": "success"}
    raise HTTPException(status_code=500, detail="Failed to add entry")


@app.put("/api/keepass/entries/{uuid}")
async def update_entry(uuid: str, entry: EntryRequest, current_user: dict = Depends(get_current_user)):
    db = require_db()
    if db.update_entry(uuid, entry.title, entry.username, entry.password,
                       entry.url, entry.notes, entry.group_uuid):
        await sio.emit("entry_change", {"action": "update", "uuid": uuid, "user": current_user["sub"]})
        audit(current_user["sub"], "entry_updated", uuid)
        return {"status": "success"}
    raise HTTPException(status_code=404, detail="Entry not found")


@app.delete("/api/keepass/entries/{uuid}")
async def delete_entry(uuid: str, current_user: dict = Depends(get_current_user)):
    db = require_db()
    if db.delete_entry(uuid):
        await sio.emit("entry_change", {"action": "delete", "uuid": uuid, "user": current_user["sub"]})
        audit(current_user["sub"], "entry_deleted", uuid)
        return {"status": "success"}
    raise HTTPException(status_code=404, detail="Entry not found")


@app.get("/api/keepass/export")
async def export_keepass(current_user: dict = Depends(require_admin)):
    config = load_config()
    file_path = config.get("keepass_file_path")
    if not file_path or not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="Archivo no encontrado")
    audit(current_user["sub"], "db_exported")
    return FileResponse(file_path, filename="keepass_backup.kdbx")


# --------------------------------------------------------------------------- #
# Config (admin only)
# --------------------------------------------------------------------------- #
@app.get("/api/config")
async def get_config(current_user: dict = Depends(require_admin)):
    config = load_config()
    # Never leak secrets back to the client
    safe = dict(config)
    for k in ("admin_pass", "keepass_password", "azure_client_secret", "secret_key"):
        if safe.get(k):
            safe[k] = ""
            safe[f"{k}_set"] = True
    return safe


@app.post("/api/config")
async def update_config(new_config: dict, current_user: dict = Depends(require_admin)):
    from auth import hash_password
    config = load_config()
    allowed_keys = [
        "keepass_file_path", "ad_server", "ad_domain", "ad_group",
        "admin_user", "azure_tenant_id", "azure_client_id", "azure_group_id",
        "save_keepass_password",
    ]
    for key in allowed_keys:
        if key in new_config:
            config[key] = new_config[key]

    if new_config.get("admin_pass"):
        config["admin_pass"] = hash_password(new_config["admin_pass"])
    if new_config.get("azure_client_secret"):
        config["azure_client_secret"] = encrypt_value(new_config["azure_client_secret"])
    if new_config.get("keepass_password"):
        config["keepass_password"] = encrypt_value(new_config["keepass_password"])

    save_config(config)
    audit(current_user["sub"], "config_updated")
    return {"status": "success"}


class ADTestRequest(BaseModel):
    ad_server: str
    ad_domain: str
    ad_group: Optional[str] = ""
    test_user: str
    test_pass: str


@app.post("/api/config/test-ad")
async def test_ad_config(req: ADTestRequest, current_user: dict = Depends(require_admin)):
    import requests as _requests
    clean_user = req.test_user.strip()
    clean_pass = req.test_pass.strip()
    try:
        bridge_res = _requests.post(
            "http://host.docker.internal:8888/auth",
            json={"username": clean_user, "password": clean_pass},
            timeout=3,
        )
        if bridge_res.status_code == 200:
            result = bridge_res.json()
            if result.get("valid"):
                if req.ad_group:
                    groups = result.get("groups", [])
                    if not any(req.ad_group.lower() in g.lower() for g in groups):
                        return {"status": "error", "message": f"El usuario no pertenece al grupo: {req.ad_group}"}
                return {"status": "success", "message": "¡Conexión y autenticación exitosas (vía Bridge)!"}
            return {"status": "error", "message": f"Fallo de autenticación: {result.get('error', 'Credenciales inválidas')}"}
    except _requests.exceptions.RequestException:
        pass

    from auth import _parse_ldap_host
    from ldap3 import Server as LDAPServer, Connection as LDAPConnection, NTLM as LDAP_NTLM
    host, port = _parse_ldap_host(req.ad_server)
    try:
        server = LDAPServer(host, port=port, connect_timeout=5)
        conn = LDAPConnection(server, user=f"{req.ad_domain.strip()}\\{clean_user}",
                              password=clean_pass, authentication=LDAP_NTLM,
                              receive_timeout=10, auto_referrals=False)
        if not conn.bind():
            return {"status": "error", "message": f"Fallo de autenticación: {conn.result.get('description', 'Bind fallido')}"}
        return {"status": "success", "message": "¡Conexión y autenticación exitosas!"}
    except Exception as e:
        return {"status": "error", "message": f"Error de conexión: {str(e)}"}


# --------------------------------------------------------------------------- #
# Socket.io — require a valid token to connect
# --------------------------------------------------------------------------- #
@sio.event
async def connect(sid, environ, auth):
    token = (auth or {}).get("token")
    if not token or not verify_token(token):
        logger.info("Socket connection rejected (no/invalid token)")
        return False
    return True


# --------------------------------------------------------------------------- #
# Serve frontend
# --------------------------------------------------------------------------- #
frontend_path = os.path.join(os.path.dirname(__file__), "..", "frontend")
app.mount("/", StaticFiles(directory=frontend_path, html=True), name="frontend")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(socket_app, host="0.0.0.0", port=3007)
