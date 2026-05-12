import os
import json
from fastapi import FastAPI, HTTPException, Depends, Request, Response
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
import socketio
from pydantic import BaseModel
from typing import Optional
from keepass_manager import KeePassManager
from fastapi.security import OAuth2PasswordBearer
from auth import authenticate_user, load_config, create_access_token, verify_token, save_config, encrypt_value
from ldap3 import Server as LDAPServer, Connection as LDAPConnection, ALL as LDAP_ALL, NTLM as LDAP_NTLM
import traceback

app = FastAPI()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="api/login")

# Socket.io setup
sio = socketio.AsyncServer(async_mode='asgi', cors_allowed_origins='*')
socket_app = socketio.ASGIApp(sio, app)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global KeePass Manager instance
kp_manager = None
kp_master_password = None # Cache password to check if new logins use the same one

async def get_current_user(request: Request, token: Optional[str] = Depends(oauth2_scheme)):
    # Try header first (via oauth2_scheme), then query param
    final_token = token
    if not final_token:
        final_token = request.query_params.get("token")
        
    if not final_token:
        raise HTTPException(status_code=401, detail="Missing token")
        
    payload = verify_token(final_token)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    return payload

class LoginRequest(BaseModel):
    username: str
    password: str

class KeePassOpenRequest(BaseModel):
    password: str

class EntryRequest(BaseModel):
    uuid: Optional[str] = None
    title: str
    username: str
    password: str
    url: Optional[str] = ""
    notes: Optional[str] = ""
    group: Optional[str] = "Root"

@app.post("/api/login")
async def login(req: LoginRequest):
    clean_user = req.username.strip()
    clean_pass = req.password.strip()
    user = authenticate_user(clean_user, clean_pass)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    access_token = create_access_token(data={"sub": user["username"], "role": user["role"]})
    return {"user": user, "access_token": access_token, "token_type": "bearer"}

@app.post("/api/keepass/open")
async def open_keepass(req: KeePassOpenRequest, current_user: dict = Depends(get_current_user)):
    global kp_manager, kp_master_password
    config = load_config()
    file_path = config.get("keepass_file_path")
    
    if not os.path.exists(file_path):
        raise HTTPException(status_code=400, detail=f"Archivo no encontrado en {file_path}")
    
    # Si ya está abierto, solo verificamos si la contraseña es la misma
    if kp_manager and kp_manager.kp:
        if req.password == kp_master_password:
            return {"status": "success", "message": "Database already open"}
        else:
            # Intentar abrir con la nueva contraseña por si cambió en disco
            if kp_manager.open(req.password):
                kp_master_password = req.password
                return {"status": "success"}
            else:
                raise HTTPException(status_code=401, detail="Contraseña maestra incorrecta")
    
    # Abrir por primera vez
    kp_manager = KeePassManager(file_path)
    if kp_manager.open(req.password):
        kp_master_password = req.password
        return {"status": "success"}
    else:
        raise HTTPException(status_code=401, detail="Contraseña maestra incorrecta")

@app.get("/api/keepass/entries")
async def get_entries(current_user: dict = Depends(get_current_user)):
    if not kp_manager or not kp_manager.kp:
        raise HTTPException(status_code=400, detail="Base de datos bloqueada")
    return kp_manager.get_entries()

@app.get("/api/keepass/groups")
async def get_groups(current_user: dict = Depends(get_current_user)):
    if not kp_manager or not kp_manager.kp:
        raise HTTPException(status_code=400, detail="Base de datos bloqueada")
    return kp_manager.get_groups()

class GroupRequest(BaseModel):
    name: str

@app.post("/api/keepass/groups")
async def add_group(group: GroupRequest, current_user: dict = Depends(get_current_user)):
    if not kp_manager or not kp_manager.kp:
        raise HTTPException(status_code=400, detail="Base de datos bloqueada")
    
    if kp_manager.add_group(group.name):
        return {"status": "success"}
    raise HTTPException(status_code=500, detail="Failed to add group")

@app.post("/api/keepass/entries")
async def add_entry(entry: EntryRequest, current_user: dict = Depends(get_current_user)):
    if not kp_manager or not kp_manager.kp:
        raise HTTPException(status_code=400, detail="Base de datos bloqueada")
    
    if kp_manager.add_entry(entry.group, entry.title, entry.username, entry.password, entry.url, entry.notes):
        await sio.emit('entry_change', {'action': 'add', 'user': current_user["sub"]})
        return {"status": "success"}
    raise HTTPException(status_code=500, detail="Failed to add entry")

@app.put("/api/keepass/entries/{uuid}")
async def update_entry(uuid: str, entry: EntryRequest, current_user: dict = Depends(get_current_user)):
    if not kp_manager or not kp_manager.kp:
        raise HTTPException(status_code=400, detail="Base de datos bloqueada")
    
    if kp_manager.update_entry(uuid, entry.title, entry.username, entry.password, entry.url, entry.notes):
        await sio.emit('entry_change', {'action': 'update', 'uuid': uuid, 'user': current_user["sub"]})
        return {"status": "success"}
    raise HTTPException(status_code=404, detail="Entry not found")

@app.delete("/api/keepass/entries/{uuid}")
async def delete_entry(uuid: str, current_user: dict = Depends(get_current_user)):
    if not kp_manager or not kp_manager.kp:
        raise HTTPException(status_code=400, detail="Base de datos bloqueada")
    
    if kp_manager.delete_entry(uuid):
        await sio.emit('entry_change', {'action': 'delete', 'uuid': uuid, 'user': current_user["sub"]})
        return {"status": "success"}
    raise HTTPException(status_code=404, detail="Entry not found")

@app.get("/api/keepass/export")
async def export_keepass(current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Permisos insuficientes")
    
    config = load_config()
    file_path = config.get("keepass_file_path")
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="Archivo no encontrado")
        
    return FileResponse(file_path, filename="keepass_backup.kdbx")

@app.get("/api/config")
async def get_config(current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Not authorized")
    return load_config()

@app.post("/api/config")
async def update_config(new_config: dict, current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Not authorized")
    
    config = load_config()
    
    # Whitelist of keys allowed to be updated from the UI
    allowed_keys = [
        "keepass_file_path", "ad_server", "ad_domain", "ad_group", 
        "admin_user", "azure_tenant_id", "azure_client_id", "azure_group_id"
    ]
    
    for key in allowed_keys:
        if key in new_config:
            config[key] = new_config[key]
            
    # Special handling for secrets (encrypt only if provided)
    if "admin_pass" in new_config and new_config["admin_pass"]:
        config["admin_pass"] = encrypt_value(new_config["admin_pass"])
        
    if "azure_client_secret" in new_config and new_config["azure_client_secret"]:
        config["azure_client_secret"] = encrypt_value(new_config["azure_client_secret"])
    
    # Ensure secret_key is NEVER lost
    if "secret_key" not in config:
        config["secret_key"] = "your-secret-key-change-me"
        
    save_config(config)
    return {"status": "success"}

class ADTestRequest(BaseModel):
    ad_server: str
    ad_domain: str
    ad_group: Optional[str] = ""
    test_user: str
    test_pass: str

@app.post("/api/config/test-ad")
async def test_ad_config(req: ADTestRequest, current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Not authorized")
    
    # We use a modified version of authenticate_user logic but with custom config
    clean_server = req.ad_server.strip()
    clean_domain = req.ad_domain.strip()
    clean_user = req.test_user.strip()
    clean_pass = req.test_pass.strip()
    
    # Robust parsing
    import re
    host = clean_server
    port = 389
    host = re.sub(r'^ldaps?://', '', host)
    if ':' in host:
        parts = host.split(':')
        host = parts[0]
        try: port = int(parts[1])
        except: pass

    try:
        server = LDAPServer(host, port=port, connect_timeout=5)
        conn = LDAPConnection(server, user=f"{clean_domain}\\{clean_user}", password=clean_pass, authentication=LDAP_NTLM, receive_timeout=10, auto_referrals=False)
        
        if not conn.bind():
            return {"status": "error", "message": f"Fallo de autenticación: {conn.result.get('description', 'Bind fallido')}"}
        
        # Check group if provided
        if req.ad_group:
            search_base = ",".join([f"DC={part}" for part in req.ad_domain.split(".")])
            search_filter = f"(sAMAccountName={clean_user})"
            print(f"DEBUG AUTH: Searching user with filter='{search_filter}' in base='{search_base}'")
            
            # Use SEARCH_SCOPE_WHOLE_SUBTREE (default but explicit)
            
            from ldap3 import SUBTREE
            conn.search(search_base=search_base, 
                       search_filter=search_filter, 
                       search_scope=SUBTREE,
                       attributes=['memberOf', 'sAMAccountName'])
            
            if not conn.entries:
                # Fallback: try searching in just the root DC if multiple levels
                if "," in search_base:
                    new_base = search_base.split(",", 1)[1] if "," in search_base else search_base
                    conn.search(search_base=new_base, search_filter=search_filter, search_scope=SUBTREE, attributes=['memberOf'])
                
                if not conn.entries:
                    return {"status": "error", "message": "Usuario no encontrado en AD"}
        
        return {"status": "success", "message": "¡Conexión y autenticación exitosas!"}
    except Exception as e:
        traceback.print_exc()
        return {"status": "error", "message": f"Error de conexión (DEBUG): {str(e)}"}

# Serve Frontend
frontend_path = os.path.join(os.path.dirname(__file__), "..", "frontend")
app.mount("/", StaticFiles(directory=frontend_path, html=True), name="frontend")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(socket_app, host="0.0.0.0", port=3007)
