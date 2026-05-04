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
from auth import authenticate_user, load_config, create_access_token, verify_token

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
    user = authenticate_user(req.username, req.password)
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
        await sio.emit('entry_change', {'action': 'add', 'user': current_user["sub"], 'data': entry.dict()})
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
    allowed_keys = ["keepass_file_path", "ad_server", "ad_domain", "ad_group", "admin_user"]
    
    for key in allowed_keys:
        if key in new_config:
            config[key] = new_config[key]
            
    # Special handling for admin_pass (encrypt only if provided)
    if "admin_pass" in new_config and new_config["admin_pass"]:
        config["admin_pass"] = encrypt_value(new_config["admin_pass"])
    
    # Ensure secret_key is NEVER lost
    if "secret_key" not in config:
        config["secret_key"] = "your-secret-key-change-me"
        
    save_config(config)
    return {"status": "success"}

# Serve Frontend
frontend_path = os.path.join(os.path.dirname(__file__), "..", "frontend")
app.mount("/", StaticFiles(directory=frontend_path, html=True), name="frontend")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(socket_app, host="0.0.0.0", port=3007)
