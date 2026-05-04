import json
import os
from ldap3 import Server, Connection, ALL, NTLM

from jose import JWTError, jwt
from datetime import datetime, timedelta, timezone
from typing import Optional
from cryptography.fernet import Fernet
import base64

CONFIG_PATH = os.path.join(os.path.dirname(__file__), "config.json")

def get_fernet():
    config = load_config()
    # Use secret_key as a base for Fernet key (must be 32 bytes)
    key = config.get("secret_key", "default-secret-key-32-chars-long!!").encode()
    # Fernet key must be 32 url-safe base64-encoded bytes
    # We'll pad/truncate and encode it
    key_32 = (key + b"0" * 32)[:32]
    fernet_key = base64.urlsafe_b64encode(key_32)
    return Fernet(fernet_key)

def encrypt_value(value: str) -> str:
    if not value: return ""
    f = get_fernet()
    return f.encrypt(value.encode()).decode()

def decrypt_value(value: str) -> str:
    if not value: return ""
    try:
        f = get_fernet()
        return f.decrypt(value.encode()).decode()
    except:
        return value # Return as is if decryption fails (e.g. already plain)

def load_config():
    if os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH, "r") as f:
            return json.load(f)
    return {}

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    config = load_config()
    secret_key = config.get("secret_key", "secret")
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=600) # 10 hours default
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, secret_key, algorithm="HS256")
    return encoded_jwt

def verify_token(token: str):
    config = load_config()
    secret_key = config.get("secret_key", "secret")
    try:
        payload = jwt.decode(token, secret_key, algorithms=["HS256"])
        username: str = payload.get("sub")
        if username is None:
            return None
        return payload
    except JWTError:
        return None

def authenticate_user(username, password):
    config = load_config()
    
    # Simple admin check
    admin_u = config.get("admin_user")
    admin_p = decrypt_value(config.get("admin_pass"))
    
    if username == admin_u and password == admin_p:
        return {"username": username, "role": "admin"}
    
    # AD Authentication
    ad_server = config.get("ad_server")
    ad_domain = config.get("ad_domain")
    
    if not ad_server:
        # If no AD server, only local admin works
        return None

    try:
        server = Server(ad_server, get_info=ALL)
        conn = Connection(server, user=f"{ad_domain}\\{username}", password=password, authentication=NTLM)
        if conn.bind():
            # Check group membership if configured
            required_group = config.get("ad_group")
            if required_group:
                search_base = ",".join([f"DC={part}" for part in ad_domain.split(".")])
                conn.search(search_base=search_base, 
                           search_filter=f"(sAMAccountName={username})", 
                           attributes=['memberOf'])
                
                if not conn.entries:
                    return None
                
                user_groups = conn.entries[0].memberOf.value
                # Check if required_group (as DN or Name) is in user_groups
                is_member = any(required_group.lower() in g.lower() for g in user_groups)
                if not is_member:
                    print(f"User {username} is not member of {required_group}")
                    return None
                    
            return {"username": username, "role": "user"}
    except Exception as e:
        print(f"AD Auth error: {e}")
    
    return None
