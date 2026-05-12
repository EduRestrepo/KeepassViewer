import json
import os
import threading
import uuid
from ldap3 import Server as LDAPServer, Connection as LDAPConnection, ALL as LDAP_ALL, NTLM as LDAP_NTLM

from jose import JWTError, jwt
from datetime import datetime, timedelta, timezone
from typing import Optional
from cryptography.fernet import Fernet
import base64
import requests
try:
    import msal
except ImportError:
    msal = None

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

CONFIG_LOCK = threading.Lock()

def save_config(config):
    with CONFIG_LOCK:
        with open(CONFIG_PATH, "w") as f:
            json.dump(config, f, indent=4)

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

    # Robust parsing for auth
    import re
    host = ad_server.strip()
    port = 389
    host = re.sub(r'^ldaps?://', '', host)
    if ':' in host:
        parts = host.split(':')
        host = parts[0]
        try: port = int(parts[1])
        except: pass

    # Attempt AD Authentication
    try:
        server = LDAPServer(host, port=port, get_info=LDAP_ALL)
        
        # Format: domain\user
        bind_user = f"{ad_domain.strip()}\\{username.strip()}"
        conn = LDAPConnection(server, user=bind_user, password=password, authentication=LDAP_NTLM, receive_timeout=10, auto_referrals=False)
        
        if not conn.bind():
            return None

        # Check group membership if configured
        required_group = config.get("ad_group")
        if required_group:
            search_base = ",".join([f"DC={part}" for part in ad_domain.strip().split(".")])
            search_filter = f"(sAMAccountName={username.strip()})"
            
            from ldap3 import SUBTREE
            conn.search(search_base=search_base, 
                       search_filter=search_filter, 
                       search_scope=SUBTREE,
                       attributes=['memberOf', 'primaryGroupID'])
            
            if not conn.entries:
                conn.search(search_base='', search_filter=search_filter, search_scope=SUBTREE, attributes=['memberOf'])

            if not conn.entries:
                return None
            
            user_entry = conn.entries[0]
            user_groups = user_entry.memberOf.value if hasattr(user_entry, 'memberOf') else []
            
            is_member = any(required_group.lower() in g.lower() for g in user_groups)
            if not is_member:
                return None
                
        return {"username": username, "role": "user"}
    except Exception as e:
        print(f"DEBUG AUTH: Critical AD error: {e}")
        import traceback
        traceback.print_exc()
        return None

    # Entra ID (Azure) Authentication
    tenant_id = config.get("azure_tenant_id")
    client_id = config.get("azure_client_id")
    client_secret = decrypt_value(config.get("azure_client_secret"))
    group_id = config.get("azure_group_id")

    if msal and tenant_id and client_id:
        try:
            authority = f"https://login.microsoftonline.com/{tenant_id}"
            
            if client_secret:
                app = msal.ConfidentialClientApplication(client_id, client_credential=client_secret, authority=authority)
            else:
                app = msal.PublicClientApplication(client_id, authority=authority)

            # Try ROPC flow
            # Username should be the full email if possible, or we try to append domain if missing
            full_username = username
            if "@" not in username and config.get("ad_domain"):
                full_username = f"{username}@{config.get('ad_domain')}"
            
            result = app.acquire_token_by_username_password(full_username, password, scopes=["User.Read"])
            
            if "access_token" in result:
                # User authenticated. Check group membership.
                if group_id:
                    headers = {'Authorization': f'Bearer {result["access_token"]}'}
                    # Note: /me/memberOf only returns groups the user is a DIRECT member of.
                    # For nested groups, /me/getMemberGroups might be needed.
                    graph_res = requests.get('https://graph.microsoftonline.com/v1.0/me/memberOf', headers=headers)
                    if graph_res.ok:
                        groups = graph_res.json().get('value', [])
                        # Check by ID (Object ID)
                        is_member = any(g.get('id') == group_id or g.get('displayName') == group_id for g in groups)
                        
                        if not is_member:
                            # Try check by name if ID didn't match (user might have put name in group_id field)
                            is_member = any(g.get('displayName') == config.get("ad_group") for g in groups)
                            
                        if not is_member:
                            print(f"User {username} is not member of Entra group {group_id}")
                            return None
                            
                return {"username": username, "role": "user"}
            else:
                print(f"Entra ID Auth failed: {result.get('error_description')}")
        except Exception as e:
            print(f"Entra ID Auth exception: {e}")
    
    return None
