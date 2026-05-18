import json
import os
import threading
import uuid
from ldap3 import Server as LDAPServer, Connection as LDAPConnection, ALL as LDAP_ALL, NTLM as LDAP_NTLM, SIMPLE as LDAP_SIMPLE

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
    
    # 1. Local Admin Fallback check (Always check if AD server is not configured)
    admin_u = config.get("admin_user")
    admin_p = decrypt_value(config.get("admin_pass"))
    
    # AD Authentication Configuration
    ad_server = config.get("ad_server")
    ad_domain = config.get("ad_domain")
    
    if not ad_server or not ad_domain:
        # If no AD server, only local admin works
        if username == admin_u and password == admin_p:
            return {"username": username, "role": "admin"}
        return None

    # 2. Attempt AD Authentication via Host Auth Bridge (ideal for GPO-restricted Domain Admins)
    try:
        import requests
        print(f"DEBUG AUTH: Attempting authentication via Host Auth Bridge for {username}")
        # Connect to the lightweight bridge running natively on the host
        bridge_res = requests.post(
            "http://host.docker.internal:8888/auth",
            json={"username": username, "password": password},
            timeout=5
        )
        if bridge_res.status_code == 200:
            result = bridge_res.json()
            if result.get("valid"):
                print(f"DEBUG AUTH: Host Auth Bridge successfully validated credentials for {username}")
                
                # Check group membership if configured
                required_group = config.get("ad_group")
                if required_group:
                    user_groups = result.get("groups", [])
                    is_member = any(required_group.lower() in g.lower() for g in user_groups)
                    if not is_member:
                        print(f"DEBUG AUTH: User {username} is not member of the required group: {required_group}")
                        return None
                        
                role = "admin" if username.lower() == admin_u.lower() else "user"
                return {"username": username, "role": role}
            else:
                print(f"DEBUG AUTH: Host Auth Bridge returned invalid credentials for {username}. Error: {result.get('error')}")
                return None
    except requests.exceptions.RequestException as e:
        print(f"DEBUG AUTH: Host Auth Bridge not available (this is expected if running in standalone mode): {e}")

    # Robust parsing for AD host and port
    import re
    host = ad_server.strip()
    port = 389
    host = re.sub(r'^ldaps?://', '', host)
    if ':' in host:
        parts = host.split(':')
        host = parts[0]
        try: port = int(parts[1])
        except: pass

    # Attempt AD Authentication via Service Account DN Lookup
    try:
        server = LDAPServer(host, port=port, get_info=LDAP_ALL)
        
        # We bind using the configured Admin / Service Account from settings
        # The user has configured 'admin_user' and 'admin_pass' as their AD service account
        service_user = admin_u
        service_pass = admin_p
        
        # Try Simple Bind first for the service account, then NTLM if Simple fails
        if "@" in service_user:
            bind_service_user = service_user
        else:
            bind_service_user = f"{service_user}@{ad_domain.strip()}"
            
        print(f"DEBUG AUTH: Attempting Simple Bind for Service Account: {bind_service_user}")
        conn = LDAPConnection(server, user=bind_service_user, password=service_pass, authentication=LDAP_SIMPLE, receive_timeout=10, auto_referrals=False)
        
        if not conn.bind():
            # If Simple Bind fails, attempt NTLM bind as fallback
            bind_service_user_ntlm = f"{ad_domain.strip()}\\{service_user}"
            print(f"DEBUG AUTH: Service Simple Bind failed. Trying NTLM Bind: {bind_service_user_ntlm}")
            conn = LDAPConnection(server, user=bind_service_user_ntlm, password=service_pass, authentication=LDAP_NTLM, receive_timeout=10, auto_referrals=False)
            
            if not conn.bind():
                print(f"DEBUG AUTH: Service account bind failed completely. Details: {conn.result}")
                # Fallback to local admin check if credentials match
                if username == admin_u and password == admin_p:
                    return {"username": username, "role": "admin"}
                return None
                
        print(f"DEBUG AUTH: Service account bound successfully.")
        
        # Search for the logging-in user to find their exact Distinguished Name (DN)
        search_base = ",".join([f"DC={part}" for part in ad_domain.strip().split(".")])
        search_filter = f"(sAMAccountName={username.strip()})"
        
        from ldap3 import SUBTREE
        conn.search(search_base=search_base, 
                    search_filter=search_filter, 
                    search_scope=SUBTREE,
                    attributes=['distinguishedName', 'memberOf'])
                    
        if not conn.entries:
            print(f"DEBUG AUTH: Logging-in user {username} not found in Active Directory.")
            # Fallback to local admin check if credentials match
            if username == admin_u and password == admin_p:
                return {"username": username, "role": "admin"}
            return None
            
        user_entry = conn.entries[0]
        user_dn = user_entry.entry_dn
        print(f"DEBUG AUTH: Successfully resolved user DN: {user_dn}")
        
        # Perform password verification by attempting a SIMPLE LDAP bind as the logging-in user using their DN!
        # Because we bind using their DN rather than sAMAccountName or UPN, AD bypasses the interactive Workstation Restriction (52f) check!
        print(f"DEBUG AUTH: Verifying user password by binding as DN: {user_dn}")
        user_conn = LDAPConnection(server, user=user_dn, password=password, authentication=LDAP_SIMPLE, receive_timeout=10, auto_referrals=False)
        
        if not user_conn.bind():
            print(f"DEBUG AUTH: User password verification failed (invalid password or AD restriction). Details: {user_conn.result}")
            return None
            
        print(f"DEBUG AUTH: User password verified successfully.")
        
        # Check group membership if configured
        required_group = config.get("ad_group")
        if required_group:
            user_groups = user_entry.memberOf.value if hasattr(user_entry, 'memberOf') else []
            is_member = any(required_group.lower() in g.lower() for g in user_groups)
            if not is_member:
                print(f"DEBUG AUTH: User {username} does not belong to the required AD group: {required_group}")
                return None
                
        # Successful login! If they log in using the configured admin username, they are admin, otherwise user
        role = "admin" if username.lower() == admin_u.lower() else "user"
        return {"username": username, "role": role}
        
    except Exception as e:
        print(f"DEBUG AUTH: Critical Active Directory Exception: {e}")
        import traceback
        traceback.print_exc()
        # Fallback to local admin check if credentials match
        if username == admin_u and password == admin_p:
            return {"username": username, "role": "admin"}
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
