from ldap3 import Server, Connection, NTLM, ALL
import traceback
import sys

def test():
    try:
        host = '192.168.1.190'
        port = 389
        user = r'perezllorca.com\erqadmin'
        password = 'M3ns083118019..'
        
        print(f"DEBUG: Connecting to {host}:{port} as {user}")
        server = Server(host, port=port, get_info=ALL)
        conn = Connection(server, user=user, password=password, authentication=NTLM)
        
        print("DEBUG: Attempting bind...")
        res = conn.bind()
        print(f"DEBUG: Bind Result: {res}")
        if not res:
            print(f"DEBUG: Connection Result: {conn.result}")
            
    except Exception as e:
        print("!!! EXCEPTION CAUGHT !!!")
        traceback.print_exc()

if __name__ == "__main__":
    test()
