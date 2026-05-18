import json
import subprocess
from http.server import HTTPServer, BaseHTTPRequestHandler

class AuthHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path == '/auth':
            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length)
            try:
                data = json.loads(post_data.decode('utf-8'))
                username = data.get('username', '')
                password = data.get('password', '')
                
                # Sanitize credentials for PowerShell inclusion
                escaped_user = username.replace("'", "''")
                escaped_pass = password.replace("'", "''")
                
                # PowerShell script block to validate via native .NET AD API
                ps_code = f"""
                Add-Type -AssemblyName System.DirectoryServices.AccountManagement
                try {{
                    $pc = [System.DirectoryServices.AccountManagement.PrincipalContext]::new([System.DirectoryServices.AccountManagement.ContextType]::Domain, 'PEREZ-LLORCA.NET')
                    $valid = $pc.ValidateCredentials('{escaped_user}', '{escaped_pass}')
                    if ($valid) {{
                        $searcher = [adsisearcher]"sAMAccountName={escaped_user}"
                        $result = $searcher.FindOne()
                        $groups = @()
                        if ($result) {{
                            $entry = $result.GetDirectoryEntry()
                            foreach ($group in $entry.memberOf) {{
                                $groups += $group
                            }}
                        }}
                        $out = @{{ valid = $true; groups = $groups }}
                    }} else {{
                        $out = @{{ valid = $false; groups = @() }}
                    }}
                }} catch {{
                    $out = @{{ valid = $false; error = $_.Exception.Message; groups = @() }}
                }}
                $out | ConvertTo-Json
                """
                
                # Execute PowerShell cleanly without profile loading
                proc = subprocess.run(
                    ["powershell", "-NoProfile", "-Command", ps_code],
                    capture_output=True,
                    text=True
                )
                
                result = json.loads(proc.stdout.strip())
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps(result).encode('utf-8'))
                
            except Exception as e:
                self.send_response(500)
                self.end_headers()
                self.wfile.write(json.dumps({"valid": False, "error": str(e)}).encode('utf-8'))
        else:
            self.send_response(404)
            self.end_headers()

def run(server_class=HTTPServer, handler_class=AuthHandler, port=8888):
    server_address = ('', port)
    httpd = server_class(server_address, handler_class)
    print(f"Starting Auth Bridge on port {port}...")
    httpd.serve_forever()

if __name__ == '__main__':
    run()
