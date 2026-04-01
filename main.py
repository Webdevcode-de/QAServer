import socket
import threading
import paramiko
import importlib
import os
import sys
import select

# Custom Exceptions
class KeepOnlineException(Exception):
    def __init__(self, target=None): self.target = target

class ExitSessionException(Exception): pass

# Host-Key Setup
KEY_FILE = "host.key"
if os.path.exists(KEY_FILE):
    HOST_KEY = paramiko.RSAKey(filename=KEY_FILE)
else:
    HOST_KEY = paramiko.RSAKey.generate(2048)
    HOST_KEY.write_private_key_file(KEY_FILE)

class SSHInterface:
    def __init__(self, channel):
        self.channel = channel
        self.data = {}

    def send(self, text):
        formatted = str(text).replace('\n', '\r\n')
        self.channel.send(formatted.encode('utf-8'))

    def answer(self, prompt):
        self.channel.send(prompt.encode('utf-8'))
        result = ""
        while True:
            raw_char = self.channel.recv(1)
            if not raw_char: raise ExitSessionException()
            
            # ESC (\x1b) or CTRL+C (\x03)
            if raw_char in (b'\x1b', b'\x03'): raise ExitSessionException()

            char = raw_char.decode('utf-8', errors='ignore')
            if char in ('\r', '\n'):
                self.channel.send(b'\r\n')
                if result.strip().lower() == "exit": raise ExitSessionException()
                return result.strip()
            elif char in ('\x7f', '\x08'):
                if len(result) > 0:
                    result = result[:-1]
                    self.channel.send(b'\b \b')
            else:
                result += char
                self.channel.send(char.encode('utf-8'))

    def force_answer(self, prompt, error="Input required!\r\n"):
        while True:
            res = self.answer(prompt)
            if res: return res
            self.send(error)

    def keeponline(self, target=None):
        raise KeepOnlineException(target)

    def bridge_to_remote(self, hostname, username, password):
        """Bridges the current user session to another SSH server."""
        self.send(f"Connecting to {hostname}...\n")
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(hostname, username=username, password=password, timeout=10)
            
            remote_chan = client.invoke_shell()
            remote_chan.setblocking(0)
            self.channel.setblocking(0)

            while True:
                # Watch both channels for data
                read_ready, _, _ = select.select([self.channel, remote_chan], [], [])
                
                if self.channel in read_ready:
                    data = self.channel.recv(1024)
                    if not data: break
                    remote_chan.send(data)

                if remote_chan in read_ready:
                    data = remote_chan.recv(1024)
                    if not data: break
                    self.channel.send(data)

                if remote_chan.exit_status_ready():
                    break
            
            client.close()
            self.channel.setblocking(1) # Reset to normal
        except Exception as e:
            self.send(f"\n[BRIDGE ERROR]: {e}\n")

class SSHRouter(paramiko.ServerInterface):
    def __init__(self):
        self.target = None
        self.event = threading.Event()

    def check_auth_none(self, user):
        if os.path.exists(f"{user}.py"):
            self.target = user
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_auth_password(self, user, pwd): return self.check_auth_none(user)
    def get_allowed_auths(self, user): return 'none,password'
    def check_channel_request(self, k, cid): return paramiko.OPEN_SUCCEEDED
    def check_channel_pty_request(self, *args): return True
    def check_channel_shell_request(self, ch):
        self.event.set()
        return True

def handle_client(client_socket, addr):
    try:
        transport = paramiko.Transport(client_socket)
        transport.add_server_key(HOST_KEY)
        server = SSHRouter()
        transport.start_server(server=server)
        channel = transport.accept(20)
        
        if channel:
            server.event.wait(10)
            connection = SSHInterface(channel)
            state = None 
            print(f"[*] {addr[0]} logged in as '{server.target}'")

            while True:
                try:
                    if server.target in sys.modules:
                        importlib.reload(sys.modules[server.target])
                    app = importlib.import_module(server.target)
                    
                    if state and hasattr(app, state):
                        getattr(app, state)(connection)
                    else:
                        app.run(connection)
                    break
                except KeepOnlineException as k:
                    state = k.target
                    continue 
                except ExitSessionException:
                    break
                except Exception as e:
                    print(f"[!] {addr[0]} error: {e}")
                    break
            
            channel.close()
            print(f"[*] {addr[0]} disconnected")
    except: pass

def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('0.0.0.0', 2222))
    sock.listen(100)
    print("--- SSH APP SERVER RUNNING ON PORT 2222 ---")
    try:
        while True:
            sock.settimeout(1.0)
            try:
                c, a = sock.accept()
                threading.Thread(target=handle_client, args=(c, a), daemon=True).start()
            except socket.timeout: continue
    except KeyboardInterrupt: pass
    finally: sock.close()

if __name__ == "__main__":
    main()