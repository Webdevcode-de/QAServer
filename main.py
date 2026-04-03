import socket
import threading
import paramiko
import importlib
import os
import sys
import select
import time
import uuid
import html
import json
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs


# =========================================================
# Custom Exceptions
# =========================================================

class KeepOnlineException(Exception):
    def __init__(self, target=None):
        self.target = target


class ExitSessionException(Exception):
    pass


class NeedWebInputException(Exception):
    def __init__(self, prompt):
        self.prompt = prompt


# =========================================================
# Host-Key Setup
# =========================================================

KEY_FILE = "host.key"

if os.path.exists(KEY_FILE):
    HOST_KEY = paramiko.RSAKey(filename=KEY_FILE)
else:
    HOST_KEY = paramiko.RSAKey.generate(2048)
    HOST_KEY.write_private_key_file(KEY_FILE)


# =========================================================
# Helpers
# =========================================================

def list_nodes():
    """Return node names based on .py files in the current directory."""
    current_script = os.path.splitext(os.path.basename(__file__))[0]
    nodes = []

    for fname in os.listdir("."):
        if not fname.endswith(".py"):
            continue

        mod = fname[:-3]

        if mod.startswith("_"):
            continue

        if mod == current_script:
            continue

        nodes.append(mod)

    return sorted(nodes)


def load_app(module_name):
    """Import or reload a node module."""
    module_file = f"{module_name}.py"
    if not os.path.exists(module_file):
        raise FileNotFoundError(f"No such node: {module_name}")

    if module_name in sys.modules:
        return importlib.reload(sys.modules[module_name])

    return importlib.import_module(module_name)


# =========================================================
# SSH Interface
# =========================================================

class SSHInterface:
    def __init__(self, channel):
        self.channel = channel
        self.data = {}

    def send(self, text):
        formatted = str(text).replace("\n", "\r\n")
        self.channel.send(formatted.encode("utf-8"))

    def answer(self, prompt):
        self.channel.send(prompt.encode("utf-8"))
        result = ""

        while True:
            raw_char = self.channel.recv(1)
            if not raw_char:
                raise ExitSessionException()

            # ESC or CTRL+C
            if raw_char in (b"\x1b", b"\x03"):
                raise ExitSessionException()

            char = raw_char.decode("utf-8", errors="ignore")

            if char in ("\r", "\n"):
                self.channel.send(b"\r\n")
                if result.strip().lower() == "exit":
                    raise ExitSessionException()
                return result.strip()

            elif char in ("\x7f", "\x08"):
                if result:
                    result = result[:-1]
                    self.channel.send(b"\b \b")

            else:
                result += char
                self.channel.send(char.encode("utf-8"))

    def force_answer(self, prompt, error="Input required!\r\n"):
        while True:
            res = self.answer(prompt)
            if res:
                return res
            self.send(error)

    def keeponline(self, target=None):
        raise KeepOnlineException(target)

    def bridge_to_remote(self, hostname, username, password):
        """Bridge the current user session to another SSH server."""
        self.send(f"Connecting to {hostname}...\n")

        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(
                hostname,
                username=username,
                password=password,
                timeout=10,
            )

            remote_chan = client.invoke_shell()
            remote_chan.setblocking(0)
            self.channel.setblocking(0)

            while True:
                read_ready, _, _ = select.select([self.channel, remote_chan], [], [])

                if self.channel in read_ready:
                    data = self.channel.recv(1024)
                    if not data:
                        break
                    remote_chan.send(data)

                if remote_chan in read_ready:
                    data = remote_chan.recv(1024)
                    if not data:
                        break
                    self.channel.send(data)

                if remote_chan.exit_status_ready():
                    break

            client.close()
            self.channel.setblocking(1)

        except Exception as e:
            self.send(f"\n[BRIDGE ERROR]: {e}\n")


# =========================================================
# SSH Router
# =========================================================

class SSHRouter(paramiko.ServerInterface):
    def __init__(self):
        self.target = None
        self.event = threading.Event()

    def check_auth_none(self, user):
        if os.path.exists(f"{user}.py"):
            self.target = user
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_auth_password(self, user, pwd):
        return self.check_auth_none(user)

    def get_allowed_auths(self, user):
        return "none,password"

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_pty_request(self, *args):
        return True

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True


# =========================================================
# Web Session Store
# =========================================================

WEB_SESSIONS = {}
WEB_SESSIONS_LOCK = threading.Lock()
WEB_SESSION_MAX_AGE = 60 * 60 * 6  # 6 hours


def cleanup_web_sessions():
    now = time.time()
    with WEB_SESSIONS_LOCK:
        expired = [
            sid
            for sid, sess in WEB_SESSIONS.items()
            if now - sess.get("updated_at", now) > WEB_SESSION_MAX_AGE
        ]
        for sid in expired:
            WEB_SESSIONS.pop(sid, None)


def create_web_session(node_name):
    session = {
        "id": uuid.uuid4().hex,
        "node": node_name,
        "answers": [],
        "created_at": time.time(),
        "updated_at": time.time(),
    }
    with WEB_SESSIONS_LOCK:
        WEB_SESSIONS[session["id"]] = session
    return session


def get_web_session(session_id):
    if not session_id:
        return None

    with WEB_SESSIONS_LOCK:
        sess = WEB_SESSIONS.get(session_id)
        if sess:
            sess["updated_at"] = time.time()
        return sess


def delete_web_session(session_id):
    with WEB_SESSIONS_LOCK:
        WEB_SESSIONS.pop(session_id, None)


# =========================================================
# Replay-based Auto Web Connection
# =========================================================

class ReplayWebConnection:
    """
    Replays an SSH-style app for the browser by rerunning the node from
    the start and feeding back previously submitted answers.
    """

    def __init__(self, answers):
        self.answers = list(answers)
        self.answer_index = 0
        self.data = {}
        self.events = []
        self.is_web = True
        self.is_replay = True

    def _push(self, role, text):
        text = "" if text is None else str(text)
        if not text:
            return

        if (
            self.events
            and self.events[-1]["role"] == role
            and role in ("output", "error", "meta")
        ):
            self.events[-1]["text"] += text
        else:
            self.events.append({"role": role, "text": text})

    def send(self, text):
        self._push("output", text)

    def answer(self, prompt):
        self._push("prompt", prompt)

        if self.answer_index >= len(self.answers):
            raise NeedWebInputException(prompt)

        value = self.answers[self.answer_index]
        self.answer_index += 1

        shown = value if value != "" else "(empty)"
        self._push("input", shown)

        if str(value).strip().lower() == "exit":
            raise ExitSessionException()

        return value

    def force_answer(self, prompt, error="Input required!\n"):
        while True:
            res = self.answer(prompt)
            if res:
                return res
            self.send(error)

    def keeponline(self, target=None):
        raise KeepOnlineException(target)

    def bridge_to_remote(self, hostname, username, password):
        self._push(
            "meta",
            f"[bridge_to_remote to {hostname} is not supported in auto web mode]\n",
        )


def replay_node_for_web(node_name, answers):
    """
    Replay node_name.run(conn) using stored answers.
    This works well for deterministic prompt/response flows.
    """
    conn = ReplayWebConnection(answers)
    current_handler = "run"

    while True:
        try:
            app = load_app(node_name)

            if not hasattr(app, current_handler):
                raise AttributeError(
                    f"Node '{node_name}' has no handler '{current_handler}'"
                )

            getattr(app, current_handler)(conn)

            return {
                "events": conn.events,
                "pending_prompt": None,
                "complete": True,
                "error": None,
            }

        except KeepOnlineException as k:
            current_handler = k.target or "run"
            continue

        except NeedWebInputException as n:
            return {
                "events": conn.events,
                "pending_prompt": str(n.prompt),
                "complete": False,
                "error": None,
            }

        except ExitSessionException:
            conn._push("meta", "\n[session closed]\n")
            return {
                "events": conn.events,
                "pending_prompt": None,
                "complete": True,
                "error": None,
            }

        except Exception as e:
            conn._push("error", f"{type(e).__name__}: {e}")
            return {
                "events": conn.events,
                "pending_prompt": None,
                "complete": True,
                "error": str(e),
            }


# =========================================================
# Web Request Wrapper For Custom web()/handle_web()
# =========================================================

class WebInterface:
    def __init__(self, handler, node_name):
        self.handler = handler
        self.node_name = node_name
        self.method = handler.command
        self.headers = handler.headers

        parsed = urlparse(handler.path)
        self.path = parsed.path
        self.query = parse_qs(parsed.query)

        parts = parsed.path.strip("/").split("/")
        self.subpath = "/" + "/".join(parts[1:]) if len(parts) > 1 else "/"

        self.body = b""
        if self.method in ("POST", "PUT", "PATCH"):
            length = int(handler.headers.get("Content-Length", 0))
            if length > 0:
                self.body = handler.rfile.read(length)

        self.data = {}

    def text(self):
        return self.body.decode("utf-8", errors="ignore")

    def json(self):
        if not self.body:
            return None
        return json.loads(self.body.decode("utf-8"))

    def send_response(self, status=200, body="", content_type="text/html; charset=utf-8"):
        if isinstance(body, str):
            body = body.encode("utf-8")

        self.handler.send_response(status)
        self.handler.send_header("Content-Type", content_type)
        self.handler.send_header("Content-Length", str(len(body)))
        self.handler.end_headers()
        self.handler.wfile.write(body)

    def send_html(self, html_body, status=200):
        self.send_response(
            status=status,
            body=html_body,
            content_type="text/html; charset=utf-8",
        )

    def send_json(self, payload, status=200):
        self.send_response(
            status=status,
            body=json.dumps(payload, indent=2),
            content_type="application/json; charset=utf-8",
        )

    def send_text(self, text, status=200):
        self.send_response(
            status=status,
            body=text,
            content_type="text/plain; charset=utf-8",
        )

    def redirect(self, location, status=302):
        self.handler.send_response(status)
        self.handler.send_header("Location", location)
        self.handler.end_headers()


# =========================================================
# Pretty HTML Renderer
# =========================================================

def _fmt(text):
    return html.escape(text).replace("\n", "<br>")


def render_index_page():
    nodes = list_nodes()
    cards = []

    for node in nodes:
        cards.append(f"""
        <a class="card" href="/{html.escape(node)}">
            <div class="card-title">/{html.escape(node)}</div>
            <div class="card-sub">Open node</div>
        </a>
        """)

    return f"""<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>Nodes</title>
<style>
:root {{
    --bg: #0b1020;
    --panel: rgba(255,255,255,0.06);
    --panel-2: rgba(255,255,255,0.08);
    --text: #eef2ff;
    --muted: #b2bdd6;
    --accent: #7c9cff;
    --border: rgba(255,255,255,0.10);
    --shadow: 0 20px 60px rgba(0,0,0,0.35);
}}
* {{ box-sizing: border-box; }}
body {{
    margin: 0;
    font-family: Inter, ui-sans-serif, system-ui, sans-serif;
    background:
        radial-gradient(circle at top left, #13203d 0%, transparent 38%),
        radial-gradient(circle at top right, #25124e 0%, transparent 32%),
        var(--bg);
    color: var(--text);
}}
.wrap {{
    max-width: 980px;
    margin: 0 auto;
    padding: 56px 24px;
}}
h1 {{
    margin: 0 0 10px;
    font-size: 40px;
}}
p {{
    margin: 0 0 28px;
    color: var(--muted);
}}
.grid {{
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(220px, 1fr));
    gap: 16px;
}}
.card {{
    display: block;
    text-decoration: none;
    color: inherit;
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 20px;
    padding: 18px;
    box-shadow: var(--shadow);
    transition: transform .15s ease, background .15s ease;
}}
.card:hover {{
    transform: translateY(-2px);
    background: var(--panel-2);
}}
.card-title {{
    font-weight: 700;
    font-size: 18px;
    margin-bottom: 6px;
}}
.card-sub {{
    color: var(--muted);
    font-size: 14px;
}}
code {{
    font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
}}
</style>
</head>
<body>
    <div class="wrap">
        <h1>Available nodes</h1>
        <p>
            SSH-style nodes are also available on the web.
            Custom <code>web()</code> or <code>handle_web()</code> handlers override the automatic fallback.
        </p>
        <div class="grid">
            {''.join(cards) if cards else '<p>No nodes found.</p>'}
        </div>
    </div>
</body>
</html>"""


def render_auto_node_page(node_name, view):
    events_html = []

    for ev in view["events"]:
        role = ev["role"]
        text = ev["text"]

        if role == "output":
            cls = "bubble output"
            label = "output"
            content = _fmt(text)
        elif role == "prompt":
            cls = "bubble prompt"
            label = "prompt"
            content = _fmt(text)
        elif role == "input":
            cls = "bubble input"
            label = "you"
            content = _fmt(text)
        elif role == "error":
            cls = "bubble error"
            label = "error"
            content = _fmt(text)
        else:
            cls = "bubble meta"
            label = "info"
            content = _fmt(text)

        events_html.append(f"""
        <div class="{cls}">
            <div class="label">{label}</div>
            <div class="content">{content}</div>
        </div>
        """)

    prompt_text = view["pending_prompt"] or "Input"
    done = view["complete"]

    composer = f"""
    <form method="post" class="composer">
        <input type="text" name="input" placeholder="{html.escape(prompt_text)}" autofocus autocomplete="off">
        <button type="submit">Send</button>
    </form>
    """ if not done else """
    <div class="done-note">Session complete.</div>
    """

    return f"""<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>/{html.escape(node_name)}</title>
<style>
:root {{
    --bg: #0b1020;
    --panel: rgba(255,255,255,0.06);
    --panel-2: rgba(255,255,255,0.09);
    --text: #eef2ff;
    --muted: #9ba9ca;
    --accent: #7c9cff;
    --green: #22c55e;
    --red: #f87171;
    --amber: #fbbf24;
    --border: rgba(255,255,255,0.10);
    --shadow: 0 20px 60px rgba(0,0,0,0.35);
}}
* {{ box-sizing: border-box; }}
body {{
    margin: 0;
    font-family: Inter, ui-sans-serif, system-ui, sans-serif;
    background:
        radial-gradient(circle at top left, #13203d 0%, transparent 38%),
        radial-gradient(circle at top right, #25124e 0%, transparent 32%),
        var(--bg);
    color: var(--text);
}}
.shell {{
    max-width: 940px;
    margin: 28px auto;
    padding: 0 20px;
}}
.window {{
    overflow: hidden;
    border-radius: 24px;
    background: var(--panel);
    border: 1px solid var(--border);
    box-shadow: var(--shadow);
    backdrop-filter: blur(12px);
}}
.topbar {{
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 16px 18px;
    border-bottom: 1px solid var(--border);
    gap: 12px;
}}
.title {{
    font-weight: 700;
    font-size: 16px;
}}
.subtitle {{
    color: var(--muted);
    font-size: 13px;
    margin-top: 4px;
}}
.actions {{
    display: flex;
    gap: 10px;
    align-items: center;
}}
.actions a,
.actions button {{
    border: 1px solid var(--border);
    background: var(--panel-2);
    color: var(--text);
    border-radius: 12px;
    padding: 10px 14px;
    text-decoration: none;
    cursor: pointer;
    font: inherit;
}}
.feed {{
    padding: 20px;
    min-height: 420px;
    max-height: 68vh;
    overflow: auto;
    display: flex;
    flex-direction: column;
    gap: 14px;
}}
.bubble {{
    max-width: 80%;
    padding: 14px 16px;
    border-radius: 18px;
    border: 1px solid var(--border);
    line-height: 1.45;
    white-space: normal;
}}
.bubble .label {{
    font-size: 12px;
    text-transform: uppercase;
    letter-spacing: .08em;
    color: var(--muted);
    margin-bottom: 8px;
}}
.bubble.output {{
    background: rgba(255,255,255,0.05);
    align-self: flex-start;
}}
.bubble.prompt {{
    background: rgba(124,156,255,0.12);
    border-color: rgba(124,156,255,0.35);
    align-self: flex-start;
}}
.bubble.input {{
    background: rgba(34,197,94,0.12);
    border-color: rgba(34,197,94,0.28);
    align-self: flex-end;
}}
.bubble.error {{
    background: rgba(248,113,113,0.12);
    border-color: rgba(248,113,113,0.30);
    align-self: flex-start;
}}
.bubble.meta {{
    background: rgba(251,191,36,0.10);
    border-color: rgba(251,191,36,0.22);
    align-self: center;
    text-align: center;
}}
.composer-wrap {{
    border-top: 1px solid var(--border);
    padding: 16px;
}}
.composer {{
    display: flex;
    gap: 12px;
}}
.composer input {{
    flex: 1;
    min-width: 0;
    border: 1px solid var(--border);
    background: rgba(0,0,0,0.18);
    color: var(--text);
    border-radius: 14px;
    padding: 14px 16px;
    font: inherit;
}}
.composer button {{
    border: 0;
    background: var(--accent);
    color: white;
    border-radius: 14px;
    padding: 14px 18px;
    font: inherit;
    font-weight: 700;
    cursor: pointer;
}}
.done-note {{
    color: var(--muted);
    padding: 10px 4px 2px;
}}
.footer-note {{
    margin-top: 12px;
    color: var(--muted);
    font-size: 13px;
}}
code {{
    font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
}}
</style>
</head>
<body>
    <div class="shell">
        <div class="window">
            <div class="topbar">
                <div>
                    <div class="title">/{html.escape(node_name)}</div>
                    <div class="subtitle">Automatic web fallback for SSH-style nodes</div>
                </div>
                <div class="actions">
                    <a href="/">Home</a>
                    <form method="post" style="margin:0;">
                        <input type="hidden" name="action" value="restart">
                        <button type="submit">Restart</button>
                    </form>
                </div>
            </div>

            <div class="feed" id="feed">
                {''.join(events_html) if events_html else '<div class="bubble meta"><div class="label">info</div><div class="content">No output yet.</div></div>'}
            </div>

            <div class="composer-wrap">
                {composer}
                <div class="footer-note">
                    This works best for deterministic prompt/response nodes.
                    For shells, live streaming, or side-effect-heavy flows, define a custom <code>web()</code>.
                </div>
            </div>
        </div>
    </div>

    <script>
    const feed = document.getElementById('feed');
    if (feed) feed.scrollTop = feed.scrollHeight;
    </script>
</body>
</html>"""


# =========================================================
# HTTP Handler
# =========================================================

class NodeHTTPHandler(BaseHTTPRequestHandler):
    server_version = "NodeHTTP/3.0"

    def do_GET(self):
        self._dispatch()

    def do_POST(self):
        self._dispatch()

    def do_PUT(self):
        self._dispatch()

    def do_PATCH(self):
        self._dispatch()

    def do_DELETE(self):
        self._dispatch()

    def log_message(self, fmt, *args):
        print(f"[WEB] {self.address_string()} - {fmt % args}")

    def _dispatch(self):
        cleanup_web_sessions()

        parsed = urlparse(self.path)
        parts = [p for p in parsed.path.strip("/").split("/") if p]

        if not parts:
            self._send_html(200, render_index_page())
            return

        node_name = parts[0]

        if not os.path.exists(f"{node_name}.py"):
            self._send_text(404, "Node not found")
            return

        try:
            app = load_app(node_name)
        except Exception as e:
            self._send_text(500, f"Module load error: {e}")
            return

        # Custom handler wins
        if hasattr(app, "handle_web") or hasattr(app, "web"):
            req = WebInterface(self, node_name)

            try:
                if hasattr(app, "handle_web"):
                    app.handle_web(req)
                    return

                result = app.web(req)

                if result is None:
                    return

                if isinstance(result, tuple) and len(result) == 3:
                    status, body, content_type = result
                    if isinstance(body, bytes):
                        self._send_bytes(status, body, content_type)
                    else:
                        self._send(status, str(body), content_type)
                    return

                if isinstance(result, bytes):
                    self._send_bytes(200, result, "application/octet-stream")
                    return

                self._send(200, str(result), "text/html; charset=utf-8")
                return

            except Exception as e:
                self._send_text(500, f"Custom web handler error: {e}")
                return

        # Automatic fallback
        session, new_cookie = self._get_or_create_session(node_name)

        if self.command == "POST":
            form = self._read_form()
            action = form.get("action", [""])[0]

            if action == "restart":
                session["answers"] = []
            else:
                session["answers"].append(form.get("input", [""])[0])

            session["updated_at"] = time.time()
            self._redirect(
                f"/{node_name}",
                cookie=new_cookie or session["id"],
                cookie_name=self._cookie_name(node_name),
            )
            return

        view = replay_node_for_web(node_name, session["answers"])
        page = render_auto_node_page(node_name, view)
        self._send_html(
            200,
            page,
            cookie=new_cookie,
            cookie_name=self._cookie_name(node_name),
        )

    def _cookie_name(self, node_name):
        return f"node_{node_name}_sid"

    def _parse_cookies(self):
        raw = self.headers.get("Cookie")
        jar = cookies.SimpleCookie()
        if raw:
            jar.load(raw)
        return jar

    def _get_or_create_session(self, node_name):
        jar = self._parse_cookies()
        cookie_name = self._cookie_name(node_name)
        session_id = jar[cookie_name].value if cookie_name in jar else None

        session = get_web_session(session_id)
        if session and session.get("node") == node_name:
            return session, None

        session = create_web_session(node_name)
        return session, session["id"]

    def _read_form(self):
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length).decode("utf-8", errors="ignore") if length > 0 else ""
        return parse_qs(raw)

    def _redirect(self, location, cookie=None, cookie_name=None):
        self.send_response(303)
        self.send_header("Location", location)
        if cookie and cookie_name:
            self.send_header(
                "Set-Cookie",
                f"{cookie_name}={cookie}; Path=/; HttpOnly; SameSite=Lax",
            )
        self.end_headers()

    def _send(self, status, body, content_type, cookie=None, cookie_name=None):
        payload = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        if cookie and cookie_name:
            self.send_header(
                "Set-Cookie",
                f"{cookie_name}={cookie}; Path=/; HttpOnly; SameSite=Lax",
            )
        self.end_headers()
        self.wfile.write(payload)

    def _send_bytes(self, status, payload, content_type):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _send_html(self, status, body, cookie=None, cookie_name=None):
        self._send(
            status,
            body,
            "text/html; charset=utf-8",
            cookie=cookie,
            cookie_name=cookie_name,
        )

    def _send_text(self, status, body):
        self._send(status, body, "text/plain; charset=utf-8")


# =========================================================
# SSH Client Handler
# =========================================================

def handle_client(client_socket, addr):
    try:
        transport = paramiko.Transport(client_socket)
        transport.add_server_key(HOST_KEY)

        server = SSHRouter()
        transport.start_server(server=server)

        channel = transport.accept(20)
        if not channel:
            return

        server.event.wait(10)
        connection = SSHInterface(channel)
        state = None

        print(f"[*] {addr[0]} logged in as '{server.target}'")

        while True:
            try:
                app = load_app(server.target)

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

    except Exception:
        pass


# =========================================================
# Servers
# =========================================================

def run_ssh_server(host="0.0.0.0", port=2222):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    sock.listen(100)

    print(f"--- SSH APP SERVER RUNNING ON {host}:{port} ---")

    try:
        while True:
            sock.settimeout(1.0)
            try:
                client, addr = sock.accept()
                threading.Thread(
                    target=handle_client,
                    args=(client, addr),
                    daemon=True,
                ).start()
            except socket.timeout:
                continue
    except KeyboardInterrupt:
        pass
    finally:
        sock.close()


def run_web_server(host="0.0.0.0", port=8080):
    httpd = ThreadingHTTPServer((host, port), NodeHTTPHandler)
    print(f"--- WEB SERVER RUNNING ON http://{host}:{port} ---")
    httpd.serve_forever()


def main():
    threading.Thread(
        target=run_web_server,
        kwargs={"host": "0.0.0.0", "port": 8080},
        daemon=True,
    ).start()

    run_ssh_server(host="0.0.0.0", port=2222)


if __name__ == "__main__":
    main()