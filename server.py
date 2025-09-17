#!/usr/bin/env python3
import os
import json
import sqlite3
import time
import secrets
import hashlib
import hmac
import base64
import urllib.parse
import pathlib
import mimetypes
import html as _html
import re
import traceback
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.request import urlopen, Request
from urllib.error import HTTPError, URLError

# Load environment variables from .env file
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass  # dotenv not available, continue without it

# --------------------------------------------------------------------------- #
#  CONFIG
# --------------------------------------------------------------------------- #
CLIENT_ID     = os.getenv("CLIENT_ID",     "your discord client ID")
CLIENT_SECRET = os.getenv("CLIENT_SECRET", "your discord secret")
REDIRECT_URI  = os.getenv("REDIRECT_URI",  "http://localhost:8080/callback")
COOKIE_KEY    = os.getenv("COOKIE_KEY",    secrets.token_urlsafe(32))
DB_FILE       = os.getenv("DB_FILE",       "users.db")
PORT          = int(os.getenv("PORT",      8080))
UPLOAD_DIR    = pathlib.Path(".")

OWNER_ID      = 209977610636230657 # your discord id
ALLOW_LIST    = {OWNER_ID, 808278434446704660} #here you can add other users in discord ids.

# root directory served
ROOT = pathlib.Path(".").resolve()

# --------------------------------------------------------------------------- #
#  SECURITY: hide server & db (define early because safe_resolve uses them)
# --------------------------------------------------------------------------- #
SERVER_PATH = pathlib.Path(__file__).resolve()
DB_PATH     = pathlib.Path(DB_FILE).resolve()

def is_hidden(path: pathlib.Path) -> bool:
    try:
        return path.resolve() in (SERVER_PATH, DB_PATH) or path.name.startswith('.')
    except Exception:
        return False

# --------------------------------------------------------------------------- #
#  UTILS
# --------------------------------------------------------------------------- #
def b64_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")

def b64_decode(s: str) -> bytes:
    if isinstance(s, bytes):
        s = s.decode()
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)

def sign_cookie(payload: str) -> str:
    header = b64_encode(b'{"alg":"HS256","typ":"JWT"}')
    payload_b64 = b64_encode(payload.encode())
    msg = f"{header}.{payload_b64}".encode()
    sig = b64_encode(hmac.new(COOKIE_KEY.encode(), msg, hashlib.sha256).digest())
    return f"{header}.{payload_b64}.{sig}"

def unsign_cookie(cookie: str) -> dict | None:
    try:
        header_b64, payload_b64, sig_b64 = cookie.split(".")
        payload_json = b64_decode(payload_b64).decode()
        expected_sig = sign_cookie(payload_json).split(".", 2)[2]
        if not hmac.compare_digest(sig_b64, expected_sig):
            return None
        payload = json.loads(payload_json)
        if payload.get("exp", 0) < int(time.time()):
            return None
        return payload
    except Exception:
        return None

def safe_resolve(path_str: str) -> pathlib.Path | None:
    if not path_str:
        path_str = "."
    if path_str.startswith("/"):
        path_str = path_str[1:]
    candidate = (ROOT / path_str).resolve()
    try:
        candidate.relative_to(ROOT)
    except Exception:
        return None
    if candidate in (SERVER_PATH, DB_PATH):
        return None
    return candidate

# --------------------------------------------------------------------------- #
#  FILE TYPE DETECTION & ICONS
# --------------------------------------------------------------------------- #
def get_file_icon(path: pathlib.Path) -> str:
    """Get appropriate icon for file based on extension"""
    if path.is_dir():
        return "📁"
    
    ext = path.suffix.lower()
    icon_map = {
        '.py': '🐍', '.js': '📄', '.ts': '📘', '.html': '🌐', '.css': '🎨',
        '.json': '📋', '.xml': '📄', '.yml': '⚙️', '.yaml': '⚙️',
        '.md': '📝', '.txt': '📄', '.log': '📜', '.ini': '⚙️', '.cfg': '⚙️',
        '.sh': '⚡', '.bat': '⚡', '.ps1': '⚡',
        '.jpg': '🖼️', '.jpeg': '🖼️', '.png': '🖼️', '.gif': '🖼️', '.svg': '🖼️',
        '.mp3': '🎵', '.wav': '🎵', '.mp4': '🎬', '.avi': '🎬',
        '.zip': '📦', '.tar': '📦', '.gz': '📦', '.rar': '📦',
        '.exe': '⚙️', '.dll': '⚙️', '.so': '⚙️',
        '.sql': '🗃️', '.db': '🗃️', '.sqlite': '🗃️'
    }
    return icon_map.get(ext, '📄')

# --------------------------------------------------------------------------- #
#  DB
# --------------------------------------------------------------------------- #
def init_db():
    with sqlite3.connect(DB_FILE) as con:
        con.execute("""
            CREATE TABLE IF NOT EXISTS users(
                discord_id INTEGER PRIMARY KEY,
                username   TEXT NOT NULL,
                perms      TEXT NOT NULL
            )
        """)
        owner = con.execute("SELECT 1 FROM users WHERE discord_id=?", (OWNER_ID,)).fetchone()
        if not owner:
            con.execute("REPLACE INTO users VALUES(?,?,?)",
                        (OWNER_ID, "owner", json.dumps(["browse","preview","download","upload","admin"])))
        for uid in ALLOW_LIST:
            if uid == OWNER_ID:
                continue
            ex = con.execute("SELECT 1 FROM users WHERE discord_id=?", (uid,)).fetchone()
            if not ex:
                con.execute("REPLACE INTO users VALUES(?,?,?)",
                            (uid, str(uid), json.dumps(["browse","preview","download","upload"])))
        con.commit()

def get_user(discord_id: int):
    with sqlite3.connect(DB_FILE) as con:
        row = con.execute("SELECT username,perms FROM users WHERE discord_id=?", (discord_id,)).fetchone()
        if row:
            return {"username": row[0], "perms": json.loads(row[1])}
    return None

def save_user(discord_id: int, username: str, perms: list[str]):
    with sqlite3.connect(DB_FILE) as con:
        con.execute("REPLACE INTO users VALUES(?,?,?)", (discord_id, username, json.dumps(perms)))
        con.commit()

# --------------------------------------------------------------------------- #
#  DISCORD OAUTH
# --------------------------------------------------------------------------- #
def exchange_code(code: str) -> tuple[int, str] | None:
    data = {
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": REDIRECT_URI
    }
    body_raw = urllib.parse.urlencode(data).encode()
    print("[exchange] request body:", urllib.parse.urlencode(data))
    req = Request(
        "https://discord.com/api/oauth2/token",
        data=body_raw,
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
            "User-Agent": "Python-Discord-OAuth/1.0"
        }
    )
    try:
        with urlopen(req) as resp:
            body = resp.read().decode()
            print("[exchange] discord status:", resp.status, resp.reason)
            print("[exchange] discord raw   :", body)
            token_data = json.loads(body)
    except HTTPError as he:
        try:
            err_body = he.read().decode()
        except Exception:
            err_body = "<no body>"
        print("[exchange] token request failed:", he.code, he.reason, err_body)
        return None
    except URLError as ue:
        print("[exchange] token request URLError:", ue)
        return None
    except Exception as e:
        print("[exchange] token request exception:", e)
        return None

    access_token = token_data.get("access_token")
    token_type = token_data.get("token_type", "Bearer")
    if not access_token:
        print("[exchange] no access_token in response")
        return None

    user_req = Request(
        "https://discord.com/api/users/@me",
        headers={
            "Authorization": f"{token_type} {access_token}",
            "Accept": "application/json",
            "User-Agent": "Python-Discord-OAuth/1.0"
        }
    )
    try:
        with urlopen(user_req) as resp:
            user = json.loads(resp.read().decode())
        print("[exchange] success ->", user.get("id"), user.get("username"))
        return int(user["id"]), user["username"]
    except HTTPError as he:
        try:
            err_body = he.read().decode()
        except Exception:
            err_body = "<no body>"
        print("[exchange] user fetch failed:", he.code, he.reason, err_body)
        return None
    except URLError as ue:
        print("[exchange] user fetch URLError:", ue)
        return None
    except Exception as e:
        print("[exchange] user fetch exception:", e)
        return None

# --------------------------------------------------------------------------- #
#  UPLOAD PARSER
# --------------------------------------------------------------------------- #
def handle_upload(post_data: bytes, boundary: bytes) -> tuple[str, bytes]:
    boundary = b"--" + boundary
    parts = post_data.split(boundary)
    for part in parts:
        if b'Content-Disposition: form-data; name="file"' not in part:
            continue
        m = re.search(rb'filename="([^"]*)"', part)
        if not m:
            raise ValueError("filename not found")
        filename = m.group(1).decode(errors="ignore")
        try:
            _, payload = part.split(b"\r\n\r\n", 1)
        except ValueError:
            raise ValueError("malformed part")
        payload = payload.rsplit(b"\r\n", 1)[0]
        return filename, payload
    raise ValueError("file field not found")

# --------------------------------------------------------------------------- #
#  small helper to detect text files
# --------------------------------------------------------------------------- #
def is_text(path: pathlib.Path, nbytes: int = 2048) -> bool:
    try:
        with path.open("rb") as f:
            data = f.read(nbytes)
        if not data:
            return True
        if b"\x00" in data:
            return False
        try:
            data.decode("utf-8")
            return True
        except Exception:
            return False
    except Exception:
        return False

# --------------------------------------------------------------------------- #
#  fallback single-file editor page
# --------------------------------------------------------------------------- #
def editor_page(path_on_disk: pathlib.Path, url_path: str):
    content = path_on_disk.read_text(encoding="utf-8", errors="replace")
    lang = {"js":"javascript","ts":"typescript","yml":"yaml"}.get(path_on_disk.suffix[1:], path_on_disk.suffix[1:] or "plaintext")
    title = _html.escape(url_path)
    return f"""<!doctype html>
<html>
<head>
  <meta charset="utf-8"/>
  <title>{title}</title>
  <link rel="stylesheet" data-name="vs/editor/editor.main"
        href="https://cdn.jsdelivr.net/npm/monaco-editor@0.44.0/min/vs/editor/editor.main.css">
  <style>html,body{{margin:0;height:100%;background:#1e1e1e;color:#d4d4d4}}</style>
</head>
<body>
<div id="editor" style="width:100%;height:100%"></div>
<script src="https://cdn.jsdelivr.net/npm/monaco-editor@0.44.0/min/vs/loader.js"></script>
<script>
require.config({{paths:{{vs:'https://cdn.jsdelivr.net/npm/monaco-editor@0.44.0/min/vs/loader.js'}}}});
require(['vs/editor/editor.main'], function (){{
  monaco.editor.create(document.getElementById('editor'),{{
    value: {repr(content)},
    language: '{lang}',
    theme: 'vs-dark',
    readOnly: true,
    minimap: {{enabled: true}},
    glyphMargin: true,
    lineNumbers: 'on',
    wordWrap: 'on'
  }});
}});
</script>
</body>
</html>"""

# --------------------------------------------------------------------------- #
#  SPA: VS Code-like UI with welcome center showing your requested title/sub
# --------------------------------------------------------------------------- #
def index_page(here: pathlib.Path, user: dict):
    admin = ''
    if "admin" in user["perms"]:
        admin = ' | <a href="/admin">admin</a>'
    upload_html = ''
    if "upload" in user["perms"]:
        upload_html = """
        <div id="upload-area" style="padding:8px;">
          <form method="post" action="/upload" enctype="multipart/form-data" style="display:flex;gap:8px;align-items:center">
            <input type="file" name="file" required>
            <button>Upload</button>
          </form>
        </div>"""

    # Improved VS Code design with better explorer
    template = """<!doctype html>
<html>
<head>
  <meta charset="utf-8"/>
  <title>Justin's Simple Code Server</title>
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <link rel="stylesheet" href="https://fonts.googleapis.com/css?family=Segoe+UI:400,600">
  <style>
    /* VS Code color palette */
    :root{
      --bg:#1e1e1e;--side:#252526;--panel:#2d2d2d;--fg:#cccccc;--muted:#969696;
      --accent:#007acc;--activity:#333333;--hover:#2a2d2e;--border:#3c3c3c;
      --selection:#094771;--tree-indent:#ffffff10;
    }
    
    * { box-sizing: border-box; }
    html,body{height:100%;margin:0;font-family:'Segoe UI',sans-serif;background:var(--bg);color:var(--fg);font-size:13px;}
    
    #app{display:flex;height:100vh;overflow:hidden}
    
    /* Activity bar */
    #activity{width:48px;background:var(--activity);display:flex;flex-direction:column;align-items:center;padding-top:8px;gap:6px;border-right:1px solid var(--border);}
    .act-btn{width:36px;height:36px;border-radius:6px;display:flex;align-items:center;justify-content:center;color:var(--muted);cursor:pointer;font-size:18px;}
    .act-btn:hover{background:var(--hover);color:#fff}
    .act-btn.active{background:var(--selection);color:#fff}
    
    /* Sidebar */
    #sidebar{width:300px;background:var(--side);border-right:1px solid var(--border);display:flex;flex-direction:column;overflow:hidden}
    .sidebar-header{padding:8px 12px;background:#2d2d2d;border-bottom:1px solid var(--border);font-weight:600;font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:0.5px;display:flex;justify-content:space-between;align-items:center;}
    
    /* Explorer */
    #explorer{flex:1;overflow:auto;font-size:13px;line-height:1.4;}
    #explorer::-webkit-scrollbar{width:10px}
    #explorer::-webkit-scrollbar-track{background:transparent}
    #explorer::-webkit-scrollbar-thumb{background:rgba(255,255,255,0.1);border-radius:5px}
    #explorer::-webkit-scrollbar-thumb:hover{background:rgba(255,255,255,0.2)}
    
    /* Tree structure */
    .tree{list-style:none;margin:0;padding:0}
    .tree-item{position:relative;user-select:none}
    .tree-row{display:flex;align-items:center;padding:2px 8px;cursor:pointer;min-height:22px;position:relative}
    .tree-row:hover{background:var(--hover)}
    .tree-row.selected{background:var(--selection);color:#fff}
    
    .tree-indent{display:inline-block;width:12px;flex-shrink:0}
    .tree-arrow{width:16px;height:16px;display:flex;align-items:center;justify-content:center;color:var(--muted);font-size:10px;flex-shrink:0;transition:transform 0.1s ease}
    .tree-arrow.expanded{transform:rotate(90deg)}
    .tree-arrow:hover{color:var(--fg)}
    
    .tree-icon{width:16px;height:16px;display:flex;align-items:center;justify-content:center;margin-right:4px;font-size:14px;flex-shrink:0}
    .tree-name{flex:1;overflow:hidden;white-space:nowrap;text-overflow:ellipsis;font-size:13px}
    .tree-size{color:var(--muted);font-size:11px;margin-left:8px}
    
    /* Nested items */
    .tree-children{display:none;padding-left:12px}
    .tree-children.expanded{display:block}
    
    /* Main content area */
    #main{flex:1;display:flex;flex-direction:column;overflow:hidden}
    
    /* Top bar */
    #topbar{height:36px;background:var(--panel);display:flex;align-items:center;border-bottom:1px solid var(--border)}
    #tabs{display:flex;gap:0;align-items:center;overflow:auto;flex:1;height:100%}
    .tab{height:36px;padding:0 12px;background:transparent;border-right:1px solid var(--border);color:var(--fg);display:flex;gap:6px;align-items:center;cursor:pointer;font-size:13px;position:relative}
    .tab:hover{background:var(--hover)}
    .tab.active{background:var(--bg);color:#fff}
    .tab.active::after{content:'';position:absolute;bottom:0;left:0;right:0;height:1px;background:var(--accent)}
    .tab .close{width:16px;height:16px;border-radius:3px;display:flex;align-items:center;justify-content:center;color:var(--muted);font-size:12px}
    .tab .close:hover{background:rgba(255,255,255,0.1);color:#fff}
    .tab .dirty::before{content:'●';color:#fff;margin-right:4px}
    
    #actions{padding:0 12px;color:var(--muted);font-size:13px;display:flex;gap:12px;align-items:center}
    #actions button{background:transparent;border:1px solid var(--border);padding:4px 8px;border-radius:3px;color:var(--fg);cursor:pointer;font-size:12px}
    #actions button:hover{border-color:var(--accent);background:var(--hover)}
    #actions a{color:var(--muted);text-decoration:none}
    #actions a:hover{color:var(--fg)}
    
    /* Breadcrumbs */
    #breadcrumbs{padding:6px 12px;font-size:12px;color:var(--muted);border-bottom:1px solid var(--border);background:var(--panel)}
    
    /* Editor container */
    #editor-container{flex:1;position:relative;background:var(--bg)}
    
    /* Welcome screen */
    #welcome{display:flex;flex-direction:column;align-items:flex-start;padding:40px;color:var(--muted);max-width:600px}
    #welcome h1{font-size:24px;margin:0 0 6px 0;color:var(--fg);font-weight:600}
    #welcome .version{font-size:13px;margin-bottom:16px;color:var(--muted)}
    #welcome .description{margin-bottom:24px;line-height:1.5}
    .welcome-actions{display:flex;gap:12px}
    .welcome-actions button{background:var(--panel);border:1px solid var(--border);padding:8px 16px;border-radius:4px;color:var(--fg);cursor:pointer;font-size:13px}
    .welcome-actions button:hover{border-color:var(--accent);background:var(--hover)}
    
    /* Status bar */
    #statusbar{height:22px;background:#1b1b1b;color:var(--muted);display:flex;align-items:center;padding:0 12px;font-size:12px;border-top:1px solid var(--border)}
    
    @media (max-width:768px){#sidebar{width:250px}}
    @media (max-width:640px){#sidebar{width:200px}}
  </style>
</head>
<body>
<div id="app">
  <div id="activity">
    <div class="act-btn active" title="Explorer">📁</div>
    <div class="act-btn" title="Search">🔍</div>
    <div class="act-btn" title="Source Control">🌿</div>
    <div class="act-btn" title="Run">▶</div>
    <div class="act-btn" title="Extensions">▣</div>
  </div>

  <div id="sidebar">
    <div class="sidebar-header">Explorer <span>__USERNAME__</span></div>
    <div id="explorer"></div>
    __UPLOAD_HTML__
  </div>

  <div id="main">
    <div id="topbar">
      <div id="tabs"></div>
      <div id="actions">
        <button id="save-btn" title="Save (Ctrl+S)">Save</button>
        <a href="/logout">Logout</a>__ADMIN__
      </div>
    </div>

    <div id="breadcrumbs"></div>

    <div id="editor-container">
      <div id="welcome">
        <h1>__WELCOME_TITLE__</h1>
        <div class="version">__WELCOME_SUB__</div>
        <div class="description">
          Welcome to your code server. Use the explorer on the left to browse and open files. Files will open in tabs using the Monaco editor with full syntax highlighting and IntelliSense support.
        </div>
        <div class="welcome-actions">
          <button id="new-file">New File</button>
          <button id="open-folder">Open Folder</button>
          <button id="refresh">Refresh Explorer</button>
        </div>
      </div>
    </div>

    <div id="statusbar">Ready</div>
  </div>
</div>

<!-- Monaco Editor -->
<script src="https://cdn.jsdelivr.net/npm/monaco-editor@0.44.0/min/vs/loader.js"></script>
<script>
require.config({ paths: { vs: 'https://cdn.jsdelivr.net/npm/monaco-editor@0.44.0/min/vs' }});

let monacoGlobal;
let tabs = [];
let activeTab = null;
let expandedFolders = new Set();

const elements = {
  explorer: document.getElementById('explorer'),
  tabs: document.getElementById('tabs'),
  editorContainer: document.getElementById('editor-container'),
  saveBtn: document.getElementById('save-btn'),
  breadcrumbs: document.getElementById('breadcrumbs'),
  status: document.getElementById('statusbar'),
  welcome: document.getElementById('welcome'),
  newFileBtn: document.getElementById('new-file'),
  refreshBtn: document.getElementById('refresh')
};

// API functions
const api = {
  list: async (path) => {
    const res = await fetch('/api/list?path=' + encodeURIComponent(path || '/'));
    if (!res.ok) throw new Error('List failed: ' + res.status);
    return res.json();
  },
  read: async (path) => {
    const res = await fetch('/api/read?path=' + encodeURIComponent(path));
    if (!res.ok) throw new Error('Read failed: ' + res.status);
    return res.text();
  },
  save: async (path, content) => {
    const res = await fetch('/api/save', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({path, content})
    });
    return res.json();
  }
};

// Utility functions
function setStatus(text) {
  elements.status.textContent = text;
}

function getFileIcon(name, isDir) {
  if (isDir) return '📁';
  
  const ext = name.split('.').pop()?.toLowerCase();
  const icons = {
    'py': '🐍', 'js': '📄', 'ts': '📘', 'html': '🌐', 'css': '🎨',
    'json': '📋', 'xml': '📄', 'yml': '⚙️', 'yaml': '⚙️',
    'md': '📝', 'txt': '📄', 'log': '📜', 'ini': '⚙️', 'cfg': '⚙️',
    'sh': '⚡', 'bat': '⚡', 'ps1': '⚡',
    'jpg': '🖼️', 'jpeg': '🖼️', 'png': '🖼️', 'gif': '🖼️', 'svg': '🖼️',
    'mp3': '🎵', 'wav': '🎵', 'mp4': '🎬', 'avi': '🎬',
    'zip': '📦', 'tar': '📦', 'gz': '📦', 'rar': '📦',
    'exe': '⚙️', 'dll': '⚙️', 'so': '⚙️',
    'sql': '🗃️', 'db': '🗃️', 'sqlite': '🗃️'
  };
  return icons[ext] || '📄';
}

function formatFileSize(bytes) {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

// Tree building functions
function createTreeItem(entry, basePath, level = 0) {
  const fullPath = (basePath + '/' + entry.name).replace(/\\/+/g, '/');
  const isExpanded = expandedFolders.has(fullPath);
  
  const item = document.createElement('div');
  item.className = 'tree-item';
  item.dataset.path = fullPath;
  item.dataset.isDir = entry.is_dir;
  
  const row = document.createElement('div');
  row.className = 'tree-row';
  
  // Indentation
  for (let i = 0; i < level; i++) {
    const indent = document.createElement('span');
    indent.className = 'tree-indent';
    row.appendChild(indent);
  }
  
  // Arrow for directories
  if (entry.is_dir) {
    const arrow = document.createElement('span');
    arrow.className = `tree-arrow ${isExpanded ? 'expanded' : ''}`;
    arrow.textContent = '▶';
    row.appendChild(arrow);
  } else {
    const spacer = document.createElement('span');
    spacer.className = 'tree-indent';
    row.appendChild(spacer);
  }
  
  // Icon
  const icon = document.createElement('span');
  icon.className = 'tree-icon';
  icon.textContent = getFileIcon(entry.name, entry.is_dir);
  row.appendChild(icon);
  
  // Name
  const name = document.createElement('span');
  name.className = 'tree-name';
  name.textContent = entry.name;
  row.appendChild(name);
  
  // Size for files
  if (!entry.is_dir && entry.size > 0) {
    const size = document.createElement('span');
    size.className = 'tree-size';
    size.textContent = formatFileSize(entry.size);
    row.appendChild(size);
  }
  
  // Click handler
  row.addEventListener('click', async (e) => {
    e.stopPropagation();
    
    if (entry.is_dir) {
      await toggleFolder(fullPath, item, row.querySelector('.tree-arrow'));
    } else {
      await openFile(fullPath);
    }
  });
  
  item.appendChild(row);
  
  // Children container
  if (entry.is_dir) {
    const children = document.createElement('div');
    children.className = `tree-children ${isExpanded ? 'expanded' : ''}`;
    item.appendChild(children);
  }
  
  return item;
}

async function toggleFolder(path, itemElement, arrowElement) {
  const childrenContainer = itemElement.querySelector('.tree-children');
  const isExpanded = expandedFolders.has(path);
  
  if (isExpanded) {
    // Collapse
    expandedFolders.delete(path);
    childrenContainer.classList.remove('expanded');
    arrowElement.classList.remove('expanded');
    childrenContainer.innerHTML = '';
  } else {
    // Expand
    try {
      setStatus(`Loading ${path}...`);
      const entries = await api.list(path);
      
      // Sort: directories first, then files, both alphabetically
      entries.sort((a, b) => {
        if (a.is_dir && !b.is_dir) return -1;
        if (!a.is_dir && b.is_dir) return 1;
        return a.name.toLowerCase().localeCompare(b.name.toLowerCase());
      });
      
      expandedFolders.add(path);
      childrenContainer.classList.add('expanded');
      arrowElement.classList.add('expanded');
      
      const level = path.split('/').length - 1;
      entries.forEach(entry => {
        const childItem = createTreeItem(entry, path, level);
        childrenContainer.appendChild(childItem);
      });
      
      setStatus('Ready');
    } catch (error) {
      setStatus('Error loading folder');
      console.error('Failed to load folder:', error);
    }
  }
}

async function buildTree() {
  setStatus('Loading explorer...');
  try {
    const entries = await api.list('/');
    
    // Sort entries
    entries.sort((a, b) => {
      if (a.is_dir && !b.is_dir) return -1;
      if (!a.is_dir && b.is_dir) return 1;
      return a.name.toLowerCase().localeCompare(b.name.toLowerCase());
    });
    
    elements.explorer.innerHTML = '';
    
    entries.forEach(entry => {
      const item = createTreeItem(entry, '', 0);
      elements.explorer.appendChild(item);
    });
    
    setStatus('Ready');
  } catch (error) {
    setStatus('Error loading explorer');
    console.error('Failed to build tree:', error);
  }
}

// File operations
async function openFile(path) {
  // Hide welcome screen
  if (elements.welcome) {
    elements.welcome.style.display = 'none';
  }
  
  // Check if file is already open
  let tab = tabs.find(t => t.path === path);
  if (tab) {
    activateTab(path);
    return;
  }
  
  setStatus(`Opening ${path}...`);
  try {
    const content = await api.read(path);
    const model = monacoGlobal.editor.createModel(
      content, 
      undefined, 
      monacoGlobal.Uri.parse('inmemory:' + path)
    );
    
    tab = {
      path,
      name: path.split('/').pop() || path,
      model,
      dirty: false,
      _savedValue: content
    };
    
    tabs.push(tab);
    renderTabs();
    activateTab(path);
    setStatus('Ready');
  } catch (error) {
    setStatus('Error opening file');
    alert('Failed to open file: ' + error.message);
  }
}

async function createNewFile() {
  const name = prompt('Enter file name (relative to root):');
  if (!name) return;
  
  try {
    const result = await api.save(name, '');
    if (result.ok) {
      await buildTree();
      await openFile('/' + name.replace(/^\/+/, ''));
    } else {
      alert('Failed to create file: ' + (result.error || 'Unknown error'));
    }
  } catch (error) {
    alert('Error creating file: ' + error.message);
  }
}

// Tab management
function renderTabs() {
  elements.tabs.innerHTML = '';
  
  tabs.forEach(tab => {
    const tabElement = document.createElement('div');
    tabElement.className = `tab ${tab.path === activeTab ? 'active' : ''}`;
    
    const icon = document.createElement('span');
    icon.textContent = getFileIcon(tab.name, false);
    
    const name = document.createElement('span');
    name.textContent = tab.name;
    
    const dirty = document.createElement('span');
    if (tab.dirty) {
      dirty.className = 'dirty';
      dirty.textContent = '●';
    }
    
    const close = document.createElement('span');
    close.className = 'close';
    close.textContent = '×';
    close.addEventListener('click', (e) => {
      e.stopPropagation();
      closeTab(tab.path);
    });
    
    tabElement.appendChild(icon);
    tabElement.appendChild(name);
    if (tab.dirty) tabElement.appendChild(dirty);
    tabElement.appendChild(close);
    
    tabElement.addEventListener('click', () => activateTab(tab.path));
    elements.tabs.appendChild(tabElement);
  });
}

let editorInstance = null;

function activateTab(path) {
  const tab = tabs.find(t => t.path === path);
  if (!tab) return;
  
  activeTab = path;
  renderTabs();
  elements.breadcrumbs.textContent = path;
  
  if (!editorInstance) {
    editorInstance = monacoGlobal.editor.create(elements.editorContainer, {
      theme: 'vs-dark',
      automaticLayout: true,
      fontSize: 14,
      lineHeight: 20,
      minimap: { enabled: true },
      scrollBeyondLastLine: false,
      wordWrap: 'on'
    });
  }
  
  editorInstance.setModel(tab.model);
  
  // Set up change listener
  tab.model.onDidChangeContent(() => {
    tab.dirty = tab.model.getValue() !== tab._savedValue;
    renderTabs();
  });
}

function closeTab(path) {
  const index = tabs.findIndex(t => t.path === path);
  if (index === -1) return;
  
  const tab = tabs[index];
  if (tab.dirty && !confirm(`Discard unsaved changes to ${tab.name}?`)) {
    return;
  }
  
  try {
    tab.model.dispose();
  } catch (e) {
    console.warn('Error disposing model:', e);
  }
  
  tabs.splice(index, 1);
  
  if (activeTab === path) {
    if (tabs.length > 0) {
      const newIndex = Math.max(0, index - 1);
      activateTab(tabs[newIndex].path);
    } else {
      activeTab = null;
      if (editorInstance) {
        editorInstance.setModel(null);
      }
      elements.breadcrumbs.textContent = '';
      if (elements.welcome) {
        elements.welcome.style.display = 'flex';
      }
    }
  }
  
  renderTabs();
}

async function saveActiveFile() {
  if (!activeTab) {
    alert('No file is currently open');
    return;
  }
  
  const tab = tabs.find(t => t.path === activeTab);
  if (!tab) return;
  
  setStatus(`Saving ${tab.name}...`);
  const content = tab.model.getValue();
  
  try {
    const result = await api.save(tab.path, content);
    if (result.ok) {
      tab._savedValue = content;
      tab.dirty = false;
      renderTabs();
      setStatus('File saved');
    } else {
      setStatus('Save failed');
      alert('Failed to save: ' + (result.error || 'Unknown error'));
    }
  } catch (error) {
    setStatus('Save error');
    alert('Save error: ' + error.message);
  }
}

// Initialize application
require(['vs/editor/editor.main'], function(monaco) {
  monacoGlobal = monaco;
  
  // Set up event listeners
  elements.saveBtn?.addEventListener('click', saveActiveFile);
  elements.newFileBtn?.addEventListener('click', createNewFile);
  elements.refreshBtn?.addEventListener('click', buildTree);
  
  // Keyboard shortcuts
  window.addEventListener('keydown', (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 's') {
      e.preventDefault();
      saveActiveFile();
    }
  });
  
  // Initialize explorer
  buildTree();
});
</script>
</body>
</html>"""

    html = template.replace("__USERNAME__", _html.escape(user["username"])) \
                   .replace("__ADMIN__", admin) \
                   .replace("__UPLOAD_HTML__", upload_html) \
                   .replace("__WELCOME_TITLE__", "Justin's Simple Code Server") \
                   .replace("__WELCOME_SUB__", "Version 1.0.0 beta")
    return html

# --------------------------------------------------------------------------- #
#  REQUEST HANDLER
# --------------------------------------------------------------------------- #
class Handler(BaseHTTPRequestHandler):
    def send(self, body: bytes, status=200, headers=None):
        headers = headers or {}
        headers.setdefault("Content-Length", str(len(body)))
        self.send_response(status)
        for k, v in headers.items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def send_json(self, obj, status=200):
        b = json.dumps(obj, ensure_ascii=False).encode('utf-8')
        self.send(b, status=status, headers={"Content-Type":"application/json; charset=utf-8"})

    def get_cookie(self) -> dict | None:
        cookie = self.headers.get("Cookie", "")
        for chunk in cookie.split(";"):
            chunk = chunk.strip()
            if chunk.startswith("session="):
                token = cookie.split("session=",1)[1].split(";",1)[0]
                return unsign_cookie(token)
        return None

    def set_cookie(self, discord_id: int):
        payload = json.dumps({"uid": discord_id, "exp": int(time.time()) + 86400})
        token = sign_cookie(payload)
        self.send_header("Set-Cookie", f"session={token}; Path=/; HttpOnly; Max-Age=86400")

    def require_auth(self):
        user = self.get_cookie()
        if not user:
            return None, self.redirect("/login")
        udata = get_user(user["uid"])
        if not udata:
            return None, self.redirect("/login")
        return udata, None

    def redirect(self, loc: str):
        return b"", 302, {"Location": loc}

    # ---------- GET ----------
    def do_GET(self):
        try:
            path = urllib.parse.urlparse(self.path).path
            query = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)

            # 1) Discord-Code directly on /callback
            if path == "/callback" and "code" in query:
                code = query["code"][0]
                pair = exchange_code(code)
                if not pair:
                    self.send(b"exchange failed", 400)
                    return
                uid, uname = pair
                if not get_user(uid):
                    save_user(uid, uname, ["browse","preview","download","upload"])
                html = b"""<!doctype html>
<meta charset="utf-8"><body>Authenticated. Redirecting...
<script>location="/"</script></body></html>"""
                self.send_response(200)
                self.set_cookie(uid)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(html)))
                self.end_headers()
                self.wfile.write(html)
                return

            # 2) login/logout
            if path == "/login":
                params = urllib.parse.urlencode({
                    "client_id": CLIENT_ID,
                    "redirect_uri": REDIRECT_URI,
                    "response_type": "code",
                    "scope": "identify"
                })
                url = f"https://discord.com/oauth2/authorize?{params}"
                self.send(*self.redirect(url))
                return
            if path == "/logout":
                html = b"""<!doctype html>
<meta charset="utf-8"><body><p>Logged out. Redirecting...</p>
<script>location="/"</script></body></html>"""
                self.send(html, headers={"Set-Cookie": "session=; Path=/; Max-Age=0"})
                return

            # API endpoints
            if path.startswith("/api/"):
                user, redir = self.require_auth()
                if redir:
                    self.send(*redir)
                    return
                if "browse" not in user["perms"]:
                    self.send_json({"error":"no browse permission"}, status=403)
                    return

                if path == "/api/list":
                    p = self._get_query_single("path") or "/"
                    target = safe_resolve(p)
                    if not target or not target.exists() or not target.is_dir():
                        self.send_json([], 200)
                        return
                    try:
                        entries = []
                        for item in target.iterdir():
                            if is_hidden(item):
                                continue
                            stat_info = item.stat()
                            entries.append({
                                "name": item.name,
                                "is_dir": item.is_dir(),
                                "size": stat_info.st_size if item.is_file() else 0,
                            })
                        
                        # Improved sorting: directories first, then files, both alphabetically
                        entries.sort(key=lambda x: (not x["is_dir"], x["name"].lower()))
                        self.send_json(entries)
                    except Exception as e:
                        print(f"Error listing directory {target}: {e}")
                        self.send_json([], 200)
                    return

                if path == "/api/read":
                    p = self._get_query_single("path")
                    if not p:
                        self.send_json({"error":"path required"}, status=400)
                        return
                    target = safe_resolve(p)
                    if not target or not target.exists() or not target.is_file():
                        self.send_json({"error":"not found"}, status=404)
                        return
                    if not is_text(target):
                        self.send_json({"error":"not a text file"}, status=400)
                        return
                    try:
                        txt = target.read_text(encoding="utf-8", errors="replace")
                        self.send(txt.encode('utf-8'), headers={"Content-Type":"text/plain; charset=utf-8"})
                    except Exception as e:
                        self.send_json({"error":str(e)}, status=500)
                    return

                self.send_json({"error":"unknown api"}, status=404)
                return

            # Serve SPA at root
            user, redir = self.require_auth()
            if redir:
                self.send(*redir)
                return
            if "browse" not in user["perms"]:
                self.send(b"no browse permission", 403)
                return

            # static file/disk serving for downloads and previews
            url_path = self.path.split("?")[0]
            disk_path = pathlib.Path("." + url_path).resolve()

            try:
                disk_path.relative_to(ROOT)
            except Exception:
                self.send(b"invalid path", 404)
                return
            if is_hidden(disk_path):
                self.send(b"not found", 404)
                return
            if not disk_path.exists():
                self.send(b"not found", 404)
                return

            # If it's a directory, return the SPA (index)
            if disk_path.is_dir():
                html = index_page(disk_path, user)
                self.send(html.encode('utf-8'))
                return

            # file: handle view/preview/download like before
            if urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query).get("view"):
                if "preview" not in user["perms"]:
                    self.send(b"no preview permission", 403)
                    return
                if not is_text(disk_path):
                    self.send(b"not a text file", 400)
                    return
                self.send(editor_page(disk_path, url_path).encode())
                return
            if urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query).get("preview"):
                if "preview" not in user["perms"]:
                    self.send(b"no preview permission", 403)
                    return
                mime, _ = mimetypes.guess_type(str(disk_path))
                self.serve_raw(disk_path, mime or "application/octet-stream")
                return
            if "download" not in user["perms"]:
                self.send(b"no download permission", 403)
                return
            mime, _ = mimetypes.guess_type(str(disk_path))
            self.serve_raw(disk_path, mime or "application/octet-stream")
        except Exception:
            traceback.print_exc()
            try:
                self.send(b"internal server error", 500)
            except Exception:
                pass

    # ---------- POST (upload & save) ----------
    def do_POST(self):
        try:
            path = urllib.parse.urlparse(self.path).path

            # upload unchanged
            if path == "/upload":
                user, redir = self.require_auth()
                if redir:
                    self.send(*redir)
                    return
                if "upload" not in user["perms"]:
                    self.send(b"no upload permission", 403)
                    return

                ctype = self.headers.get("Content-Type", "")
                if not ctype.startswith("multipart/form-data"):
                    self.send(b"need multipart", 400)
                    return
                if "boundary=" not in ctype:
                    self.send(b"no boundary", 400)
                    return
                boundary = ctype.split("boundary=")[-1].strip('"').encode()
                try:
                    length = int(self.headers.get("Content-Length", 0))
                except Exception:
                    self.send(b"invalid content-length", 400)
                    return
                post_data = self.rfile.read(length)
                try:
                    filename, payload = handle_upload(post_data, boundary)
                except ValueError as e:
                    self.send(str(e).encode(), 400)
                    return
                filename = _html.escape(filename)
                target = UPLOAD_DIR / filename
                counter = 1
                orig = target
                while target.exists():
                    stem = orig.stem
                    suffix = orig.suffix
                    target = UPLOAD_DIR / f"{stem}({counter}){suffix}"
                    counter += 1
                try:
                    target.write_bytes(payload)
                except Exception as e:
                    self.send(f"failed to write file: {e}".encode(), 500)
                    return
                html = ("""<!doctype html>
<meta charset="utf-8"><body>
<p>Uploaded <b>""" + _html.escape(target.name) + """</b> (""" + str(len(payload)) + """ bytes).</p>
<script>setTimeout(()=>location="/",1000)</script></body></html>""").encode()
                self.send(html)
                return

            # API save endpoint for editor
            if path == "/api/save":
                user, redir = self.require_auth()
                if redir:
                    self.send(*redir)
                    return
                if "upload" not in user["perms"]:
                    self.send_json({"ok":False, "error":"no upload permission"}, status=403)
                    return
                try:
                    length = int(self.headers.get("Content-Length", 0))
                except Exception:
                    self.send_json({"ok":False, "error":"invalid content-length"}, status=400)
                    return
                raw = self.rfile.read(length)
                try:
                    payload = json.loads(raw.decode('utf-8'))
                    p = payload.get("path")
                    content = payload.get("content", "")
                    if p is None:
                        self.send_json({"ok":False, "error":"path required"}, status=400)
                        return
                    target = safe_resolve(p)
                    if not target:
                        self.send_json({"ok":False, "error":"invalid path"}, status=400)
                        return
                    parent = target.parent
                    if not parent.exists():
                        try:
                            parent.mkdir(parents=True, exist_ok=True)
                        except Exception as e:
                            self.send_json({"ok":False, "error":f"cannot create parent: {e}"}, status=500)
                            return
                    if is_hidden(target):
                        self.send_json({"ok":False, "error":"forbidden"}, status=403)
                        return
                    try:
                        target.write_text(content, encoding='utf-8')
                        self.send_json({"ok":True})
                    except Exception as e:
                        self.send_json({"ok":False, "error":str(e)}, status=500)
                    return
                except json.JSONDecodeError:
                    self.send_json({"ok":False, "error":"invalid json"}, status=400)
                    return

            self.send(b"bad post url", 400)
        except Exception:
            traceback.print_exc()
            try:
                self.send(b"internal server error", 500)
            except Exception:
                pass

    # ---------- raw serve ----------
    def serve_raw(self, path: pathlib.Path, mime: str):
        try:
            data = path.read_bytes()
        except Exception:
            self.send(b"failed to read file", 500)
            return
        headers = {"Content-Type": mime}
        self.send(data, headers=headers)

    # small helper to read query single param
    def _get_query_single(self, key):
        q = urllib.parse.urlparse(self.path).query
        if not q:
            return None
        d = urllib.parse.parse_qs(q)
        v = d.get(key)
        return v[0] if v else None

# --------------------------------------------------------------------------- #
#  START
# --------------------------------------------------------------------------- #
def main():
    if not CLIENT_SECRET or not CLIENT_ID or not REDIRECT_URI:
        print("CLIENT_ID / CLIENT_SECRET / REDIRECT_URI env vars required")
        exit(1)
    init_db()
    print(f"Listening on 0.0.0.0:{PORT}")
    HTTPServer(("0.0.0.0", PORT), Handler).serve_forever()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nShutdown.")
