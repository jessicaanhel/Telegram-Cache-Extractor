"""
TelegramCacheExtractor-macos — macOS shell for Telegram-Cache-Extractor.

Reuses the crypto from app.py unchanged (get_local_key / decrypt_cache_file /
detect_ext) and serves the dark HTML UI in a native WKWebView window.
Windows build (installer.iss + the tkinter screens in app.py) is untouched.

    pip install pywebview pycryptodome
    python macos/main.py     # run from the repo root so `import app` resolves
"""

import functools
import http.server
import json
import mimetypes
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse

import webview  # pywebview

if not getattr(sys, "frozen", False):
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import (
    AES, get_local_key, decrypt_cache_file, detect_ext,
    IMAGE_EXTS, VIDEO_EXTS, AUDIO_EXTS, default_tdata_path, resource_path,
)

if getattr(sys, "frozen", False):
    UI_DIR = os.path.join(sys._MEIPASS, "ui")
else:
    UI_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ui")
DEFAULT_OUT = os.path.join(os.path.expanduser("~"), "Pictures", "TelegramCacheExtractor-macos")
SKIP = {"binlog", "version", ".DS_Store"}

# ---------------------------------------------------------------- state

STATE = {
    "items": [],          # [{id, kind, name, size, detail, source, staged, ext}]
    "staging": None,      # temp dir holding the decrypted blobs
    "tdata": default_tdata_path(),
    "outDir": DEFAULT_OUT,
    "progress": {"state": "idle", "pct": 0, "log": [], "rows": [], "eta": "", "message": "", "result": None},
    "cancel": False,
}
LOCK = threading.Lock()


def kind_of(ext):
    if ext in IMAGE_EXTS:
        return "image"
    if ext in VIDEO_EXTS:
        return "video"
    if ext in AUDIO_EXTS:
        return "audio"
    return None


def human(n):
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n/1:.1f} {unit}".replace(".0 ", " ")
        n /= 1024


def log(msg):
    with LOCK:
        STATE["progress"]["log"].append(msg)


def ffmpeg():
    """Bundled ffmpeg inside the .app, else whatever is on PATH."""
    bundled = resource_path("ffmpeg")
    return bundled if os.path.exists(bundled) else (shutil.which("ffmpeg") or "ffmpeg")


# ---------------------------------------------------------------- scan

def do_scan(tdata, passcode):
    p = STATE["progress"]
    p.update({"state": "running", "pct": 0, "log": [], "message": ""})
    STATE["cancel"] = False
    try:
        if AES is None:
            raise RuntimeError("pycryptodome is not installed (pip install pycryptodome)")
        log("reading key_datas…")
        local_key = get_local_key(tdata, passcode.encode("utf-8"))
        log(f"local key OK ({len(local_key)} bytes)")

        if STATE["staging"] and os.path.isdir(STATE["staging"]):
            shutil.rmtree(STATE["staging"], ignore_errors=True)
        staging = tempfile.mkdtemp(prefix="telegramcacheextractor-macos-")
        STATE["staging"] = staging

        blobs = []
        for root, _dirs, files in os.walk(tdata):
            low = root.lower()
            if "cache" not in low and "media_cache" not in low:
                continue
            for name in files:
                if name in SKIP:
                    continue
                full = os.path.join(root, name)
                if os.path.isfile(full):
                    blobs.append(full)
        log(f"cache blobs found: {len(blobs)}")

        items, failed = [], 0
        for n, full in enumerate(blobs, 1):
            if STATE["cancel"]:
                p["state"] = "idle"
                return
            try:
                plain = decrypt_cache_file(full, local_key)
                ext = detect_ext(plain)
                kind = kind_of(ext)
                if kind is None:
                    continue
                blob_id = os.path.basename(full)
                staged = os.path.join(staging, f"{len(items):06d}_{blob_id}.{ext}")
                with open(staged, "wb") as f:
                    f.write(plain)
                items.append({
                    "id": blob_id,
                    "kind": kind,
                    "ext": ext,
                    "name": f"{kind}_{len(items):04d}",
                    "size": human(len(plain)),
                    "detail": ext.upper(),
                    "source": f"{os.path.basename(os.path.dirname(full))}/{blob_id} · TDEF · {ext}",
                    "staged": staged,
                })
            except Exception:
                failed += 1
            if n % 25 == 0 or n == len(blobs):
                p["pct"] = n / max(len(blobs), 1) * 100
                log(f"decrypted {n}/{len(blobs)} · media {len(items)} · skipped {failed}")

        STATE["items"] = items
        STATE["tdata"] = tdata
        p.update({"pct": 100, "state": "done"})
    except Exception as e:
        p.update({"state": "error", "message": str(e)})


# ---------------------------------------------------------------- convert

PASSTHROUGH = {("jpg", "jpg"), ("png", "png"), ("webp", "webp"),
               ("mp4", "mp4"), ("webm", "webm"), ("mp3", "mp3")}

ARGS = {
    "jpg": ["-q:v", "2"],
    "png": [],
    "webp": ["-quality", "88"],
    "mp4": ["-c:v", "h264_videotoolbox", "-b:v", "6M", "-c:a", "aac", "-b:a", "192k", "-movflags", "+faststart"],
    "webm": ["-c:v", "libvpx-vp9", "-crf", "32", "-b:v", "0", "-c:a", "libopus"],
    "gif": ["-vf", "fps=12,scale=600:-1:flags=lanczos", "-loop", "0"],
    "mp3": ["-c:a", "libmp3lame", "-b:a", "320k"],
    "wav": ["-c:a", "pcm_s16le"],
    "m4a": ["-c:a", "aac", "-b:a", "256k"],
}


def do_convert(ids, targets, out_dir):
    p = STATE["progress"]
    p.update({"state": "running", "pct": 0, "rows": [], "eta": "", "message": ""})
    STATE["cancel"] = False
    by_id = {i["id"]: i for i in STATE["items"]}
    chosen = [by_id[i] for i in ids if i in by_id]
    rows = [{"id": i["id"], "status": "queued"} for i in chosen]
    p["rows"] = rows
    os.makedirs(out_dir, exist_ok=True)
    started, written, bytes_out = time.time(), 0, 0

    for n, item in enumerate(chosen):
        if STATE["cancel"]:
            p["state"] = "idle"
            return
        target = targets.get(item["id"], {"image": "jpg", "video": "mp4", "audio": "mp3"}[item["kind"]])
        rows[n]["status"] = "encoding"
        dest = os.path.join(out_dir, f"{item['name']}.{target}")
        try:
            if (item["ext"], target) in PASSTHROUGH:
                shutil.copy2(item["staged"], dest)
            else:
                subprocess.run([ffmpeg(), "-y", "-hide_banner", "-loglevel", "error",
                                "-i", item["staged"], *ARGS.get(target, []), dest],
                               check=True)
            rows[n]["status"] = "written"
            written += 1
            bytes_out += os.path.getsize(dest)
        except Exception:
            rows[n]["status"] = "failed"
        p["pct"] = (n + 1) / max(len(chosen), 1) * 100
        per = (time.time() - started) / (n + 1)
        left = per * (len(chosen) - n - 1)
        p["eta"] = f"Hardware encode · about {max(1, int(left))} s remaining"

    p.update({"pct": 100, "state": "done",
              "result": {"count": written, "bytes": human(bytes_out), "outDir": out_dir}})


# ---------------------------------------------------------------- http api

class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *a, **kw):
        super().__init__(*a, directory=UI_DIR, **kw)

    def log_message(self, *a):
        pass

    def _json(self, payload, status=200):
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _public(self, items):
        return [{k: v for k, v in i.items() if k != "staged"} for i in items]

    def do_GET(self):
        url = urllib.parse.urlparse(self.path)
        if url.path == "/api/info":
            return self._json({"tdata": STATE["tdata"], "outDir": STATE["outDir"],
                               "items": self._public(STATE["items"])})
        if url.path == "/api/items":
            return self._json({"items": self._public(STATE["items"])})
        if url.path == "/api/progress":
            return self._json(STATE["progress"])
        if url.path == "/api/thumb":
            blob_id = urllib.parse.parse_qs(url.query).get("id", [""])[0]
            item = next((i for i in STATE["items"] if i["id"] == blob_id), None)
            if not item or not os.path.exists(item["staged"]):
                return self._json({"error": "not found"}, 404)
            data = open(item["staged"], "rb").read()
            self.send_response(200)
            self.send_header("Content-Type", mimetypes.guess_type(item["staged"])[0] or "application/octet-stream")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            return self.wfile.write(data)
        return super().do_GET()

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = json.loads(self.rfile.read(length) or b"{}")
        path = urllib.parse.urlparse(self.path).path

        if path == "/api/scan":
            threading.Thread(target=do_scan, daemon=True,
                             args=(body.get("tdata") or STATE["tdata"], body.get("passcode", ""))).start()
            return self._json({"ok": True})

        if path == "/api/convert":
            STATE["outDir"] = body.get("outDir") or STATE["outDir"]
            threading.Thread(target=do_convert, daemon=True,
                             args=(body.get("ids", []), body.get("targets", {}), STATE["outDir"])).start()
            return self._json({"ok": True})

        if path == "/api/cancel":
            STATE["cancel"] = True
            return self._json({"ok": True})

        if path == "/api/pick":
            window = webview.windows[0]
            picked = window.create_file_dialog(webview.FOLDER_DIALOG)
            folder = picked[0] if picked else None
            if folder and body.get("kind") == "out":
                STATE["outDir"] = folder
            return self._json({"path": folder})

        if path == "/api/reveal":
            subprocess.Popen(["open", body.get("path") or STATE["outDir"]])
            return self._json({"ok": True})

        return self._json({"error": "unknown endpoint"}, 404)


def serve():
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", port), Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return port


def main():
    if sys.platform != "darwin":
        sys.exit("macos/main.py is the macOS shell; use app.py on Windows.")
    port = serve()
    webview.create_window("TelegramCacheExtractor-macos", f"http://127.0.0.1:{port}/index.html",
                          width=1200, height=800, min_size=(940, 620),
                          background_color="#151517")
    webview.start()
    if STATE["staging"]:
        shutil.rmtree(STATE["staging"], ignore_errors=True)


if __name__ == "__main__":
    main()
