import os
import sys
import struct
import hashlib
import threading
import webbrowser
import subprocess
import json
import shutil
import functools
import urllib.parse
import http.server
import tkinter as tk
from tkinter import filedialog, messagebox

try:
    from Crypto.Cipher import AES
except ImportError:
    AES = None


# ===========================================================================
# CONFIGURATION
# ===========================================================================

def resource_path(relative_path: str) -> str:
    if getattr(sys, "frozen", False):
        base_path = sys._MEIPASS
    else:
        base_path = os.path.abspath(os.path.dirname(__file__))
    return os.path.join(base_path, relative_path)


def default_tdata_path() -> str:
    if sys.platform == "win32":
        return os.path.join(os.environ.get("APPDATA", ""), "Telegram Desktop", "tdata")
    if sys.platform == "darwin":
        return os.path.join(os.path.expanduser("~"), "Library", "Application Support",
                             "Telegram Desktop", "tdata")
    # Linux (обычное расположение Telegram Desktop)
    return os.path.join(os.path.expanduser("~"), ".local", "share", "TelegramDesktop", "tdata")


TELEGRAM_URL = "https://t.me/IK_Flex_Air"
YOUTUBE_URL  = "https://www.youtube.com/@FlexAir-pwn"

# Color theme (тот же, что в ocr_roi_mouse.py)
BG           = "#1e1e1e"   # window background
CARD         = "#2d2d2d"   # cards / panels
BTN          = "#3a3a3a"   # buttons
BTN_HOVER    = "#505050"   # buttons on hover
TEXT         = "#ffffff"   # white text
ACCENT       = "#4CAF50"   # green accent
PREVIEW_BG   = "#252526"   # preview background
PREVIEW_TEXT = "#d4d4d4"   # preview text

current_screen: str = "main"


# ===========================================================================
# КРИПТО-ЛОГИКА (расшифровка tdata)
# ===========================================================================

def aes_ige_decrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    iv1, iv2 = iv[:16], iv[16:]  # iv1 = c0, iv2 = m0
    cipher = AES.new(key, AES.MODE_ECB)
    out = bytearray()
    prev_ct, prev_pt = iv1, iv2
    for i in range(0, len(data), 16):
        ct = data[i:i + 16]
        xored = bytes(a ^ b for a, b in zip(ct, prev_pt))
        block = cipher.decrypt(xored)
        pt = bytes(a ^ b for a, b in zip(block, prev_ct))
        out += pt
        prev_ct, prev_pt = ct, pt
    return bytes(out)


def prepare_aes_oldmtp(auth_key: bytes, msg_key: bytes):
    x = 8  # direction "Server", как в tdesktop decryptLocal
    sha1a = hashlib.sha1(msg_key + auth_key[x:x + 32]).digest()
    sha1b = hashlib.sha1(auth_key[32 + x:32 + x + 16] + msg_key + auth_key[48 + x:48 + x + 16]).digest()
    sha1c = hashlib.sha1(auth_key[64 + x:64 + x + 32] + msg_key).digest()
    sha1d = hashlib.sha1(msg_key + auth_key[96 + x:96 + x + 32]).digest()
    aes_key = sha1a[0:8] + sha1b[8:20] + sha1c[4:16]
    aes_iv = sha1a[8:20] + sha1b[0:8] + sha1c[16:20] + sha1d[0:8]
    return aes_key, aes_iv


def decrypt_local(encrypted: bytes, local_key: bytes) -> bytes:
    msg_key, data = encrypted[:16], encrypted[16:]
    aes_key, aes_iv = prepare_aes_oldmtp(local_key, msg_key)
    decrypted = aes_ige_decrypt(data, aes_key, aes_iv)
    check = hashlib.sha1(decrypted).digest()[:16]
    if check != msg_key:
        raise ValueError("bad decrypt_local: неверный passcode или битые данные")
    length = struct.unpack("<i", decrypted[:4])[0]
    return decrypted[4:4 + length]


def create_passcode_key(passcode: bytes, salt: bytes) -> bytes:
    iterations = 1 if not passcode else 100_000
    h = hashlib.sha512(salt + passcode + salt).digest()
    return hashlib.pbkdf2_hmac("sha512", h, salt, iterations, dklen=256)


def read_qt_bytearray(buf: bytes, pos: int):
    (length,) = struct.unpack_from(">i", buf, pos)
    pos += 4
    if length < 0:
        return b"", pos
    return buf[pos:pos + length], pos + length


def read_tdf_file(path: str) -> bytes:
    with open(path, "rb") as f:
        data = f.read()
    if data[:4] != b"TDF$":
        raise ValueError(f"{path}: нет сигнатуры TDF$")
    version = struct.unpack("<i", data[4:8])[0]
    body, sig = data[8:-16], data[-16:]
    md5 = hashlib.md5()
    md5.update(body)
    md5.update(struct.pack("<i", len(body)))
    md5.update(struct.pack("<i", version))
    md5.update(b"TDF$")
    if md5.digest() != sig:
        raise ValueError(f"{path}: подпись MD5 не совпала")
    return body


def get_local_key(tdata_path: str, passcode: bytes) -> bytes:
    raw = read_tdf_file(os.path.join(tdata_path, "key_datas"))
    pos = 0
    salt, pos = read_qt_bytearray(raw, pos)
    key_encrypted, pos = read_qt_bytearray(raw, pos)
    _info_encrypted, pos = read_qt_bytearray(raw, pos)
    passcode_key = create_passcode_key(passcode, salt)
    local_key_data = decrypt_local(key_encrypted, passcode_key)
    return local_key_data[:256]


def detect_ext(data: bytes) -> str:
    if data[:3] == b"\xff\xd8\xff":
        return "jpg"
    if data[:8] == b"\x89PNG\r\n\x1a\n":
        return "png"
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "webp"
    if data[:4] == b"RIFF" and data[8:12] == b"WAVE":
        return "wav"
    if data[:2] == b"\x1f\x8b":
        return "tgs"
    if data[:4] == b"GIF8":
        return "gif"
    # видео: MP4/MOV/M4A используют "ftyp" box со смещением 4 байта
    if data[4:8] == b"ftyp":
        return "mp4"
    # WebM/MKV - оба на базе Matroska/EBML
    if data[:4] == b"\x1a\x45\xdf\xa3":
        return "webm"
    if data[:4] == b"OggS":
        return "ogg"
    if data[:3] == b"ID3" or data[:2] in (b"\xff\xfb", b"\xff\xf3", b"\xff\xf2"):
        return "mp3"
    return "bin"


def decrypt_cache_file(path: str, local_key: bytes) -> bytes:
    with open(path, "rb") as f:
        data = f.read()
    if data[:4] != b"TDEF":
        raise ValueError("нет сигнатуры TDEF")
    salt = data[4:4 + 64]
    rest = data[4 + 64:]

    half = len(local_key) // 2
    real_key = hashlib.sha256(local_key[:half] + salt[:32]).digest()
    iv = hashlib.sha256(local_key[half:] + salt[32:]).digest()[:16]

    cipher = AES.new(real_key, AES.MODE_CTR, nonce=b"", initial_value=iv)
    decrypted = cipher.decrypt(rest)

    value, checksum = decrypted[:16], decrypted[16:48]
    expected = hashlib.sha256(local_key + salt + value).digest()
    if checksum != expected:
        raise ValueError("checksum mismatch: неверный ключ")

    return decrypted[48:]


IMAGE_EXTS = {"jpg", "png", "webp", "gif"}
VIDEO_EXTS = {"mp4", "webm"}
AUDIO_EXTS = {"mp3", "ogg", "wav"}


# ===========================================================================
# ЛОКАЛЬНЫЙ СЕРВЕР (открыть в проводнике / собрать папку с выбранным)
# ===========================================================================

_server_instance = None
_server_out_dir = None
_server_port = None
_server_lock = threading.Lock()


class GalleryRequestHandler(http.server.SimpleHTTPRequestHandler):
    out_dir = ""  # подставляется через type() при создании сервера

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=self.out_dir, **kwargs)

    def _safe_path(self, rel_or_abs: str):
        raw = urllib.parse.unquote(rel_or_abs)
        p = raw if os.path.isabs(raw) else os.path.join(self.out_dir, raw)
        p = os.path.abspath(os.path.normpath(p))
        root = os.path.abspath(self.out_dir)
        if p != root and not p.startswith(root + os.sep):
            return None
        return p

    def _send_json(self, status: int, payload: dict):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/reveal":
            qs = urllib.parse.parse_qs(parsed.query)
            target = self._safe_path(qs.get("path", [""])[0])
            if target and os.path.exists(target):
                try:
                    if sys.platform == "win32":
                        # explorer требует "/select," и путь СЛИТНО, без пробела между ними,
                        # поэтому собираем одну командную строку, а не список аргументов
                        subprocess.Popen(f'explorer /select,"{target}"')
                    elif sys.platform == "darwin":
                        subprocess.Popen(["open", "-R", target])
                    else:
                        subprocess.Popen(["xdg-open", os.path.dirname(target)])
                except Exception:
                    pass
                self._send_json(200, {"ok": True})
            else:
                self._send_json(404, {"ok": False, "error": "not found"})
            return
        super().do_GET()

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/copy_selected":
            length = int(self.headers.get("Content-Length", 0))
            try:
                payload = json.loads(self.rfile.read(length).decode("utf-8"))
                raw_name = str(payload.get("folder", "")).strip() or "selection"
                folder_name = "".join(c for c in raw_name if c.isalnum() or c in " _-").strip() or "selection"
                dest_dir = os.path.join(self.out_dir, "selections", folder_name)
                os.makedirs(dest_dir, exist_ok=True)

                copied = 0
                for rel in payload.get("paths", []):
                    src = self._safe_path(rel)
                    if src and os.path.isfile(src):
                        dst = os.path.join(dest_dir, os.path.basename(src))
                        shutil.copy2(src, dst)
                        copied += 1

                self._send_json(200, {"ok": True, "copied": copied, "folder": dest_dir})
            except Exception as e:
                self._send_json(500, {"ok": False, "error": str(e)})
            return
        self._send_json(404, {"ok": False, "error": "unknown endpoint"})

    def log_message(self, format, *args):
        pass  # не засоряем консоль лога


def ensure_gallery_server(out_dir: str) -> int:
    """Поднимает локальный сервер (если ещё не запущен для этой папки) и возвращает порт."""
    global _server_instance, _server_out_dir, _server_port
    with _server_lock:
        if _server_instance is not None and _server_out_dir == out_dir:
            return _server_port

        if _server_instance is not None:
            try:
                _server_instance.shutdown()
            except Exception:
                pass

        handler_cls = type("BoundGalleryHandler", (GalleryRequestHandler,), {"out_dir": out_dir})
        httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
        port = httpd.server_address[1]
        threading.Thread(target=httpd.serve_forever, daemon=True).start()

        _server_instance, _server_out_dir, _server_port = httpd, out_dir, port
        return port


def build_gallery(out_dir: str, by_ext: dict) -> str:
    html_parts = [
        "<!DOCTYPE html><html><head><meta charset='utf-8'>",
        "<title>Telegram Cache Viewer</title>",
        "<style>",
        "*{box-sizing:border-box;}",
        "body{background:#111;color:#eee;font-family:'Segoe UI',Arial,sans-serif;margin:0;padding:16px 16px 90px;}",
        "details{margin-bottom:14px;background:#181818;border-radius:10px;}",
        "summary{cursor:pointer;list-style:none;padding:14px 18px;font-size:16px;font-weight:600;",
        "background:#232323;user-select:none;display:flex;align-items:center;gap:8px;",
        "position:sticky;top:0;z-index:10;border-radius:10px 10px 0 0;",
        "box-shadow:0 2px 6px rgba(0,0,0,.35);}",
        "details:not([open]) summary{border-radius:10px;}",
        "summary::-webkit-details-marker{display:none;}",
        "summary::before{content:'▸';display:inline-block;transition:transform .15s;color:#4CAF50;}",
        "details[open] summary::before{transform:rotate(90deg);}",
        "summary:hover{background:#2a2a2a;}",
        ".count-badge{background:#333;color:#aaa;border-radius:12px;padding:2px 10px;font-size:12px;margin-left:auto;}",
        ".grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(190px,1fr));gap:12px;padding:16px;}",
        ".card{background:#1c1c1c;border-radius:8px;overflow:hidden;position:relative;}",
        ".card img{width:100%;height:180px;object-fit:cover;display:block;background:#000;}",
        ".card video{width:100%;height:180px;object-fit:contain;display:block;background:#000;}",
        ".card-check{position:absolute;top:8px;left:8px;width:20px;height:20px;z-index:2;",
        "accent-color:#4CAF50;cursor:pointer;}",
        ".filename-link{display:flex;align-items:center;gap:6px;font-size:11px;padding:6px 8px;",
        "color:#8ab4f8;background:#222;border:none;width:100%;text-align:left;cursor:pointer;",
        "word-break:break-all;font-family:Consolas,monospace;}",
        ".filename-link:hover{background:#2d3b52;color:#a9c8ff;text-decoration:underline;}",
        ".filename-link .folder-ico{opacity:.8;flex-shrink:0;}",
        ".audio-row{display:flex;align-items:center;gap:12px;background:#1c1c1c;",
        "border-radius:8px;padding:10px 14px;margin:8px 16px;}",
        ".audio-row .card-check{position:static;}",
        ".audio-row .filename-link{width:auto;flex:1;background:none;padding:0;}",
        ".audio-row .filename-link:hover{background:none;}",
        "#selection-bar{position:fixed;left:0;right:0;bottom:0;background:#1b1b1b;",
        "border-top:1px solid #333;padding:12px 20px;display:none;align-items:center;",
        "gap:14px;box-shadow:0 -4px 16px rgba(0,0,0,.4);z-index:100;}",
        "#selection-bar.visible{display:flex;}",
        "#selection-bar .sel-count{font-size:14px;color:#4CAF50;font-weight:600;}",
        "#selection-bar button{font-family:inherit;font-size:14px;padding:8px 16px;border:none;",
        "border-radius:6px;cursor:pointer;}",
        ".btn-primary{background:#4CAF50;color:#fff;}",
        ".btn-primary:hover{background:#5cc760;}",
        ".btn-secondary{background:#3a3a3a;color:#ddd;}",
        ".btn-secondary:hover{background:#505050;}",
        "#toast{position:fixed;left:50%;bottom:80px;transform:translateX(-50%);",
        "background:#2d6cdf;color:#fff;padding:10px 20px;border-radius:8px;font-size:13px;",
        "opacity:0;transition:opacity .2s;pointer-events:none;z-index:200;}",
        "#toast.visible{opacity:1;}",
        "#file-warning{display:none;background:#5a1e1e;color:#ffb3b3;padding:12px 18px;",
        "border-radius:8px;margin-bottom:14px;font-size:13px;line-height:1.5;}",
        "</style></head><body>",
        "<div id='file-warning'>⚠ Похоже, страница открыта напрямую (не через приложение), поэтому кнопки "
        "«открыть в проводнике» и «собрать папку» работать не будут — им нужен запущенный локальный сервер. "
        "Закрой эту вкладку, открой приложение Telegram Cache Extractor заново и нажми «Открыть галерею» — "
        "не закрывай окно приложения, пока пользуешься галереей.</div>",
        "<script>if (location.protocol === 'file:') "
        "document.getElementById('file-warning').style.display = 'block';</script>",
    ]

    sections = [
        ("Изображения", image_names := [(ext, n) for ext in IMAGE_EXTS for n in by_ext.get(ext, [])], "images"),
        ("Видео", video_names := [(ext, n) for ext in VIDEO_EXTS for n in by_ext.get(ext, [])], "videos"),
    ]

    for title, items, sec_id in sections:
        html_parts.append(f"<details id='sec-{sec_id}'><summary>{title}"
                           f"<span class='count-badge'>{len(items)}</span></summary>")
        html_parts.append("<div class='grid'>")
        for ext, name in items:
            rel_path = f"{ext}/{name}"
            media_tag = (
                f"<video src='{rel_path}' controls preload='metadata'></video>"
                if ext in VIDEO_EXTS else
                f"<img src='{rel_path}' loading='lazy'>"
            )
            html_parts.append(
                f"<div class='card'>"
                f"<input type='checkbox' class='card-check' data-path=\"{rel_path}\" onchange='onToggle(this)'>"
                f"{media_tag}"
                f"<button class='filename-link' onclick=\"revealFile('{rel_path}')\" title='Открыть в проводнике'>"
                f"<span class='folder-ico'>📁</span>{name}</button>"
                f"</div>"
            )
        html_parts.append("</div></details>")

    audio_names = [(ext, n) for ext in AUDIO_EXTS for n in by_ext.get(ext, [])]
    html_parts.append(f"<details id='sec-audio'><summary>Аудио"
                       f"<span class='count-badge'>{len(audio_names)}</span></summary>")
    for ext, name in audio_names:
        rel_path = f"{ext}/{name}"
        html_parts.append(
            f"<div class='audio-row'>"
            f"<input type='checkbox' class='card-check' data-path=\"{rel_path}\" onchange='onToggle(this)'>"
            f"<button class='filename-link' onclick=\"revealFile('{rel_path}')\" title='Открыть в проводнике'>"
            f"<span class='folder-ico'>📁</span>{name}</button>"
            f"<audio src='{rel_path}' controls preload='none'></audio>"
            f"</div>"
        )
    html_parts.append("</details>")

    html_parts.append("""
<div id="selection-bar">
  <span class="sel-count"><span id="sel-n">0</span> выбрано</span>
  <button class="btn-primary" onclick="createFolder()">Создать папку с выбранным</button>
  <button class="btn-secondary" onclick="clearSelection()">Очистить выбор</button>
</div>
<div id="toast"></div>
<script>
const selected = new Set();

function onToggle(el) {
  if (el.checked) selected.add(el.dataset.path);
  else selected.delete(el.dataset.path);
  updateBar();
}

function updateBar() {
  const bar = document.getElementById('selection-bar');
  document.getElementById('sel-n').textContent = selected.size;
  bar.classList.toggle('visible', selected.size > 0);
}

function clearSelection() {
  selected.clear();
  document.querySelectorAll('.card-check').forEach(c => c.checked = false);
  updateBar();
}

function showToast(text) {
  const t = document.getElementById('toast');
  t.textContent = text;
  t.classList.add('visible');
  setTimeout(() => t.classList.remove('visible'), 3000);
}

function revealFile(relPath) {
  fetch('/reveal?path=' + encodeURIComponent(relPath))
    .then(r => r.ok ? showToast('Открыто в проводнике') : r.json().then(d => showToast('Ошибка: ' + (d.error || r.status))))
    .catch(e => showToast('Локальный сервер недоступен (' + e.message + '). Открой галерею через приложение.'));
}

function createFolder() {
  if (selected.size === 0) return;
  const name = prompt('Название папки:', 'selection_' + new Date().toISOString().slice(0,10));
  if (!name) return;
  fetch('/copy_selected', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({folder: name, paths: Array.from(selected)})
  })
    .then(r => r.json())
    .then(data => {
      if (data.ok) {
        showToast(`Готово: ${data.copied} файлов -> ${data.folder}`);
        clearSelection();
      } else {
        showToast('Ошибка: ' + (data.error || 'неизвестная'));
      }
    })
    .catch(e => showToast('Локальный сервер недоступен (' + e.message + '). Открой галерею через приложение.'));
}
</script>
""")

    html_parts.append("</body></html>")

    index_path = os.path.join(out_dir, "Viewer.html")
    with open(index_path, "w", encoding="utf-8") as f:
        f.write("\n".join(html_parts))
    return index_path


def run_pipeline(tdata_path: str, out_dir: str, passcode: str, log, done):
    try:
        if AES is None:
            log("Ошибка: не установлен pycryptodome. Выполни: pip install pycryptodome")
            done(None)
            return

        log("Получаю localKey из key_datas...")
        local_key = get_local_key(tdata_path, passcode.encode("utf-8"))
        log(f"localKey получен (длина {len(local_key)} байт).")

        os.makedirs(out_dir, exist_ok=True)
        count, errors = 0, 0
        by_ext = {}

        cache_dirs = []
        for root, _dirs, _files in os.walk(tdata_path):
            low = root.lower()
            if "cache" in low or "media_cache" in low:
                cache_dirs.append(root)

        total_files = 0
        for d in cache_dirs:
            for name in os.listdir(d):
                full = os.path.join(d, name)
                if os.path.isfile(full) and name not in ("binlog", "version"):
                    total_files += 1

        log(f"Найдено файлов кэша для обработки: {total_files}")
        processed = 0

        for d in cache_dirs:
            for name in os.listdir(d):
                if name in ("binlog", "version"):
                    continue
                full = os.path.join(d, name)
                if not os.path.isfile(full):
                    continue
                processed += 1
                try:
                    plain = decrypt_cache_file(full, local_key)
                    ext = detect_ext(plain)
                    ext_dir = os.path.join(out_dir, ext)
                    os.makedirs(ext_dir, exist_ok=True)
                    out_name = f"{count:06d}_{name}.{ext}"
                    with open(os.path.join(ext_dir, out_name), "wb") as f:
                        f.write(plain)
                    by_ext.setdefault(ext, []).append(out_name)
                    count += 1
                except Exception:
                    errors += 1
                if processed % 100 == 0 or processed == total_files:
                    log(f"...обработано {processed}/{total_files}")

        log(f"Готово. Извлечено файлов: {count}. Пропущено с ошибкой: {errors}.")
        log("По типам: " + ", ".join(f"{k}: {len(v)}" for k, v in by_ext.items()))

        log("Собираю HTML-галерею...")
        index_path = build_gallery(out_dir, by_ext)
        port = ensure_gallery_server(out_dir)
        gallery_url = f"http://127.0.0.1:{port}/Viewer.html"

        try:
            import urllib.request as _urlreq
            with _urlreq.urlopen(gallery_url, timeout=2) as resp:
                if resp.status == 200:
                    log(f"Локальный сервер отвечает (порт {port}) - OK.")
                else:
                    log(f"ВНИМАНИЕ: сервер ответил статусом {resp.status}, ожидался 200.")
        except Exception as e:
            log(f"ВНИМАНИЕ: сервер не отвечает на самопроверке ({e}). "
                f"Проверь брандмауэр Windows / антивирус для этого приложения.")

        log(f"Готово! Галерея: {gallery_url}")
        done(gallery_url)
    except Exception as e:
        log(f"ОШИБКА: {e}")
        done(None)


# ===========================================================================
# GUI — ССЫЛКИ И БУФЕР ОБМЕНА
# ===========================================================================

def _clipboard_copy(text: str) -> None:
    root.clipboard_clear()
    root.clipboard_append(text)


def open_link(url: str) -> None:
    webbrowser.open(url)


def copy_link(url: str) -> None:
    _clipboard_copy(url)
    messagebox.showinfo("Copied", "Link copied to clipboard")


def copy_address(address: str, widget: tk.Widget) -> None:
    _clipboard_copy(address)
    widget.tooltip_label.config(text="Copied!")
    widget.after(1500, lambda: widget.tooltip_label.config(text="Copy to clipboard"))


def show_tooltip(event: tk.Event, text: str) -> None:
    widget = event.widget
    widget.tooltip_label = tk.Label(
        root, text=text,
        bg="#ffffe0", relief="solid", borderwidth=1, font=("Arial", 9),
    )
    widget.tooltip_label.place(
        x=event.x_root - root.winfo_rootx() + 15,
        y=event.y_root - root.winfo_rooty() + 15,
    )


def move_tooltip(event: tk.Event) -> None:
    widget = event.widget
    if hasattr(widget, "tooltip_label"):
        widget.tooltip_label.place(
            x=event.x_root - root.winfo_rootx() + 15,
            y=event.y_root - root.winfo_rooty() + 15,
        )


def hide_tooltip(event: tk.Event) -> None:
    widget = event.widget
    if hasattr(widget, "tooltip_label"):
        widget.tooltip_label.destroy()


# ===========================================================================
# GUI — НАВИГАЦИЯ МЕЖДУ ЭКРАНАМИ
# ===========================================================================

def show_main() -> None:
    global current_screen
    current_screen = "main"
    donate_frame.pack_forget()
    main_frame.pack(fill="both", expand=True)


def show_donate() -> None:
    global current_screen
    current_screen = "donate"
    main_frame.pack_forget()
    build_donate_screen()
    donate_frame.pack(fill="both", expand=True)


def on_esc(event: tk.Event) -> None:
    if current_screen != "main":
        show_main()


# ===========================================================================
# GUI — DONATE SCREEN
# ===========================================================================

def build_donate_screen() -> None:
    for widget in donate_frame.winfo_children():
        widget.destroy()

    tk.Label(
        donate_frame, text="Донаты/Donations",
        font=("Segoe UI", 26, "bold"), bg=BG, fg=TEXT,
    ).pack(pady=10)

    for name, icon, address in DONATE_DATA:
        row = tk.Frame(donate_frame, cursor="hand2", bg=CARD, borderwidth=0)
        row.pack(anchor="center", pady=5)

        tk.Label(row, image=icon, fg=TEXT, cursor="hand2", bg=CARD, borderwidth=0).pack(
            side="left", padx=5
        )
        if name != "BTC":
            tk.Label(row, text="(Chain address - send any token)", fg=TEXT, cursor="hand2", bg=CARD, borderwidth=0).pack(
                side="left", padx=5
            )

        addr_label = tk.Label(
            row, text=address, fg=TEXT, cursor="hand2",
            font=("Consolas", 11), bg=BTN_HOVER,
            activebackground=BTN_HOVER, activeforeground=TEXT,
            relief="flat", borderwidth=0,
        )
        addr_label.pack(side="left", padx=5)

        addr_label.bind("<Enter>",  lambda e: show_tooltip(e, "Copy to clipboard"))
        addr_label.bind("<Leave>",  hide_tooltip)
        addr_label.bind("<Motion>", move_tooltip)
        addr_label.bind(
            "<Button-1>",
            lambda e, addr=address, w=addr_label: copy_address(addr, w),
        )

    tk.Button(
        donate_frame, text="Назад/Back", command=show_main,
        font=("Arial", 15), bg=BTN, fg=TEXT,
        activebackground=BTN_HOVER, activeforeground=TEXT,
        relief="flat", borderwidth=0, cursor="hand2",
    ).pack(pady=20)


# ===========================================================================
# GUI — MAIN SCREEN ACTIONS
# ===========================================================================

def pick_tdata() -> None:
    path = filedialog.askdirectory(title="Выбери папку tdata")
    if path:
        tdata_var.set(path)


def pick_out() -> None:
    path = filedialog.askdirectory(title="Выбери папку для сохранения")
    if path:
        out_var.set(path)


def log(text: str) -> None:
    log_text.insert("end", text + "\n")
    log_text.see("end")


def start_extraction() -> None:
    tdata_path = tdata_var.get().strip()
    out_dir = out_var.get().strip()
    passcode = passcode_var.get()

    if not os.path.isdir(tdata_path):
        log("Ошибка: папка tdata не найдена по указанному пути.")
        return
    if not os.path.isfile(os.path.join(tdata_path, "key_datas")):
        log("Ошибка: в этой папке нет файла key_datas. Проверь путь до tdata.")
        return

    start_btn.config(state="disabled")
    gallery_btn.config(state="disabled")
    log_text.delete("1.0", "end")
    status_label.config(text="Извлечение...", fg=ACCENT)

    def log_safe(text):
        root.after(0, log, text)

    def done(gallery_url):
        def finish():
            start_btn.config(state="normal")
            status_label.config(
                text="✓ Готово!" if gallery_url else "Ошибка, см. лог",
                fg=ACCENT,
            )
            if gallery_url:
                gallery_btn.config(state="normal")
                gallery_btn.gallery_url = gallery_url
        root.after(0, finish)

    threading.Thread(
        target=run_pipeline,
        args=(tdata_path, out_dir, passcode, log_safe, done),
        daemon=True,
    ).start()


def open_gallery() -> None:
    url = getattr(gallery_btn, "gallery_url", None)
    if url:
        webbrowser.open(url)


# ===========================================================================
# GUI — WINDOW CONSTRUCTION
# ===========================================================================

if __name__ == "__main__":
    if sys.platform == "win32":
        try:
            import ctypes
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except Exception:
            try:
                ctypes.windll.user32.SetProcessDPIAware()
            except Exception:
                pass

    root = tk.Tk()
    root.title("Telegram Cache Extractor - by Flex Air")

    _screen_w = root.winfo_screenwidth()
    _screen_h = root.winfo_screenheight()
    _win_w = max(700, min(860, int(_screen_w * 0.55)))
    _win_h = max(680, min(900, int(_screen_h * 0.85)))
    root.geometry(f"{_win_w}x{_win_h}")
    root.minsize(700, 640)
    root.configure(bg=BG)

    try:
        # На macOS Tk ожидает .icns, на Windows/Linux - .ico
        icon_name = "icon.icns" if sys.platform == "darwin" else "icon.ico"
        root.iconbitmap(resource_path(icon_name))
    except Exception:
        pass  # если файл иконки не найден (например, запуск без сборки) - используем иконку по умолчанию

    main_frame   = tk.Frame(root, bg=BG)
    donate_frame = tk.Frame(root, bg=BG)
    social_frame = tk.Frame(root, bg=BG)
    social_frame.place(relx=1.0, x=-10, y=10, anchor="ne")

    # ── Icons ────────────────────────────────────────────────────────────────────
    btc_icon      = tk.PhotoImage(file=resource_path("icons/btc_icon.png"))
    eth_icon      = tk.PhotoImage(file=resource_path("icons/etherium_icon.png"))
    bnb_icon      = tk.PhotoImage(file=resource_path("icons/bnb_icon.png"))
    sol_icon      = tk.PhotoImage(file=resource_path("icons/solana_icon.png"))
    ton_icon      = tk.PhotoImage(file=resource_path("icons/ton_icon.png"))
    tron_icon     = tk.PhotoImage(file=resource_path("icons/tron_icon.png"))
    copy_icon     = tk.PhotoImage(file=resource_path("icons/Copy_icon.png"))
    telegram_icon = tk.PhotoImage(file=resource_path("icons/telegram_icon.png"))
    youtube_icon  = tk.PhotoImage(file=resource_path("icons/YT_icon.png"))

    DONATE_DATA = [
        ("BTC", btc_icon,  "bc1qnjv8d2ecf3uwwugdf3jlxyc020e2ztc8s0zghv"),
        ("ETH", eth_icon,  "0x108e08febfbe3e47a9c15e484fd6587f4a0c6279"),
        ("BNB", bnb_icon,  "0x108e08febfbe3e47a9c15e484fd6587f4a0c6279"),
        ("SOL", sol_icon,  "GEgnqADD4WJTDz1syRMyaK9qjn2jhhEknhreoZwWXT9T"),
        ("TON", ton_icon,  "UQBZb8OHkXr08m1CWM_eGX40TMbeIUAVEWQeMLKl8RWZ2462"),
        ("TRX", tron_icon, "TJxdGZTtp9MeXF2EijYAR4BK5wNH99kJgW"),
    ]

    # ── Main frame: header ────────────────────────────────────────────────────────
    tk.Label(
        main_frame, text="TELEGRAM CACHE EXTRACTOR",
        font=("Segoe UI", 26, "bold"), bg=BG, fg=TEXT,
    ).pack(pady=(45, 0))

    tk.Label(
        main_frame, text="by IK of Flex Air",
        font=("Segoe UI", 10), bg=BG, fg="#aaaaaa",
    ).pack(pady=(0, 15))

    status_label = tk.Label(
        main_frame, text="Ready",
        font=("Arial", 18), bg=BG, fg=ACCENT,
    )
    status_label.pack(pady=(0, 10))

    # ── Main frame: пути и passcode ────────────────────────────────────────────────
    form = tk.Frame(main_frame, bg=BG)
    form.pack(pady=5, fill="x", padx=30)

    default_tdata = default_tdata_path()
    default_out = os.path.join(os.path.expanduser("~"), "Desktop", "telegram_extracted")

    tk.Label(form, text="Папка tdata:", bg=BG, fg=TEXT, font=("Arial", 11)).grid(row=0, column=0, sticky="w", pady=6)
    tdata_var = tk.StringVar(value=default_tdata)
    tk.Entry(form, textvariable=tdata_var, font=("Consolas", 10), bg=CARD, fg=TEXT,
             insertbackground=TEXT, relief="flat").grid(row=0, column=1, sticky="we", padx=8, pady=6)
    tk.Button(form, text="Обзор...", command=pick_tdata, font=("Arial", 10), bg=BTN, fg=TEXT,
              activebackground=BTN_HOVER, activeforeground=TEXT, relief="flat",
              borderwidth=0, cursor="hand2").grid(row=0, column=2, pady=6)

    tk.Label(form, text="Куда сохранить:", bg=BG, fg=TEXT, font=("Arial", 11)).grid(row=1, column=0, sticky="w", pady=6)
    out_var = tk.StringVar(value=default_out)
    tk.Entry(form, textvariable=out_var, font=("Consolas", 10), bg=CARD, fg=TEXT,
             insertbackground=TEXT, relief="flat").grid(row=1, column=1, sticky="we", padx=8, pady=6)
    tk.Button(form, text="Обзор...", command=pick_out, font=("Arial", 10), bg=BTN, fg=TEXT,
              activebackground=BTN_HOVER, activeforeground=TEXT, relief="flat",
              borderwidth=0, cursor="hand2").grid(row=1, column=2, pady=6)

    tk.Label(form, text="Passcode (если не задан - оставь пустым):", bg=BG, fg=TEXT,
             font=("Arial", 11)).grid(row=2, column=0, columnspan=2, sticky="w", pady=6)
    passcode_var = tk.StringVar(value="")
    tk.Entry(form, textvariable=passcode_var, show="*", font=("Consolas", 10), bg=CARD, fg=TEXT,
             insertbackground=TEXT, relief="flat", width=25).grid(row=3, column=0, sticky="w", pady=(0, 6))

    form.grid_columnconfigure(1, weight=1)

    # ── Main frame: кнопка запуска ─────────────────────────────────────────────────
    start_btn = tk.Button(
        main_frame, text="Начать извлечение", command=start_extraction,
        width=35, font=("Arial", 16), bg=BTN, fg=TEXT,
        activebackground=BTN_HOVER, activeforeground=TEXT,
        relief="flat", borderwidth=0, cursor="hand2",
    )
    start_btn.pack(pady=10)

    # ── Main frame: лог ──────────────────────────────────────────────────────────
    tk.Label(main_frame, text="Лог", font=("Arial", 13), bg=BG, fg=TEXT).pack(pady=(10, 5))

    log_frame = tk.Frame(main_frame, bg=CARD)
    log_frame.pack(fill="both", expand=True, padx=30, pady=(0, 10))

    scrollbar = tk.Scrollbar(log_frame, bg=BTN, troughcolor=BG)
    log_text = tk.Text(
        log_frame,
        font=("Consolas", 10), bg=PREVIEW_BG, fg=PREVIEW_TEXT,
        insertbackground="white", relief="flat",
        yscrollcommand=scrollbar.set,
    )
    scrollbar.config(command=log_text.yview)
    scrollbar.pack(side="right", fill="y")
    log_text.pack(side="left", fill="both", expand=True)

    gallery_btn = tk.Button(
        main_frame, text="Открыть галерею", command=open_gallery, state="disabled",
        width=35, font=("Arial", 16), bg=BTN, fg=TEXT,
        activebackground=BTN_HOVER, activeforeground=TEXT,
        relief="flat", borderwidth=0, cursor="hand2",
    )
    gallery_btn.pack(pady=(0, 15))

    # ── Main frame: Donate (top-left) ─────────────────────────────────────────────
    btn_donate = tk.Button(
        main_frame, text="Donate", command=show_donate,
        font=("Arial", 15), bg=BTN, fg=TEXT,
        activebackground=BTN_HOVER, activeforeground=TEXT,
        relief="flat", borderwidth=0, cursor="hand2",
    )
    btn_donate.place(x=10, y=10)

    # ── Social bar (top-right) ────────────────────────────────────────────────────
    socials_row = tk.Frame(social_frame, bg=BG)
    socials_row.pack(anchor="e", pady=2)

    btn_telegram = tk.Button(
        socials_row, image=telegram_icon, command=lambda: open_link(TELEGRAM_URL),
        bg=BTN, fg=TEXT, activebackground=BTN_HOVER, activeforeground=TEXT,
        relief="flat", borderwidth=0, cursor="hand2",
    )
    btn_telegram.pack(side="left")

    btn_copy_tg = tk.Button(
        socials_row, image=copy_icon, command=lambda: copy_link(TELEGRAM_URL),
        bg=BTN, fg=TEXT, activebackground=BTN_HOVER, activeforeground=TEXT,
        relief="flat", borderwidth=0, cursor="hand2",
    )
    btn_copy_tg.pack(side="left", padx=5)

    btn_youtube = tk.Button(
        socials_row, image=youtube_icon, command=lambda: open_link(YOUTUBE_URL),
        bg=BTN, fg=TEXT, activebackground=BTN_HOVER, activeforeground=TEXT,
        relief="flat", borderwidth=0, cursor="hand2",
    )
    btn_youtube.pack(side="left", padx=(20, 0))

    btn_copy_yt = tk.Button(
        socials_row, image=copy_icon, command=lambda: copy_link(YOUTUBE_URL),
        bg=BTN, fg=TEXT, activebackground=BTN_HOVER, activeforeground=TEXT,
        relief="flat", borderwidth=0, cursor="hand2",
    )
    btn_copy_yt.pack(side="left", padx=5)

    for btn, img in [
        (btn_telegram, telegram_icon),
        (btn_youtube,  youtube_icon),
        (btn_copy_tg,  copy_icon),
        (btn_copy_yt,  copy_icon),
    ]:
        btn.image = img

    # ===========================================================================
    # STARTUP
    # ===========================================================================

    root.bind("<Escape>", on_esc)

    main_frame.pack(fill="both", expand=True)
    root.mainloop()
