/* TelegramCacheExtractor-macos — macOS UI controller.
   Talks to the local Python API (main.py). If the API is not reachable
   the UI falls back to demo data so the interface can be reviewed in a browser. */

const $ = (s) => document.querySelector(s);
const $$ = (s) => Array.from(document.querySelectorAll(s));

const TARGETS = { image: ["jpg", "png", "webp"], video: ["mp4", "webm", "gif"], audio: ["mp3", "wav", "m4a"] };
const DEFAULT_TARGET = { image: "jpg", video: "mp4", audio: "mp3" };
const KIND_LABEL = { image: "photo", video: "video", audio: "audio" };

const S = {
  demo: false,
  screen: "empty",
  filter: "all",
  query: "",
  items: [],
  selected: new Set(),
  targets: {},          // id -> ext
  outDir: "",
  tdata: "",
  result: null,
  poll: null,
};

/* ---------- api ---------- */

async function api(path, body) {
  const res = await fetch("/api" + path, body ? {
    method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body),
  } : undefined);
  if (!res.ok) throw new Error((await res.text()) || res.statusText);
  return res.json();
}

async function boot() {
  try {
    const info = await api("/info");
    S.tdata = info.tdata || "";
    S.outDir = info.outDir || "";
    $("#tdata").value = S.tdata;
    if (info.items && info.items.length) { setItems(info.items); go("library"); } else { go("empty"); }
  } catch {
    S.demo = true;
    document.body.classList.add("demo-mode");
    S.tdata = "~/Library/Application Support/Telegram Desktop/tdata";
    S.outDir = "~/Pictures/TelegramCacheExtractor-macos";
    $("#tdata").value = S.tdata;
    setItems(demoItems());
    go("library");
  }
  paintSource();
  paintOut();
}

/* ---------- items ---------- */

function setItems(items) {
  S.items = items;
  S.selected = new Set(items.map((i) => i.id));
  S.targets = {};
  paintCounts();
}

function visible() {
  const q = S.query.trim().toLowerCase();
  return S.items.filter((i) =>
    (S.filter === "all" || i.kind === S.filter) &&
    (!q || i.name.toLowerCase().includes(q) || (i.source || "").toLowerCase().includes(q)));
}

const targetOf = (i) => S.targets[i.id] || DEFAULT_TARGET[i.kind];
const outName = (i) => i.name + "." + targetOf(i);

/* ---------- screens ---------- */

const TITLES = {
  empty: ["Open a tdata folder", "Nothing indexed yet"],
  scanning: ["Scanning", "Decrypting cache blobs"],
  library: ["Library", ""],
  converting: ["Converting", "Writing to disk"],
  done: ["Finished", "All conversions complete"],
};

function go(screen) {
  S.screen = screen;
  const id = { empty: "s-empty", scanning: "s-scan", library: "s-lib", converting: "s-conv", done: "s-done" }[screen];
  $$(".screen").forEach((el) => el.classList.toggle("on", el.id === id));
  $("#title").textContent = TITLES[screen][0];
  $("#subtitle").textContent = screen === "library"
    ? S.items.length + " recoverable files"
    : TITLES[screen][1];
  $("#btn-rescan").disabled = screen === "scanning" || screen === "converting";
  if (screen === "library") paintGrid();
}

/* ---------- painting ---------- */

function paintCounts() {
  const c = { all: S.items.length, image: 0, video: 0, audio: 0 };
  S.items.forEach((i) => { c[i.kind] = (c[i.kind] || 0) + 1; });
  $$("[data-count]").forEach((el) => { el.textContent = c[el.dataset.count] || 0; });
}

function paintSource() {
  $("#src-path").textContent = S.tdata || "—";
  const ok = S.items.length > 0;
  $("#src-dot").className = "dot" + (ok ? " live" : " bad");
  $("#src-state").textContent = S.demo ? "demo data" : ok ? "local key decrypted" : "not opened";
}

function paintOut() { $("#out-path").textContent = S.outDir || "—"; }

function paintGrid() {
  const items = visible();
  const grid = $("#grid");
  grid.innerHTML = "";
  for (const i of items) {
    const cell = document.createElement("div");
    cell.className = "cell";
    cell.setAttribute("aria-selected", S.selected.has(i.id));
    const thumb = i.kind === "image" && !S.demo
      ? `<img src="/api/thumb?id=${encodeURIComponent(i.id)}" alt="" loading="lazy" />`
      : `<span class="kind">${KIND_LABEL[i.kind]}</span>`;
    const opts = TARGETS[i.kind].map((t) =>
      `<option value="${t}"${t === targetOf(i) ? " selected" : ""}>${t.toUpperCase()}</option>`).join("");
    cell.innerHTML =
      `<div class="thumb">${thumb}<div class="tick"><i></i></div>` +
      (i.detail ? `<span class="badge">${i.detail}</span>` : "") + `</div>` +
      `<div class="meta">` +
        `<div class="src-name">${i.source}</div>` +
        `<div class="out">${outName(i)}</div>` +
        `<div class="line"><span>${i.size}</span><select data-id="${i.id}">${opts}</select></div>` +
      `</div>`;
    cell.addEventListener("click", (e) => {
      if (e.target.tagName === "SELECT") return;
      S.selected.has(i.id) ? S.selected.delete(i.id) : S.selected.add(i.id);
      cell.setAttribute("aria-selected", S.selected.has(i.id));
      paintSelection();
    });
    cell.querySelector("select").addEventListener("change", (e) => {
      S.targets[i.id] = e.target.value;
      cell.querySelector(".out").textContent = outName(i);
    });
    grid.appendChild(cell);
  }
  paintSelection();
}

function paintSelection() {
  const n = S.selected.size;
  $("#selection").textContent = n ? `${n} of ${S.items.length} selected` : "Nothing selected";
  $("#btn-convert").textContent = n ? `Convert ${n}` : "Convert";
  $("#btn-convert").disabled = !n;
  const vis = visible();
  const all = vis.length > 0 && vis.every((i) => S.selected.has(i.id));
  $("#btn-select-all").textContent = all ? "Deselect all" : "Select all";
}

function setFilter(f) {
  S.filter = f;
  $$("#nav .nav-item").forEach((b) => b.setAttribute("aria-selected", b.dataset.filter === f));
  $$("#chips .chip").forEach((b) => b.setAttribute("aria-pressed", b.dataset.filter === f));
  if (S.screen !== "library") go("library"); else paintGrid();
}

/* ---------- scan ---------- */

async function startScan() {
  $("#err-empty").textContent = "";
  const tdata = $("#tdata").value.trim();
  const passcode = $("#pass").value;
  if (!tdata) { $("#err-empty").textContent = "Choose the tdata folder first."; return; }
  S.tdata = tdata;
  $("#scan-log").textContent = "";
  $("#scan-bar").style.width = "0%";
  $("#scan-pct").textContent = "0%";
  go("scanning");
  if (S.demo) return fakeProgress("#scan-bar", "#scan-pct", () => { paintSource(); go("library"); });
  try {
    await api("/scan", { tdata, passcode });
    pollProgress("scan");
  } catch (e) { fail(e); }
}

/* ---------- convert ---------- */

async function startConvert() {
  const ids = S.items.filter((i) => S.selected.has(i.id)).map((i) => i.id);
  if (!ids.length) return;
  const targets = {};
  ids.forEach((id) => { const i = S.items.find((x) => x.id === id); targets[id] = targetOf(i); });
  $("#conv-title").textContent = `Converting ${ids.length} files`;
  paintQueue(ids.map((id) => ({ id, status: "queued" })));
  $("#conv-bar").style.width = "0%";
  $("#conv-pct").textContent = "0%";
  go("converting");
  if (S.demo) return fakeProgress("#conv-bar", "#conv-pct", () => finish({ count: ids.length, bytes: "412 MB", outDir: S.outDir }), ids);
  try {
    await api("/convert", { ids, targets, outDir: S.outDir });
    pollProgress("convert");
  } catch (e) { fail(e); }
}

function paintQueue(rows) {
  const q = $("#queue");
  q.innerHTML = "";
  for (const r of rows) {
    const i = S.items.find((x) => x.id === r.id);
    if (!i) continue;
    const cls = r.status === "written" ? "done" : r.status === "encoding" ? "live" : r.status === "failed" ? "fail" : "";
    const el = document.createElement("div");
    el.className = "qrow";
    el.innerHTML = `<span class="kind">${KIND_LABEL[i.kind]}</span><span class="name">${outName(i)}</span><span class="st ${cls}">${r.status}</span>`;
    q.appendChild(el);
  }
}

function finish(result) {
  S.result = result;
  $("#done-title").textContent = `${result.count} files recovered`;
  $("#done-sub").textContent = `Written to ${result.outDir}${result.bytes ? " · " + result.bytes : ""}`;
  go("done");
}

/* ---------- progress ---------- */

function pollProgress(phase) {
  clearInterval(S.poll);
  S.poll = setInterval(async () => {
    let p;
    try { p = await api("/progress"); } catch (e) { clearInterval(S.poll); return fail(e); }
    const bar = phase === "scan" ? "#scan-bar" : "#conv-bar";
    const pct = phase === "scan" ? "#scan-pct" : "#conv-pct";
    $(bar).style.width = p.pct + "%";
    $(pct).textContent = Math.round(p.pct) + "%";
    if (phase === "scan" && p.log) $("#scan-log").textContent = p.log.slice(-5).join("\n");
    if (phase === "convert") {
      if (p.rows) paintQueue(p.rows);
      $("#conv-eta").textContent = p.eta || "";
    }
    if (p.state === "error") { clearInterval(S.poll); return fail(new Error(p.message)); }
    if (p.state === "done") {
      clearInterval(S.poll);
      if (phase === "scan") {
        const info = await api("/items");
        setItems(info.items);
        paintSource();
        go("library");
      } else {
        finish(p.result);
      }
    }
  }, 400);
}

function fail(e) {
  clearInterval(S.poll);
  $("#err-empty").textContent = String(e.message || e);
  go("empty");
}

/* ---------- demo ---------- */

function fakeProgress(bar, pct, done, ids) {
  let v = 0;
  clearInterval(S.poll);
  S.poll = setInterval(() => {
    v = Math.min(100, v + 7);
    $(bar).style.width = v + "%";
    $(pct).textContent = v + "%";
    if (bar === "#scan-bar") {
      $("#scan-log").textContent = ["key_datas → local key OK (256 bytes)", "walking user_data/cache/…",
        "TDEF blobs read: " + v * 47, "sniffing magic bytes → jpg / mp4 / ogg"].slice(0, 1 + Math.floor(v / 25)).join("\n");
    }
    if (ids) {
      paintQueue(ids.map((id, n) => ({
        id, status: n / ids.length * 100 < v ? "written" : n / ids.length * 100 < v + 20 ? "encoding" : "queued",
      })));
      $("#conv-eta").textContent = "Hardware encode · about " + Math.max(1, Math.round((100 - v) / 12)) + " s remaining";
    }
    if (v >= 100) { clearInterval(S.poll); done(); }
  }, 240);
}

function demoItems() {
  const raw = [
    ["4a9f2e1c", "image", "jpg", "IMG_2291", "2.4 MB", "1920×1440"],
    ["8b03df57", "video", "mp4", "clip_0412", "18.7 MB", "0:24"],
    ["12c7aa90", "image", "webp", "IMG_2292", "1.9 MB", "1280×960"],
    ["7fe4b118", "audio", "ogg", "voice_0093", "640 KB", "0:41"],
    ["93ad2266", "image", "jpg", "receipt_may", "820 KB", "1080×1440"],
    ["5c1e77b4", "video", "mp4", "clip_0413", "42.1 MB", "1:12"],
    ["a02b39ff", "image", "png", "screenshot_ticket", "3.1 MB", "1668×2388"],
    ["6d8c4a13", "audio", "ogg", "voice_0094", "1.2 MB", "1:18"],
    ["ee7710b8", "image", "jpg", "IMG_2305", "2.8 MB", "3024×4032"],
    ["31f6c2d9", "video", "webm", "screen_rec", "96.4 MB", "3:05"],
    ["bb920e4a", "image", "webp", "sticker_03", "540 KB", "512×512"],
    ["0f45d8c6", "audio", "mp3", "song_snip", "4.6 MB", "2:52"],
    ["c7a11f30", "image", "jpg", "IMG_2318", "2.2 MB", "4032×3024"],
    ["9e6b0d72", "video", "mp4", "clip_0418", "24.9 MB", "0:37"],
  ];
  return raw.map(([id, kind, ext, name, size, detail]) => ({
    id, kind, name, size, detail, source: `cache/${id.slice(0, 2)}/${id} · TDEF · ${ext}`,
  }));
}

/* ---------- wiring ---------- */

$("#btn-scan").addEventListener("click", startScan);
$("#btn-convert").addEventListener("click", startConvert);
$("#btn-rescan").addEventListener("click", () => go("empty"));
$("#btn-reopen").addEventListener("click", () => go("empty"));
$("#btn-back").addEventListener("click", () => go("library"));
$("#btn-cancel-scan").addEventListener("click", async () => { clearInterval(S.poll); if (!S.demo) await api("/cancel", {}); go("empty"); });
$("#btn-cancel-conv").addEventListener("click", async () => { clearInterval(S.poll); if (!S.demo) await api("/cancel", {}); go("library"); });
$("#btn-select-all").addEventListener("click", () => {
  const vis = visible();
  const all = vis.every((i) => S.selected.has(i.id));
  vis.forEach((i) => (all ? S.selected.delete(i.id) : S.selected.add(i.id)));
  paintGrid();
});
$("#search").addEventListener("input", (e) => { S.query = e.target.value; if (S.screen === "library") paintGrid(); });
$$("#nav .nav-item, #chips .chip").forEach((b) => b.addEventListener("click", () => setFilter(b.dataset.filter)));

$("#btn-pick").addEventListener("click", async () => {
  if (S.demo) return;
  const r = await api("/pick", { kind: "tdata" });
  if (r.path) { $("#tdata").value = r.path; S.tdata = r.path; paintSource(); }
});
$("#btn-out").addEventListener("click", async () => {
  if (S.demo) return;
  const r = await api("/pick", { kind: "out" });
  if (r.path) { S.outDir = r.path; paintOut(); }
});
$("#btn-reveal").addEventListener("click", () => { if (!S.demo) api("/reveal", { path: (S.result && S.result.outDir) || S.outDir }); });

const drop = $("#drop");
["dragenter", "dragover"].forEach((ev) => drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.add("hot"); }));
["dragleave", "drop"].forEach((ev) => drop.addEventListener(ev, () => drop.classList.remove("hot")));
drop.addEventListener("drop", (e) => {
  e.preventDefault();
  const f = e.dataTransfer.files[0];
  if (f) { $("#tdata").value = f.path || f.name; S.tdata = $("#tdata").value; paintSource(); }
});

document.addEventListener("keydown", (e) => {
  if (e.metaKey && e.key === "a" && S.screen === "library") { e.preventDefault(); $("#btn-select-all").click(); }
  if (e.key === "Enter" && S.screen === "empty") startScan();
});

boot();
