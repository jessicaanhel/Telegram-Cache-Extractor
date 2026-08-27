# TelegramCacheExtractor-macos — macOS front end

Dark UI for Telegram-Cache-Extractor, running in a native WKWebView window.
The Windows path (`app.py`'s tkinter screens, `installer.iss`, `build_macos.sh`)
is left completely untouched — this is additive.

## Files

| File | What it is |
| --- | --- |
| `ui/index.html` | The dark interface: sidebar, library grid, action bar, five states. No build step, no CDN. |
| `ui/app.js` | UI controller. Talks to the local API; falls back to demo data if the backend isn't running, so you can open `index.html` in a browser to review the design. |
| `main.py` | The macOS shell: imports the crypto from `app.py` unchanged, serves the UI on `127.0.0.1:<random port>`, opens the pywebview window. |
| `build.sh` | PyInstaller `.app` → ad-hoc sign → `.dmg`. |

## Run it

From the repo root:

```bash
pip install -r requirements.txt   # pywebview + pycryptodome
brew install ffmpeg               # for anything other than a passthrough copy
python macos/main.py              # run from the repo root so `import app` resolves
```

## Build the .app + .dmg

```bash
chmod +x macos/build.sh
./macos/build.sh
```

Produces `dist/TelegramCacheExtractor-macos.app` and
`dist/TelegramCacheExtractor-macos-<version>.dmg`, ad-hoc signed. Requires
`ffmpeg` on `PATH` (`brew install ffmpeg`) — the script bundles it into the
`.app` via `--add-binary`, and `icon.icns` in the repo root.

## API the UI expects

| Endpoint | Purpose |
| --- | --- |
| `GET /api/info` | tdata path, output folder, any already-indexed items |
| `POST /api/scan` | `{tdata, passcode}` — decrypts every cache blob into a temp staging dir |
| `GET /api/progress` | `{state, pct, log[], rows[], eta, result}` — polled 2.5×/s |
| `GET /api/items` | the indexed media list |
| `GET /api/thumb?id=` | serves the staged file, so photo cells show real thumbnails |
| `POST /api/convert` | `{ids, targets:{id:ext}, outDir}` — ffmpeg per file |
| `POST /api/pick` | native folder dialog (`{kind:"tdata"\|"out"}`) |
| `POST /api/cancel`, `POST /api/reveal` | stop a job; open the output in Finder |

## Notes before shipping

- **ffmpeg is required** for anything other than a passthrough copy — the build
  bundles the Homebrew binary via `--add-binary`. Video encodes use
  `h264_videotoolbox` (hardware, Apple Silicon and Intel alike).
- **Notarize.** An unsigned or ad-hoc-signed `.dmg` is blocked by Gatekeeper on
  any other Mac. The build script prints the two `notarytool` commands.
- Decrypted blobs live in a `tempfile.mkdtemp()` staging dir and are deleted when
  the window closes — nothing is written outside it until the user converts.
- The passcode field is never persisted; it goes straight into
  `get_local_key()` and is dropped.
