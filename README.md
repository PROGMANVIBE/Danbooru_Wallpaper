# Danbooru Wallpaper Application

A standalone Windows desktop wallpaper application that streams Danbooru artwork, animated GIFs, and silent MP4 videos (`≤ 15 MB`, audio strictly muted) directly behind your desktop icons. Powered by an ephemeral WebView2 renderer and a cookie-free local Python proxy (`http://127.0.0.1:8088/media`) with Cloudflare DNS-over-HTTPS (DoH) resolution, it features three distinct display modes (**Continuous 4-Way Scroll**, **Polaroid Collage**, and **Orientation-Matched Fullscreen Slideshow**), a floating search bar with live tag autocomplete, search bookmarks, Light/Dark mode UI theming, DPAPI-encrypted credentials, real-time diagnostic logs with a built-in Glossary, multi-monitor support, and system tray controls.

---

# FEATURES

- **Ephemeral Zero-Cache Architecture**: Runs WebView2 in strict in-memory private mode (`private_mode=True`) with disk caching disabled and automatically cleans up any legacy `webview_profile` folder.
- **Full Local Media Proxy (`127.0.0.1:8088/media`)**: All `<img>` and `<video>` elements in the WebView point exclusively to the local Python `/media` proxy endpoint rather than contacting `cdn.donmai.us` directly. WebView2 never makes external network requests, preventing Cloudflare `403 Forbidden` blocks and eliminating browser disk cache creation.
- **Hybrid HTTP/2 & Cloudflare DoH Transport Engine**:
  - Resolves `danbooru.donmai.us` and `cdn.donmai.us` hostnames via Cloudflare's public DNS-over-HTTPS endpoint (`https://cloudflare-dns.com/dns-query` over `1.1.1.1` / `1.0.0.1`) prior to connection, bypassing ISP-level plain-text DNS blocks and poisoning.
  - Uses `curl_cffi` with Chrome HTTP/2 impersonation when available, and automatically falls back to a built-in Python standard-library TLS 1.3 + SNI transport (`DoHSNIHTTPSConnection` / `StdlibDoHSession`) if `curl_cffi` is absent—ensuring compiled executables never crash with `ModuleNotFoundError`.
  - Operates 100% cookie-free using pure Danbooru API authentication (no `cf_clearance` cookies, no "Verify Human" challenge browser windows, and no profile cache purging required).
- **Three Configurable Display Modes (Per-Monitor)**:
  1. **Scrolling Slideshow (`scroll`)**: Continuous infinite ribbon supporting **4-way scroll directions** (**Scroll Left `←`**, **Scroll Right `→`**, **Scroll Up `↑`**, and **Scroll Down `↓`**), adjustable **Scroll Speed** (`0.1 – 600 px/s`), and **Image Gap** (`0 – 64 px`).
  2. **Polaroid Collage (`collage`)**: Continuous stacking Polaroid drop animation with hybrid canvas-baking to keep DOM memory low, adjustable **Drop Speed** (`0.2 – 4.0`), **Minimum Size** (`120 – 600 px`), **Maximum Size** (`150 – 900 px`), **Spawn/Drop Delay** (`0 – 600 s`), and a **Fill Screen** burst button (with a 30-second cooldown).
  3. **Fullscreen Slideshow (`slideshow`)**: Displays one file at a time filling the entire screen (`100vw × 100vh`). Automatically filters API posts so only files matching the monitor's orientation are displayed (landscape media on landscape screens such as `16:9`; portrait media on portrait screens such as `9:16`), with automatic fast pagination if a batch contains only opposite-orientation posts. Includes adjustable **Fade Transition** (`0 – 10`, where `0` is an instant `0.0s` cut and `10` is a smooth `1.0s` cross-fade) and **Slide Display Time** (`0 – 600 s`).
- **Dynamic Mode-Specific Display Tab**: In the Application Settings window, the **Display** tab dynamically hides settings for inactive display modes and only shows the controls belonging to the currently selected mode (`scroll`, `collage`, or `slideshow`).
- **Light Mode & Dark Mode Theme Switcher**: Located on the **Credentials** tab of the Application Settings window. Toggles both the Application Settings window (including the Glossary modal) and the Floating Search Bar between **Light Mode** (clean white/light-gray theme with dark text) and **Dark Mode** (black/charcoal theme with white text), saving your preference automatically.
- **Floating Desktop Search Bar**: A movable on-screen search widget that lets you query Danbooru tags directly from your desktop.
- **Free 2D Movement & Position Lock**: Drag the search bar anywhere across your screen using the move handle (`✥`), or toggle the lock button (`🔓 Unlocked` / `🔒 Locked`) on the Credentials tab to fix it in place.
- **Live Tag Autocomplete Suggestions**: Queries Danbooru's `/tags.json` endpoint as you type to display the top 5 matching tags along with their post counts.
- **Search Bookmarks**: Save frequently used tag combinations and recall or delete them via the `▲` drop-down menu.
- **Dual-Level Pause Controls**:
  - **Search Bar `PAUSE` Button**: Pauses wallpaper movement and slide transitions (scrolling, collage drops, or slideshow timer) while keeping onscreen animated GIFs and silent MP4 videos playing.
  - **Logs Tab `PAUSE APPLICATION` Master Button**: Freezes the entire wallpaper onto a static canvas snapshot, pauses all video decoding, and halts all local proxy streams and outbound Danbooru API requests.
- **Buffered & Shuffled Playback**: Pre-fetches pages of up to 100 posts (`.jpg`, `.jpeg`, `.png`, `.webp`, `.gif`, and `.mp4` files up to `15 MB` with audio strictly muted), shuffles them randomly per page, and deduplicates posts per screen.
- **Multi-Monitor Support**: Automatically detects all connected monitors via Win32 `EnumDisplayMonitors`, attaches independent wallpaper surfaces behind desktop icons (`Progman` / `WorkerW` across Windows 10, Windows 11 21H2–23H2, and Windows 11 24H2+), and supports per-monitor enable/disable and display mode settings.
- **Aggregated Real-Time Logs & Built-In Glossary**: The **Logs** tab captures live server, DoH, API, proxy, and UI events and includes a **Glossary** button that opens a reference dialog explaining every log category.
- **Zero Hardcoded Credentials & DPAPI Encryption**: No default credentials exist in the codebase. Credentials entered on the **Credentials** tab are stored locally in `%APPDATA%\DanbooruWallpaper\config.json` with your API Key encrypted at rest via Windows Data Protection API (`CryptProtectData` / `CryptUnprotectData`).

---

# HOW TO USE THE PROGRAM

- **Searching Tags**: Type any standard Danbooru tag combination into the search bar (default search: `scenery no_humans`) and press **Enter** to queue the search for the next buffer cycle, or click the refresh button (`⟳`) / press **Shift + Enter** for an immediate refresh. All streamed files are shuffled per page so repeated searches never play in the same static order. To stream your Danbooru favorites, search `ordfav:YOUR_USERNAME`.
- **Immediate Refresh**: Press **Shift + Enter** in the search box or click the `⟳` button to immediately clear the media buffer, increment the cache epoch, and fetch fresh posts for your query.
- **Selecting Tag Suggestions**: Use the **Up** and **Down** arrow keys to highlight a suggested tag from the autocomplete popup, then press **Enter** (or click the item) to insert it.
- **Saving & Managing Bookmarks**: Click the arrow button (`▲`) on the right side of the search input to open the bookmarks menu. Click **💾 Save Current Search** to bookmark the current query, click any saved query to run it immediately, or click `-` next to a saved query to remove it.
- **Pausing Wallpaper Motion vs. Pausing the Application**:
  - Click **PAUSE** on the floating search bar to pause scrolling, collage drops, or slideshow transitions while keeping animated GIFs and MP4s looping.
  - Open **Settings → Logs** and click **PAUSE APPLICATION** to completely freeze the display and stop all network/proxy activity.
- **Minimizing to System Tray**: Click the vertical accent bar on the far-left edge of the search widget, press **Escape** when no dropdowns are open, or right-click the cardboard box system tray icon and select **Show Search Bar**.
- **Configuring Credentials, Theme, Display Modes & Logs**: Right-click the cardboard box system tray icon and select **Settings**:
  - **Credentials Tab**: Enter your Danbooru `Username`, `User ID`, and `API Key`, lock/unlock the search bar position, and switch between **Light Mode** and **Dark Mode**.
  - **Display Tab**: Select a target monitor, enable or disable the wallpaper on that screen, and choose **Display Mode** (`scroll`, `collage`, or `slideshow`). Only the settings for the active mode are shown, and slider/input changes apply live.
  - **Logs Tab**: Pause/resume the entire application, click **Glossary** to view definitions for all log prefixes, or click **Clear Logs**.

---

# REQUIREMENTS

### Runtime Requirements
- **Operating System**: Windows 10 or Windows 11 (64-bit), including Windows 11 24H2+
- **WebView2 Runtime**: Microsoft Edge WebView2 Evergreen Runtime (pre-installed on Windows 11 and modern Windows 10 systems)
- **Internet Connection**: Active broadband connection to communicate with Danbooru and Cloudflare DoH (`1.1.1.1`)

### Build / Source Requirements (If running from source or compiling)
- **Python**: Version 3.10 or higher
- **Python Packages**:
  - `pywebview`
  - `pystray`
  - `Pillow`
  - `curl_cffi` *(recommended for Chrome HTTP/2 impersonation; automatic stdlib DoH + TLS 1.3 SNI fallback is built in if omitted)*
  - `pyinstaller` *(for building the standalone `.exe`)*

---

# INSTALLATION & BUILDING THE EXECUTABLE

### Installing Dependencies (Source / Build Environment)
```powershell
pip install pyinstaller pywebview pystray pillow curl_cffi
```

### Compiling the Standalone Executable (`.exe`) with PyInstaller
Run the following command in PowerShell or Command Prompt from the folder containing `danbooru_service.py`, `index.html`, and `project.json`:

```powershell
python -m PyInstaller --noconfirm --onefile --noconsole `
  --name "DanbooruWallpaper" `
  --add-data "index.html;." `
  --add-data "project.json;." `
  --hidden-import "webview" `
  --hidden-import "pystray" `
  --hidden-import "PIL" `
  --hidden-import "curl_cffi" `
  --collect-all "curl_cffi" `
  danbooru_service.py
```

*(Note: You can replace `--onefile` with `--onedir` if you prefer an unpacked release directory. Even if `curl_cffi` is not installed in the build environment, the executable will launch cleanly using its built-in standard-library DoH + TLS 1.3 SNI transport layer.)*

Launch `dist\DanbooruWallpaper.exe`.

---

# HOW TO FIND YOUR DANBOORU USERNAME, USER ID, AND API KEY

While the application can run in anonymous API mode (limited by Danbooru to 2 search tags at a time and lower rate limits), configuring your Danbooru account credentials unlocks higher rate limits, multi-tag searches (for Gold/Platinum tiers), and authenticated HTTP Basic Auth requests:

1. Log into your account on [https://danbooru.donmai.us/](https://danbooru.donmai.us/).
2. Click on **My Account** (Profile).
3. **Username**: Your account name as displayed on your profile.
4. **User ID**: Listed near the top of your account profile (a numeric ID, e.g., 6–7 digits).

### Generating / Viewing Your API Key:
1. Log into your account on [https://danbooru.donmai.us/](https://danbooru.donmai.us/).
2. Click on **My Account**.
3. Locate **API Key** at the bottom of your profile settings and click **View** (or **Manage**).
4. If an API Key already exists, copy it; otherwise, generate a new API Key and copy the alphanumeric key.

---
> **IMPORTANT SECURITY NOTICE**: Your API key is equivalent to your account password. Anyone with your API key has full access to your Danbooru account. Never share your API key with untrusted applications or post it publicly.

The application encrypts your API key at rest using the native Windows Data Protection API (**DPAPI** via `CryptProtectData` / `CryptUnprotectData` in `ctypes`) tied specifically to your logged-in Windows user account on your machine. All configuration files (`config.json`, `project.json`, `saved_searches.json`) are stored in:
`C:\Users\<Current_User>\AppData\Roaming\DanbooruWallpaper`
This folder can be deleted at any time and the application will cleanly recreate it on the next launch.

Enter your **Username**, **User ID**, and **API Key** into the **Credentials** tab of the Application Settings window and click **Save Credentials**.

---

# WHY IS THIS INFORMATION NEEDED?

Danbooru's API guidelines require `USERNAME` and `API_KEY` for HTTP Basic Authentication / API query authentication—unlocking account-tier tag limits and higher rate limits—while your `USER_ID` and `USERNAME` are used to construct a descriptive, compliant `User-Agent` header:
`DanbooruWallpaperService/2.0 (by <USERNAME>; user #<USER_ID>)`

Combined with Cloudflare DNS-over-HTTPS (`1.1.1.1`) hostname resolution and local `/media` binary streaming, this pure API architecture avoids ISP DNS blocks and Cloudflare browser challenges without ever writing persistent browser profile caches or cookies to disk.

More information on Danbooru's official API guidelines can be found at:
[https://danbooru.donmai.us/wiki_pages/help:api](https://danbooru.donmai.us/wiki_pages/help:api)

---

## APPLICATION LOGS GLOSSARY

This glossary explains every log prefix and message that can appear in the **Logs** tab of the Application Settings window (also accessible anytime in-app by clicking the **Glossary** button on the Logs tab).

---

### NORMAL OPERATION LOGS (Routine)

**`[SERVER] Service running on http://127.0.0.1:8088 (<transport_mode>)`**
- **What it means**: The local Python HTTP server and `/media` streaming proxy started on `127.0.0.1:8088`, indicating whether `curl_cffi HTTP/2 + DoH` or the `stdlib TLS 1.3 + DoH SNI fallback` transport is active.
- **When it happens**: Once, immediately when you launch the application.

**`[DOH] Resolved <hostname> -> <ip_address> via Cloudflare DoH`**
- **What it means**: Python queried Cloudflare's DNS-over-HTTPS service (`1.1.1.1`) to resolve `danbooru.donmai.us` or `cdn.donmai.us` and cached the IP for 15 minutes.
- **When it happens**: On startup and once every 15 minutes when the DoH DNS cache refreshes.

**`[AUTH] Active transport engine: <transport_mode>`**
- **What it means**: Reports whether the application is using `curl_cffi HTTP/2` or the built-in `stdlib TLS 1.3 + DoH SNI fallback`.
- **When it happens**: On startup when initializing the HTTP session.

**`[AUTH] Loaded DPAPI-protected credentials for user '<username>' (#<id>)`**
- **What it means**: The program decrypted your saved Danbooru credentials from `config.json` in `%APPDATA%\DanbooruWallpaper` and applied them to the session.
- **When it happens**: Once at startup if credentials were previously saved (otherwise logs that it is running in anonymous 2-tag mode and opens Settings).

**`[AUTH] Credentials updated from Settings for user '<username>'.`**
- **What it means**: You clicked **Save Credentials** on the Credentials tab. Your DPAPI-encrypted API key and username are now active.
- **When it happens**: Whenever you save changes on the Credentials tab.

**`[WIN32] Win11 24H2+ mode / Classic WorkerW mode: Attached '<window_title>' HWND ...`**
- **What it means**: The native Windows desktop attachment engine positioned the WebView2 wallpaper window behind your desktop icons for a connected monitor.
- **When it happens**: Once per monitor during startup.

**`[WEBVIEW] Applied display properties to <screen_id> (enabled=<True/False>).`**
- **What it means**: Synchronized the selected Display Mode (`scroll`, `collage`, or `slideshow`), sliders, and screen enable state to the target monitor's WebView2 instance.
- **When it happens**: At startup and whenever you adjust controls on the **Display** tab.

**`[API] Requesting Page <page_number> for tags: '<search_tags>' via <transport_mode>`**
- **What it means**: Python is querying `https://danbooru.donmai.us/posts.json` for a page of up to 100 posts matching your tags.
- **When it happens**: On startup, after a search refresh, or when the in-memory post buffer runs low.

**`[FETCH] Fetched and shuffled <N> media items (Page <P>) for '<search_tags>' (filtered <M> oversized MP4s).`**
- **What it means**: Python received the posts from Danbooru, filtered out unsupported formats or MP4 videos larger than `15 MB`, rewrote all media URLs to point to `http://127.0.0.1:8088/media`, and shuffled the batch randomly.
- **When it happens**: Immediately after an `[API]` page request completes.

**`[SERVER] Client '<screen_id>' requested batch from /api`**
- **What it means**: A monitor's WebView2 wallpaper client requested the next batch of shuffled posts from Python's RAM buffer.
- **When it happens**: Periodically as your wallpaper scrolls, drops Polaroids, or advances slides.

**`[PING] Client polled /epoch (<count> times in last <seconds>s)`**
- **What it means**: Heartbeat summary confirming that active WebView2 wallpaper windows are polling `/epoch` every second for refresh and pause updates (aggregated once every 60 seconds to keep logs clean).
- **When it happens**: Once every 60 seconds while the application is unpaused.

---

### USER INTERACTION LOGS (Informational)

**`[SEARCH] Queued tags: '<search_tags>'`**
- **What it means**: You typed tags in the search bar and pressed **Enter**. The query is queued and will load once the current buffer drains.
- **When it happens**: When pressing **Enter** in the search bar.

**`[REFRESH] Immediate refresh triggered. Epoch: <E> | Tags: '<search_tags>'`**
- **What it means**: You clicked `⟳` or pressed **Shift + Enter**. The in-memory buffer was cleared, the epoch incremented, and a new API fetch started immediately.
- **When it happens**: When forcing an immediate refresh.

**`[SEARCH] Saved query to bookmarks: '<search_tags>'` / `Removed query from bookmarks: '<search_tags>'`**
- **What it means**: You added or deleted a saved search in the `▲` bookmarks dropdown.
- **When it happens**: When managing saved searches.

**`[UI] Switched application theme to LIGHT / DARK mode.`**
- **What it means**: You clicked the **Dark Mode** / **Light Mode** toggle button on the Credentials tab, re-theming the Settings window, Glossary dialog, and Floating Search Bar.
- **When it happens**: When toggling the application theme.

**`[UI] Search bar lock state set to: True / False`**
- **What it means**: You toggled the `🔓 Unlocked` / `🔒 Locked` button on the Credentials tab.
- **When it happens**: When locking or unlocking the search bar position.

**`[UI] Wallpaper motion paused via search bar (GIFs and MP4 videos remain playing).` / `Wallpaper motion resumed via search bar.`**
- **What it means**: You clicked the **PAUSE** button on the floating search bar to pause or resume scrolling/collage/slideshow motion.
- **When it happens**: When toggling the search bar `PAUSE` button.

**`[COLLAGE] Triggered Fill Screen burst on <screen_id>.`**
- **What it means**: You clicked the **Fill Screen** button in Collage mode on the Display tab, spawning a rapid burst of Polaroids to cover the monitor and starting the 30-second button cooldown.
- **When it happens**: When clicking **Fill Screen** on the Display tab.

**`[APP] Application PAUSED (display frozen, proxy streams & API calls stopped).` / `Application RESUMED.`**
- **What it means**: You toggled the master **PAUSE APPLICATION** button on the Logs tab.
- **When it happens**: When pausing or resuming the entire application from the Logs tab.

**`[APP] Shutting down application...`**
- **What it means**: You clicked **Exit** in the system tray menu. All threads, sockets, and WebView2 windows are closing cleanly.
- **When it happens**: When exiting the program.

---

### ERROR, SECURITY & WARNING LOGS

**`[API] HTTP 422 (2-tag limit on current account tier). Retrying with '<first_two_tags>'`**
- **What it means**: Anonymous and Member-tier Danbooru accounts are limited to searching 2 tags at a time. Python automatically trimmed your query to the first 2 tags and retried so your wallpaper continues streaming.
- **Action needed**: Use up to 2 tags, or enter credentials for a Gold/Platinum account on the Credentials tab.

**`[ERROR] No posts found for '<search_tags>'. Backing off <N>s...`**
- **What it means**: The tag combination returned 0 results on Danbooru (often due to a typo or incompatible tags).
- **Action needed**: Check tag spelling in the search bar or use autocomplete suggestions.

**`[ERROR] Fetch error: HTTP 401 Unauthorized: Check Username and API Key in Credentials tab. Backing off <N>s...`**
- **What it means**: Danbooru rejected the Username or API Key entered in Settings.
- **Action needed**: Open **Settings → Credentials** and verify your Danbooru Username and API Key.

**`[ERROR] Fetch error: HTTP 429 Too Many Requests: Rate limit reached, backing off. Backing off <N>s...`**
- **What it means**: Danbooru rate-limited the connection temporarily.
- **Action needed**: None. Exponential backoff will automatically wait and retry.

**`[FETCH] Multiple pages returned 0 usable items for '<tags>'. Cooling down 10s.`**
- **What it means**: Danbooru returned posts, but all of them were either already seen recently, unsupported file types, or MP4s larger than `15 MB`.
- **Action needed**: None, or try broader search tags if the query only contains long/large videos.

**`[PROXY] Filtered oversized MP4 (<bytes> bytes > 15 MB): <url>`**
- **What it means**: The `/media` proxy blocked an MP4 video that exceeded the `15 MB` cap to protect memory and bandwidth.
- **Action needed**: None.

**`[PROXY] Upstream media HTTP <status_code> for <url>` / `Proxy stream error for <url>: <error>`**
- **What it means**: An individual CDN media download timed out or dropped mid-stream.
- **Action needed**: None. The WebView preloader automatically discards the failed item and loads the next one.

**`[SECURITY] Blocked unauthorized media host: <hostname>` / `Blocked unauthorized cross-origin request`**
- **What it means**: The local proxy rejected a request that did not originate from the local WebView or attempted to fetch a URL outside `danbooru.donmai.us` / `cdn.donmai.us`.
- **Action needed**: None.

**`[SUGGEST] Suggestion fetch failed: <error details>`**
- **What it means**: A live tag autocomplete request timed out.
- **Action needed**: None.

**`[CONFIG] Failed to load/save app config / project.json: <error details>`**
- **What it means**: Python encountered a filesystem error reading or writing in `%APPDATA%\DanbooruWallpaper`.
- **Action needed**: Verify your Windows user account has normal write permissions to `%APPDATA%`.
