import os
import sys

# Configure WebView2 Chromium flags BEFORE importing webview:
# - Ephemeral in-memory operation: zero persistent "webview_profile" disk cache or telemetry folders
# - Prevents GPU occlusion/background throttling when reparented behind SHELLDLL_DefView
# - Strictly mutes all audio (--mute-audio)
os.environ.setdefault(
    "WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS",
    "--disable-features=CalculateNativeWinOcclusion,WinUseBrowserSpellChecker,msSmartScreenProtection "
    "--disable-background-timer-throttling "
    "--disable-renderer-backgrounding "
    "--disable-backgrounding-occluded-windows "
    "--autoplay-policy=no-user-gesture-required "
    "--mute-audio "
    "--inprivate "
    "--incognito "
    "--disk-cache-size=1 "
    "--media-cache-size=1 "
    "--disable-gpu-shader-disk-cache "
    "--disable-application-cache "
    "--disable-offline-load-stale-cache "
    "--disable-component-update "
    "--disable-domain-reliability "
    "--disable-breakpad "
    "--disable-crash-reporter "
    "--disable-sync "
    "--disable-translate "
    "--disable-extensions "
    "--disable-background-networking",
)

import urllib.request
import urllib.parse
import urllib.error
import http.client
import ssl
import gzip
import zlib
import json
import threading
import random
import shutil
import time
import base64
import socket
import ctypes
from ctypes import wintypes
from queue import Queue, Empty
from collections import deque
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
import tkinter as tk
from tkinter import ttk

# Optional curl_cffi import with automatic stdlib DoH + TLS 1.3 SNI fallback
try:
    from curl_cffi import requests as curl_requests
    try:
        from curl_cffi.const import CurlOpt, CurlHttpVersion
    except ImportError:
        CurlOpt = None
        CurlHttpVersion = None
    CURL_CFFI_AVAILABLE = True
except ImportError:
    curl_requests = None
    CurlOpt = None
    CurlHttpVersion = None
    CURL_CFFI_AVAILABLE = False

import pystray
from PIL import Image, ImageDraw, ImageTk
import webview


def safe_console_print(msg: str):
    """Safely prints to stdout when a console is attached (prevents PyInstaller --noconsole crashes)."""
    if sys.stdout is not None:
        try:
            print(msg, flush=True)
        except Exception:
            pass


# =============================================================================
# 1. DPI AWARENESS, DPAPI ENCRYPTION & 64-BIT SAFE WIN32 CTYPES DEFINITIONS
# =============================================================================
def enable_dpi_awareness():
    try:
        ctypes.windll.user32.SetProcessDpiAwarenessContext(ctypes.c_void_p(-4))
    except Exception:
        try:
            ctypes.windll.shcore.SetProcessDpiAwareness(2)
        except Exception:
            try:
                ctypes.windll.user32.SetProcessDPIAware()
            except Exception:
                pass


enable_dpi_awareness()

user32 = ctypes.windll.user32
crypt32 = ctypes.windll.crypt32
kernel32 = ctypes.windll.kernel32
LONG_PTR = ctypes.c_ssize_t


class DATA_BLOB(ctypes.Structure):
    _fields_ = [
        ("cbData", wintypes.DWORD),
        ("pbData", ctypes.POINTER(ctypes.c_char)),
    ]


crypt32.CryptProtectData.argtypes = [
    ctypes.POINTER(DATA_BLOB),
    wintypes.LPCWSTR,
    ctypes.POINTER(DATA_BLOB),
    ctypes.c_void_p,
    ctypes.c_void_p,
    wintypes.DWORD,
    ctypes.POINTER(DATA_BLOB),
]
crypt32.CryptProtectData.restype = wintypes.BOOL

crypt32.CryptUnprotectData.argtypes = [
    ctypes.POINTER(DATA_BLOB),
    ctypes.POINTER(wintypes.LPWSTR),
    ctypes.POINTER(DATA_BLOB),
    ctypes.c_void_p,
    ctypes.c_void_p,
    wintypes.DWORD,
    ctypes.POINTER(DATA_BLOB),
]
crypt32.CryptUnprotectData.restype = wintypes.BOOL

kernel32.LocalFree.argtypes = [wintypes.HLOCAL]
kernel32.LocalFree.restype = wintypes.HLOCAL

CRYPTPROTECT_UI_FORBIDDEN = 0x1


def dpapi_encrypt(plaintext: str) -> str:
    """Encrypts a plaintext string using Windows DPAPI tied to the current Windows user."""
    if not plaintext:
        return ""
    if plaintext.startswith("dpapi:"):
        return plaintext
    raw = plaintext.encode("utf-8")
    buf = ctypes.create_string_buffer(raw, len(raw))
    blob_in = DATA_BLOB(len(raw), buf)
    blob_out = DATA_BLOB()
    if crypt32.CryptProtectData(
        ctypes.byref(blob_in),
        "DanbooruWallpaperConfig",
        None,
        None,
        None,
        CRYPTPROTECT_UI_FORBIDDEN,
        ctypes.byref(blob_out),
    ):
        try:
            encrypted_bytes = ctypes.string_at(blob_out.pbData, blob_out.cbData)
            return "dpapi:" + base64.b64encode(encrypted_bytes).decode("ascii")
        finally:
            kernel32.LocalFree(ctypes.cast(blob_out.pbData, wintypes.HLOCAL))
    return ""


def dpapi_decrypt(ciphertext: str) -> str:
    """Decrypts a DPAPI-protected string, supporting transparent fallback for legacy plaintext."""
    if not ciphertext:
        return ""
    if not ciphertext.startswith("dpapi:"):
        return ciphertext
    try:
        raw = base64.b64decode(ciphertext[6:])
        buf = ctypes.create_string_buffer(raw, len(raw))
        blob_in = DATA_BLOB(len(raw), buf)
        blob_out = DATA_BLOB()
        if crypt32.CryptUnprotectData(
            ctypes.byref(blob_in),
            None,
            None,
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN,
            ctypes.byref(blob_out),
        ):
            try:
                return ctypes.string_at(blob_out.pbData, blob_out.cbData).decode("utf-8")
            finally:
                kernel32.LocalFree(ctypes.cast(blob_out.pbData, wintypes.HLOCAL))
    except Exception:
        pass
    return ""


SMTO_NORMAL = 0x0000
GWL_STYLE = -16
GWL_EXSTYLE = -20

WS_CAPTION = 0x00C00000
WS_THICKFRAME = 0x00040000
WS_MINIMIZEBOX = 0x00020000
WS_MAXIMIZEBOX = 0x00010000
WS_SYSMENU = 0x00080000
WS_POPUP = 0x80000000
WS_CHILD = 0x40000000
WS_VISIBLE = 0x10000000
WS_CLIPSIBLINGS = 0x04000000
WS_CLIPCHILDREN = 0x02000000

WS_EX_APPWINDOW = 0x00040000
WS_EX_TOOLWINDOW = 0x00000080
WS_EX_LAYERED = 0x00080000
WS_EX_NOACTIVATE = 0x08000000
WS_EX_NOREDIRECTIONBITMAP = 0x00200000

LWA_ALPHA = 0x00000002

SWP_NOSIZE = 0x0001
SWP_NOMOVE = 0x0002
SWP_NOZORDER = 0x0004
SWP_NOACTIVATE = 0x0010
SWP_FRAMECHANGED = 0x0020
SWP_SHOWWINDOW = 0x0040
SWP_HIDEWINDOW = 0x0080

HWND_TOP = 0
HWND_BOTTOM = 1

RDW_INVALIDATE = 0x0001
RDW_UPDATENOW = 0x0100
RDW_ALLCHILDREN = 0x0080
RDW_FRAME = 0x0400

WM_SIZE = 0x0005
SIZE_RESTORED = 0

SM_CXSCREEN = 0
SM_CYSCREEN = 1

WNDENUMPROC = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
MONITORENUMPROC = ctypes.WINFUNCTYPE(
    wintypes.BOOL, wintypes.HMONITOR, wintypes.HDC, ctypes.POINTER(wintypes.RECT), wintypes.LPARAM
)


class MONITORINFOEXW(ctypes.Structure):
    _fields_ = [
        ("cbSize", wintypes.DWORD),
        ("rcMonitor", wintypes.RECT),
        ("rcWork", wintypes.RECT),
        ("dwFlags", wintypes.DWORD),
        ("szDevice", wintypes.WCHAR * 32),
    ]


user32.FindWindowW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR]
user32.FindWindowW.restype = wintypes.HWND

user32.FindWindowExW.argtypes = [wintypes.HWND, wintypes.HWND, wintypes.LPCWSTR, wintypes.LPCWSTR]
user32.FindWindowExW.restype = wintypes.HWND

user32.EnumWindows.argtypes = [WNDENUMPROC, wintypes.LPARAM]
user32.EnumWindows.restype = wintypes.BOOL

user32.EnumChildWindows.argtypes = [wintypes.HWND, WNDENUMPROC, wintypes.LPARAM]
user32.EnumChildWindows.restype = wintypes.BOOL

user32.EnumDisplayMonitors.argtypes = [
    wintypes.HDC, ctypes.POINTER(wintypes.RECT), MONITORENUMPROC, wintypes.LPARAM
]
user32.EnumDisplayMonitors.restype = wintypes.BOOL

user32.GetMonitorInfoW.argtypes = [wintypes.HMONITOR, ctypes.POINTER(MONITORINFOEXW)]
user32.GetMonitorInfoW.restype = wintypes.BOOL

user32.GetClassNameW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
user32.GetClassNameW.restype = ctypes.c_int

user32.IsWindowVisible.argtypes = [wintypes.HWND]
user32.IsWindowVisible.restype = wintypes.BOOL

user32.ScreenToClient.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.POINT)]
user32.ScreenToClient.restype = wintypes.BOOL

user32.RedrawWindow.argtypes = [wintypes.HWND, ctypes.c_void_p, wintypes.HRGN, wintypes.UINT]
user32.RedrawWindow.restype = wintypes.BOOL

user32.SendMessageTimeoutW.argtypes = [
    wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM,
    wintypes.UINT, wintypes.UINT, ctypes.POINTER(ctypes.c_size_t)
]
user32.SendMessageTimeoutW.restype = wintypes.LPARAM

user32.SendMessageW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
user32.SendMessageW.restype = wintypes.LPARAM

user32.SetParent.argtypes = [wintypes.HWND, wintypes.HWND]
user32.SetParent.restype = wintypes.HWND

user32.SetWindowPos.argtypes = [
    wintypes.HWND, wintypes.HWND, ctypes.c_int, ctypes.c_int,
    ctypes.c_int, ctypes.c_int, wintypes.UINT
]
user32.SetWindowPos.restype = wintypes.BOOL

user32.SetLayeredWindowAttributes.argtypes = [
    wintypes.HWND, wintypes.COLORREF, wintypes.BYTE, wintypes.DWORD
]
user32.SetLayeredWindowAttributes.restype = wintypes.BOOL

GetWindowLongPtrW = getattr(user32, "GetWindowLongPtrW", user32.GetWindowLongW)
GetWindowLongPtrW.argtypes = [wintypes.HWND, ctypes.c_int]
GetWindowLongPtrW.restype = LONG_PTR

# Fixed 32-bit fallback to SetWindowLongW (previously GetWindowLongW)
SetWindowLongPtrW = getattr(user32, "SetWindowLongPtrW", user32.SetWindowLongW)
SetWindowLongPtrW.argtypes = [wintypes.HWND, ctypes.c_int, LONG_PTR]
SetWindowLongPtrW.restype = LONG_PTR

INJECTION_LOCK = threading.Lock()


def enumerate_connected_monitors():
    """Enumerates all physical displays via Win32 EnumDisplayMonitors."""
    raw_monitors = []

    def _monitor_enum_proc(hMonitor, hdcMonitor, lprcMonitor, dwData):
        info = MONITORINFOEXW()
        info.cbSize = ctypes.sizeof(MONITORINFOEXW)
        if user32.GetMonitorInfoW(hMonitor, ctypes.byref(info)):
            r = info.rcMonitor
            w = r.right - r.left
            h = r.bottom - r.top
            is_primary = bool(info.dwFlags & 1)
            raw_monitors.append({
                "x": int(r.left),
                "y": int(r.top),
                "width": int(w),
                "height": int(h),
                "is_primary": is_primary,
                "device": info.szDevice,
            })
        return True

    cb = MONITORENUMPROC(_monitor_enum_proc)
    try:
        user32.EnumDisplayMonitors(None, None, cb, 0)
    except Exception:
        pass

    if not raw_monitors:
        sw = user32.GetSystemMetrics(SM_CXSCREEN)
        sh = user32.GetSystemMetrics(SM_CYSCREEN)
        raw_monitors.append({
            "x": 0, "y": 0, "width": sw, "height": sh, "is_primary": True, "device": "DISPLAY1"
        })

    raw_monitors.sort(key=lambda m: (0 if m["is_primary"] else 1, m["x"], m["y"]))

    screens = []
    for idx, m in enumerate(raw_monitors, start=1):
        screen_id = f"screen_{idx}"
        primary_tag = " (Primary)" if m["is_primary"] else ""
        screens.append({
            "id": screen_id,
            "index": idx,
            "name": f"Screen {idx}",
            "label": f"Screen {idx}: {m['width']}x{m['height']}{primary_tag}",
            "x": m["x"],
            "y": m["y"],
            "width": m["width"],
            "height": m["height"],
            "is_primary": m["is_primary"],
        })
    return screens


def has_webview_render_child(hwnd):
    """Checks whether WebView2 has created its internal Chrome_WidgetWin_0/1 child surface."""
    found = [False]
    class_buf = ctypes.create_unicode_buffer(256)

    def _check_child(child_hwnd, lparam):
        if user32.GetClassNameW(child_hwnd, class_buf, 256) > 0:
            cname = class_buf.value
            if cname.startswith("Chrome_WidgetWin_") or cname == "Intermediate D3D Window":
                found[0] = True
                return False
        return True

    cb = WNDENUMPROC(_check_child)
    user32.EnumChildWindows(hwnd, cb, 0)
    return found[0]


def get_webview_hwnd(window, window_title):
    """Retrieves the native Win32 HWND once the nested WebView2 rendering surface is initialized."""
    hwnd = None

    if window is not None and hasattr(window, "native") and window.native is not None:
        try:
            hwnd_val = window.native.Handle.ToInt64()
            if hwnd_val:
                hwnd = hwnd_val
        except Exception:
            pass

    if not hwnd:
        hwnd = user32.FindWindowW(None, window_title)

    if hwnd and has_webview_render_child(hwnd):
        return hwnd
    return None


def enumerate_desktop_topology(progman):
    """
    Sends 0x052C to Progman and resolves the desktop window topology across
    Windows 10, Windows 11 (21H2-23H2), and Windows 11 24H2+.
    """
    result = ctypes.c_size_t(0)
    user32.SendMessageTimeoutW(progman, 0x052C, 0, 0, SMTO_NORMAL, 1000, ctypes.byref(result))
    user32.SendMessageTimeoutW(progman, 0x052C, 0xD, 0x1, SMTO_NORMAL, 1000, ctypes.byref(result))
    time.sleep(0.05)

    progman_ex = GetWindowLongPtrW(progman, GWL_EXSTYLE) & 0xFFFFFFFF
    is_noref_bitmap = bool(progman_ex & WS_EX_NOREDIRECTIONBITMAP)

    shell_view_in_progman = user32.FindWindowExW(progman, 0, "SHELLDLL_DefView", None)
    workerw_in_progman = user32.FindWindowExW(progman, 0, "WorkerW", None)

    classic_workerw = []

    def _enum_proc(top_hwnd, lparam):
        shell_view = user32.FindWindowExW(top_hwnd, 0, "SHELLDLL_DefView", None)
        if shell_view:
            sibling = user32.FindWindowExW(0, top_hwnd, "WorkerW", None)
            if sibling:
                classic_workerw.append(sibling)
                return False
        return True

    enum_cb = WNDENUMPROC(_enum_proc)
    user32.EnumWindows(enum_cb, 0)

    is_win11_24h2 = (
        is_noref_bitmap
        and bool(shell_view_in_progman)
        and bool(workerw_in_progman)
        and not classic_workerw
    )

    return {
        "is_win11_24h2": is_win11_24h2,
        "shell_view_in_progman": shell_view_in_progman,
        "workerw_in_progman": workerw_in_progman,
        "classic_workerw": classic_workerw[0] if classic_workerw else None,
    }


def resize_webview_child_containers(hwnd, screen_w, screen_h):
    """
    Forces all inner WinForms and Chromium host controls to fill (0, 0, screen_w, screen_h).
    """
    lparam_size = (screen_h << 16) | (screen_w & 0xFFFF)
    user32.SendMessageW(hwnd, WM_SIZE, SIZE_RESTORED, lparam_size)

    class_buf = ctypes.create_unicode_buffer(256)

    def _resize_child(child_hwnd, lparam):
        child_style = GetWindowLongPtrW(child_hwnd, GWL_STYLE) & 0xFFFFFFFF
        if not (child_style & WS_VISIBLE):
            return True
        if user32.GetClassNameW(child_hwnd, class_buf, 256) > 0:
            cname = class_buf.value
            if (
                cname.startswith("WindowsForms10.")
                or cname.startswith("Chrome_WidgetWin_")
                or cname == "Chrome_RenderWidgetHostHWND"
                or cname == "Intermediate D3D Window"
            ):
                user32.SetWindowPos(
                    child_hwnd, 0, 0, 0, screen_w, screen_h,
                    SWP_NOZORDER | SWP_NOACTIVATE | SWP_FRAMECHANGED
                )
                user32.SendMessageW(child_hwnd, WM_SIZE, SIZE_RESTORED, lparam_size)
        return True

    child_cb = WNDENUMPROC(_resize_child)
    user32.EnumChildWindows(hwnd, child_cb, 0)


def sync_all_screens_z_order_and_geometry(target_screen_id=None):
    """
    Synchronizes geometry, visibility, and desktop Z-order across ALL attached monitor HWNDs.
    """
    with INJECTION_LOCK:
        progman = user32.FindWindowW("Progman", None)
        if not progman:
            return
        topo = enumerate_desktop_topology(progman)
        target_parent = (
            progman
            if topo["is_win11_24h2"]
            else (topo["classic_workerw"] or topo["workerw_in_progman"] or progman)
        )
        insert_after = (
            topo["shell_view_in_progman"]
            if (topo["is_win11_24h2"] and topo["shell_view_in_progman"])
            else HWND_TOP
        )

        screens_by_id = {s["id"]: s for s in CONNECTED_SCREENS}

        for sid, hwnd in list(DESKTOP_HWNDS.items()):
            if not hwnd or sid not in screens_by_id:
                continue

            s_info = screens_by_id[sid]
            sc_cfg = get_screen_config(sid)
            enabled = sc_cfg["enabled"]

            screen_w = s_info["width"]
            screen_h = s_info["height"]
            pt = wintypes.POINT(s_info["x"], s_info["y"])
            user32.ScreenToClient(target_parent, ctypes.byref(pt))

            style = GetWindowLongPtrW(hwnd, GWL_STYLE) & 0xFFFFFFFF
            if enabled:
                style |= WS_VISIBLE
                SetWindowLongPtrW(hwnd, GWL_STYLE, LONG_PTR(style))

                if target_screen_id is None or target_screen_id == sid:
                    user32.SetWindowPos(
                        hwnd, insert_after, pt.x, pt.y, screen_w - 1, screen_h - 1,
                        SWP_NOACTIVATE | SWP_FRAMECHANGED | SWP_SHOWWINDOW
                    )
                user32.SetWindowPos(
                    hwnd, insert_after, pt.x, pt.y, screen_w, screen_h,
                    SWP_NOACTIVATE | SWP_FRAMECHANGED | SWP_SHOWWINDOW
                )
                resize_webview_child_containers(hwnd, screen_w, screen_h)
                user32.RedrawWindow(
                    hwnd, None, None,
                    RDW_INVALIDATE | RDW_UPDATENOW | RDW_ALLCHILDREN | RDW_FRAME
                )
                insert_after = hwnd
            else:
                style &= ~WS_VISIBLE
                SetWindowLongPtrW(hwnd, GWL_STYLE, LONG_PTR(style))
                user32.SetWindowPos(
                    hwnd, 0, pt.x, pt.y, screen_w, screen_h,
                    SWP_NOZORDER | SWP_NOACTIVATE | SWP_HIDEWINDOW
                )

        if topo["is_win11_24h2"] and topo["workerw_in_progman"]:
            user32.SetWindowPos(
                topo["workerw_in_progman"],
                wintypes.HWND(HWND_BOTTOM),
                0, 0, 0, 0,
                SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE
            )


def attach_window_to_desktop(window, window_title, mon_x=0, mon_y=0, mon_w=None, mon_h=None):
    """
    Injects a pywebview window behind desktop icons at the target monitor's coordinates.
    """
    hwnd = None
    for _ in range(80):
        hwnd = get_webview_hwnd(window, window_title)
        if hwnd:
            break
        time.sleep(0.1)

    if not hwnd:
        log_event("win32", f"Failed to locate initialized WebView2 HWND for '{window_title}'")
        return None

    with INJECTION_LOCK:
        progman = user32.FindWindowW("Progman", None)
        if not progman:
            log_event("win32", "Failed to locate Progman window.")
            return None

        topo = enumerate_desktop_topology(progman)
        screen_w = mon_w if mon_w is not None else user32.GetSystemMetrics(SM_CXSCREEN)
        screen_h = mon_h if mon_h is not None else user32.GetSystemMetrics(SM_CYSCREEN)

        style = GetWindowLongPtrW(hwnd, GWL_STYLE) & 0xFFFFFFFF
        clear_mask = WS_CAPTION | WS_THICKFRAME | WS_MINIMIZEBOX | WS_MAXIMIZEBOX | WS_SYSMENU | WS_POPUP
        style = (style & ~clear_mask) | WS_CHILD | WS_VISIBLE | WS_CLIPSIBLINGS | WS_CLIPCHILDREN
        SetWindowLongPtrW(hwnd, GWL_STYLE, LONG_PTR(style))

        ex_style = GetWindowLongPtrW(hwnd, GWL_EXSTYLE) & 0xFFFFFFFF

        if topo["is_win11_24h2"]:
            ex_style = (ex_style & ~WS_EX_APPWINDOW) | WS_EX_TOOLWINDOW | WS_EX_NOACTIVATE | WS_EX_LAYERED
            SetWindowLongPtrW(hwnd, GWL_EXSTYLE, LONG_PTR(ex_style))
            user32.SetLayeredWindowAttributes(hwnd, 0, 255, LWA_ALPHA)

            target_parent = progman
            user32.SetParent(hwnd, target_parent)

            pt = wintypes.POINT(mon_x, mon_y)
            user32.ScreenToClient(target_parent, ctypes.byref(pt))

            insert_after = topo["shell_view_in_progman"] if topo["shell_view_in_progman"] else HWND_TOP
            user32.SetWindowPos(
                hwnd, insert_after, pt.x, pt.y, screen_w - 1, screen_h - 1,
                SWP_NOACTIVATE | SWP_FRAMECHANGED | SWP_SHOWWINDOW
            )
            user32.SetWindowPos(
                hwnd, insert_after, pt.x, pt.y, screen_w, screen_h,
                SWP_NOACTIVATE | SWP_FRAMECHANGED | SWP_SHOWWINDOW
            )

            if topo["workerw_in_progman"]:
                user32.SetWindowPos(
                    topo["workerw_in_progman"],
                    wintypes.HWND(HWND_BOTTOM),
                    0, 0, 0, 0,
                    SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE
                )

            log_event(
                "win32",
                f"Win11 24H2+ mode: Attached '{window_title}' HWND {hex(hwnd)} to Progman {hex(progman)} "
                f"at ({pt.x},{pt.y}) {screen_w}x{screen_h}"
            )
        else:
            ex_style = (ex_style & ~(WS_EX_APPWINDOW | WS_EX_LAYERED)) | WS_EX_TOOLWINDOW | WS_EX_NOACTIVATE
            SetWindowLongPtrW(hwnd, GWL_EXSTYLE, LONG_PTR(ex_style))

            target_parent = topo["classic_workerw"] or topo["workerw_in_progman"] or progman
            user32.SetParent(hwnd, target_parent)

            pt = wintypes.POINT(mon_x, mon_y)
            user32.ScreenToClient(target_parent, ctypes.byref(pt))

            user32.SetWindowPos(
                hwnd, HWND_TOP, pt.x, pt.y, screen_w - 1, screen_h - 1,
                SWP_NOACTIVATE | SWP_FRAMECHANGED | SWP_SHOWWINDOW
            )
            user32.SetWindowPos(
                hwnd, HWND_TOP, pt.x, pt.y, screen_w, screen_h,
                SWP_NOACTIVATE | SWP_FRAMECHANGED | SWP_SHOWWINDOW
            )
            log_event(
                "win32",
                f"Classic WorkerW mode: Attached '{window_title}' HWND {hex(hwnd)} to WorkerW {hex(target_parent)} "
                f"at ({pt.x},{pt.y}) {screen_w}x{screen_h}"
            )

        resize_webview_child_containers(hwnd, screen_w, screen_h)
        user32.RedrawWindow(
            hwnd, None, None,
            RDW_INVALIDATE | RDW_UPDATENOW | RDW_ALLCHILDREN | RDW_FRAME
        )
        return hwnd


# =============================================================================
# 2. PATH ROUTING & EPHEMERAL CONFIGURATION STORAGE (NO WEBVIEW_PROFILE DISK CACHE)
# =============================================================================
def get_resource_path(relative_path):
    base_path = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base_path, relative_path)


APPDATA_ROOT = os.getenv("APPDATA") or os.path.expanduser("~")
PERSISTENT_DIR = os.path.join(APPDATA_ROOT, "DanbooruWallpaper")
os.makedirs(PERSISTENT_DIR, exist_ok=True)

SAVED_SEARCHES_FILE = os.path.join(PERSISTENT_DIR, "saved_searches.json")
CONFIG_FILE = os.path.join(PERSISTENT_DIR, "config.json")
PROJECT_JSON_FILE = os.path.join(PERSISTENT_DIR, "project.json")

BUNDLED_HTML_FILE = get_resource_path("index.html")
BUNDLED_PROJECT_JSON = get_resource_path("project.json")


def cleanup_legacy_webview_profile():
    """Removes any leftover legacy webview_profile disk directory from previous versions."""
    legacy_profile = os.path.join(PERSISTENT_DIR, "webview_profile")
    if os.path.exists(legacy_profile):
        try:
            shutil.rmtree(legacy_profile, ignore_errors=True)
        except Exception:
            pass


def get_default_properties_dict():
    return {
        "schemecolor": {"order": 0, "text": "Scheme Color", "type": "color", "value": "0.04 0.04 0.05"},
        "displaymode": {"order": 1, "text": "Display Mode", "type": "combo", "value": "scroll"},
        "scrolldirection": {"order": 2, "text": "Scroll Direction", "type": "combo", "value": "left"},
        "scrollspeed": {
            "order": 3,
            "text": "Scroll Speed (0.1 – 600 px/s)",
            "type": "slider",
            "min": 0.1,
            "max": 600,
            "step": 0.1,
            "precision": 2,
            "value": 120,
        },
        "gapsize": {
            "order": 4,
            "text": "Image Gap (0 – 64 px)",
            "type": "slider",
            "min": 0,
            "max": 64,
            "step": 1,
            "value": 12,
        },
        "dropspeed": {
            "order": 5,
            "text": "Drop Speed (0.2 – 4.0)",
            "type": "slider",
            "min": 0.2,
            "max": 4.0,
            "step": 0.1,
            "precision": 2,
            "value": 1.0,
        },
        "minsize": {
            "order": 6,
            "text": "Minimum Size (120 – 600 px)",
            "type": "slider",
            "min": 120,
            "max": 600,
            "step": 1,
            "value": 220,
        },
        "maxsize": {
            "order": 7,
            "text": "Maximum Size (150 – 900 px)",
            "type": "slider",
            "min": 150,
            "max": 900,
            "step": 1,
            "value": 440,
        },
        "dropdelay": {
            "order": 8,
            "text": "Spawn/Drop Delay (0 – 600 s)",
            "type": "slider",
            "min": 0,
            "max": 600,
            "step": 1,
            "value": 0,
        },
        "slideshowfade": {
            "order": 9,
            "text": "Fade Transition (0 – 10 [0s – 1.0s])",
            "type": "slider",
            "min": 0,
            "max": 10,
            "step": 0.1,
            "precision": 1,
            "value": 5,
        },
        "slideshowduration": {
            "order": 10,
            "text": "Slide Display Time (0 – 600 s)",
            "type": "slider",
            "min": 0,
            "max": 600,
            "step": 1,
            "value": 10,
        },
    }


DEFAULT_PROJECT_SCHEMA = {
    "file": "index.html",
    "general": {
        "properties": get_default_properties_dict()
    },
    "screens": {},
    "title": "Danbooru Infinite Scroll, Polaroid Collage & Fullscreen Slideshow",
    "type": "web",
    "version": 2,
}


def init_persistent_storage():
    cleanup_legacy_webview_profile()

    if not os.path.exists(PROJECT_JSON_FILE):
        try:
            if os.path.exists(BUNDLED_PROJECT_JSON):
                shutil.copyfile(BUNDLED_PROJECT_JSON, PROJECT_JSON_FILE)
            else:
                with open(PROJECT_JSON_FILE, "w", encoding="utf-8") as f:
                    json.dump(DEFAULT_PROJECT_SCHEMA, f, indent=2)
        except Exception as e:
            safe_console_print(f"[INIT] Failed to initialize project.json in APPDATA: {e}")

    if not os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "w", encoding="utf-8") as f:
                json.dump({}, f, indent=2)
        except Exception:
            pass

    if not os.path.exists(SAVED_SEARCHES_FILE):
        try:
            with open(SAVED_SEARCHES_FILE, "w", encoding="utf-8") as f:
                json.dump([], f, indent=2)
        except Exception:
            pass


init_persistent_storage()

# =============================================================================
# 3. HYBRID TRANSPORT ENGINE (curl_cffi HTTP/2 + STDLIB DoH/SNI TLS 1.3 FALLBACK)
# =============================================================================
DEFAULT_TAGS = "scenery no_humans"
PORT = 8088
WEBVIEW_WINDOW_TITLE_PREFIX = "DanbooruWallpaperRendererHost"

# Danbooru API Guidelines rate-limit interval
MIN_API_INTERVAL = 2.0

# Max MP4 file size allowed through API metadata & Proxy stream (15 MB = 15,728,640 bytes)
MAX_MP4_FILE_SIZE_BYTES = 15 * 1024 * 1024
ALLOWED_EXTENSIONS = {"jpg", "jpeg", "png", "webp", "gif", "mp4"}

ALLOWED_MEDIA_HOSTS = {
    "danbooru.donmai.us",
    "cdn.donmai.us",
}

ALLOWED_LOCAL_ORIGINS = {
    f"http://127.0.0.1:{PORT}",
    f"http://localhost:{PORT}",
}

CLOUDFLARE_DOH_ENDPOINT = "https://cloudflare-dns.com/dns-query"
CLOUDFLARE_DOH_IPS = ("1.1.1.1", "1.0.0.1")
DOH_CACHE_TTL = 900  # 15 minutes
DOH_CACHE = {}       # hostname -> (ip_str, expires_at)
DOH_LOCK = threading.Lock()

# Credentials are never hardcoded; pulled strictly from the Credentials tab (config.json)
USERNAME = ""
USER_ID = ""
API_KEY = ""

HTTP2_SESSION = None
SESSION_LOCK = threading.Lock()

# Theme Palettes for Light Mode & Dark Mode (Credentials tab toggle)
THEME_PALETTES = {
    "light": {
        "bg_base": "#f6f6f8",
        "input_bg": "#ffffff",
        "border_col": "#dcdce0",
        "text_dark": "#1c1c1c",
        "text_muted": "#5c5c5c",
        "btn_bg": "#e8e8ed",
        "btn_active": "#dcdce0",
        "hover_bg": "#f0f7ff",
        "row_hover": "#f0f0f3",
        "min_bar": "#cfcfd4",
        "arrow_bg": "#f0f0f3",
        "flash_bg": "#e8f0fe",
    },
    "dark": {
        "bg_base": "#0f0f12",
        "input_bg": "#1a1a20",
        "border_col": "#2e2e38",
        "text_dark": "#ffffff",
        "text_muted": "#b0b0be",
        "btn_bg": "#25252e",
        "btn_active": "#343442",
        "hover_bg": "#1e2a3a",
        "row_hover": "#25252e",
        "min_bar": "#343442",
        "arrow_bg": "#25252e",
        "flash_bg": "#1f3252",
    },
}

CURRENT_THEME = "light"

# Glossary Definitions for Logs Tab
LOG_GLOSSARY_ENTRIES = [
    ("[SERVER]", "Local Python HTTP proxy server lifecycle events, port binding (127.0.0.1:8088), and client batch dispatches."),
    ("[DOH]", "Cloudflare DNS-over-HTTPS (https://cloudflare-dns.com/dns-query via 1.1.1.1) hostname resolutions for danbooru.donmai.us and cdn.donmai.us."),
    ("[API]", "Authenticated requests sent to Danbooru's REST API (/posts.json) including page numbers, tags, and rate-limit fallbacks."),
    ("[FETCH]", "Background post buffer population, media deduplication, MP4 size filtering (>15 MB), and shuffling statistics."),
    ("[PROXY]", "Binary media streaming (/media) over the authenticated transport pipeline, Range requests for video playback, and stream errors."),
    ("[AUTH]", "Credential loading, DPAPI encryption/decryption status, active transport engine (curl_cffi vs. stdlib DoH+SNI), and HTTP Basic Auth updates."),
    ("[CONFIG]", "Reading and writing persistent configuration files (config.json, project.json, saved_searches.json) in %APPDATA%."),
    ("[UI]", "Floating Search Bar, Application Settings window, Light/Dark mode theme switches, and lock/pause interactions."),
    ("[SEARCH]", "Tag queries queued from the search bar and saved/removed bookmark entries."),
    ("[SUGGEST]", "Live tag autocomplete queries executed against Danbooru's /tags.json endpoint."),
    ("[REFRESH]", "Immediate cache epoch increments triggered by pressing the refresh button or Shift+Enter."),
    ("[WEBVIEW]", "Synchronization of per-screen display properties, modes (Scroll, Collage, Slideshow), and enabled states to WebView2."),
    ("[WIN32]", "Native Windows API desktop window attachment (Progman / WorkerW / SHELLDLL_DefView) and multi-monitor Z-order management."),
    ("[COLLAGE]", "Collage mode actions such as triggering the 30-second cooldown Fill Screen burst."),
    ("[APP]", "Application-wide master pause/resume state changes and clean shutdown sequences."),
    ("[PING]", "Periodic heartbeat summary confirming active WebView2 wallpaper clients are polling /epoch."),
    ("[SECURITY]", "Localhost origin verification blocking unauthorized cross-origin or external browser requests."),
    ("[ERROR]", "Network timeouts, upstream HTTP errors, or unexpected exceptions with automatic exponential backoff."),
]

CURRENT_TAGS = DEFAULT_TAGS
CURRENT_PAGE = 1
CACHE_EPOCH = 1

MAX_SEEN_IDS = 1500
SEEN_POST_IDS = set()
SEEN_POST_ORDER = deque()
SCREEN_SEEN_IDS = {}

PENDING_TAG_QUEUE = deque(maxlen=20)
POST_BUFFER = deque(maxlen=500)
LOG_HISTORY = deque(maxlen=500)

DATA_LOCK = threading.Lock()
FETCH_CONDITION = threading.Condition(DATA_LOCK)
IS_FETCHING = False
CONSECUTIVE_FAILURES = 0
CONSECUTIVE_EMPTY_PAGES = 0
LAST_API_CALL_TIME = 0.0
NEXT_ALLOWED_FETCH_TIME = 0.0

APP_PAUSED = False        # Master application pause (freezes display, stops proxy & API calls)
WALLPAPER_PAUSED = False  # Search bar pause (pauses scrolling/collage/slideshow, keeps GIFs/MP4s playing)

EPOCH_POLL_COUNT = 0
LAST_EPOCH_LOG_TIME = 0.0

LAST_STATUS = {"status": "idle", "page": 0, "count": 0}
IS_RUNNING = True

SUGGESTION_QUEUE = Queue(maxsize=1)

TRAY_ICON = None
TK_ROOT = None
APP_INSTANCE = None
HTTP_SERVER = None
SETTINGS_DIALOG_INSTANCE = None
GLOSSARY_DIALOG_INSTANCE = None

CONNECTED_SCREENS = enumerate_connected_monitors()
WEBVIEW_WINDOWS = {}       # screen_id -> webview.Window
DESKTOP_HWNDS = {}         # screen_id -> int HWND
DESKTOP_INJECTED_SET = set()


def log_event(category, message):
    timestamp = time.strftime("%H:%M:%S")
    formatted_msg = f"[{timestamp}] [{category.upper()}] {message}"
    safe_console_print(formatted_msg)
    LOG_HISTORY.append(formatted_msg)
    if TK_ROOT and SETTINGS_DIALOG_INSTANCE and getattr(SETTINGS_DIALOG_INSTANCE, "is_open", False):
        try:
            TK_ROOT.after(0, lambda msg=formatted_msg: SETTINGS_DIALOG_INSTANCE.append_log(msg))
        except (tk.TclError, RuntimeError):
            pass


def build_danbooru_user_agent() -> str:
    """
    Constructs a compliant, descriptive User-Agent header following
    https://danbooru.donmai.us/wiki_pages/help:api
    """
    if USERNAME and USER_ID:
        return f"DanbooruWallpaperService/2.0 (by {USERNAME}; user #{USER_ID})"
    if USERNAME:
        return f"DanbooruWallpaperService/2.0 (by {USERNAME})"
    return "DanbooruWallpaperService/2.0 (Anonymous Client)"


def create_modern_tls_context() -> ssl.SSLContext:
    """Creates a hardened TLS 1.2/1.3 SSLContext with modern cipher suites for stdlib connections."""
    ctx = ssl.create_default_context()
    try:
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    except Exception:
        pass
    try:
        ctx.set_alpn_protocols(["http/1.1"])
    except Exception:
        pass
    return ctx


STDLIB_SSL_CONTEXT = create_modern_tls_context()


def _query_cloudflare_doh_direct(hostname: str) -> str:
    """
    Queries Cloudflare's public DoH endpoint (https://cloudflare-dns.com/dns-query)
    by connecting directly to Cloudflare's anycast IP (1.1.1.1 / 1.0.0.1) over TLS 1.3
    with SNI 'cloudflare-dns.com'. Works with zero third-party dependencies and cannot recurse.
    """
    query_path = f"/dns-query?{urllib.parse.urlencode({'name': hostname, 'type': 'A'})}"
    for cf_ip in CLOUDFLARE_DOH_IPS:
        raw_sock = None
        tls_sock = None
        try:
            raw_sock = socket.create_connection((cf_ip, 443), timeout=4.0)
            tls_sock = STDLIB_SSL_CONTEXT.wrap_socket(raw_sock, server_hostname="cloudflare-dns.com")
            req_lines = (
                f"GET {query_path} HTTP/1.1\r\n"
                f"Host: cloudflare-dns.com\r\n"
                f"Accept: application/dns-json\r\n"
                f"User-Agent: {build_danbooru_user_agent()}\r\n"
                f"Connection: close\r\n\r\n"
            )
            tls_sock.sendall(req_lines.encode("utf-8"))
            response_chunks = []
            while True:
                data = tls_sock.recv(16384)
                if not data:
                    break
                response_chunks.append(data)
            raw_response = b"".join(response_chunks)
            if b"\r\n\r\n" in raw_response:
                header_bytes, body_bytes = raw_response.split(b"\r\n\r\n", 1)
                first_line = header_bytes.split(b"\r\n", 1)[0].decode("latin-1", errors="ignore")
                if " 200 " in first_line:
                    # Handle chunked transfer encoding if present
                    if b"transfer-encoding: chunked" in header_bytes.lower():
                        decoded_body = bytearray()
                        idx = 0
                        while idx < len(body_bytes):
                            crlf_pos = body_bytes.find(b"\r\n", idx)
                            if crlf_pos == -1:
                                break
                            chunk_len_hex = body_bytes[idx:crlf_pos].split(b";", 1)[0].strip()
                            if not chunk_len_hex:
                                break
                            chunk_len = int(chunk_len_hex, 16)
                            if chunk_len == 0:
                                break
                            start_data = crlf_pos + 2
                            decoded_body.extend(body_bytes[start_data:start_data + chunk_len])
                            idx = start_data + chunk_len + 2
                        body_bytes = bytes(decoded_body)

                    payload = json.loads(body_bytes.decode("utf-8", errors="replace"))
                    for ans in payload.get("Answer", []):
                        if ans.get("type") == 1 and ans.get("data"):
                            return str(ans["data"]).strip()
        except Exception:
            pass
        finally:
            if tls_sock is not None:
                try:
                    tls_sock.close()
                except Exception:
                    pass
            elif raw_sock is not None:
                try:
                    raw_sock.close()
                except Exception:
                    pass
    return ""


def resolve_hostname_doh(hostname: str) -> str:
    """
    Resolves Danbooru and CDN hostnames via Cloudflare DNS-over-HTTPS (DoH)
    (https://cloudflare-dns.com/dns-query) to bypass ISP plain-text DNS blocks/poisoning.
    """
    if not hostname:
        return ""

    now = time.time()
    with DOH_LOCK:
        cached = DOH_CACHE.get(hostname)
        if cached and cached[1] > now:
            return cached[0]

    resolved_ip = _query_cloudflare_doh_direct(hostname)
    if not resolved_ip:
        try:
            resolved_ip = socket.gethostbyname(hostname)
        except Exception:
            resolved_ip = ""

    if resolved_ip:
        with DOH_LOCK:
            DOH_CACHE[hostname] = (resolved_ip, now + DOH_CACHE_TTL)
        log_event("doh", f"Resolved {hostname} -> {resolved_ip} via Cloudflare DoH")

    return resolved_ip


def build_curl_resolve_list(hostnames=None) -> list:
    """
    Builds libcurl CURLOPT_RESOLVE list entries (["host:443:ip", "host:80:ip"])
    using Cloudflare DoH resolution so TLS SNI, certificate verification, and
    HTTP/2 multiplexing work natively over the DoH IP.
    """
    targets = hostnames if hostnames is not None else ALLOWED_MEDIA_HOSTS
    entries = []
    for host in targets:
        if not host:
            continue
        ip_addr = resolve_hostname_doh(host)
        if ip_addr:
            entries.append(f"{host}:443:{ip_addr}")
            entries.append(f"{host}:80:{ip_addr}")
    return entries


# =============================================================================
# 3B. STANDARD-LIBRARY DoH + TLS SNI FALLBACK & UNIFIED HYBRID SESSION
# =============================================================================
class DoHSNIHTTPSConnection(http.client.HTTPSConnection):
    """
    Custom HTTPSConnection that connects the TCP socket to the Cloudflare DoH-resolved IP
    while passing the original hostname to `server_hostname` during the TLS handshake.
    """
    def __init__(self, host, port=None, **kwargs):
        super().__init__(host, port=port, **kwargs)

    def connect(self):
        target_host = self._tunnel_host if self._tunnel_host else self.host
        target_port = self._tunnel_port if self._tunnel_host else self.port

        connect_ip = resolve_hostname_doh(target_host) if target_host in ALLOWED_MEDIA_HOSTS else ""
        dial_host = connect_ip if connect_ip else target_host

        self.sock = socket.create_connection(
            (dial_host, target_port),
            self.timeout,
            self.source_address,
        )
        if self._tunnel_host:
            self._tunnel()

        self.sock = self._context.wrap_socket(
            self.sock,
            server_hostname=target_host,
        )


class DoHSNIHTTPSHandler(urllib.request.HTTPSHandler):
    def __init__(self, context=None):
        super().__init__(context=context or STDLIB_SSL_CONTEXT)

    def https_open(self, req):
        return self.do_open(DoHSNIHTTPSConnection, req, context=self._context)


class SafeDoHRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Validates redirect targets against ALLOWED_MEDIA_HOSTS while preserving DoH+SNI routing."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        parsed = urllib.parse.urlparse(newurl)
        host = (parsed.hostname or "").lower()
        if parsed.scheme != "https" or host not in ALLOWED_MEDIA_HOSTS:
            raise urllib.error.HTTPError(
                newurl, 403, f"Redirect to unauthorized host blocked: {host}", headers, fp
            )
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class StdlibResponseAdapter:
    """Provides a curl_cffi / requests-compatible Response interface over a urllib response."""
    def __init__(self, status_code: int, headers: dict, raw_fp=None, body_bytes: bytes = None):
        self.status_code = status_code
        self.headers = headers or {}
        self._raw_fp = raw_fp
        self._body_bytes = body_bytes

    def _read_all(self) -> bytes:
        if self._body_bytes is None:
            if self._raw_fp is not None:
                try:
                    self._body_bytes = self._raw_fp.read()
                finally:
                    self.close()
            else:
                self._body_bytes = b""
            enc = (self.headers.get("Content-Encoding") or self.headers.get("content-encoding") or "").lower()
            if "gzip" in enc and self._body_bytes:
                try:
                    self._body_bytes = gzip.decompress(self._body_bytes)
                except Exception:
                    pass
            elif "deflate" in enc and self._body_bytes:
                try:
                    self._body_bytes = zlib.decompress(self._body_bytes)
                except Exception:
                    pass
        return self._body_bytes

    @property
    def content(self) -> bytes:
        return self._read_all()

    def json(self):
        raw = self._read_all()
        return json.loads(raw.decode("utf-8", errors="replace"))

    def iter_content(self, chunk_size: int = 65536):
        if self._raw_fp is not None:
            try:
                while True:
                    chunk = self._raw_fp.read(chunk_size)
                    if not chunk:
                        break
                    yield chunk
            finally:
                self.close()
        elif self._body_bytes:
            for i in range(0, len(self._body_bytes), chunk_size):
                yield self._body_bytes[i:i + chunk_size]

    def close(self):
        if self._raw_fp is not None:
            try:
                self._raw_fp.close()
            except Exception:
                pass
            self._raw_fp = None


def iter_response_chunks(resp, chunk_size: int = 65536):
    """
    Safely yields binary chunks from either a curl_cffi Response or a StdlibResponseAdapter.
    """
    if isinstance(resp, StdlibResponseAdapter):
        for chunk in resp.iter_content(chunk_size=chunk_size):
            if chunk:
                yield chunk
        return

    content = getattr(resp, "content", None)
    if content:
        for i in range(0, len(content), chunk_size):
            yield content[i:i + chunk_size]
        return

    if hasattr(resp, "iter_content"):
        try:
            for chunk in resp.iter_content(chunk_size=chunk_size):
                if chunk:
                    yield chunk
        except TypeError:
            for chunk in resp.iter_content():
                if chunk:
                    yield chunk


class StdlibDoHSession:
    """
    Drop-in fallback session when `curl_cffi` is not installed or fails at runtime.
    Routes all HTTPS traffic over Cloudflare DoH IPs with proper TLS 1.3 SNI and HTTP Basic Auth.
    """
    def __init__(self):
        self.headers = {}
        self.auth = None
        self._opener = urllib.request.build_opener(
            DoHSNIHTTPSHandler(STDLIB_SSL_CONTEXT),
            SafeDoHRedirectHandler(),
        )

    def get(self, url: str, params: dict = None, headers: dict = None, stream: bool = False, timeout: float = 15.0, **kwargs):
        if params:
            qs = urllib.parse.urlencode(params)
            sep = "&" if "?" in url else "?"
            url = f"{url}{sep}{qs}"

        merged_headers = dict(self.headers)
        if headers:
            merged_headers.update(headers)

        if self.auth and isinstance(self.auth, tuple) and len(self.auth) == 2:
            user, key = self.auth
            if user and key:
                token = base64.b64encode(f"{user}:{key}".encode("utf-8")).decode("ascii")
                merged_headers["Authorization"] = f"Basic {token}"

        req = urllib.request.Request(url, headers=merged_headers, method="GET")
        try:
            res = self._opener.open(req, timeout=timeout)
            status = getattr(res, "status", 200) or 200
            resp_headers = {k: v for k, v in res.headers.items()}
            if stream:
                return StdlibResponseAdapter(status, resp_headers, raw_fp=res)
            body = res.read()
            res.close()
            return StdlibResponseAdapter(status, resp_headers, body_bytes=body)
        except urllib.error.HTTPError as e:
            err_headers = {k: v for k, v in e.headers.items()} if e.headers else {}
            try:
                err_body = e.read()
            except Exception:
                err_body = b""
            finally:
                try:
                    e.close()
                except Exception:
                    pass
            return StdlibResponseAdapter(e.code or 500, err_headers, body_bytes=err_body)

    def close(self):
        pass


class HybridDoHSession:
    """
    Unified transport wrapper that uses `curl_cffi` (Chrome HTTP/2 + DoH) when available
    and automatically falls back at runtime to `StdlibDoHSession` (TLS 1.3 + DoH SNI)
    if `curl_cffi` raises any initialization or per-request error.
    """
    def __init__(self, headers: dict = None, auth: tuple = None):
        self.headers = dict(headers or {})
        self.auth = auth
        self._stdlib_session = StdlibDoHSession()
        self._stdlib_session.headers.update(self.headers)
        self._stdlib_session.auth = self.auth
        self._curl_session = None
        self._init_curl_session()

    def _init_curl_session(self):
        global CURL_CFFI_AVAILABLE
        if not CURL_CFFI_AVAILABLE or curl_requests is None:
            return
        try:
            base_kwargs = {"impersonate": "chrome"}
            if CurlHttpVersion is not None:
                base_kwargs["http_version"] = CurlHttpVersion.V2_0

            c_sess = None
            if CurlOpt is not None:
                with DOH_LOCK:
                    now = time.time()
                    cached_entries = [
                        f"{h}:{p}:{ip}"
                        for h, (ip, exp) in DOH_CACHE.items()
                        if exp > now and ip
                        for p in (443, 80)
                    ]
                if cached_entries:
                    try:
                        c_sess = curl_requests.Session(
                            **base_kwargs,
                            curl_options={CurlOpt.RESOLVE: cached_entries},
                        )
                    except TypeError:
                        c_sess = None

            if c_sess is None:
                c_sess = curl_requests.Session(**base_kwargs)

            c_sess.headers.update(self.headers)
            c_sess.auth = self.auth
            self._curl_session = c_sess
        except Exception as e:
            log_event("auth", f"curl_cffi session init failed ({e}); falling back to stdlib DoH+SNI transport.")
            CURL_CFFI_AVAILABLE = False
            self._curl_session = None

    def _apply_doh_to_curl_session(self, target_host: str):
        """Resolves target_host via Cloudflare DoH and attaches CURLOPT_RESOLVE to the session if supported."""
        if not target_host or target_host not in ALLOWED_MEDIA_HOSTS:
            return
        ip_addr = resolve_hostname_doh(target_host)
        if not ip_addr or self._curl_session is None or CurlOpt is None:
            return
        resolve_entries = build_curl_resolve_list(ALLOWED_MEDIA_HOSTS)
        if not resolve_entries:
            return
        try:
            if hasattr(self._curl_session, "_curl_options") and isinstance(self._curl_session._curl_options, dict):
                self._curl_session._curl_options[CurlOpt.RESOLVE] = resolve_entries
            elif hasattr(self._curl_session, "curl_options") and isinstance(self._curl_session.curl_options, dict):
                self._curl_session.curl_options[CurlOpt.RESOLVE] = resolve_entries
        except Exception:
            pass

    def get(
        self,
        url: str,
        params: dict = None,
        headers: dict = None,
        stream: bool = False,
        timeout: float = 15.0,
        allow_redirects: bool = True,
    ):
        global CURL_CFFI_AVAILABLE
        parsed = urllib.parse.urlparse(url)
        target_host = (parsed.hostname or "").lower()

        self._stdlib_session.headers.update(self.headers)
        self._stdlib_session.auth = self.auth

        if self._curl_session is not None and CURL_CFFI_AVAILABLE:
            try:
                self._curl_session.headers.update(self.headers)
                self._curl_session.auth = self.auth
                self._apply_doh_to_curl_session(target_host)

                # Execute request via curl_cffi without 'curl_options' kwarg (not supported on Session.get)
                return self._curl_session.get(
                    url,
                    params=params,
                    headers=headers,
                    timeout=timeout,
                    allow_redirects=allow_redirects,
                )
            except Exception as e:
                log_event(
                    "auth",
                    f"curl_cffi request failed ({e}); automatically switching to stdlib TLS 1.3 + DoH SNI fallback."
                )
                CURL_CFFI_AVAILABLE = False
                try:
                    self._curl_session.close()
                except Exception:
                    pass
                self._curl_session = None

        return self._stdlib_session.get(
            url,
            params=params,
            headers=headers,
            stream=stream,
            timeout=timeout,
            allow_redirects=allow_redirects,
        )

    def close(self):
        if self._curl_session is not None:
            try:
                self._curl_session.close()
            except Exception:
                pass
            self._curl_session = None
        if self._stdlib_session is not None:
            try:
                self._stdlib_session.close()
            except Exception:
                pass


def rebuild_http2_session():
    """
    Creates/recreates the cookie-free HybridDoHSession (curl_cffi HTTP/2 with automatic
    runtime fallback to StdlibDoHSession).
    """
    global HTTP2_SESSION
    with SESSION_LOCK:
        if HTTP2_SESSION is not None:
            try:
                HTTP2_SESSION.close()
            except Exception:
                pass

        default_headers = {
            "User-Agent": build_danbooru_user_agent(),
            "Accept": "application/json, text/javascript, */*; q=0.01",
            "Accept-Language": "en-US,en;q=0.9",
        }
        auth_tuple = (USERNAME, API_KEY) if (USERNAME and API_KEY) else None
        HTTP2_SESSION = HybridDoHSession(headers=default_headers, auth=auth_tuple)
        return HTTP2_SESSION


def get_http2_session():
    with SESSION_LOCK:
        if HTTP2_SESSION is None:
            return rebuild_http2_session()
        return HTTP2_SESSION


def apply_credentials(user: str, uid: str, key: str):
    """
    Applies credentials entered in the Credentials tab of the Application Settings window.
    No default credentials are ever embedded in code.
    """
    global USERNAME, USER_ID, API_KEY
    USERNAME = (user or "").strip()
    USER_ID = (uid or "").strip()
    API_KEY = (key or "").strip()
    rebuild_http2_session()


def load_saved_searches():
    if os.path.exists(SAVED_SEARCHES_FILE):
        try:
            with open(SAVED_SEARCHES_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, list):
                    return [str(item).strip() for item in data if str(item).strip()]
        except Exception as e:
            log_event("config", f"Failed to load saved searches: {e}")
    return []


def store_saved_searches(searches):
    try:
        with open(SAVED_SEARCHES_FILE, "w", encoding="utf-8") as f:
            json.dump(searches, f, ensure_ascii=False, indent=2)
    except Exception as e:
        log_event("config", f"Failed to save searches: {e}")


def load_app_config():
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            if not isinstance(data, dict):
                return {}
            if "CF_COOKIE" in data:
                data.pop("CF_COOKIE", None)
            raw_key = data.get("API_KEY", "")
            if raw_key:
                was_plaintext = not str(raw_key).startswith("dpapi:")
                data["API_KEY"] = dpapi_decrypt(str(raw_key))
                if was_plaintext and data["API_KEY"]:
                    store_app_config(data)
            return data
        except Exception as e:
            log_event("config", f"Failed to load app config: {e}")
    return {}


def store_app_config(config_data):
    try:
        to_save = dict(config_data)
        to_save.pop("CF_COOKIE", None)
        if to_save.get("API_KEY"):
            encrypted_key = dpapi_encrypt(str(to_save["API_KEY"]))
            if encrypted_key:
                to_save["API_KEY"] = encrypted_key
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(to_save, f, indent=2)
    except Exception as e:
        log_event("config", f"Failed to save app config: {e}")


def load_project_json():
    if os.path.exists(PROJECT_JSON_FILE):
        try:
            with open(PROJECT_JSON_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict):
                general_props = data.setdefault("general", {}).setdefault("properties", {})
                for k, v in get_default_properties_dict().items():
                    if k not in general_props or not isinstance(general_props[k], dict):
                        general_props[k] = json.loads(json.dumps(v))
                    else:
                        saved_val = general_props[k].get("value", v["value"])
                        merged_meta = json.loads(json.dumps(v))
                        merged_meta["value"] = saved_val
                        general_props[k] = merged_meta
                data.setdefault("screens", {})
                return data
        except Exception as e:
            log_event("config", f"Failed to read project.json: {e}")
    return json.loads(json.dumps(DEFAULT_PROJECT_SCHEMA))


def store_project_json(project_data):
    try:
        with open(PROJECT_JSON_FILE, "w", encoding="utf-8") as f:
            json.dump(project_data, f, indent=2)
    except Exception as e:
        log_event("config", f"Failed to save project.json: {e}")


def get_screen_config(screen_id="screen_1"):
    """Returns {'enabled': bool, 'properties': dict} for the specified screen_id."""
    proj = load_project_json()
    base_props = proj.get("general", {}).get("properties", get_default_properties_dict())
    screens_dict = proj.get("screens", {})

    if screen_id in screens_dict and isinstance(screens_dict[screen_id], dict):
        sc = screens_dict[screen_id]
        enabled = bool(sc.get("enabled", screen_id == "screen_1"))
        merged_props = json.loads(json.dumps(base_props))
        for k, v in sc.get("properties", {}).items():
            if k in merged_props and isinstance(v, dict) and "value" in v:
                merged_props[k]["value"] = v["value"]
            else:
                merged_props[k] = v
        return {"enabled": enabled, "properties": merged_props}

    return {
        "enabled": (screen_id == "screen_1"),
        "properties": json.loads(json.dumps(base_props)),
    }


def push_properties_to_webview(target_screen_id=None):
    """
    Synchronizes Win32 multi-monitor Z-order/visibility and pushes per-screen
    properties and enabled states to one or all WebView instances.
    """
    sync_all_screens_z_order_and_geometry(target_screen_id)

    targets = (
        [(target_screen_id, WEBVIEW_WINDOWS.get(target_screen_id))]
        if target_screen_id and target_screen_id in WEBVIEW_WINDOWS
        else list(WEBVIEW_WINDOWS.items())
    )
    for sid, win in targets:
        if not win:
            continue
        try:
            sc_cfg = get_screen_config(sid)
            enabled = sc_cfg["enabled"]
            props = sc_cfg["properties"]
            payload = json.dumps(props)
            enabled_js = "true" if enabled else "false"
            js_code = (
                f"if (window.setScreenEnabled) {{ window.setScreenEnabled({enabled_js}); }} "
                f"if (window.wallpaperPropertyListener && window.wallpaperPropertyListener.applyUserProperties) {{ "
                f"window.wallpaperPropertyListener.applyUserProperties({payload}); }} "
                f"window.dispatchEvent(new Event('resize'));"
            )
            win.evaluate_js(js_code)
            log_event("webview", f"Applied display properties to {sid} (enabled={enabled}).")
        except Exception as e:
            log_event("webview", f"Failed to push properties to {sid}: {e}")


def push_pause_states_to_webviews():
    """Immediately synchronizes master APP_PAUSED and search bar WALLPAPER_PAUSED states to all screens."""
    app_p = "true" if APP_PAUSED else "false"
    wp_p = "true" if WALLPAPER_PAUSED else "false"
    js_code = f"if (window.applyPauseStates) {{ window.applyPauseStates({app_p}, {wp_p}); }}"
    for sid, win in list(WEBVIEW_WINDOWS.items()):
        if win:
            try:
                win.evaluate_js(js_code)
            except Exception:
                pass


def trigger_fill_screen_on_webview(screen_id):
    """Triggers the Collage Fill Screen burst on the specified screen."""
    win = WEBVIEW_WINDOWS.get(screen_id)
    if win:
        try:
            win.evaluate_js("if (window.triggerFillCollageScreen) { window.triggerFillCollageScreen(); }")
            log_event("collage", f"Triggered Fill Screen burst on {screen_id}.")
        except Exception as e:
            log_event("collage", f"Failed to trigger Fill Screen on {screen_id}: {e}")


_initial_cfg = load_app_config()
CURRENT_THEME = "dark" if _initial_cfg.get("theme") == "dark" else "light"
apply_credentials(
    _initial_cfg.get("USERNAME", ""),
    _initial_cfg.get("USER_ID", ""),
    _initial_cfg.get("API_KEY", ""),
)


# =============================================================================
# 4. ICON GENERATION & DANBOORU API LOGIC (HYBRID HTTP/2 + DoH)
# =============================================================================
def create_cardboard_box_icon():
    img = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    box_base = (194, 142, 86, 255)
    box_dark = (150, 105, 60, 255)
    box_interior = (115, 78, 42, 255)
    flap_color = (212, 162, 106, 255)
    tape_color = (130, 88, 50, 255)

    draw.polygon([(14, 25), (32, 33), (50, 25), (32, 18)], fill=box_interior)
    draw.polygon([(14, 25), (32, 33), (32, 57), (14, 49)], fill=box_dark)
    draw.polygon([(32, 33), (50, 25), (50, 49), (32, 57)], fill=box_base)
    draw.line([(32, 33), (32, 57)], fill=tape_color, width=2)
    draw.polygon([(14, 25), (32, 33), (25, 23), (8, 17)], fill=flap_color)
    draw.line([(14, 25), (8, 17)], fill=box_dark, width=1)
    draw.polygon([(32, 33), (50, 25), (56, 17), (39, 23)], fill=flap_color)
    draw.line([(50, 25), (56, 17)], fill=box_dark, width=1)
    draw.polygon([(14, 25), (32, 18), (28, 11), (11, 16)], fill=flap_color)
    draw.polygon([(32, 18), (50, 25), (53, 16), (36, 11)], fill=flap_color)
    return img


def apply_app_icon(root):
    try:
        box_img = create_cardboard_box_icon()
        tk_icon = ImageTk.PhotoImage(box_img)
        root._app_icon = tk_icon
        root.iconphoto(True, tk_icon)
    except Exception as e:
        log_event("ui", f"Could not set window icon: {e}")


def track_post_id_locked(post_id):
    if post_id not in SEEN_POST_IDS:
        SEEN_POST_IDS.add(post_id)
        SEEN_POST_ORDER.append(post_id)
        if len(SEEN_POST_ORDER) > MAX_SEEN_IDS:
            oldest = SEEN_POST_ORDER.popleft()
            SEEN_POST_IDS.discard(oldest)


def _execute_danbooru_request(tags: str, page_num: int):
    if APP_PAUSED:
        raise RuntimeError("Application is currently paused.")

    params = {
        "tags": tags,
        "limit": 100,
        "page": page_num,
    }
    if USERNAME and API_KEY:
        params["login"] = USERNAME
        params["api_key"] = API_KEY

    url = "https://danbooru.donmai.us/posts.json"
    transport_label = "curl_cffi HTTP/2 + DoH" if CURL_CFFI_AVAILABLE else "stdlib TLS 1.3 + DoH SNI"
    log_event("api", f"Requesting Page {page_num} for tags: '{tags}' via {transport_label}")

    sess = get_http2_session()
    resp = sess.get(
        url,
        params=params,
        headers={
            "User-Agent": build_danbooru_user_agent(),
            "Accept": "application/json",
        },
        timeout=15,
    )
    if resp.status_code == 422:
        raise ValueError("HTTP_422_TAG_LIMIT")
    if resp.status_code == 401:
        raise PermissionError("HTTP 401 Unauthorized: Check Username and API Key in Credentials tab.")
    if resp.status_code == 429:
        raise RuntimeError("HTTP 429 Too Many Requests: Rate limit reached, backing off.")
    if resp.status_code >= 400:
        raise RuntimeError(f"Danbooru API HTTP {resp.status_code}")

    return resp.json()


def fetch_danbooru_page(tags, page_num):
    global LAST_API_CALL_TIME

    if APP_PAUSED:
        return []

    with DATA_LOCK:
        now = time.time()
        wait_for = max(0.0, (LAST_API_CALL_TIME + MIN_API_INTERVAL) - now)
        LAST_API_CALL_TIME = now + wait_for

    if wait_for > 0:
        time.sleep(wait_for)

    if APP_PAUSED:
        return []

    try:
        data = _execute_danbooru_request(tags, page_num)
    except ValueError as e:
        tokens = [t for t in tags.split() if t]
        if str(e) == "HTTP_422_TAG_LIMIT" and len(tokens) > 2:
            fallback_tags = " ".join(tokens[:2])
            log_event(
                "api",
                f"HTTP 422 (2-tag limit on current account tier). Retrying with '{fallback_tags}'"
            )
            time.sleep(1.0)
            data = _execute_danbooru_request(fallback_tags, page_num)
        else:
            raise

    if isinstance(data, dict):
        error_msg = data.get("message", data.get("error", "API Error"))
        raise ValueError(f"Danbooru error: {error_msg}")
    if not isinstance(data, list):
        raise ValueError("Invalid format received from Danbooru.")
    return data


def fetch_tag_suggestions(query_prefix):
    if APP_PAUSED:
        return []
    params = {
        "search[name_matches]": f"*{query_prefix}*",
        "search[order]": "count",
        "limit": 5,
    }
    if USERNAME and API_KEY:
        params["login"] = USERNAME
        params["api_key"] = API_KEY

    url = "https://danbooru.donmai.us/tags.json"
    try:
        sess = get_http2_session()
        resp = sess.get(
            url,
            params=params,
            headers={
                "User-Agent": build_danbooru_user_agent(),
                "Accept": "application/json",
            },
            timeout=5,
        )
        if resp.status_code == 200:
            data = resp.json()
            if isinstance(data, list):
                return [(item.get("name"), item.get("post_count", 0)) for item in data if item.get("name")]
    except Exception as e:
        log_event("suggest", f"Suggestion fetch failed: {e}")
    return []


def suggestion_worker_loop():
    while IS_RUNNING:
        try:
            fragment, req_id = SUGGESTION_QUEUE.get(timeout=1.0)
        except Empty:
            continue

        if APP_PAUSED:
            SUGGESTION_QUEUE.task_done()
            continue

        results = fetch_tag_suggestions(fragment)
        if IS_RUNNING and APP_INSTANCE and req_id == APP_INSTANCE._suggest_req_id:
            try:
                if TK_ROOT:
                    TK_ROOT.after(0, lambda r=results, q=req_id: APP_INSTANCE.display_suggestions(r, q))
            except (tk.TclError, RuntimeError):
                pass
        SUGGESTION_QUEUE.task_done()


def fill_post_buffer(wait_if_busy=False):
    global CURRENT_TAGS, CURRENT_PAGE, LAST_STATUS, IS_FETCHING
    global CONSECUTIVE_FAILURES, CONSECUTIVE_EMPTY_PAGES, NEXT_ALLOWED_FETCH_TIME

    if APP_PAUSED:
        return

    with FETCH_CONDITION:
        if IS_FETCHING:
            if wait_if_busy:
                FETCH_CONDITION.wait(timeout=20.0)
            return

        now = time.time()
        if now < NEXT_ALLOWED_FETCH_TIME and not PENDING_TAG_QUEUE:
            return

        IS_FETCHING = True

    try:
        while IS_RUNNING and not APP_PAUSED:
            with DATA_LOCK:
                if PENDING_TAG_QUEUE:
                    CURRENT_TAGS = PENDING_TAG_QUEUE.popleft()
                    CURRENT_PAGE = 1
                    CONSECUTIVE_EMPTY_PAGES = 0
                    SEEN_POST_IDS.clear()
                    SEEN_POST_ORDER.clear()
                    SCREEN_SEEN_IDS.clear()

                target_tags = CURRENT_TAGS
                target_page = CURRENT_PAGE
                epoch = CACHE_EPOCH

            posts = fetch_danbooru_page(target_tags, target_page)

            with DATA_LOCK:
                if epoch != CACHE_EPOCH or APP_PAUSED:
                    continue

            if not posts:
                if target_page == 1:
                    with DATA_LOCK:
                        CONSECUTIVE_FAILURES += 1
                        backoff = min(30, max(5, 2 ** CONSECUTIVE_FAILURES))
                        NEXT_ALLOWED_FETCH_TIME = time.time() + backoff
                        LAST_STATUS = {"status": "error", "page": 1, "count": 0}
                    log_event("error", f"No posts found for '{target_tags}'. Backing off {backoff}s...")
                    return

                with DATA_LOCK:
                    CURRENT_PAGE = 1
                    CONSECUTIVE_EMPTY_PAGES = 0
                    SEEN_POST_IDS.clear()
                    SEEN_POST_ORDER.clear()
                    SCREEN_SEEN_IDS.clear()
                target_page = 1
                posts = fetch_danbooru_page(target_tags, target_page)

                with DATA_LOCK:
                    if epoch != CACHE_EPOCH or APP_PAUSED:
                        continue

            new_items = []
            skipped_large_mp4 = 0
            with DATA_LOCK:
                if epoch != CACHE_EPOCH:
                    continue

                for p in posts:
                    if not isinstance(p, dict):
                        continue
                    pid = p.get("id")
                    file_url = p.get("file_url")
                    ext = p.get("file_ext", "").lower()
                    file_size = int(p.get("file_size") or 0)

                    if not pid or pid in SEEN_POST_IDS or not file_url or ext not in ALLOWED_EXTENSIONS:
                        continue

                    if ext == "mp4" and (file_size <= 0 or file_size > MAX_MP4_FILE_SIZE_BYTES):
                        skipped_large_mp4 += 1
                        continue

                    track_post_id_locked(pid)
                    safe_url = urllib.parse.quote(file_url, safe="")
                    local_media_endpoint = (
                        f"http://127.0.0.1:{PORT}/media?url={safe_url}&ext={ext}&size={file_size}"
                    )
                    p["media_url"] = local_media_endpoint
                    p["proxy_url"] = local_media_endpoint
                    p["epoch"] = epoch
                    new_items.append(p)

                random.shuffle(new_items)
                POST_BUFFER.extend(new_items)
                CURRENT_PAGE = target_page + 1
                LAST_STATUS = {"status": "ok", "page": target_page, "count": len(new_items)}
                CONSECUTIVE_FAILURES = 0

                if len(new_items) == 0:
                    CONSECUTIVE_EMPTY_PAGES += 1
                    if CONSECUTIVE_EMPTY_PAGES >= 2:
                        NEXT_ALLOWED_FETCH_TIME = time.time() + 10.0
                        log_event("fetch", f"Multiple pages returned 0 usable items for '{target_tags}'. Cooling down 10s.")
                    else:
                        NEXT_ALLOWED_FETCH_TIME = time.time() + MIN_API_INTERVAL
                else:
                    CONSECUTIVE_EMPTY_PAGES = 0
                    NEXT_ALLOWED_FETCH_TIME = time.time() + MIN_API_INTERVAL

            extra_msg = f" (filtered {skipped_large_mp4} oversized MP4s)" if skipped_large_mp4 else ""
            log_event(
                "fetch",
                f"Fetched and shuffled {len(new_items)} media items (Page {target_page}) for '{target_tags}'{extra_msg}."
            )
            break

    except Exception as e:
        with DATA_LOCK:
            CONSECUTIVE_FAILURES += 1
            backoff = min(30, max(4, 2 ** CONSECUTIVE_FAILURES))
            NEXT_ALLOWED_FETCH_TIME = time.time() + backoff
            LAST_STATUS = {"status": "error", "page": CURRENT_PAGE, "count": 0}

        log_event("error", f"Fetch error: {e}. Backing off {backoff}s...")
    finally:
        with FETCH_CONDITION:
            IS_FETCHING = False
            FETCH_CONDITION.notify_all()


# =============================================================================
# 5. HTTP SERVER & LOCAL /media STREAMING PROXY (HYBRID HTTP/2 + DoH)
# =============================================================================
class ReusableThreadingHTTPServer(ThreadingHTTPServer):
    allow_reuse_address = True


class ProxyHandler(BaseHTTPRequestHandler):
    def _is_authorized_local_request(self):
        origin = self.headers.get("Origin")
        sec_site = self.headers.get("Sec-Fetch-Site")
        if origin and origin not in ALLOWED_LOCAL_ORIGINS:
            log_event("security", f"Blocked unauthorized cross-origin request from Origin: {origin}")
            return False
        if sec_site and sec_site not in ("same-origin", "none"):
            log_event("security", f"Blocked external browser request (Sec-Fetch-Site: {sec_site})")
            return False
        return True

    def do_OPTIONS(self):
        if not self._is_authorized_local_request():
            self.send_response(403)
            self.send_header("Connection", "close")
            self.end_headers()
            return
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", f"http://127.0.0.1:{PORT}")
        self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Range")
        self.send_header("Connection", "close")
        self.end_headers()

    def do_GET(self):
        global EPOCH_POLL_COUNT, LAST_EPOCH_LOG_TIME

        if not self._is_authorized_local_request():
            self.send_response(403)
            self.send_header("Connection", "close")
            self.end_headers()
            return

        parsed_url = urllib.parse.urlparse(self.path)
        path_only = parsed_url.path
        query_params = urllib.parse.parse_qs(parsed_url.query)
        screen_id = query_params.get("screen", ["screen_1"])[0]

        if path_only in ("/", "/index.html"):
            try:
                with open(BUNDLED_HTML_FILE, "rb") as f:
                    html_bytes = f.read()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(html_bytes)))
                self.send_header("Cache-Control", "no-store, no-cache, must-revalidate")
                self.send_header("Referrer-Policy", "no-referrer")
                self.send_header("X-Frame-Options", "DENY")
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(html_bytes)
            except Exception as e:
                log_event("server", f"Error serving index.html: {e}")
                self.send_response(500)
                self.end_headers()
            return

        if path_only == "/properties":
            try:
                sc_cfg = get_screen_config(screen_id)
                payload = {
                    "enabled": sc_cfg["enabled"],
                    "properties": sc_cfg["properties"],
                    "app_paused": APP_PAUSED,
                    "wallpaper_paused": WALLPAPER_PAUSED,
                }
                props_body = json.dumps(payload).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(props_body)))
                self.send_header("Cache-Control", "no-store")
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(props_body)
            except Exception:
                pass
            return

        if path_only == "/epoch":
            now = time.time()
            should_log_ping = False
            poll_count_snapshot = 0
            elapsed_snapshot = 0

            with DATA_LOCK:
                if LAST_EPOCH_LOG_TIME == 0.0:
                    LAST_EPOCH_LOG_TIME = now

                EPOCH_POLL_COUNT += 1
                res_body = json.dumps({
                    "epoch": CACHE_EPOCH,
                    "app_paused": APP_PAUSED,
                    "wallpaper_paused": WALLPAPER_PAUSED,
                }).encode("utf-8")

                elapsed = now - LAST_EPOCH_LOG_TIME
                if elapsed >= 60.0:
                    should_log_ping = True
                    poll_count_snapshot = EPOCH_POLL_COUNT
                    elapsed_snapshot = int(elapsed)
                    EPOCH_POLL_COUNT = 0
                    LAST_EPOCH_LOG_TIME = now

            if should_log_ping and not APP_PAUSED:
                log_event("ping", f"Client polled /epoch ({poll_count_snapshot} times in last {elapsed_snapshot}s)")

            try:
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Cache-Control", "no-store")
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(res_body)
            except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError, OSError):
                pass
            return

        if path_only == "/api":
            if APP_PAUSED:
                try:
                    empty_body = b"[]"
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(empty_body)))
                    self.send_header("Connection", "close")
                    self.end_headers()
                    self.wfile.write(empty_body)
                except Exception:
                    pass
                return

            log_event("server", f"Client '{screen_id}' requested batch from /api")
            try:
                with DATA_LOCK:
                    needs_blocking_fill = (len(POST_BUFFER) == 0)

                if needs_blocking_fill:
                    fill_post_buffer(wait_if_busy=True)

                batch = []
                active_screen_count = max(1, sum(1 for s in CONNECTED_SCREENS if get_screen_config(s["id"])["enabled"]))
                batch_target = 25 if active_screen_count > 1 else 40

                with DATA_LOCK:
                    screen_seen = SCREEN_SEEN_IDS.setdefault(screen_id, set())
                    skipped_for_this_screen = []

                    while POST_BUFFER and len(batch) < batch_target:
                        candidate = POST_BUFFER.popleft()
                        cid = candidate.get("id")
                        if cid and cid not in screen_seen:
                            screen_seen.add(cid)
                            if len(screen_seen) > 1000:
                                screen_seen.clear()
                                screen_seen.add(cid)
                            batch.append(candidate)
                        else:
                            skipped_for_this_screen.append(candidate)

                    for item in reversed(skipped_for_this_screen):
                        POST_BUFFER.appendleft(item)

                    active_epoch = CACHE_EPOCH
                    now = time.time()
                    needs_background_refill = (
                        len(POST_BUFFER) < 30
                        and not IS_FETCHING
                        and now >= NEXT_ALLOWED_FETCH_TIME
                    )

                if needs_background_refill and not APP_PAUSED:
                    threading.Thread(target=fill_post_buffer, daemon=True).start()

                response_body = json.dumps(batch).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(response_body)))
                self.send_header("X-Danbooru-Epoch", str(active_epoch))
                self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(response_body)

            except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError, OSError):
                pass
            except Exception as e:
                log_event("error", f"API dispatch error: {e}")
                try:
                    err_payload = json.dumps([]).encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Connection", "close")
                    self.end_headers()
                    self.wfile.write(err_payload)
                except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError, OSError):
                    pass
            return

        if path_only in ("/media", "/image"):
            if APP_PAUSED:
                self.send_response(503)
                self.send_header("Connection", "close")
                self.end_headers()
                return

            target_url = query_params.get("url", [None])[0]
            ext_hint = query_params.get("ext", [""])[0].lower()
            size_hint_str = query_params.get("size", ["0"])[0]

            if not target_url:
                self.send_response(400)
                self.send_header("Connection", "close")
                self.end_headers()
                return

            parsed_target = urllib.parse.urlparse(target_url)
            target_host = (parsed_target.hostname or "").lower()
            if parsed_target.scheme != "https" or target_host not in ALLOWED_MEDIA_HOSTS:
                log_event("security", f"Blocked unauthorized media host: {target_host}")
                self.send_response(403)
                self.send_header("Connection", "close")
                self.end_headers()
                return

            is_mp4 = ext_hint == "mp4" or parsed_target.path.lower().endswith(".mp4")

            if is_mp4:
                try:
                    if int(size_hint_str) > MAX_MP4_FILE_SIZE_BYTES:
                        log_event("proxy", f"Filtered oversized MP4 ({size_hint_str} bytes > 15 MB): {target_url}")
                        self.send_response(413)
                        self.send_header("Connection", "close")
                        self.end_headers()
                        return
                except ValueError:
                    pass

            req_headers = {
                "User-Agent": build_danbooru_user_agent(),
                "Referer": "https://danbooru.donmai.us/",
                "Accept": "image/avif,image/webp,image/apng,image/*,video/mp4,video/*;q=0.9,*/*;q=0.8",
            }
            if is_mp4:
                client_range = self.headers.get("Range")
                if client_range:
                    req_headers["Range"] = client_range

            headers_sent = False
            resp = None
            try:
                sess = get_http2_session()
                resp = sess.get(
                    target_url,
                    headers=req_headers,
                    stream=True,
                    timeout=20,
                    allow_redirects=True,
                )
                status_code = resp.status_code or 200

                if status_code >= 400:
                    log_event("proxy", f"Upstream media HTTP {status_code} for {target_url}")
                    self.send_response(status_code)
                    self.send_header("Connection", "close")
                    self.end_headers()
                    return

                content_type = (
                    resp.headers.get("Content-Type")
                    or resp.headers.get("content-type")
                    or ("video/mp4" if is_mp4 else "image/jpeg")
                )
                content_len_str = resp.headers.get("Content-Length") or resp.headers.get("content-length")
                content_range = resp.headers.get("Content-Range") or resp.headers.get("content-range")

                if "video/mp4" in content_type.lower():
                    is_mp4 = True

                if is_mp4 and content_len_str:
                    try:
                        if int(content_len_str) > MAX_MP4_FILE_SIZE_BYTES:
                            log_event(
                                "proxy",
                                f"Filtered oversized MP4 from stream ({int(content_len_str):,} bytes > 15 MB): {target_url}"
                            )
                            self.send_response(413)
                            self.send_header("Connection", "close")
                            self.end_headers()
                            return
                    except ValueError:
                        pass

                self.send_response(status_code)
                self.send_header("Content-Type", content_type)
                if content_len_str:
                    self.send_header("Content-Length", content_len_str)
                if content_range:
                    self.send_header("Content-Range", content_range)
                self.send_header("Accept-Ranges", "bytes")
                self.send_header("Cache-Control", "no-store")
                self.send_header("Connection", "close")
                self.end_headers()
                headers_sent = True

                bytes_streamed = 0
                for chunk in iter_response_chunks(resp, chunk_size=65536):
                    if APP_PAUSED or not chunk:
                        break
                    bytes_streamed += len(chunk)
                    if is_mp4 and bytes_streamed > MAX_MP4_FILE_SIZE_BYTES:
                        log_event("proxy", f"Aborted MP4 stream exceeding 15 MB cap: {target_url}")
                        break
                    self.wfile.write(chunk)

            except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
                pass
            except Exception as e:
                log_event("proxy", f"Proxy stream error for {target_url}: {e}")
                if not headers_sent:
                    try:
                        self.send_response(502)
                        self.send_header("Connection", "close")
                        self.end_headers()
                    except Exception:
                        pass
            finally:
                if resp is not None:
                    try:
                        resp.close()
                    except Exception:
                        pass
            return

        self.send_response(404)
        self.send_header("Connection", "close")
        self.end_headers()

    def log_message(self, format, *args):
        pass


# =============================================================================
# 6. GLOSSARY WINDOW, TABBED SETTINGS DIALOG & FLOATING SEARCH BAR (LIGHT/DARK)
# =============================================================================
class GlossaryDialog(tk.Toplevel):
    """
    Modal/Floating window triggered by the 'Glossary' button on the Logs tab.
    Displays every log output category and what it means, styled with the active theme.
    """
    def __init__(self, parent):
        super().__init__(parent)
        self.is_open = True
        self._drag_x = 0
        self._drag_y = 0

        self.overrideredirect(True)
        self.attributes("-alpha", 0.98)
        self.attributes("-topmost", True)

        width = 560
        height = 440
        parent.update_idletasks()
        px = parent.winfo_x()
        py = parent.winfo_y()
        sw = self.winfo_screenwidth()
        sh = self.winfo_screenheight()

        x = max(20, min(px + 30, sw - width - 20))
        y = max(20, min(py + 40, sh - height - 20))
        self.geometry(f"{width}x{height}+{x}+{y}")

        self.container = tk.Frame(self, highlightthickness=1)
        self.container.pack(fill="both", expand=True, padx=1, pady=1)

        self.header = tk.Frame(self.container)
        self.header.pack(fill="x", padx=14, pady=(10, 6))

        self.title_lbl = tk.Label(
            self.header, text="📖 LOG OUTPUT GLOSSARY", font=("Segoe UI", 10, "bold")
        )
        self.title_lbl.pack(side="left")

        self.close_btn = tk.Label(
            self.header, text="✕", font=("Segoe UI", 10, "bold"), cursor="hand2"
        )
        self.close_btn.pack(side="right")
        self.close_btn.bind("<Button-1>", lambda e: self.close_glossary())

        self.header.bind("<Button-1>", self.start_move)
        self.header.bind("<B1-Motion>", self.do_move)
        self.title_lbl.bind("<Button-1>", self.start_move)
        self.title_lbl.bind("<B1-Motion>", self.do_move)

        self.body_frame = tk.Frame(self.container)
        self.body_frame.pack(fill="both", expand=True, padx=14, pady=(4, 14))

        self.text_box_frame = tk.Frame(self.body_frame, highlightthickness=1)
        self.text_box_frame.pack(fill="both", expand=True)

        self.glossary_text = tk.Text(
            self.text_box_frame, wrap="word", font=("Segoe UI", 9),
            bd=0, relief="flat", padx=10, pady=8
        )
        scrollbar = ttk.Scrollbar(self.text_box_frame, orient="vertical", command=self.glossary_text.yview)
        self.glossary_text.configure(yscrollcommand=scrollbar.set)

        scrollbar.pack(side="right", fill="y")
        self.glossary_text.pack(side="left", fill="both", expand=True)

        self.glossary_text.tag_configure("tag_name", font=("Consolas", 9, "bold"), foreground="#0067c0")
        for tag_label, desc in LOG_GLOSSARY_ENTRIES:
            self.glossary_text.insert(tk.END, f"{tag_label}\n", ("tag_name",))
            self.glossary_text.insert(tk.END, f"  {desc}\n\n")
        self.glossary_text.configure(state="disabled")

        self.apply_theme()
        self.bind("<Escape>", lambda e: self.close_glossary())

    def apply_theme(self):
        pal = THEME_PALETTES[CURRENT_THEME]
        self.configure(bg=pal["border_col"])
        self.container.configure(bg=pal["bg_base"], highlightbackground=pal["border_col"])
        self.header.configure(bg=pal["bg_base"])
        self.title_lbl.configure(bg=pal["bg_base"], fg=pal["text_dark"])
        self.close_btn.configure(bg=pal["bg_base"], fg=pal["text_muted"])
        self.body_frame.configure(bg=pal["bg_base"])
        self.text_box_frame.configure(bg=pal["input_bg"], highlightbackground=pal["border_col"])
        self.glossary_text.configure(bg=pal["input_bg"], fg=pal["text_dark"])
        self.glossary_text.tag_configure(
            "tag_name",
            font=("Consolas", 9, "bold"),
            foreground="#4da3ff" if CURRENT_THEME == "dark" else "#0067c0",
        )

    def start_move(self, event):
        self._drag_x = event.x
        self._drag_y = event.y

    def do_move(self, event):
        x = self.winfo_x() + (event.x - self._drag_x)
        y = self.winfo_y() + (event.y - self._drag_y)
        self.geometry(f"+{x}+{y}")

    def close_glossary(self):
        self.is_open = False
        self.destroy()


class SettingsDialog(tk.Toplevel):
    """
    Unified tabbed settings dialog containing:
    - Tab 1: Credentials (account credentials, search bar lock/unlock, Light/Dark Mode toggle)
    - Tab 2: Display (per-screen selector, enable checkbox, dynamic mode-specific section visibility)
    - Tab 3: Logs (PAUSE APPLICATION master button, Glossary button, Clear Logs button, smart log history)
    """
    NUMERIC_SPECS = {
        "scrollspeed": {
            "label": "Scroll Speed (0.1 – 600 px/s):",
            "min": 0.1,
            "max": 600.0,
            "default": 120,
            "is_float": True,
            "precision": 2,
        },
        "gapsize": {
            "label": "Image Gap (0 – 64 px):",
            "min": 0,
            "max": 64,
            "default": 12,
            "is_float": False,
            "precision": 0,
        },
        "dropspeed": {
            "label": "Drop Speed (0.2 – 4.0):",
            "min": 0.2,
            "max": 4.0,
            "default": 1.0,
            "is_float": True,
            "precision": 2,
        },
        "minsize": {
            "label": "Minimum Size (120 – 600 px):",
            "min": 120,
            "max": 600,
            "default": 220,
            "is_float": False,
            "precision": 0,
        },
        "maxsize": {
            "label": "Maximum Size (150 – 900 px):",
            "min": 150,
            "max": 900,
            "default": 440,
            "is_float": False,
            "precision": 0,
        },
        "dropdelay": {
            "label": "Spawn/Drop Delay (0 – 600 s):",
            "min": 0,
            "max": 600,
            "default": 0,
            "is_float": False,
            "precision": 0,
        },
        "slideshowfade": {
            "label": "Fade Transition (0 – 10 [0s–1s]):",
            "min": 0.0,
            "max": 10.0,
            "default": 5.0,
            "is_float": True,
            "precision": 1,
        },
        "slideshowduration": {
            "label": "Display Duration (0 – 600 s):",
            "min": 0,
            "max": 600,
            "default": 10,
            "is_float": False,
            "precision": 0,
        },
    }

    def __init__(self, parent, on_save_credentials_callback, initial_values=None):
        super().__init__(parent)
        self.on_save_credentials_callback = on_save_credentials_callback
        self.is_open = True
        self._drag_x = 0
        self._drag_y = 0
        self._fill_cooldown_remaining = 0
        self._fill_timer_job = None
        self._live_apply_job = None
        self._syncing_controls = False

        self._themed_frames = []
        self._themed_borders = []
        self._themed_labels_dark = []
        self._themed_labels_muted = []
        self._themed_entries = []
        self._themed_neutral_btns = []

        self.overrideredirect(True)
        self.attributes("-alpha", 0.97)
        self.attributes("-topmost", True)

        pal = THEME_PALETTES[CURRENT_THEME]
        self.bg_base = pal["bg_base"]
        self.input_bg = pal["input_bg"]
        self.border_col = pal["border_col"]
        self.text_dark = pal["text_dark"]
        self.text_muted = pal["text_muted"]

        self.configure(bg=self.border_col)

        width = 610
        height = 540
        parent.update_idletasks()
        px = parent.winfo_x()
        py = parent.winfo_y()
        sw = self.winfo_screenwidth()
        sh = self.winfo_screenheight()

        x = max(20, min(px + (parent.winfo_width() - width) // 2, sw - width - 20))
        y = max(20, min(py - height - 10 if py - height - 10 > 0 else py + 60, sh - height - 20))
        self.geometry(f"{width}x{height}+{x}+{y}")

        self.container = tk.Frame(self, bg=self.bg_base, highlightthickness=1, highlightbackground=self.border_col)
        self.container.pack(fill="both", expand=True, padx=1, pady=1)
        self._themed_borders.append(self.container)

        self.header = tk.Frame(self.container, bg=self.bg_base)
        self.header.pack(fill="x", padx=14, pady=(10, 6))
        self._themed_frames.append(self.header)

        self.title_lbl = tk.Label(
            self.header, text="⚙ APPLICATION SETTINGS", font=("Segoe UI", 10, "bold"),
            fg=self.text_dark, bg=self.bg_base
        )
        self.title_lbl.pack(side="left")
        self._themed_labels_dark.append(self.title_lbl)

        self.close_btn = tk.Label(
            self.header, text="✕", font=("Segoe UI", 10, "bold"),
            fg=self.text_muted, bg=self.bg_base, cursor="hand2"
        )
        self.close_btn.pack(side="right")
        self.close_btn.bind("<Button-1>", lambda e: self.close_dialog())
        self._themed_labels_muted.append(self.close_btn)

        self.header.bind("<Button-1>", self.start_move)
        self.header.bind("<B1-Motion>", self.do_move)
        self.title_lbl.bind("<Button-1>", self.start_move)
        self.title_lbl.bind("<B1-Motion>", self.do_move)

        self.style = ttk.Style(self)
        self.notebook = ttk.Notebook(self.container)
        self.notebook.pack(fill="both", expand=True, padx=12, pady=(4, 12))

        self.tab_credentials = tk.Frame(self.notebook, bg=self.bg_base)
        self.tab_display = tk.Frame(self.notebook, bg=self.bg_base)
        self.tab_logs = tk.Frame(self.notebook, bg=self.bg_base)
        self._themed_frames.extend([self.tab_credentials, self.tab_display, self.tab_logs])

        self.notebook.add(self.tab_credentials, text="Credentials")
        self.notebook.add(self.tab_display, text="Display")
        self.notebook.add(self.tab_logs, text="Logs")

        self._build_credentials_tab(initial_values or {})
        self._build_display_tab()
        self._build_logs_tab()

        self.apply_theme()
        self.bind("<Escape>", lambda e: self.close_dialog())

    # -------------------------------------------------------------------------
    # TAB 1: CREDENTIALS (PURE API AUTH + SEARCH LOCK + LIGHT/DARK MODE BUTTON)
    # -------------------------------------------------------------------------
    def _build_credentials_tab(self, vals):
        pad_frame = tk.Frame(self.tab_credentials, bg=self.bg_base)
        pad_frame.pack(fill="both", expand=True, padx=16, pady=14)
        self._themed_frames.append(pad_frame)

        sec_lbl = tk.Label(
            pad_frame, text="DANBOORU API CREDENTIALS (HTTP/2 + DoH)",
            font=("Segoe UI", 8, "bold"), fg=self.text_muted, bg=self.bg_base
        )
        sec_lbl.pack(anchor="w", pady=(0, 8))
        self._themed_labels_muted.append(sec_lbl)

        self.cred_entries = {}
        fields = [
            ("USERNAME", "Username:"),
            ("USER_ID", "User ID:"),
            ("API_KEY", "API Key (DPAPI):"),
        ]

        for key, label_text in fields:
            row = tk.Frame(pad_frame, bg=self.bg_base)
            row.pack(fill="x", pady=5)
            self._themed_frames.append(row)

            lbl = tk.Label(
                row, text=label_text, width=16, anchor="w",
                font=("Segoe UI", 9), fg=self.text_dark, bg=self.bg_base
            )
            lbl.pack(side="left")
            self._themed_labels_dark.append(lbl)

            entry_box = tk.Frame(row, bg=self.input_bg, highlightthickness=1, highlightbackground=self.border_col)
            entry_box.pack(side="right", fill="x", expand=True)
            self._themed_borders.append(entry_box)

            entry = tk.Entry(
                entry_box, bg=self.input_bg, fg=self.text_dark, insertbackground=self.text_dark,
                bd=0, font=("Segoe UI", 9), relief="flat"
            )
            entry.pack(fill="x", padx=6, pady=4)
            if key == "API_KEY":
                entry.configure(show="•")
            if vals.get(key):
                entry.insert(0, vals[key])
            self.cred_entries[key] = entry
            self._themed_entries.append((entry_box, entry))

        self.cred_sep = tk.Frame(pad_frame, bg=self.border_col, height=1)
        self.cred_sep.pack(fill="x", pady=14)

        lock_row = tk.Frame(pad_frame, bg=self.bg_base)
        lock_row.pack(fill="x", pady=6)
        self._themed_frames.append(lock_row)

        lock_lbl = tk.Label(
            lock_row, text="Search Bar Position:", width=16, anchor="w",
            font=("Segoe UI", 9), fg=self.text_dark, bg=self.bg_base
        )
        lock_lbl.pack(side="left")
        self._themed_labels_dark.append(lock_lbl)

        is_locked_now = APP_INSTANCE.is_locked if APP_INSTANCE else False
        self.lock_btn = tk.Button(
            lock_row,
            text="🔒 Locked" if is_locked_now else "🔓 Unlocked",
            fg=self.text_dark, bg="#e8e8ed", activebackground="#dcdce0",
            bd=0, relief="flat", font=("Segoe UI Emoji", 9, "bold"), cursor="hand2",
            padx=14, pady=4, command=self.toggle_search_lock
        )
        self.lock_btn.pack(side="left")
        self._themed_neutral_btns.append(self.lock_btn)

        # Light Mode / Dark Mode switch button on Credentials tab
        theme_row = tk.Frame(pad_frame, bg=self.bg_base)
        theme_row.pack(fill="x", pady=8)
        self._themed_frames.append(theme_row)

        theme_lbl = tk.Label(
            theme_row, text="Application Theme:", width=16, anchor="w",
            font=("Segoe UI", 9), fg=self.text_dark, bg=self.bg_base
        )
        theme_lbl.pack(side="left")
        self._themed_labels_dark.append(theme_lbl)

        self.theme_btn = tk.Button(
            theme_row,
            text="Dark Mode" if CURRENT_THEME == "light" else "Light Mode",
            fg=self.text_dark, bg="#e8e8ed", activebackground="#dcdce0",
            bd=0, relief="flat", font=("Segoe UI", 9, "bold"), cursor="hand2",
            padx=14, pady=4, command=self.toggle_theme_mode
        )
        self.theme_btn.pack(side="left")
        self._themed_neutral_btns.append(self.theme_btn)

        btn_row = tk.Frame(pad_frame, bg=self.bg_base)
        btn_row.pack(fill="x", side="bottom", pady=(10, 0))
        self._themed_frames.append(btn_row)

        save_cred_btn = tk.Button(
            btn_row, text="Save Credentials", bg="#0067c0", fg="#ffffff",
            activebackground="#005da6", activeforeground="#ffffff",
            font=("Segoe UI", 9, "bold"), bd=0, relief="flat",
            padx=20, pady=6, cursor="hand2", command=self.save_credentials_only
        )
        save_cred_btn.pack(side="right")

    def toggle_search_lock(self):
        if APP_INSTANCE:
            APP_INSTANCE.toggle_lock()
            self.lock_btn.configure(text="🔒 Locked" if APP_INSTANCE.is_locked else "🔓 Unlocked")

    def toggle_theme_mode(self):
        global CURRENT_THEME
        CURRENT_THEME = "dark" if CURRENT_THEME == "light" else "light"
        if APP_INSTANCE:
            APP_INSTANCE.config["theme"] = CURRENT_THEME
            store_app_config(APP_INSTANCE.config)
            APP_INSTANCE.apply_theme()
        self.apply_theme()
        if GLOSSARY_DIALOG_INSTANCE and getattr(GLOSSARY_DIALOG_INSTANCE, "is_open", False):
            try:
                GLOSSARY_DIALOG_INSTANCE.apply_theme()
            except Exception:
                pass
        log_event("ui", f"Switched application theme to {CURRENT_THEME.upper()} mode.")

    def save_credentials_only(self):
        user = self.cred_entries["USERNAME"].get().strip()
        uid = self.cred_entries["USER_ID"].get().strip()
        key = self.cred_entries["API_KEY"].get().strip()
        self.on_save_credentials_callback(user, uid, key)

    # -------------------------------------------------------------------------
    # TAB 2: DISPLAY (DYNAMIC PER-MODE SECTIONS: SCROLL | COLLAGE | SLIDESHOW)
    # -------------------------------------------------------------------------
    def _build_display_tab(self):
        self.prop_entries = {}
        self.prop_sliders = {}
        self.prop_vars = {}

        pad_frame = tk.Frame(self.tab_display, bg=self.bg_base)
        pad_frame.pack(fill="both", expand=True, padx=16, pady=10)
        self._themed_frames.append(pad_frame)

        global CONNECTED_SCREENS
        CONNECTED_SCREENS = enumerate_connected_monitors()
        self.screen_map = {s["label"]: s["id"] for s in CONNECTED_SCREENS}
        screen_labels = [s["label"] for s in CONNECTED_SCREENS]

        screen_row = tk.Frame(pad_frame, bg=self.bg_base)
        screen_row.pack(fill="x", pady=3)
        self._themed_frames.append(screen_row)

        scr_lbl = tk.Label(
            screen_row, text="Select Screen:", width=26, anchor="w",
            font=("Segoe UI", 9, "bold"), fg=self.text_dark, bg=self.bg_base
        )
        scr_lbl.pack(side="left")
        self._themed_labels_dark.append(scr_lbl)

        self.selected_screen_label = tk.StringVar(value=screen_labels[0])
        self.screen_combo = ttk.Combobox(
            screen_row, textvariable=self.selected_screen_label,
            values=screen_labels, state="readonly"
        )
        self.screen_combo.pack(side="right", fill="x", expand=True)
        self.screen_combo.bind("<<ComboboxSelected>>", self._on_screen_selection_changed)

        enable_row = tk.Frame(pad_frame, bg=self.bg_base)
        enable_row.pack(fill="x", pady=(4, 6))
        self._themed_frames.append(enable_row)

        self.screen_enabled_var = tk.BooleanVar(value=True)
        self.screen_enable_chk = tk.Checkbutton(
            enable_row,
            text="Display wallpaper on this screen",
            variable=self.screen_enabled_var,
            bg=self.bg_base, fg=self.text_dark, activebackground=self.bg_base,
            font=("Segoe UI", 9, "bold"), cursor="hand2",
            command=self._schedule_live_apply
        )
        self.screen_enable_chk.pack(anchor="w")

        self.disp_sep = tk.Frame(pad_frame, bg=self.border_col, height=1)
        self.disp_sep.pack(fill="x", pady=4)

        mode_row = tk.Frame(pad_frame, bg=self.bg_base)
        mode_row.pack(fill="x", pady=3)
        self._themed_frames.append(mode_row)

        mode_lbl = tk.Label(
            mode_row, text="Display Mode:", width=26, anchor="w",
            font=("Segoe UI", 9, "bold"), fg=self.text_dark, bg=self.bg_base
        )
        mode_lbl.pack(side="left")
        self._themed_labels_dark.append(mode_lbl)

        self.mode_var = tk.StringVar(value="scroll")
        self.mode_combo = ttk.Combobox(
            mode_row,
            textvariable=self.mode_var,
            values=["scroll", "collage", "slideshow"],
            state="readonly",
        )
        self.mode_combo.pack(side="right", fill="x", expand=True)
        self.mode_combo.bind(
            "<<ComboboxSelected>>",
            lambda e: (
                self._update_mode_sections_visibility(),
                self._update_fill_btn_state(),
                self._schedule_live_apply(),
            ),
        )

        # Container holding the mode-specific sections (only active mode is visible)
        self.mode_sections_holder = tk.Frame(pad_frame, bg=self.bg_base)
        self.mode_sections_holder.pack(fill="both", expand=True, pady=(6, 4))
        self._themed_frames.append(self.mode_sections_holder)

        # 1. SCROLL MODE SECTION
        self.scroll_section_frame = tk.Frame(self.mode_sections_holder, bg=self.bg_base)
        self._themed_frames.append(self.scroll_section_frame)

        scroll_hdr = tk.Label(
            self.scroll_section_frame, text="CONTINUOUS SCROLL SETTINGS",
            font=("Segoe UI", 8, "bold"), fg=self.text_muted, bg=self.bg_base
        )
        scroll_hdr.pack(anchor="w", pady=(4, 4))
        self._themed_labels_muted.append(scroll_hdr)

        dir_row = tk.Frame(self.scroll_section_frame, bg=self.bg_base)
        dir_row.pack(fill="x", pady=3)
        self._themed_frames.append(dir_row)

        dir_lbl = tk.Label(
            dir_row, text="Scroll Direction:", width=26, anchor="w",
            font=("Segoe UI", 9), fg=self.text_dark, bg=self.bg_base
        )
        dir_lbl.pack(side="left")
        self._themed_labels_dark.append(dir_lbl)

        self.dir_var = tk.StringVar(value="left")
        dir_combo = ttk.Combobox(
            dir_row,
            textvariable=self.dir_var,
            values=["left", "right", "up", "down"],
            state="readonly",
        )
        dir_combo.pack(side="right", fill="x", expand=True)
        dir_combo.bind("<<ComboboxSelected>>", lambda e: self._schedule_live_apply())

        for pkey in ("scrollspeed", "gapsize"):
            self._create_numeric_row(self.scroll_section_frame, pkey, self.NUMERIC_SPECS[pkey])

        # 2. COLLAGE MODE SECTION
        self.collage_section_frame = tk.Frame(self.mode_sections_holder, bg=self.bg_base)
        self._themed_frames.append(self.collage_section_frame)

        collage_hdr = tk.Label(
            self.collage_section_frame, text="POLAROID COLLAGE SETTINGS",
            font=("Segoe UI", 8, "bold"), fg=self.text_muted, bg=self.bg_base
        )
        collage_hdr.pack(anchor="w", pady=(4, 4))
        self._themed_labels_muted.append(collage_hdr)

        for pkey in ("dropspeed", "minsize", "maxsize", "dropdelay"):
            self._create_numeric_row(self.collage_section_frame, pkey, self.NUMERIC_SPECS[pkey])

        fill_row = tk.Frame(self.collage_section_frame, bg=self.bg_base)
        fill_row.pack(fill="x", pady=(8, 4))
        self._themed_frames.append(fill_row)

        fill_lbl = tk.Label(
            fill_row, text="Collage Action:", width=26, anchor="w",
            font=("Segoe UI", 9), fg=self.text_dark, bg=self.bg_base
        )
        fill_lbl.pack(side="left")
        self._themed_labels_dark.append(fill_lbl)

        self.fill_screen_btn = tk.Button(
            fill_row, text="Fill Screen", bg="#0067c0", fg="#ffffff",
            activebackground="#005da6", activeforeground="#ffffff",
            disabledforeground="#a0a0a5",
            font=("Segoe UI", 9, "bold"), bd=0, relief="flat",
            padx=14, pady=4, cursor="hand2", command=self._on_fill_screen_clicked
        )
        self.fill_screen_btn.pack(side="left")

        self.fill_timer_lbl = tk.Label(
            fill_row, text="", font=("Segoe UI", 9, "bold"),
            fg="#d13438", bg=self.bg_base
        )
        self.fill_timer_lbl.pack(side="left", padx=(10, 0))
        self._themed_frames.append(self.fill_timer_lbl)

        # 3. SLIDESHOW MODE SECTION
        self.slideshow_section_frame = tk.Frame(self.mode_sections_holder, bg=self.bg_base)
        self._themed_frames.append(self.slideshow_section_frame)

        slide_hdr = tk.Label(
            self.slideshow_section_frame,
            text="FULLSCREEN SLIDESHOW SETTINGS (ORIENTATION-MATCHED)",
            font=("Segoe UI", 8, "bold"), fg=self.text_muted, bg=self.bg_base
        )
        slide_hdr.pack(anchor="w", pady=(4, 4))
        self._themed_labels_muted.append(slide_hdr)

        for pkey in ("slideshowfade", "slideshowduration"):
            self._create_numeric_row(self.slideshow_section_frame, pkey, self.NUMERIC_SPECS[pkey])

        slide_note = tk.Label(
            self.slideshow_section_frame,
            text="• Automatically filters API posts to match screen orientation (Landscape vs. Portrait).\n"
                 "• Fade Transition: 0 = instant change (0.0s), 10 = 1.0 second smooth cross-fade.",
            justify="left", anchor="w",
            font=("Segoe UI", 8), fg=self.text_muted, bg=self.bg_base
        )
        slide_note.pack(anchor="w", pady=(8, 2))
        self._themed_labels_muted.append(slide_note)

        btn_row = tk.Frame(pad_frame, bg=self.bg_base)
        btn_row.pack(fill="x", side="bottom", pady=(6, 0))
        self._themed_frames.append(btn_row)

        save_disp_btn = tk.Button(
            btn_row, text="Save & Apply Display Settings", bg="#0067c0", fg="#ffffff",
            activebackground="#005da6", activeforeground="#ffffff",
            font=("Segoe UI", 9, "bold"), bd=0, relief="flat",
            padx=18, pady=6, cursor="hand2", command=self.save_display_settings
        )
        save_disp_btn.pack(side="right")

        self._load_screen_values_into_form(self._get_current_selected_screen_id())

    def _update_mode_sections_visibility(self):
        """Hides all display mode settings sections except the currently selected display mode."""
        self.scroll_section_frame.pack_forget()
        self.collage_section_frame.pack_forget()
        self.slideshow_section_frame.pack_forget()

        active_mode = self.mode_var.get()
        if active_mode == "scroll":
            self.scroll_section_frame.pack(fill="both", expand=True)
        elif active_mode == "collage":
            self.collage_section_frame.pack(fill="both", expand=True)
        elif active_mode == "slideshow":
            self.slideshow_section_frame.pack(fill="both", expand=True)

    def _format_numeric_value(self, pkey, val):
        spec = self.NUMERIC_SPECS[pkey]
        if not spec["is_float"]:
            return str(int(round(float(val))))
        rounded = round(float(val), spec["precision"])
        if pkey in ("scrollspeed", "slideshowfade") and rounded.is_integer():
            return str(int(rounded))
        text = f"{rounded:.{spec['precision']}f}".rstrip("0").rstrip(".")
        if pkey == "dropspeed" and "." not in text:
            text += ".0"
        return text

    def _clamp_numeric_value(self, pkey, raw_val):
        spec = self.NUMERIC_SPECS[pkey]
        clamped = max(float(spec["min"]), min(float(spec["max"]), float(raw_val)))
        if spec["is_float"]:
            res = round(clamped, spec["precision"])
            if pkey in ("scrollspeed", "slideshowfade") and res.is_integer():
                return int(res)
            return res
        return int(round(clamped))

    def _create_numeric_row(self, parent_frame, pkey, spec):
        prow = tk.Frame(parent_frame, bg=self.bg_base)
        prow.pack(fill="x", pady=3)
        self._themed_frames.append(prow)

        lbl = tk.Label(
            prow, text=spec["label"], width=26, anchor="w",
            font=("Segoe UI", 9), fg=self.text_dark, bg=self.bg_base
        )
        lbl.pack(side="left")
        self._themed_labels_dark.append(lbl)

        ctrl_container = tk.Frame(prow, bg=self.bg_base)
        ctrl_container.pack(side="right", fill="x", expand=True)
        ctrl_container.columnconfigure(0, weight=1, uniform="dual_ctrl")
        ctrl_container.columnconfigure(1, weight=3, uniform="dual_ctrl")
        self._themed_frames.append(ctrl_container)

        pbox = tk.Frame(
            ctrl_container, bg=self.input_bg,
            highlightthickness=1, highlightbackground=self.border_col
        )
        pbox.grid(row=0, column=0, sticky="ew", padx=(0, 8))
        self._themed_borders.append(pbox)

        pentry = tk.Entry(
            pbox, bg=self.input_bg, fg=self.text_dark, insertbackground=self.text_dark,
            bd=0, width=6, font=("Segoe UI", 9), relief="flat"
        )
        pentry.pack(fill="x", padx=6, pady=2)
        pentry.insert(0, self._format_numeric_value(pkey, spec["default"]))
        self._themed_entries.append((pbox, pentry))

        slider_var = tk.DoubleVar(value=float(spec["default"]))
        slider = ttk.Scale(
            ctrl_container,
            from_=float(spec["min"]),
            to=float(spec["max"]),
            orient="horizontal",
            variable=slider_var,
            style="Display.Horizontal.TScale",
            command=lambda val, k=pkey: self._on_slider_moved(k, val),
        )
        slider.grid(row=0, column=1, sticky="ew")

        pentry.bind("<KeyRelease>", lambda e, k=pkey: self._on_entry_key_release(k, e))
        pentry.bind("<FocusOut>", lambda e, k=pkey: self._on_entry_commit(k, e))
        pentry.bind("<Return>", lambda e, k=pkey: self._on_entry_commit(k, e))

        self.prop_entries[pkey] = pentry
        self.prop_sliders[pkey] = slider
        self.prop_vars[pkey] = slider_var

    def _enforce_size_bounds(self, changed_key):
        if changed_key not in ("minsize", "maxsize"):
            return
        try:
            min_v = int(round(float(self.prop_vars["minsize"].get())))
            max_v = int(round(float(self.prop_vars["maxsize"].get())))
        except (ValueError, KeyError):
            return

        if changed_key == "minsize" and min_v > max_v:
            new_max = self._clamp_numeric_value("maxsize", min_v)
            self.prop_vars["maxsize"].set(float(new_max))
            self.prop_entries["maxsize"].delete(0, tk.END)
            self.prop_entries["maxsize"].insert(0, str(new_max))
        elif changed_key == "maxsize" and max_v < min_v:
            new_min = self._clamp_numeric_value("minsize", max_v)
            self.prop_vars["minsize"].set(float(new_min))
            self.prop_entries["minsize"].delete(0, tk.END)
            self.prop_entries["minsize"].insert(0, str(new_min))

    def _on_slider_moved(self, pkey, raw_val):
        if self._syncing_controls:
            return
        try:
            clamped = self._clamp_numeric_value(pkey, float(raw_val))
        except ValueError:
            return

        self._syncing_controls = True
        try:
            self.prop_vars[pkey].set(float(clamped))
            entry = self.prop_entries[pkey]
            entry.delete(0, tk.END)
            entry.insert(0, self._format_numeric_value(pkey, clamped))
            self._enforce_size_bounds(pkey)
        finally:
            self._syncing_controls = False

        self._schedule_live_apply()

    def _on_entry_key_release(self, pkey, event):
        if self._syncing_controls:
            return
        if event and event.keysym in (
            "Left", "Right", "Up", "Down", "Home", "End",
            "Tab", "Shift_L", "Shift_R", "Control_L", "Control_R", "Return"
        ):
            return

        raw_text = self.prop_entries[pkey].get().strip()
        if not raw_text or raw_text in ("-", ".", "-."):
            return
        try:
            typed_val = float(raw_text)
        except ValueError:
            return

        spec = self.NUMERIC_SPECS[pkey]
        slider_pos = max(float(spec["min"]), min(float(spec["max"]), typed_val))

        self._syncing_controls = True
        try:
            self.prop_vars[pkey].set(slider_pos)
        finally:
            self._syncing_controls = False

        if float(spec["min"]) <= typed_val <= float(spec["max"]):
            self._schedule_live_apply()

    def _on_entry_commit(self, pkey, event=None):
        if self._syncing_controls:
            return
        spec = self.NUMERIC_SPECS[pkey]
        raw_text = self.prop_entries[pkey].get().strip()
        try:
            parsed = float(raw_text)
        except ValueError:
            parsed = float(self.prop_vars[pkey].get() if pkey in self.prop_vars else spec["default"])

        clamped = self._clamp_numeric_value(pkey, parsed)
        self._syncing_controls = True
        try:
            self.prop_vars[pkey].set(float(clamped))
            entry = self.prop_entries[pkey]
            entry.delete(0, tk.END)
            entry.insert(0, self._format_numeric_value(pkey, clamped))
            self._enforce_size_bounds(pkey)
        finally:
            self._syncing_controls = False

        self.save_display_settings()

    def _schedule_live_apply(self):
        if self._live_apply_job is not None:
            try:
                self.after_cancel(self._live_apply_job)
            except Exception:
                pass
        self._live_apply_job = self.after(40, self._execute_live_apply)

    def _execute_live_apply(self):
        self._live_apply_job = None
        if self.is_open:
            self.save_display_settings(clamp_entries=False)

    def _get_current_selected_screen_id(self):
        lbl = self.selected_screen_label.get()
        return self.screen_map.get(lbl, "screen_1")

    def _on_screen_selection_changed(self, event=None):
        sid = self._get_current_selected_screen_id()
        self._load_screen_values_into_form(sid)

    def _load_screen_values_into_form(self, screen_id):
        sc_cfg = get_screen_config(screen_id)
        self.screen_enabled_var.set(sc_cfg["enabled"])
        props = sc_cfg["properties"]

        mode_val = props.get("displaymode", {}).get("value", "scroll")
        if mode_val not in ("scroll", "collage", "slideshow"):
            mode_val = "scroll"
        self.mode_var.set(mode_val)

        dir_val = props.get("scrolldirection", {}).get("value", "left")
        if dir_val not in ("left", "right", "up", "down"):
            dir_val = "left"
        self.dir_var.set(dir_val)

        self._syncing_controls = True
        try:
            for key, spec in self.NUMERIC_SPECS.items():
                raw_val = props.get(key, {}).get("value", spec["default"])
                try:
                    clamped = self._clamp_numeric_value(key, raw_val)
                except (ValueError, TypeError):
                    clamped = spec["default"]

                entry = self.prop_entries.get(key)
                if entry:
                    entry.delete(0, tk.END)
                    entry.insert(0, self._format_numeric_value(key, clamped))
                if key in self.prop_vars:
                    self.prop_vars[key].set(float(clamped))
        finally:
            self._syncing_controls = False

        self._update_mode_sections_visibility()
        self._update_fill_btn_state()

    def _update_fill_btn_state(self):
        is_collage = (self.mode_var.get() == "collage")
        if is_collage and self._fill_cooldown_remaining <= 0:
            self.fill_screen_btn.configure(state="normal", bg="#0067c0", cursor="hand2")
        else:
            self.fill_screen_btn.configure(state="disabled", bg="#555560" if CURRENT_THEME == "dark" else "#c8c8d0", cursor="arrow")

    def _on_fill_screen_clicked(self):
        if self.mode_var.get() != "collage" or self._fill_cooldown_remaining > 0:
            return
        self.save_display_settings()
        sid = self._get_current_selected_screen_id()
        trigger_fill_screen_on_webview(sid)

        self._fill_cooldown_remaining = 30
        self._update_fill_btn_state()
        self._tick_fill_cooldown()

    def _tick_fill_cooldown(self):
        if not self.is_open:
            return
        if self._fill_cooldown_remaining > 0:
            self.fill_timer_lbl.configure(text=f"{self._fill_cooldown_remaining}s")
            self._fill_cooldown_remaining -= 1
            self._fill_timer_job = self.after(1000, self._tick_fill_cooldown)
        else:
            self.fill_timer_lbl.configure(text="")
            self._update_fill_btn_state()

    def save_display_settings(self, clamp_entries=True):
        sid = self._get_current_selected_screen_id()
        project_data = load_project_json()

        base_props = project_data.setdefault("general", {}).setdefault(
            "properties", get_default_properties_dict()
        )
        screens_dict = project_data.setdefault("screens", {})
        screen_entry = screens_dict.setdefault(sid, {
            "enabled": True,
            "properties": json.loads(json.dumps(base_props)),
        })

        screen_entry["enabled"] = bool(self.screen_enabled_var.get())
        s_props = screen_entry.setdefault("properties", json.loads(json.dumps(base_props)))

        s_props.setdefault("displaymode", {})["value"] = self.mode_var.get()
        s_props.setdefault("scrolldirection", {})["value"] = self.dir_var.get()

        self._syncing_controls = True
        try:
            for key, spec in self.NUMERIC_SPECS.items():
                raw_str = self.prop_entries[key].get().strip()
                try:
                    parsed = float(raw_str)
                except ValueError:
                    parsed = float(self.prop_vars[key].get())

                clamped = self._clamp_numeric_value(key, parsed)
                s_props.setdefault(key, {})["value"] = clamped
                self.prop_vars[key].set(float(clamped))

                if clamp_entries:
                    self.prop_entries[key].delete(0, tk.END)
                    self.prop_entries[key].insert(0, self._format_numeric_value(key, clamped))
        finally:
            self._syncing_controls = False

        if sid == "screen_1":
            for k, val_obj in s_props.items():
                if k in base_props and isinstance(val_obj, dict) and "value" in val_obj:
                    base_props[k]["value"] = val_obj["value"]

        store_project_json(project_data)
        push_properties_to_webview(sid)
        self._update_fill_btn_state()

    # -------------------------------------------------------------------------
    # TAB 3: LOGS (PAUSE APPLICATION + GLOSSARY BUTTON + CLEAR LOGS)
    # -------------------------------------------------------------------------
    def _build_logs_tab(self):
        pad_frame = tk.Frame(self.tab_logs, bg=self.bg_base)
        pad_frame.pack(fill="both", expand=True, padx=12, pady=10)
        self._themed_frames.append(pad_frame)

        top_bar = tk.Frame(pad_frame, bg=self.bg_base)
        top_bar.pack(fill="x", pady=(0, 8))
        self._themed_frames.append(top_bar)

        self.pause_app_btn = tk.Button(
            top_bar,
            text="PAUSE APPLICATION",
            bg="#d13438" if APP_PAUSED else "#107c10",
            fg="#ffffff",
            activebackground="#b02a2e" if APP_PAUSED else "#0e6b0e",
            activeforeground="#ffffff",
            font=("Segoe UI", 9, "bold"),
            bd=0, relief="flat", padx=16, pady=5, cursor="hand2",
            command=self.toggle_application_pause
        )
        self.pause_app_btn.pack(side="left")

        self.clear_btn = tk.Button(
            top_bar, text="Clear Logs", fg="#0067c0", bg="#e8e8ed",
            activebackground="#dcdce0", font=("Segoe UI", 8, "bold"),
            bd=0, relief="flat", padx=10, pady=4, cursor="hand2",
            command=self.clear_logs
        )
        self.clear_btn.pack(side="right")

        self.glossary_btn = tk.Button(
            top_bar, text="Glossary", fg=self.text_dark, bg="#e8e8ed",
            activebackground="#dcdce0", font=("Segoe UI", 8, "bold"),
            bd=0, relief="flat", padx=12, pady=4, cursor="hand2",
            command=self.open_glossary_dialog
        )
        self.glossary_btn.pack(side="right", padx=(0, 8))
        self._themed_neutral_btns.append(self.glossary_btn)

        self.log_box_frame = tk.Frame(pad_frame, bg=self.input_bg, highlightthickness=1, highlightbackground=self.border_col)
        self.log_box_frame.pack(fill="both", expand=True)
        self._themed_borders.append(self.log_box_frame)

        self.log_text = tk.Text(
            self.log_box_frame, bg=self.input_bg, fg=self.text_dark, wrap="word",
            font=("Consolas", 8), bd=0, relief="flat", state="disabled"
        )
        scrollbar = ttk.Scrollbar(self.log_box_frame, orient="vertical", command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=scrollbar.set)

        scrollbar.pack(side="right", fill="y")
        self.log_text.pack(side="left", fill="both", expand=True, padx=4, pady=4)

        if LOG_HISTORY:
            self.log_text.configure(state="normal")
            self.log_text.insert(tk.END, "\n".join(LOG_HISTORY) + "\n")
            self.log_text.see(tk.END)
            self.log_text.configure(state="disabled")

    def open_glossary_dialog(self):
        global GLOSSARY_DIALOG_INSTANCE
        if GLOSSARY_DIALOG_INSTANCE and getattr(GLOSSARY_DIALOG_INSTANCE, "is_open", False):
            try:
                GLOSSARY_DIALOG_INSTANCE.lift()
                return
            except tk.TclError:
                pass
        GLOSSARY_DIALOG_INSTANCE = GlossaryDialog(self)

    def apply_theme(self):
        pal = THEME_PALETTES[CURRENT_THEME]
        self.bg_base = pal["bg_base"]
        self.input_bg = pal["input_bg"]
        self.border_col = pal["border_col"]
        self.text_dark = pal["text_dark"]
        self.text_muted = pal["text_muted"]

        self.configure(bg=self.border_col)
        try:
            self.style.configure("TNotebook", background=self.bg_base, borderwidth=0)
            self.style.configure(
                "TNotebook.Tab",
                font=("Segoe UI", 9, "bold"),
                padding=(14, 5),
                background=pal["btn_bg"],
                foreground="#1c1c1c",
            )
            self.style.configure("Display.Horizontal.TScale", background=self.bg_base)
        except Exception:
            pass

        for frm in self._themed_frames:
            try:
                frm.configure(bg=self.bg_base)
            except Exception:
                pass

        for brd in self._themed_borders:
            try:
                brd.configure(highlightbackground=self.border_col)
            except Exception:
                pass

        self.container.configure(bg=self.bg_base, highlightbackground=self.border_col)
        self.cred_sep.configure(bg=self.border_col)
        self.disp_sep.configure(bg=self.border_col)

        for lbl in self._themed_labels_dark:
            try:
                lbl.configure(bg=self.bg_base, fg=self.text_dark)
            except Exception:
                pass

        for lbl in self._themed_labels_muted:
            try:
                lbl.configure(bg=self.bg_base, fg=self.text_muted)
            except Exception:
                pass

        for box, ent in self._themed_entries:
            try:
                box.configure(bg=self.input_bg, highlightbackground=self.border_col)
                ent.configure(bg=self.input_bg, fg=self.text_dark, insertbackground=self.text_dark)
            except Exception:
                pass

        for btn in self._themed_neutral_btns:
            try:
                btn.configure(
                    bg=pal["btn_bg"],
                    fg=self.text_dark,
                    activebackground=pal["btn_active"],
                    activeforeground=self.text_dark,
                )
            except Exception:
                pass

        self.theme_btn.configure(text="Dark Mode" if CURRENT_THEME == "light" else "Light Mode")
        self.screen_enable_chk.configure(
            bg=self.bg_base,
            fg=self.text_dark,
            activebackground=self.bg_base,
            activeforeground=self.text_dark,
            selectcolor=self.input_bg,
        )
        self.clear_btn.configure(
            bg=pal["btn_bg"],
            fg="#4da3ff" if CURRENT_THEME == "dark" else "#0067c0",
            activebackground=pal["btn_active"],
        )
        self.log_box_frame.configure(bg=self.input_bg, highlightbackground=self.border_col)
        self.log_text.configure(bg=self.input_bg, fg=self.text_dark)
        self._update_fill_btn_state()

    def toggle_application_pause(self):
        global APP_PAUSED
        APP_PAUSED = not APP_PAUSED
        if APP_PAUSED:
            self.pause_app_btn.configure(bg="#d13438", activebackground="#b02a2e")
            log_event("app", "Application PAUSED (display frozen, proxy streams & API calls stopped).")
        else:
            self.pause_app_btn.configure(bg="#107c10", activebackground="#0e6b0e")
            log_event("app", "Application RESUMED.")
            if len(POST_BUFFER) < 20 and not IS_FETCHING:
                threading.Thread(target=fill_post_buffer, daemon=True).start()

        push_pause_states_to_webviews()

    def append_log(self, message):
        try:
            _, bottom_fraction = self.log_text.yview()
            was_at_bottom = (bottom_fraction >= 0.99)

            self.log_text.configure(state="normal")
            self.log_text.insert(tk.END, message + "\n")
            line_count = int(self.log_text.index("end-1c").split(".")[0])
            if line_count > 500:
                self.log_text.delete("1.0", f"{line_count - 500 + 1}.0")

            if was_at_bottom:
                self.log_text.see(tk.END)
            self.log_text.configure(state="disabled")
        except tk.TclError:
            pass

    def clear_logs(self):
        LOG_HISTORY.clear()
        try:
            self.log_text.configure(state="normal")
            self.log_text.delete("1.0", tk.END)
            self.log_text.configure(state="disabled")
        except tk.TclError:
            pass

    def start_move(self, event):
        self._drag_x = event.x
        self._drag_y = event.y

    def do_move(self, event):
        x = self.winfo_x() + (event.x - self._drag_x)
        y = self.winfo_y() + (event.y - self._drag_y)
        self.geometry(f"+{x}+{y}")

    def close_dialog(self):
        self.is_open = False
        if getattr(self, "_live_apply_job", None):
            try:
                self.after_cancel(self._live_apply_job)
            except Exception:
                pass
        if self._fill_timer_job:
            try:
                self.after_cancel(self._fill_timer_job)
            except Exception:
                pass
        if GLOSSARY_DIALOG_INSTANCE and getattr(GLOSSARY_DIALOG_INSTANCE, "is_open", False):
            try:
                GLOSSARY_DIALOG_INSTANCE.close_glossary()
            except Exception:
                pass
        self.destroy()


class FloatingSearchBar:
    def __init__(self, root):
        self.root = root

        self.root.overrideredirect(True)
        self.root.attributes("-alpha", 0.92)
        self.root.attributes("-topmost", True)

        self.bar_width = 680
        self.bar_height = 48

        self.config = load_app_config()
        self.is_locked = self.config.get("locked", False)

        screen_w = self.root.winfo_screenwidth()
        screen_h = self.root.winfo_screenheight()

        default_x = max(0, (screen_w - self.bar_width) // 2)
        default_y = max(0, screen_h - 100)

        initial_x = self.config.get("pos_x", default_x)
        initial_y = self.config.get("pos_y", default_y)

        initial_x = max(0, min(initial_x, screen_w - self.bar_width))
        initial_y = max(0, min(initial_y, screen_h - self.bar_height))

        self.root.geometry(f"{self.bar_width}x{self.bar_height}+{initial_x}+{initial_y}")

        pal = THEME_PALETTES[CURRENT_THEME]
        self.bg_base = pal["bg_base"]
        self.input_bg = pal["input_bg"]
        self.border_col = pal["border_col"]
        self.text_dark = pal["text_dark"]
        self.text_muted = pal["text_muted"]

        self.root.configure(bg=self.bg_base)

        self.main_frame = tk.Frame(root, bg=self.bg_base, highlightthickness=1, highlightbackground=self.border_col)
        self.main_frame.pack(fill="both", expand=True)

        self.min_bar = tk.Frame(self.main_frame, bg=pal["min_bar"], width=8, cursor="hand2")
        self.min_bar.pack(side="left", fill="y")
        self.min_bar.pack_propagate(False)

        self.min_bar.bind("<Button-1>", lambda e: self.minimize_to_tray())
        self.min_bar.bind("<Enter>", lambda e: self.min_bar.configure(bg="#0067c0"))
        self.min_bar.bind("<Leave>", lambda e: self.min_bar.configure(bg=THEME_PALETTES[CURRENT_THEME]["min_bar"]))

        self.drag_handle = tk.Label(
            self.main_frame, text=" ✥ ", fg=self.text_muted, bg=self.bg_base,
            font=("Segoe UI", 10, "bold"), cursor="arrow" if self.is_locked else "fleur"
        )
        self.drag_handle.pack(side="left", padx=(4, 4))

        self.status_label = tk.Label(
            self.main_frame, text="● Ready", fg=self.text_muted, bg=pal["btn_bg"],
            font=("Segoe UI", 8, "bold"), padx=8, pady=3
        )
        self.status_label.pack(side="left", padx=(0, 6), pady=8)

        self.tag_label = tk.Label(
            self.main_frame, text="TAGS =", fg=self.text_dark, bg=self.bg_base,
            font=("Segoe UI", 9, "bold")
        )
        self.tag_label.pack(side="left", padx=(0, 4))

        self.pause_btn = tk.Button(
            self.main_frame,
            text="PAUSE",
            fg=self.text_dark,
            bg=pal["btn_bg"],
            activebackground=pal["btn_active"],
            bd=0,
            relief="flat",
            font=("Segoe UI", 8, "bold"),
            cursor="hand2",
            padx=10,
            pady=4,
            command=self.toggle_wallpaper_pause
        )
        self.pause_btn.pack(side="right", padx=(2, 6), pady=7)

        self.refresh_btn = tk.Button(
            self.main_frame, text="⟳", fg=self.text_dark, bg=self.bg_base, activebackground=pal["btn_active"],
            activeforeground="#0067c0", bd=0, relief="flat", font=("Segoe UI", 12, "bold"),
            cursor="hand2", padx=8, command=self.immediate_refresh
        )
        self.refresh_btn.pack(side="right", padx=(0, 2), pady=6)

        self.search_container = tk.Frame(self.main_frame, bg=self.input_bg, highlightthickness=1, highlightbackground=self.border_col)
        self.search_container.pack(side="left", fill="both", expand=True, padx=(0, 4), pady=7)

        self.entry = tk.Entry(
            self.search_container, bg=self.input_bg, fg=self.text_dark, insertbackground=self.text_dark,
            bd=0, font=("Segoe UI", 9), relief="flat"
        )
        self.entry.insert(0, DEFAULT_TAGS)
        self.entry.pack(side="left", fill="both", expand=True, padx=(8, 0))

        self.saved_arrow_btn = tk.Button(
            self.search_container, text="▲", fg=self.text_muted, bg=pal["arrow_bg"],
            activebackground=pal["btn_active"], activeforeground=self.text_dark, bd=0, relief="flat",
            font=("Segoe UI", 7), width=3, cursor="hand2", command=self.toggle_saved_dropdown
        )
        self.saved_arrow_btn.pack(side="right", fill="y")

        self.entry.bind("<KeyRelease>", self.on_key_release)
        self.entry.bind("<Down>", self.focus_suggestion_down)
        self.entry.bind("<Up>", self.focus_suggestion_up)
        self.entry.bind("<Return>", self.on_enter_pressed)
        self.entry.bind("<Shift-Return>", self.immediate_refresh)

        self.root.bind("<Escape>", self.on_escape)
        self.root.bind("<FocusOut>", self.on_focus_out)

        for widget in [self.drag_handle, self.tag_label, self.main_frame]:
            widget.bind("<Button-1>", self.start_move)
            widget.bind("<B1-Motion>", self.do_move)
            widget.bind("<ButtonRelease-1>", self.stop_move)

        self._drag_start_x = 0
        self._drag_start_y = 0
        self._moved = False

        self.dropdown = tk.Toplevel(self.root)
        self.dropdown.overrideredirect(True)
        self.dropdown.attributes("-alpha", 0.95)
        self.dropdown.attributes("-topmost", True)
        self.dropdown.configure(bg=self.border_col)
        self.dropdown.withdraw()

        self.suggest_labels = []
        self.suggest_items = []
        self.selected_index = -1
        self._debounce_timer = None
        self._suggest_req_id = 0

        for i in range(5):
            lbl = tk.Label(
                self.dropdown, text="", anchor="w", fg=self.text_dark, bg=self.input_bg,
                font=("Segoe UI", 9), padx=10, pady=5, cursor="hand2"
            )
            lbl.pack(fill="x", padx=1, pady=1)
            lbl.bind("<Enter>", lambda e, idx=i: self.highlight_index(idx))
            lbl.bind("<Button-1>", lambda e, idx=i: self.select_suggestion(idx))
            self.suggest_labels.append(lbl)

        self.saved_dropdown = tk.Toplevel(self.root)
        self.saved_dropdown.overrideredirect(True)
        self.saved_dropdown.attributes("-alpha", 0.95)
        self.saved_dropdown.attributes("-topmost", True)
        self.saved_dropdown.configure(bg=self.border_col)
        self.saved_dropdown.withdraw()

        self.saved_list = load_saved_searches()
        self.apply_theme()
        self.poll_status()

        self.root.after(200, self.check_credentials_on_startup)

    def apply_theme(self):
        pal = THEME_PALETTES[CURRENT_THEME]
        self.bg_base = pal["bg_base"]
        self.input_bg = pal["input_bg"]
        self.border_col = pal["border_col"]
        self.text_dark = pal["text_dark"]
        self.text_muted = pal["text_muted"]

        self.root.configure(bg=self.bg_base)
        self.main_frame.configure(bg=self.bg_base, highlightbackground=self.border_col)
        self.min_bar.configure(bg=pal["min_bar"])
        self.drag_handle.configure(bg=self.bg_base, fg=self.text_muted)
        self.tag_label.configure(bg=self.bg_base, fg=self.text_dark)
        self.refresh_btn.configure(bg=self.bg_base, fg=self.text_dark, activebackground=pal["btn_active"])

        if WALLPAPER_PAUSED:
            self.pause_btn.configure(bg="#0067c0", fg="#ffffff", activebackground="#005da6")
        else:
            self.pause_btn.configure(bg=pal["btn_bg"], fg=self.text_dark, activebackground=pal["btn_active"])

        self.search_container.configure(bg=self.input_bg, highlightbackground=self.border_col)
        self.entry.configure(bg=self.input_bg, fg=self.text_dark, insertbackground=self.text_dark)
        self.saved_arrow_btn.configure(
            bg=pal["arrow_bg"], fg=self.text_muted,
            activebackground=pal["btn_active"], activeforeground=self.text_dark
        )

        self.dropdown.configure(bg=self.border_col)
        for lbl in self.suggest_labels:
            lbl.configure(bg=self.input_bg, fg=self.text_dark)

        self.saved_dropdown.configure(bg=self.border_col)
        if self.saved_dropdown.winfo_viewable():
            self.render_saved_dropdown()

    def toggle_wallpaper_pause(self):
        global WALLPAPER_PAUSED
        WALLPAPER_PAUSED = not WALLPAPER_PAUSED
        pal = THEME_PALETTES[CURRENT_THEME]
        if WALLPAPER_PAUSED:
            self.pause_btn.configure(bg="#0067c0", fg="#ffffff", activebackground="#005da6")
            log_event("ui", "Wallpaper motion paused via search bar (GIFs and MP4 videos remain playing).")
        else:
            self.pause_btn.configure(bg=pal["btn_bg"], fg=self.text_dark, activebackground=pal["btn_active"])
            log_event("ui", "Wallpaper motion resumed via search bar.")
        push_pause_states_to_webviews()

    def check_credentials_on_startup(self):
        user = self.config.get("USERNAME", "")
        uid = self.config.get("USER_ID", "")
        key = self.config.get("API_KEY", "")

        apply_credentials(user, uid, key)
        transport_mode = "curl_cffi HTTP/2" if CURL_CFFI_AVAILABLE else "stdlib TLS 1.3 + DoH SNI fallback"
        log_event("auth", f"Active transport engine: {transport_mode}")

        if user and key:
            log_event("auth", f"Loaded DPAPI-protected credentials for user '{user}'" + (f" (#{uid})" if uid else ""))
        else:
            log_event("auth", "No credentials configured yet; running in anonymous API mode (2-tag limit).")
            self.open_settings_dialog()

        threading.Thread(target=fill_post_buffer, daemon=True).start()

    def open_settings_dialog(self):
        global SETTINGS_DIALOG_INSTANCE
        if SETTINGS_DIALOG_INSTANCE and getattr(SETTINGS_DIALOG_INSTANCE, "is_open", False):
            try:
                SETTINGS_DIALOG_INSTANCE.lift()
                return
            except tk.TclError:
                pass

        initial = {
            "USERNAME": self.config.get("USERNAME", USERNAME),
            "USER_ID": self.config.get("USER_ID", USER_ID),
            "API_KEY": self.config.get("API_KEY", API_KEY)
        }
        SETTINGS_DIALOG_INSTANCE = SettingsDialog(self.root, self.save_credentials, initial_values=initial)

    def save_credentials(self, user, uid, key):
        old_creds = (self.config.get("USERNAME", ""), self.config.get("USER_ID", ""), self.config.get("API_KEY", ""))
        new_creds = (user, uid, key)

        self.config["USERNAME"] = user
        self.config["USER_ID"] = uid
        self.config["API_KEY"] = key
        store_app_config(self.config)
        apply_credentials(user, uid, key)
        log_event("auth", f"Credentials updated from Settings for user '{user or 'anonymous'}'.")

        if old_creds != new_creds or len(POST_BUFFER) == 0:
            self.immediate_refresh()

    def minimize_to_tray(self):
        self.hide_dropdown()
        self.saved_dropdown.withdraw()
        self.root.withdraw()

    def restore_from_tray(self):
        self.root.deiconify()
        self.root.lift()

    def toggle_lock(self):
        self.is_locked = not self.is_locked
        self.drag_handle.configure(cursor="arrow" if self.is_locked else "fleur")

        self.config["pos_x"] = self.root.winfo_x()
        self.config["pos_y"] = self.root.winfo_y()
        self.config["locked"] = self.is_locked
        store_app_config(self.config)
        log_event("ui", f"Search bar lock state set to: {self.is_locked}")

    def start_move(self, event):
        if self.is_locked:
            return
        self._drag_start_x = event.x
        self._drag_start_y = event.y
        self._moved = False

    def do_move(self, event):
        if self.is_locked:
            return
        screen_w = self.root.winfo_screenwidth()
        screen_h = self.root.winfo_screenheight()

        target_x = self.root.winfo_pointerx() - self._drag_start_x
        target_y = self.root.winfo_pointery() - self._drag_start_y

        x = max(0, min(target_x, screen_w - self.bar_width))
        y = max(0, min(target_y, screen_h - self.bar_height))

        self.root.geometry(f"+{x}+{y}")

        self.config["pos_x"] = x
        self.config["pos_y"] = y
        self._moved = True

        self.hide_dropdown()
        self.saved_dropdown.withdraw()

    def stop_move(self, event):
        if self._moved:
            self._moved = False
            store_app_config(self.config)

    def on_focus_out(self, event):
        if event.widget == self.root:
            self.root.after(150, self._check_focus_and_hide)

    def _check_focus_and_hide(self):
        try:
            focus_widget = self.root.focus_get()
            if focus_widget is None:
                self.hide_dropdown()
                self.saved_dropdown.withdraw()
        except tk.TclError:
            pass

    def toggle_saved_dropdown(self):
        if self.saved_dropdown.winfo_viewable():
            self.saved_dropdown.withdraw()
            return
        self.hide_dropdown()
        self.render_saved_dropdown()

    def render_saved_dropdown(self):
        for widget in self.saved_dropdown.winfo_children():
            widget.destroy()

        pal = THEME_PALETTES[CURRENT_THEME]
        accent_fg = "#4da3ff" if CURRENT_THEME == "dark" else "#0067c0"

        save_btn = tk.Label(
            self.saved_dropdown, text="💾 Save Current Search", anchor="w",
            fg=accent_fg, bg=self.input_bg, font=("Segoe UI", 9, "bold"),
            padx=10, pady=6, cursor="hand2"
        )
        save_btn.pack(fill="x", padx=1, pady=(1, 2))
        save_btn.bind("<Enter>", lambda e: save_btn.configure(bg=pal["hover_bg"]))
        save_btn.bind("<Leave>", lambda e: save_btn.configure(bg=self.input_bg))
        save_btn.bind("<Button-1>", lambda e: self.save_current_search())

        if not self.saved_list:
            empty_lbl = tk.Label(
                self.saved_dropdown, text="(No saved searches)", anchor="w",
                fg=self.text_muted, bg=self.bg_base, font=("Segoe UI", 8, "italic"),
                padx=10, pady=5
            )
            empty_lbl.pack(fill="x", padx=1, pady=1)
        else:
            for item in self.saved_list:
                row = tk.Frame(self.saved_dropdown, bg=self.input_bg)
                row.pack(fill="x", padx=1, pady=1)

                item_lbl = tk.Label(
                    row, text=item, anchor="w", fg=self.text_dark, bg=self.input_bg,
                    font=("Segoe UI", 9), padx=10, pady=4, cursor="hand2"
                )
                item_lbl.pack(side="left", fill="x", expand=True)

                del_btn = tk.Label(
                    row, text=" - ", fg="#ff5f5f" if CURRENT_THEME == "dark" else "#d83b01",
                    bg=self.input_bg, font=("Segoe UI", 10, "bold"), padx=8, cursor="hand2"
                )
                del_btn.pack(side="right")

                item_lbl.bind(
                    "<Enter>",
                    lambda e, r=row, d=del_btn, il=item_lbl: (
                        r.configure(bg=pal["row_hover"]),
                        il.configure(bg=pal["row_hover"]),
                        d.configure(bg=pal["row_hover"]),
                    ),
                )
                item_lbl.bind(
                    "<Leave>",
                    lambda e, r=row, d=del_btn, il=item_lbl: (
                        r.configure(bg=self.input_bg),
                        il.configure(bg=self.input_bg),
                        d.configure(bg=self.input_bg),
                    ),
                )
                item_lbl.bind("<Button-1>", lambda e, text=item: self.apply_saved_search(text))

                del_btn.bind("<Enter>", lambda e, d=del_btn: d.configure(bg=pal["row_hover"]))
                del_btn.bind("<Leave>", lambda e, d=del_btn: d.configure(bg=self.input_bg))
                del_btn.bind("<Button-1>", lambda e, text=item: self.delete_saved_search(text))

        self.root.update_idletasks()
        rx = self.search_container.winfo_rootx()
        rw = self.search_container.winfo_width()

        item_count = max(1, len(self.saved_list))
        calc_height = 36 + (item_count * 28) + 4

        if self.root.winfo_y() - calc_height - 2 < 0:
            ry = self.search_container.winfo_rooty() + self.search_container.winfo_height() + 2
        else:
            ry = self.search_container.winfo_rooty() - calc_height - 2

        self.saved_dropdown.geometry(f"{rw}x{calc_height}+{rx}+{ry}")
        self.saved_dropdown.deiconify()
        self.saved_dropdown.lift()

    def save_current_search(self):
        query = self.entry.get().strip()
        if query and query not in self.saved_list:
            self.saved_list.insert(0, query)
            store_saved_searches(self.saved_list)
            log_event("search", f"Saved query to bookmarks: '{query}'")
        self.render_saved_dropdown()

    def apply_saved_search(self, saved_tags):
        self.entry.delete(0, tk.END)
        self.entry.insert(0, saved_tags)
        self.saved_dropdown.withdraw()
        self.immediate_refresh()

    def delete_saved_search(self, target_tags):
        if target_tags in self.saved_list:
            self.saved_list.remove(target_tags)
            store_saved_searches(self.saved_list)
            log_event("search", f"Removed query from bookmarks: '{target_tags}'")
        self.render_saved_dropdown()

    def get_current_tag_fragment(self):
        cursor_pos = self.entry.index(tk.INSERT)
        text_before = self.entry.get()[:cursor_pos]
        parts = text_before.split(" ")
        return parts[-1] if parts else ""

    def on_key_release(self, event):
        if event.keysym in ("Up", "Down", "Return", "Shift_L", "Shift_R", "Escape", "Left", "Right"):
            return

        if self._debounce_timer:
            self.root.after_cancel(self._debounce_timer)

        fragment = self.get_current_tag_fragment().strip()
        if len(fragment) < 2:
            self.hide_dropdown()
            return

        self._suggest_req_id += 1
        current_req = self._suggest_req_id
        self._debounce_timer = self.root.after(450, lambda: self.request_suggestions(fragment, current_req))

    def request_suggestions(self, fragment, req_id):
        while not SUGGESTION_QUEUE.empty():
            try:
                SUGGESTION_QUEUE.get_nowait()
            except Empty:
                break
        SUGGESTION_QUEUE.put((fragment, req_id))

    def display_suggestions(self, results, req_id):
        if req_id != self._suggest_req_id:
            return

        self.suggest_items = results
        self.selected_index = -1

        if not results:
            self.hide_dropdown()
            return

        self.saved_dropdown.withdraw()
        self.root.update_idletasks()
        rx = self.entry.winfo_rootx()
        rw = self.entry.winfo_width()

        for i in range(5):
            if i < len(results):
                tag_name, count = results[i]
                count_str = f"({count:,})" if count else ""
                self.suggest_labels[i].configure(
                    text=f"{tag_name}  {count_str}",
                    bg=self.input_bg,
                    fg=self.text_dark
                )
                self.suggest_labels[i].pack(fill="x", padx=1, pady=1)
            else:
                self.suggest_labels[i].pack_forget()

        calc_height = len(results) * 28 + 4
        if self.root.winfo_y() - calc_height - 2 < 0:
            ry = self.entry.winfo_rooty() + self.entry.winfo_height() + 2
        else:
            ry = self.entry.winfo_rooty() - calc_height - 2

        self.dropdown.geometry(f"{rw}x{calc_height}+{rx}+{ry}")
        self.dropdown.deiconify()
        self.dropdown.lift()

    def hide_dropdown(self):
        self.dropdown.withdraw()
        self.selected_index = -1

    def highlight_index(self, index):
        self.selected_index = index
        pal = THEME_PALETTES[CURRENT_THEME]
        accent_fg = "#4da3ff" if CURRENT_THEME == "dark" else "#0067c0"
        for i, lbl in enumerate(self.suggest_labels):
            if i == index:
                lbl.configure(bg=pal["hover_bg"], fg=accent_fg)
            else:
                lbl.configure(bg=self.input_bg, fg=self.text_dark)

    def focus_suggestion_down(self, event):
        if not self.suggest_items or not self.dropdown.winfo_viewable():
            return
        new_idx = self.selected_index + 1
        if new_idx >= len(self.suggest_items):
            new_idx = 0
        self.highlight_index(new_idx)
        return "break"

    def focus_suggestion_up(self, event):
        if not self.suggest_items or not self.dropdown.winfo_viewable():
            return
        new_idx = self.selected_index - 1
        if new_idx < 0:
            new_idx = len(self.suggest_items) - 1
        self.highlight_index(new_idx)
        return "break"

    def select_suggestion(self, index):
        if index < 0 or index >= len(self.suggest_items):
            return
        chosen_tag, _ = self.suggest_items[index]

        cursor_pos = self.entry.index(tk.INSERT)
        full_text = self.entry.get()
        before_cursor = full_text[:cursor_pos]
        after_cursor = full_text[cursor_pos:]

        words = before_cursor.split(" ")
        words[-1] = chosen_tag
        new_before = " ".join(words) + " "

        self.entry.delete(0, tk.END)
        self.entry.insert(0, new_before + after_cursor)
        self.entry.icursor(len(new_before))
        self.hide_dropdown()

    def on_enter_pressed(self, event):
        if self.dropdown.winfo_viewable() and self.selected_index >= 0:
            self.select_suggestion(self.selected_index)
            return "break"

        self.hide_dropdown()
        self.saved_dropdown.withdraw()
        self.enqueue_search()
        return "break"

    def on_escape(self, event):
        if self.saved_dropdown.winfo_viewable():
            self.saved_dropdown.withdraw()
        elif self.dropdown.winfo_viewable():
            self.hide_dropdown()
        else:
            self.minimize_to_tray()

    def enqueue_search(self, event=None):
        if self._debounce_timer:
            self.root.after_cancel(self._debounce_timer)
            self._debounce_timer = None
        self._suggest_req_id += 1
        self.hide_dropdown()
        self.saved_dropdown.withdraw()
        query = self.entry.get().strip()
        if query:
            with DATA_LOCK:
                PENDING_TAG_QUEUE.append(query)
            log_event("search", f"Queued tags: '{query}'")
            pal = THEME_PALETTES[CURRENT_THEME]
            self.entry.configure(bg=pal["flash_bg"])
            self.root.after(150, lambda: self.entry.configure(bg=self.input_bg))

    def immediate_refresh(self, event=None):
        global CURRENT_TAGS, CURRENT_PAGE, CACHE_EPOCH
        global CONSECUTIVE_FAILURES, CONSECUTIVE_EMPTY_PAGES, NEXT_ALLOWED_FETCH_TIME

        if self._debounce_timer:
            self.root.after_cancel(self._debounce_timer)
            self._debounce_timer = None
        self._suggest_req_id += 1

        self.hide_dropdown()
        self.saved_dropdown.withdraw()
        query = self.entry.get().strip()
        if not query:
            return

        with DATA_LOCK:
            CURRENT_TAGS = query
            CURRENT_PAGE = 1
            CACHE_EPOCH += 1
            CONSECUTIVE_FAILURES = 0
            CONSECUTIVE_EMPTY_PAGES = 0
            NEXT_ALLOWED_FETCH_TIME = 0.0
            PENDING_TAG_QUEUE.clear()
            POST_BUFFER.clear()
            SEEN_POST_IDS.clear()
            SEEN_POST_ORDER.clear()
            SCREEN_SEEN_IDS.clear()
            should_spawn_worker = not IS_FETCHING and not APP_PAUSED

        log_event("refresh", f"Immediate refresh triggered. Epoch: {CACHE_EPOCH} | Tags: '{query}'")

        pal = THEME_PALETTES[CURRENT_THEME]
        self.refresh_btn.configure(fg="#0067c0")
        self.entry.configure(bg=pal["flash_bg"])
        self.root.after(200, lambda: (
            self.refresh_btn.configure(fg=self.text_dark),
            self.entry.configure(bg=self.input_bg)
        ))

        if should_spawn_worker:
            threading.Thread(target=fill_post_buffer, daemon=True).start()

    def poll_status(self):
        if not IS_RUNNING:
            return

        with DATA_LOCK:
            status_data = dict(LAST_STATUS)

        status = status_data.get("status")
        try:
            if APP_PAUSED:
                self.status_label.configure(
                    text="⏸ App Paused",
                    fg="#ff8080" if CURRENT_THEME == "dark" else "#a80000",
                    bg="#3d1a1e" if CURRENT_THEME == "dark" else "#fde7e9"
                )
            elif status == "ok":
                page = status_data.get("page", 1)
                count = status_data.get("count", 0)
                self.status_label.configure(
                    text=f"✔ P:{page} ({count} items)",
                    fg="#6ccb5f" if CURRENT_THEME == "dark" else "#0f7b0f",
                    bg="#18331a" if CURRENT_THEME == "dark" else "#dff6dd"
                )
            elif status == "error":
                self.status_label.configure(
                    text="✖ Error",
                    fg="#ff8080" if CURRENT_THEME == "dark" else "#a80000",
                    bg="#3d1a1e" if CURRENT_THEME == "dark" else "#fde7e9"
                )

            if IS_RUNNING:
                self.root.after(500, self.poll_status)
        except tk.TclError:
            pass


# =============================================================================
# 7. SYSTEM TRAY, TKINTER THREAD & EPHEMERAL MULTI-SCREEN PYWEBVIEW LIFECYCLE
# =============================================================================
def on_tray_show(icon=None, item=None):
    if APP_INSTANCE and TK_ROOT:
        TK_ROOT.after(0, APP_INSTANCE.restore_from_tray)


def on_tray_settings(icon=None, item=None):
    if APP_INSTANCE and TK_ROOT:
        TK_ROOT.after(0, APP_INSTANCE.open_settings_dialog)


def shutdown_app(icon=None, item=None):
    global IS_RUNNING
    if not IS_RUNNING:
        return
    IS_RUNNING = False
    log_event("app", "Shutting down application...")

    if TRAY_ICON:
        try:
            TRAY_ICON.stop()
        except Exception:
            pass
    if TK_ROOT:
        try:
            TK_ROOT.after(0, TK_ROOT.destroy)
        except Exception:
            pass
    if HTTP_SERVER:
        try:
            HTTP_SERVER.server_close()
        except Exception:
            pass
    with SESSION_LOCK:
        if HTTP2_SESSION is not None:
            try:
                HTTP2_SESSION.close()
            except Exception:
                pass
    for win in list(WEBVIEW_WINDOWS.values()):
        try:
            win.destroy()
        except Exception:
            pass

    cleanup_legacy_webview_profile()
    os._exit(0)


def setup_tray():
    global TRAY_ICON
    box_icon = create_cardboard_box_icon()
    menu = pystray.Menu(
        pystray.MenuItem("Show Search Bar", on_tray_show, default=True),
        pystray.MenuItem("Settings", on_tray_settings),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem("Exit", shutdown_app)
    )
    TRAY_ICON = pystray.Icon("DanbooruService", box_icon, "Danbooru Wallpaper Service", menu)
    TRAY_ICON.run()


def run_tkinter_ui():
    global TK_ROOT, APP_INSTANCE
    TK_ROOT = tk.Tk()
    apply_app_icon(TK_ROOT)
    APP_INSTANCE = FloatingSearchBar(TK_ROOT)
    try:
        TK_ROOT.mainloop()
    except Exception as e:
        log_event("ui", f"Tkinter loop exited: {e}")


def inject_and_sync_screen(screen_info, window, win_title):
    sid = screen_info["id"]
    with INJECTION_LOCK:
        if sid in DESKTOP_INJECTED_SET:
            return
        DESKTOP_INJECTED_SET.add(sid)

    hwnd = attach_window_to_desktop(
        window,
        win_title,
        mon_x=screen_info["x"],
        mon_y=screen_info["y"],
        mon_w=screen_info["width"],
        mon_h=screen_info["height"],
    )
    if hwnd:
        with INJECTION_LOCK:
            DESKTOP_HWNDS[sid] = hwnd
    else:
        with INJECTION_LOCK:
            DESKTOP_INJECTED_SET.discard(sid)
        return

    push_properties_to_webview(sid)
    push_pause_states_to_webviews()


def on_webview_started():
    for screen_info in CONNECTED_SCREENS:
        sid = screen_info["id"]
        win = WEBVIEW_WINDOWS.get(sid)
        win_title = f"{WEBVIEW_WINDOW_TITLE_PREFIX}_{sid}"
        if win:
            win.events.loaded += (
                lambda s=screen_info, w=win, t=win_title: threading.Thread(
                    target=inject_and_sync_screen, args=(s, w, t), daemon=True
                ).start()
            )
    time.sleep(2.0)
    for screen_info in CONNECTED_SCREENS:
        sid = screen_info["id"]
        if sid not in DESKTOP_INJECTED_SET and sid in WEBVIEW_WINDOWS:
            win_title = f"{WEBVIEW_WINDOW_TITLE_PREFIX}_{sid}"
            inject_and_sync_screen(screen_info, WEBVIEW_WINDOWS[sid], win_title)

    sync_all_screens_z_order_and_geometry()


if __name__ == "__main__":
    HTTP_SERVER = ReusableThreadingHTTPServer(("127.0.0.1", PORT), ProxyHandler)
    server_thread = threading.Thread(target=HTTP_SERVER.serve_forever, daemon=True)
    server_thread.start()
    transport_summary = "curl_cffi HTTP/2 + DoH" if CURL_CFFI_AVAILABLE else "stdlib TLS 1.3 + DoH SNI fallback"
    log_event("server", f"Service running on http://127.0.0.1:{PORT} ({transport_summary})")

    suggestion_thread = threading.Thread(target=suggestion_worker_loop, daemon=True)
    suggestion_thread.start()

    tray_thread = threading.Thread(target=setup_tray, daemon=True)
    tray_thread.start()

    tk_thread = threading.Thread(target=run_tkinter_ui, daemon=True)
    tk_thread.start()

    CONNECTED_SCREENS = enumerate_connected_monitors()
    for screen_info in CONNECTED_SCREENS:
        sid = screen_info["id"]
        win_title = f"{WEBVIEW_WINDOW_TITLE_PREFIX}_{sid}"
        win = webview.create_window(
            title=win_title,
            url=f"http://127.0.0.1:{PORT}/?screen={sid}",
            x=screen_info["x"],
            y=screen_info["y"],
            width=screen_info["width"],
            height=screen_info["height"],
            frameless=True,
            easy_drag=False,
            background_color="#0b0b0d",
        )
        WEBVIEW_WINDOWS[sid] = win

    try:
        # Run WebView2 in ephemeral private_mode without a persistent storage_path folder
        webview.start(
            on_webview_started,
            debug=False,
            private_mode=True,
        )
    except KeyboardInterrupt:
        pass
    finally:
        shutdown_app()
