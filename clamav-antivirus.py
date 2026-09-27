#!/usr/bin/env python3
"""
ClamAV Antivirus - ClamAV GUI for Linux Mint
A modern HTML/CSS/JS interface for ClamAV with system tray integration.

Les opérations privilégiées (scan complet du système, mise à jour des signatures)
sont déléguées au service système clamav-antivirus-daemon (root) via un socket
Unix : aucun mot de passe n'est demandé. Si le service est absent, l'application
se rabat sur pkexec (demande de mot de passe administrateur).

L'application affiche aussi les notifications glissantes (popups en bas à droite)
émises par le service : rafales d'écritures, danger potentiel, signatures à jour,
scan terminé, analyse des clés USB, question pour les disques durs USB.

(c) 2026 Dukiwi SA - Estavayer-le-Lac
"""

import gi
gi.require_version('Gtk', '3.0')
gi.require_version('Gdk', '3.0')
gi.require_version('WebKit2', '4.1')
gi.require_version('AppIndicator3', '0.1')

from gi.repository import Gtk, Gdk, WebKit2, GLib, AppIndicator3
import subprocess
import threading
import socket
import json
import os
import time
import sys
import shutil
from pathlib import Path
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from clamav_common import (  # noqa: E402
    VERSION, DAEMON_ALLOWED_ROOTS, UPDATE_TIMER_UNIT, DAEMON_UNIT, LANGUAGES,
    daemon_connect, daemon_request, find_command, is_noise_line,
    classify_line, db_last_update, db_files_info, systemd_next_elapse,
    systemd_is_active, load_i18n, pick_language, t as translate,
)

# ─── Paths ───────────────────────────────────────────────────────────────────
APP_DIR = os.path.dirname(os.path.abspath(__file__))
UI_DIR = os.path.join(APP_DIR, "ui")
ICONS_DIR = os.path.join(APP_DIR, "icons")
DATA_DIR           = os.path.expanduser("~/.local/share/clamav-antivirus")
INSTANCE_SOCKET    = os.path.join(DATA_DIR, "instance.sock")
LOG_FILE           = os.path.join(DATA_DIR, "scan.log")
STATE_FILE         = os.path.join(DATA_DIR, "state.json")
QUARANTINE_DIR     = os.path.join(DATA_DIR, "quarantine")
SCAN_PROGRESS_FILE = os.path.join(DATA_DIR, "scan_progress.json")
SCAN_FILES_CACHE   = os.path.join(DATA_DIR, "scan_filelist.txt")
HOME_DIR           = os.path.expanduser("~")

PROGRESS_INTERVAL = 0.25
PROGRESS_SAVE_INTERVAL = 2.0
LOG_MAX_BYTES = 5 * 1024 * 1024

os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(QUARANTINE_DIR, exist_ok=True)


def now_iso():
    return datetime.now().isoformat(timespec="seconds")


def format_size(num):
    num = float(num or 0)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if num < 1024 or unit == "TB":
            return f"{num:.0f} {unit}" if unit == "B" else f"{num:.1f} {unit}"
        num /= 1024
    return f"{num:.1f} TB"


# ═══════════════════════════════════════════════════════════════════════════
# État local (utilisateur)
# ═══════════════════════════════════════════════════════════════════════════

def load_state():
    try:
        with open(STATE_FILE, "r") as f:
            return json.load(f)
    except Exception:
        return {}


def save_state(data):
    state = load_state()
    state.update(data)
    with open(STATE_FILE, "w") as f:
        json.dump(state, f, indent=2, ensure_ascii=False)


def add_history(entry):
    state = load_state()
    hist = state.get("history", [])
    hist.insert(0, entry)
    state["history"] = hist[:20]
    with open(STATE_FILE, "w") as f:
        json.dump(state, f, indent=2, ensure_ascii=False)


def write_log(text):
    try:
        if os.path.exists(LOG_FILE) and os.path.getsize(LOG_FILE) > LOG_MAX_BYTES:
            with open(LOG_FILE) as f:
                lines = f.readlines()[-2000:]
            with open(LOG_FILE, "w") as f:
                f.writelines(lines)
        with open(LOG_FILE, "a") as f:
            f.write(f"[{now_iso()}] {text}\n")
    except OSError:
        pass


# ═══════════════════════════════════════════════════════════════════════════
# Client du service système
# ═══════════════════════════════════════════════════════════════════════════

class DaemonClient:
    """Abonnement permanent aux événements du daemon (reconnexion automatique)."""

    def __init__(self, on_event):
        self.on_event = on_event
        self.available = False
        threading.Thread(target=self._loop, daemon=True, name="daemon-subscribe").start()

    @staticmethod
    def request(cmd, **kwargs):
        return daemon_request(cmd, timeout=3, **kwargs)

    def _loop(self):
        while True:
            try:
                conn = daemon_connect(timeout=3)
                conn.send({"cmd": "subscribe"})
                initial = conn.recv()
                conn.sock.settimeout(None)
            except (OSError, ValueError):
                if self.available:
                    self.available = False
                    GLib.idle_add(self.on_event, {"event": "disconnected"})
                time.sleep(5)
                continue
            self.available = True
            GLib.idle_add(self.on_event, {"event": "connected", "status": initial})
            try:
                while True:
                    ev = conn.recv()
                    if ev is None:
                        break
                    GLib.idle_add(self.on_event, ev)
            except (OSError, ValueError):
                pass
            finally:
                conn.close()
            self.available = False
            GLib.idle_add(self.on_event, {"event": "disconnected"})
            time.sleep(3)


def daemon_can_scan(path):
    """Le service accepte-t-il ce chemin pour l'utilisateur courant ?"""
    norm = os.path.normpath(path)
    if norm in DAEMON_ALLOWED_ROOTS or norm.startswith(("/media/", "/mnt/")):
        return True
    return norm == HOME_DIR or norm.startswith(HOME_DIR.rstrip("/") + "/")


# ═══════════════════════════════════════════════════════════════════════════
# Opérations locales (sans le service)
# ═══════════════════════════════════════════════════════════════════════════

class LocalScan:
    """Scan exécuté par l'utilisateur lui-même (ou via pkexec pour le scan complet)."""

    def __init__(self, path, callback, resume=False, use_sudo=False):
        self.path = path
        self.callback = callback
        self.resume = resume
        self.use_sudo = use_sudo
        self.cancel_event = threading.Event()
        self.proc = None
        self.proc_lock = threading.Lock()
        self.scanned = 0
        self.total = 0
        self.found = 0
        self.infected = 0
        self.denied = 0
        self.errors = 0
        self.current_file = ""
        self.threats = []
        self.started_at = time.time()
        self.phase = "prepare"

    def progress(self):
        return {
            "phase": self.phase, "path": self.path, "scanned": self.scanned,
            "total": self.total, "found": self.found, "file": self.current_file,
            "infected": self.infected, "denied": self.denied, "errors": self.errors,
            "started_at": self.started_at, "elapsed": time.time() - self.started_at,
            "source": "local", "threats": self.threats[-50:],
        }

    def summary(self):
        return {
            "path": self.path, "files": self.total, "infected": self.infected,
            "denied": self.denied, "errors": self.errors,
            "duration": time.time() - self.started_at, "threats": self.threats[-50:],
        }

    def emit(self, event, data):
        GLib.idle_add(self.callback, event, data)

    def done(self, status, key, params=None):
        self.emit("done", {"status": status, "msg_key": key, "msg_params": params or {},
                           "summary": self.summary()})

    def cancel(self):
        self.cancel_event.set()
        with self.proc_lock:
            if self.proc and self.proc.poll() is None:
                try:
                    self.proc.terminate()
                except OSError:
                    pass

    def start(self):
        threading.Thread(target=self._run, daemon=True).start()

    def _save_progress(self, in_progress):
        try:
            with open(SCAN_PROGRESS_FILE, "w") as f:
                json.dump({"path": self.path, "total": self.total, "scanned": self.scanned,
                           "last_file": self.current_file, "in_progress": in_progress,
                           "infected": self.infected, "use_sudo": self.use_sudo}, f)
        except OSError:
            pass

    def _count(self):
        self.phase = "counting"
        self.emit("progress", self.progress())
        prefix = ["pkexec"] if self.use_sudo else []
        cmd = prefix + find_command(self.path)
        with self.proc_lock:
            self.proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                         stderr=subprocess.DEVNULL, text=True, bufsize=1)
        last = time.time()
        with open(SCAN_FILES_CACHE, "w") as out:
            for line in self.proc.stdout:
                if self.cancel_event.is_set():
                    break
                if line.strip():
                    out.write(line)
                    self.found += 1
                    if time.time() - last >= PROGRESS_INTERVAL:
                        self.emit("progress", self.progress())
                        last = time.time()
        rc = self.proc.wait()
        if self.use_sudo and rc in (126, 127):
            raise PermissionError("auth")
        return self.found

    def _resume_offset(self):
        try:
            with open(SCAN_PROGRESS_FILE) as f:
                prog = json.load(f)
        except Exception:
            return None
        if not (prog.get("in_progress") and prog.get("path") == self.path):
            return None
        if not os.path.exists(SCAN_FILES_CACHE):
            return None
        last_file = prog.get("last_file") or ""
        idx, total = None, 0
        with open(SCAN_FILES_CACHE) as f:
            for i, line in enumerate(f):
                total += 1
                if idx is None and last_file and line.rstrip("\n") == last_file:
                    idx = i + 1
        self.total = total
        self.infected = int(prog.get("infected", 0) or 0)
        return idx if idx is not None else 0

    def _run(self):
        try:
            start_idx = 0
            resumed = False
            if self.resume:
                idx = self._resume_offset()
                if idx is not None:
                    start_idx, resumed = idx, True

            if not resumed:
                write_log(f"▶ scan {self.path}")
                self.emit("line", {"kind": "info", "text": f"▶ {self.path}"})
                self.total = self._count()
                if self.cancel_event.is_set():
                    self._save_progress(False)
                    self.done("cancelled", "msg.scan.cancelled_counting")
                    return
                self.scanned = 0
                self.infected = 0
                self._save_progress(True)
            else:
                self.scanned = start_idx
                self.emit("line", {"kind": "info", "text": f"▶ {start_idx} / {self.total}"})

            if self.total == 0:
                self._save_progress(False)
                self._record("clean")
                self.done("clean", "msg.scan.nofiles")
                return

            tmp_list = SCAN_FILES_CACHE + ".tmp"
            with open(SCAN_FILES_CACHE) as src, open(tmp_list, "w") as dst:
                for i, line in enumerate(src):
                    if i >= start_idx:
                        dst.write(line)

            self.phase = "scanning"
            self.emit("progress", self.progress())
            self.emit("line", {"kind": "info", "text": f"▶ clamscan × {self.total}"})

            prefix = ["pkexec"] if self.use_sudo else []
            cmd = prefix + ["nice", "-n", "5", "clamscan", "--verbose", "--suppress-ok-results",
                            f"--move={QUARANTINE_DIR}", f"--file-list={tmp_list}"]
            with self.proc_lock:
                self.proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                             stderr=subprocess.STDOUT, text=True, bufsize=1)
            last_emit = last_save = time.time()
            for raw in self.proc.stdout:
                line = raw.rstrip("\n")
                if not line:
                    continue
                counted = False
                if line.startswith("Scanning "):
                    self.current_file = line[9:]
                    counted = True
                elif line.endswith((": Empty file", ": No such file or directory", ": Excluded")):
                    self.current_file = line.rsplit(": ", 1)[0]
                    counted = True
                elif line.endswith(" FOUND"):
                    self.infected += 1
                    path, _, sig = line[:-6].rpartition(": ")
                    self.threats.append({"path": path, "signature": sig, "time": now_iso()})
                    write_log(line)
                    self.emit("line", {"kind": "found", "text": line})
                elif not is_noise_line(line):
                    kind = classify_line(line)
                    if kind == "denied":
                        self.denied += 1
                    elif kind == "error":
                        self.errors += 1
                    if kind in ("error", "summary", "denied"):
                        write_log(line)
                    self.emit("line", {"kind": kind, "text": line})
                if counted:
                    self.scanned += 1
                    now = time.time()
                    if now - last_emit >= PROGRESS_INTERVAL:
                        self.emit("progress", self.progress())
                        last_emit = now
                    if now - last_save >= PROGRESS_SAVE_INTERVAL:
                        self._save_progress(True)
                        last_save = now
            rc = self.proc.wait()

            if self.cancel_event.is_set():
                self._save_progress(True)
                write_log(f"■ interrupted {self.scanned}/{self.total}")
                self.done("cancelled", "msg.scan.cancelled", {"scanned": self.scanned, "total": self.total})
                return

            self.scanned = self.total
            self.current_file = ""
            self._save_progress(False)
            try:
                os.remove(tmp_list)
            except OSError:
                pass
            if self.use_sudo and rc in (126, 127):
                raise PermissionError("auth")
            if rc not in (0, 1, 2):
                self._record("error")
                self.done("error", "msg.scan.failed", {"code": rc})
                return
            status = "infected" if self.infected else "clean"
            self._record(status)
            write_log(f"■ done: {self.infected} infected / {self.total} files")
            if self.infected:
                self.done("infected", "msg.scan.infected", {"count": self.infected})
            else:
                self.done("clean", "msg.scan.clean", {"files": self.total})
        except PermissionError:
            self.done("error", "msg.auth_cancelled")
        except Exception as e:  # noqa: BLE001
            self.done("error", "msg.scan.internal", {"error": str(e)})

    def _record(self, status):
        duration = round(time.time() - self.started_at)
        entry = {"date": now_iso(), "path": self.path, "files": self.total,
                 "infected": self.infected, "duration": duration, "status": status,
                 "source": "local", "auto": False}
        save_state({"last_scan": entry["date"], "last_scan_path": self.path,
                    "last_scan_infected": self.infected, "last_scan_files": self.total,
                    "last_scan_duration": duration, "last_scan_status": status})
        add_history(entry)


class ClamAVBackend:
    """Opérations ClamAV exécutées localement (installation, MàJ via pkexec, quarantaine locale)."""

    @staticmethod
    def is_installed():
        return shutil.which("clamscan") is not None

    @staticmethod
    def is_freshclam_installed():
        return shutil.which("freshclam") is not None

    @staticmethod
    def install_clamav(callback):
        def run():
            try:
                proc = subprocess.Popen(
                    ["pkexec", "bash", "-c",
                     "apt-get update && apt-get install -y clamav clamav-daemon clamav-freshclam"],
                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
                )
                for line in proc.stdout:
                    GLib.idle_add(callback, "progress", line.strip(), None)
                proc.wait()
                if proc.returncode == 0:
                    GLib.idle_add(callback, "success", "msg.install.success", {})
                elif proc.returncode in (126, 127):
                    GLib.idle_add(callback, "error", "msg.auth_cancelled", {})
                else:
                    GLib.idle_add(callback, "error", "msg.install.failed", {"code": proc.returncode})
            except Exception as e:  # noqa: BLE001
                GLib.idle_add(callback, "error", "msg.scan.internal", {"error": str(e)})
        threading.Thread(target=run, daemon=True).start()

    @staticmethod
    def update_database_pkexec(callback):
        """Mise à jour via pkexec (mot de passe) — utilisée si le service est absent."""
        def run():
            try:
                update_script = (
                    "systemctl stop clamav-freshclam 2>/dev/null || true && "
                    "sleep 1 && "
                    "freshclam --stdout 2>&1 ; "
                    "RETCODE=$? && "
                    "systemctl start clamav-freshclam 2>/dev/null || true && "
                    "exit $RETCODE"
                )
                proc = subprocess.Popen(
                    ["pkexec", "bash", "-c", update_script],
                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
                )
                output = []
                for line in proc.stdout:
                    output.append(line.strip())
                    GLib.idle_add(callback, "progress", line.strip(), None)
                proc.wait()
                if proc.returncode == 0:
                    save_state({"last_update": now_iso()})
                    changed = any("updated (" in line for line in output)
                    db = db_last_update()
                    GLib.idle_add(callback, "success",
                                  "msg.update.updated" if changed else "msg.update.uptodate",
                                  {"date": db.strftime("%d.%m.%Y %H:%M") if db else ""})
                elif proc.returncode in (126, 127):
                    GLib.idle_add(callback, "error", "msg.auth_cancelled", {})
                else:
                    GLib.idle_add(callback, "error", "msg.update.failed", {"code": proc.returncode})
            except Exception as e:  # noqa: BLE001
                GLib.idle_add(callback, "error", "msg.scan.internal", {"error": str(e)})
        threading.Thread(target=run, daemon=True).start()

    @staticmethod
    def get_quarantine_files():
        files = []
        try:
            for f in sorted(Path(QUARANTINE_DIR).iterdir(), key=lambda x: x.stat().st_mtime, reverse=True):
                if f.is_file() and not f.name.startswith(".clamav-quarantine-lock"):
                    st = f.stat()
                    files.append({
                        "name": f.name, "path": str(f), "size": st.st_size,
                        "date": datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M"),
                        "scope": "user",
                    })
        except Exception:
            pass
        return files

    @staticmethod
    def _in_quarantine(path):
        try:
            p = Path(path).resolve()
            return p.parent == Path(QUARANTINE_DIR).resolve() and p.is_file()
        except OSError:
            return False

    @classmethod
    def delete_quarantine_file(cls, filepath):
        if not cls._in_quarantine(filepath):
            return "error", "msg.forbidden", {}
        os.remove(filepath)
        return "success", "msg.quarantine.deleted", {"name": os.path.basename(filepath)}

    @classmethod
    def restore_quarantine_file(cls, filepath, dest):
        if not cls._in_quarantine(filepath):
            return "error", "msg.forbidden", {}
        if not os.path.isdir(dest):
            return "error", "msg.restore_dest", {}
        shutil.move(filepath, os.path.join(dest, os.path.basename(filepath)))
        return "success", "msg.quarantine.restored", {"name": os.path.basename(filepath)}

    @staticmethod
    def empty_quarantine():
        count = 0
        for f in Path(QUARANTINE_DIR).iterdir():
            if f.is_file() and not f.name.startswith(".clamav-quarantine-lock"):
                f.unlink()
                count += 1
        return "success", "msg.quarantine.emptied", {"count": count}


# ═══════════════════════════════════════════════════════════════════════════
# Statut de protection
# ═══════════════════════════════════════════════════════════════════════════

def effective_last_update(daemon_status=None):
    """Date la plus récente connue de mise à jour des signatures (datetime ou None)."""
    candidates = []
    db = db_last_update()
    if db:
        candidates.append(db)
    for src in (load_state(), (daemon_status or {}).get("state") or {}):
        v = src.get("last_update")
        if v:
            try:
                candidates.append(datetime.fromisoformat(v))
            except ValueError:
                pass
    return max(candidates) if candidates else None


def get_protection_status(lang, daemon_status=None):
    """(couleur, message) : vert < 1 jour, bleu < 2 jours, rouge sinon."""
    def T(key, **p):
        return translate(lang, key, **p)
    if not ClamAVBackend.is_installed():
        return "red", T("status.not_installed")
    last = effective_last_update(daemon_status)
    if not last:
        return "red", T("status.no_db")
    age = datetime.now() - last
    if age < timedelta(days=1):
        hours = int(age.total_seconds() // 3600)
        return "green", T("status.protected_h", hours=hours) if hours else T("status.protected")
    elif age < timedelta(days=2):
        return "blue", T("status.update_recommended", days=age.days)
    else:
        return "red", T("status.not_protected", days=age.days)


# ═══════════════════════════════════════════════════════════════════════════
# Popups glissants (bas à droite, sortent de derrière la barre des tâches)
# ═══════════════════════════════════════════════════════════════════════════

POPUP_CSS = b"""
.popup-window { background-color: transparent; }
.popup-card {
    background-color: #111827;
    border: 1px solid rgba(255,255,255,0.12);
    border-radius: 14px;
    padding: 14px 16px;
    color: #f1f5f9;
    box-shadow: 0 12px 32px rgba(0,0,0,0.45);
}
.popup-card.info    { border-color: rgba(59,130,246,0.55); }
.popup-card.success { border-color: rgba(34,197,94,0.55); }
.popup-card.danger  { border-color: rgba(239,68,68,0.75); background-color: #1a1116; }
.popup-card.warning { border-color: rgba(245,158,11,0.6); }
.popup-card.usb     { border-color: rgba(59,130,246,0.55); }
.popup-title { font-weight: bold; font-size: 14px; color: #f1f5f9; }
.popup-body  { font-size: 12px; color: #cbd5e1; }
.popup-meta  { font-size: 11px; color: #94a3b8; }
.popup-close { background: transparent; border: none; color: #94a3b8; padding: 0 4px; min-height: 0; min-width: 0; }
.popup-close:hover { color: #f1f5f9; }
.popup-btn { padding: 4px 12px; border-radius: 6px; font-size: 12px; background-color: #1f2b42; color: #f1f5f9; border: 1px solid rgba(255,255,255,0.1); }
.popup-btn.primary { background-color: #16a34a; border-color: #16a34a; color: white; }
.popup-btn.danger  { background-color: #dc2626; border-color: #dc2626; color: white; }
.popup-progress trough { min-height: 6px; border-radius: 3px; background-color: rgba(255,255,255,0.08); border: none; }
.popup-progress progress { min-height: 6px; border-radius: 3px; background-color: #3b82f6; border: none; }
"""

POPUP_ICONS = {
    "info": "shield-blue", "success": "shield-green", "danger": "shield-red",
    "warning": "shield-blue", "usb": "shield-blue",
}


class Popup(Gtk.Window):
    WIDTH = 380
    MARGIN = 16
    GAP = 10

    def __init__(self, manager, kind, title, body, buttons=None, progress=None,
                 timeout=None, on_activate=None, key=None, meta=None):
        super().__init__(type=Gtk.WindowType.TOPLEVEL)
        self.manager = manager
        self.kind = kind
        self.key = key
        self.on_activate = on_activate
        self.timeout = timeout
        self.timeout_id = None
        self.anim_id = None
        self.target_y = 0
        self.closing = False

        self.set_decorated(False)
        self.set_resizable(False)
        self.set_type_hint(Gdk.WindowTypeHint.NOTIFICATION)
        self.set_keep_above(True)
        self.set_skip_taskbar_hint(True)
        self.set_skip_pager_hint(True)
        self.set_accept_focus(False)
        self.set_focus_on_map(False)
        self.stick()
        self.set_default_size(self.WIDTH, -1)
        self.set_size_request(self.WIDTH, -1)
        self.get_style_context().add_class("popup-window")
        screen = self.get_screen()
        visual = screen.get_rgba_visual()
        if visual and screen.is_composited():
            self.set_visual(visual)
            self.set_app_paintable(True)

        card = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        card.get_style_context().add_class("popup-card")
        card.get_style_context().add_class(kind)
        event_box = Gtk.EventBox()
        event_box.set_visible_window(False)
        event_box.add(card)
        event_box.connect("button-press-event", self._on_click)
        self.add(event_box)

        icon = Gtk.Image.new_from_file(os.path.join(ICONS_DIR, f"{POPUP_ICONS.get(kind, 'shield-blue')}.svg"))
        icon.set_pixel_size(36)
        icon.set_valign(Gtk.Align.START)
        card.pack_start(icon, False, False, 0)

        col = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        card.pack_start(col, True, True, 0)

        head = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        self.title_label = Gtk.Label(label=title, xalign=0)
        self.title_label.set_line_wrap(True)
        self.title_label.set_max_width_chars(34)
        self.title_label.get_style_context().add_class("popup-title")
        head.pack_start(self.title_label, True, True, 0)
        close_btn = Gtk.Button(label="✕")
        close_btn.get_style_context().add_class("popup-close")
        close_btn.set_relief(Gtk.ReliefStyle.NONE)
        close_btn.set_valign(Gtk.Align.START)
        close_btn.connect("clicked", lambda *_: self.close())
        head.pack_end(close_btn, False, False, 0)
        col.pack_start(head, False, False, 0)

        self.body_label = Gtk.Label(label=body, xalign=0)
        self.body_label.set_line_wrap(True)
        self.body_label.set_max_width_chars(40)
        self.body_label.get_style_context().add_class("popup-body")
        col.pack_start(self.body_label, False, False, 0)

        self.meta_label = Gtk.Label(label=meta or "", xalign=0)
        self.meta_label.set_line_wrap(True)
        self.meta_label.set_max_width_chars(40)
        self.meta_label.get_style_context().add_class("popup-meta")
        self.meta_label.set_no_show_all(not meta)
        col.pack_start(self.meta_label, False, False, 0)

        self.progress_bar = Gtk.ProgressBar()
        self.progress_bar.get_style_context().add_class("popup-progress")
        self.progress_bar.set_no_show_all(progress is None)
        if progress is not None:
            self.progress_bar.set_fraction(max(0.0, min(1.0, progress)))
        col.pack_start(self.progress_bar, False, False, 2)

        if buttons:
            row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
            row.set_margin_top(6)
            for label, style, callback in buttons:
                btn = Gtk.Button(label=label)
                btn.get_style_context().add_class("popup-btn")
                if style:
                    btn.get_style_context().add_class(style)
                btn.connect("clicked", self._on_button, callback)
                row.pack_start(btn, False, False, 0)
            col.pack_start(row, False, False, 0)

    # ── Interaction ──────────────────────────────────────────────────────
    def _on_click(self, _widget, event):
        if event.button == 1 and self.on_activate:
            self.on_activate()
            self.close()
        return True

    def _on_button(self, _btn, callback):
        try:
            if callback:
                callback()
        finally:
            self.close()

    def update(self, title=None, body=None, progress=None, meta=None):
        if title is not None:
            self.title_label.set_text(title)
        if body is not None:
            self.body_label.set_text(body)
        if meta is not None:
            self.meta_label.set_no_show_all(False)
            self.meta_label.set_text(meta)
            self.meta_label.show()
        if progress is not None:
            self.progress_bar.set_no_show_all(False)
            self.progress_bar.show()
            self.progress_bar.set_fraction(max(0.0, min(1.0, progress)))

    # ── Animation ────────────────────────────────────────────────────────
    def present_sliding(self, target_x, target_y, start_y):
        self.target_y = target_y
        self.move(target_x, start_y)
        self.show_all()
        self._animate(start_y, target_y, target_x, on_done=self._arm_timeout)

    def slide_to(self, target_x, target_y):
        if self.closing:
            return
        _cur_x, cur_y = self.get_position()
        self.target_y = target_y
        self._animate(cur_y, target_y, target_x)

    def _animate(self, y0, y1, x, duration=0.32, on_done=None):
        if self.anim_id:
            GLib.source_remove(self.anim_id)
            self.anim_id = None
        start = time.monotonic()

        def step():
            p = min(1.0, (time.monotonic() - start) / duration)
            eased = 1 - (1 - p) ** 3
            self.move(x, int(round(y0 + (y1 - y0) * eased)))
            if p >= 1.0:
                self.anim_id = None
                if on_done:
                    on_done()
                return False
            return True
        self.anim_id = GLib.timeout_add(16, step)

    def _arm_timeout(self):
        if self.timeout and not self.timeout_id:
            self.timeout_id = GLib.timeout_add_seconds(int(self.timeout), self._timeout_close)

    def _timeout_close(self):
        self.timeout_id = None
        self.close()
        return False

    def close(self):
        if self.closing:
            return
        self.closing = True
        if self.timeout_id:
            GLib.source_remove(self.timeout_id)
            self.timeout_id = None
        x, y = self.get_position()
        geo = self.manager.monitor_geometry()
        self._animate(y, geo.y + geo.height + 10, x, duration=0.22, on_done=self._destroy)

    def _destroy(self):
        self.manager.forget(self)
        self.destroy()


class PopupManager:
    """Empile les popups en bas à droite et les fait glisser depuis derrière la barre des tâches."""

    def __init__(self):
        self.popups = []
        provider = Gtk.CssProvider()
        provider.load_from_data(POPUP_CSS)
        Gtk.StyleContext.add_provider_for_screen(
            Gdk.Screen.get_default(), provider, Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION)

    @staticmethod
    def _monitor():
        display = Gdk.Display.get_default()
        return display.get_primary_monitor() or display.get_monitor(0)

    def monitor_geometry(self):
        return self._monitor().get_geometry()

    def workarea(self):
        return self._monitor().get_workarea()

    def show(self, popup):
        # Un popup avec la même clé (ex. même clé USB) remplace le précédent
        if popup.key:
            for old in list(self.popups):
                if old.key == popup.key:
                    old.close()
        self.popups.append(popup)
        popup.show_all()
        popup.hide()
        height = popup.get_preferred_height()[1]
        wa = self.workarea()
        geo = self.monitor_geometry()
        x = wa.x + wa.width - Popup.WIDTH - Popup.MARGIN
        offset = sum(p.get_preferred_height()[1] + Popup.GAP
                     for p in self.popups if p is not popup and not p.closing)
        y = wa.y + wa.height - height - Popup.MARGIN - offset
        popup.present_sliding(x, y, geo.y + geo.height)
        return popup

    def find(self, key):
        for p in self.popups:
            if p.key == key and not p.closing:
                return p
        return None

    def close_key(self, key):
        p = self.find(key)
        if p:
            p.close()

    def forget(self, popup):
        if popup in self.popups:
            self.popups.remove(popup)
        self.relayout()

    def relayout(self):
        wa = self.workarea()
        x = wa.x + wa.width - Popup.WIDTH - Popup.MARGIN
        offset = 0
        for p in [p for p in self.popups if not p.closing]:
            height = p.get_preferred_height()[1]
            y = wa.y + wa.height - height - Popup.MARGIN - offset
            p.slide_to(x, y)
            offset += height + Popup.GAP


# ═══════════════════════════════════════════════════════════════════════════
# Tray
# ═══════════════════════════════════════════════════════════════════════════

class TrayIcon:
    """Bouclier dans la barre des tâches avec couleur selon l'état."""

    def __init__(self, app):
        self.app = app
        self.indicator = AppIndicator3.Indicator.new(
            "clamav-antivirus",
            os.path.join(ICONS_DIR, "shield-green.svg"),
            AppIndicator3.IndicatorCategory.APPLICATION_STATUS
        )
        self.indicator.set_status(AppIndicator3.IndicatorStatus.ACTIVE)
        self.indicator.set_title("ClamAV Antivirus")

        menu = Gtk.Menu()
        self.item_show = Gtk.MenuItem(label="")
        self.item_show.connect("activate", self.on_show)
        menu.append(self.item_show)
        self.item_scan = Gtk.MenuItem(label="")
        self.item_scan.connect("activate", self.on_full_scan)
        menu.append(self.item_scan)
        self.item_update = Gtk.MenuItem(label="")
        self.item_update.connect("activate", self.on_update)
        menu.append(self.item_update)
        self.item_system = Gtk.MenuItem(label="")
        self.item_system.connect("activate", self.on_system)
        menu.append(self.item_system)
        menu.append(Gtk.SeparatorMenuItem())
        self.item_status = Gtk.MenuItem(label="")
        self.item_status.set_sensitive(False)
        menu.append(self.item_status)
        self.item_job = Gtk.MenuItem(label="")
        self.item_job.set_sensitive(False)
        self.item_job.set_no_show_all(True)
        menu.append(self.item_job)
        menu.append(Gtk.SeparatorMenuItem())
        self.item_quit = Gtk.MenuItem(label="")
        self.item_quit.connect("activate", self.on_quit)
        menu.append(self.item_quit)
        menu.show_all()
        self.indicator.set_menu(menu)

        self.relabel()
        self.update_status()
        GLib.timeout_add_seconds(300, self.update_status)

    def relabel(self):
        T = self.app.T
        self.item_show.set_label(T("tray.open"))
        self.item_scan.set_label(T("tray.full_scan"))
        self.item_update.set_label(T("tray.update"))
        self.item_system.set_label(T("tray.system"))
        self.item_quit.set_label(T("tray.quit"))

    def update_status(self):
        color, message = get_protection_status(self.app.lang, self.app.last_daemon_status)
        self.indicator.set_icon_full(os.path.join(ICONS_DIR, f"shield-{color}.svg"), message)
        self.item_status.set_label(self.app.T("tray.status", message=message))
        self.app.run_js(f'if(typeof updateTrayStatus==="function")updateTrayStatus({json.dumps(color)},{json.dumps(message)});')
        return True

    def set_job(self, text):
        if text:
            self.item_job.set_label(text)
            self.item_job.show()
        else:
            self.item_job.hide()

    def on_show(self, _):
        self.app.window.present()

    def on_full_scan(self, _):
        self.app.window.present()
        self.app.run_js('if(typeof startFullSystemScan==="function")startFullSystemScan();')

    def on_update(self, _):
        self.app.window.present()
        self.app.run_js('if(typeof triggerUpdate==="function")triggerUpdate();')

    def on_system(self, _):
        self.app.show_tab("system")

    def on_quit(self, _):
        Gtk.main_quit()


# ═══════════════════════════════════════════════════════════════════════════
# Application
# ═══════════════════════════════════════════════════════════════════════════

class ClamAVAntivirusApp:
    """Fenêtre principale (WebKit2) + tray + popups + pont vers le service système."""

    def __init__(self, start_hidden=False):
        self.webview = None
        self.local_scan = None
        self.scan_source = None          # 'daemon' | 'local' | None
        self.updating = False
        self.last_daemon_status = None
        self.daemon_job = None
        self.page_loaded = False
        self.last_security_count = None
        self.lang = pick_language(load_state().get("language"))
        load_i18n()

        self.window = Gtk.Window(title="ClamAV Antivirus")
        self.window.set_default_size(1040, 720)
        self.window.set_position(Gtk.WindowPosition.CENTER)
        self.window.set_icon_from_file(os.path.join(ICONS_DIR, "shield-green.svg"))
        self.window.connect("delete-event", self.on_close)

        ucm = WebKit2.UserContentManager()
        ucm.register_script_message_handler("backend")
        ucm.connect("script-message-received::backend", self.on_message_from_js)

        self.webview = WebKit2.WebView.new_with_user_content_manager(ucm)
        settings = self.webview.get_settings()
        settings.set_enable_developer_extras(True)
        settings.set_javascript_can_access_clipboard(True)
        self.webview.connect("load-changed", self.on_load_changed)
        self.webview.load_uri(f"file://{os.path.join(UI_DIR, 'index.html')}")
        self.window.add(self.webview)

        self.popups = PopupManager()
        self.tray = TrayIcon(self)
        self.daemon = DaemonClient(self.on_daemon_event)

        self.window.show_all()
        if start_hidden:
            self.window.hide()
        else:
            self.window.present()

    # ── Traduction ──────────────────────────────────────────────────────
    def T(self, key, **params):
        return translate(self.lang, key, **params)

    def msg(self, key, params=None):
        return self.T(key, **(params or {}))

    # ── Fenêtre ─────────────────────────────────────────────────────────
    def on_close(self, widget, event):
        self.window.hide()
        return True

    def on_load_changed(self, _webview, load_event):
        if load_event == WebKit2.LoadEvent.FINISHED:
            self.page_loaded = True
            self.run_js(f'if(typeof setLanguage==="function")setLanguage({json.dumps(self.lang)});')

    def run_js(self, js):
        if self.webview:
            self.webview.run_javascript(js, None, None, None)

    def send_to_js(self, event, data):
        payload = json.dumps({"event": event, "data": data}, ensure_ascii=False)
        self.run_js(f'if(typeof onBackendMessage==="function")onBackendMessage({payload});')

    def show_tab(self, tab):
        self.window.present()
        self.run_js(f'if(typeof switchTab==="function")switchTab({json.dumps(tab)});')

    # ── Popups ──────────────────────────────────────────────────────────
    def popup(self, kind, title, body, **kwargs):
        return self.popups.show(Popup(self.popups, kind, title, body, **kwargs))

    def show_alert(self, alert):
        T = self.T
        severity = alert.get("severity", "info")
        comm = alert.get("comm") or "?"
        count = alert.get("count", 0)
        top_dir = alert.get("top_dir") or "/"
        meta_parts = []
        if alert.get("exe"):
            meta_parts.append(alert["exe"])
        if alert.get("user"):
            meta_parts.append(T("popup.alert.user", user=alert["user"]))
        reasons = alert.get("reasons") or []
        reason_text = ", ".join(T(f"alert.reason.{r}") for r in reasons if r)
        if severity == "danger":
            body = T("popup.alert.danger_body", program=comm, count=count, dir=top_dir)
            if reason_text:
                body += f"\n{reason_text}"
            self.popup("danger", T("popup.alert.danger_title"), body,
                       buttons=[(T("popup.btn.scan_folder"), "danger", lambda d=top_dir: self.request_scan(d)),
                                (T("popup.btn.details"), None, lambda: self.show_tab("system"))],
                       meta=" · ".join(meta_parts) or None,
                       on_activate=lambda: self.show_tab("system"))
        else:
            body = T("popup.alert.body", program=comm, count=count, seconds=alert.get("window", 15), dir=top_dir)
            self.popup("info", T("popup.alert.info_title"), body, timeout=14,
                       meta=" · ".join(meta_parts) or None,
                       on_activate=lambda: self.show_tab("system"))

    def request_scan(self, path):
        self.window.present()
        self.run_js(f'if(typeof startScan==="function")startScan({json.dumps(path)});')

    # ── Événements du service système ───────────────────────────────────
    def on_daemon_event(self, ev):
        et = ev.get("event")
        if et == "connected":
            self.last_daemon_status = ev.get("status") or {}
            job = self.last_daemon_status.get("job")
            if job:
                self._daemon_job_started(job)
            for usb in self.last_daemon_status.get("usb_pending") or []:
                self.ask_usb(usb)
            sys_status = self.last_daemon_status.get("system_status")
            if sys_status:
                self.last_security_count = sys_status.get("security")
            self.send_status()
        elif et == "disconnected":
            self.last_daemon_status = None
            if self.scan_source == "daemon":
                self.scan_source = None
                self.send_to_js("scanDone", {"status": "error", "source": "daemon",
                                             "message": self.T("msg.daemon_lost")})
            self.send_status()
        elif et == "job_started":
            self._daemon_job_started(ev.get("job") or {})
        elif et == "job_queued":
            if ev.get("waiting"):
                self.send_to_js("jobQueued", ev.get("job") or {})
        elif et == "progress":
            if ev.get("kind") == "scan":
                self.send_to_js("scanProgress", ev)
                if ev.get("usb"):
                    self.update_usb_popup(ev)
        elif et == "line":
            if self.daemon_job and self.daemon_job.get("kind") == "update":
                self.send_to_js("updateLine", {"text": ev.get("text", "")})
            else:
                self.send_to_js("scanLine", {"kind": ev.get("kind"), "text": ev.get("text", "")})
        elif et == "job_done":
            self._daemon_job_done(ev)
        elif et == "alert":
            self.show_alert(ev.get("alert") or {})
            self.send_to_js("alertEvent", ev.get("alert") or {})
        elif et == "usb_ask":
            self.ask_usb(ev.get("usb") or {})
        elif et == "usb_done":
            self.usb_done(ev)
        elif et == "usb_error":
            usb = ev.get("usb") or {}
            self.popup("warning", self.T("popup.usb.error_title"),
                       self.T("popup.usb.error_body", name=self.usb_name(usb), error=ev.get("error", "")),
                       timeout=20)
        elif et == "usb_removed":
            self.popups.close_key(f"usb:{ev.get('devnode')}")
        elif et == "system_status":
            status = ev.get("status") or {}
            self.send_to_js("systemStatus", {"status": status, "refreshing": False, "available": True})
            self.maybe_notify_security(status)
        elif et == "system_status_refreshing":
            self.send_to_js("systemStatus", {"status": None, "refreshing": True, "available": True})
        return False

    def _daemon_job_started(self, job):
        self.daemon_job = job
        if job.get("kind") == "scan":
            self.scan_source = "daemon"
            self.tray.set_job(self.T("tray.scanning", path=job.get("path")))
            self.send_to_js("scanStarted", {"source": "daemon", "path": job.get("path"),
                                            "resume": job.get("resume"), "auto": job.get("auto"),
                                            "usb": job.get("usb"),
                                            "started_at": job.get("started_at"), "job": job})
            if job.get("usb"):
                self.show_usb_progress(job)
        else:
            self.updating = True
            self.tray.set_job(self.T("tray.updating"))
            self.send_to_js("updateStarted", {"source": "daemon", "auto": job.get("auto")})

    def _daemon_job_done(self, ev):
        self.daemon_job = None
        self.tray.set_job(None)
        status = ev.get("status")
        message = self.msg(ev.get("msg_key", ""), ev.get("msg_params"))
        if ev.get("kind") == "scan":
            self.scan_source = None
            self.send_to_js("scanDone", {"status": status, "message": message,
                                         "summary": ev.get("summary", {}), "source": "daemon",
                                         "auto": ev.get("auto"), "path": ev.get("path"),
                                         "usb": ev.get("usb")})
            if not ev.get("usb"):
                self.notify_scan_result(status, message, ev.get("summary", {}))
        else:
            self.updating = False
            ok = status == "success"
            self.send_to_js("operationResult", {"status": "success" if ok else "error",
                                                "message": message, "op": "update"})
            if ok:
                self.popup("success", self.T("popup.update.title"), message, timeout=12,
                           on_activate=lambda: self.show_tab("update"))
        st = DaemonClient.request("status")
        if st.get("ok"):
            self.last_daemon_status = st
        self.send_status()
        self.tray.update_status()

    def notify_scan_result(self, status, message, summary):
        T = self.T
        path = (summary or {}).get("path") or ""
        if status == "clean":
            self.popup("success", T("popup.scan.clean_title"), message, timeout=12,
                       meta=path, on_activate=lambda: self.show_tab("scan"))
        elif status == "infected":
            self.popup("danger", T("popup.scan.infected_title"), message, meta=path,
                       buttons=[(T("popup.btn.quarantine"), "danger", lambda: self.show_tab("quarantine"))],
                       on_activate=lambda: self.show_tab("quarantine"))

    def maybe_notify_security(self, status):
        count = status.get("security") or 0
        previous = self.last_security_count
        self.last_security_count = count
        if count and count != previous:
            self.popup("warning", self.T("popup.security.title"),
                       self.T("popup.security.body", count=count, cves=status.get("cve_count") or 0),
                       timeout=25,
                       buttons=[(self.T("popup.btn.details"), "primary", lambda: self.show_tab("system"))],
                       on_activate=lambda: self.show_tab("system"))

    # ── USB ─────────────────────────────────────────────────────────────
    @staticmethod
    def usb_name(usb):
        return usb.get("label") or usb.get("model") or usb.get("devnode") or "USB"

    def show_usb_progress(self, job):
        usb = job.get("usb") or {}
        key = f"usb:{usb.get('devnode')}"
        title = self.T("popup.usb.scanning_title", name=self.usb_name(usb))
        return self.popup("usb", title, self.T("popup.usb.preparing"), key=key, progress=0.0,
                          meta=f"{usb.get('devnode', '')} · {format_size(usb.get('size', 0))}",
                          on_activate=lambda: self.show_tab("scan"))

    def update_usb_popup(self, ev):
        usb = ev.get("usb") or {}
        p = self.popups.find(f"usb:{usb.get('devnode')}")
        if not p:
            return
        if ev.get("phase") == "counting":
            p.update(body=self.T("popup.usb.counting", found=ev.get("found", 0)))
        elif ev.get("total"):
            frac = ev.get("scanned", 0) / max(1, ev.get("total", 1))
            p.update(body=self.T("popup.usb.progress", scanned=ev.get("scanned", 0),
                                 total=ev.get("total", 0), infected=ev.get("infected", 0)),
                     progress=frac)

    def usb_done(self, ev):
        usb = ev.get("usb") or {}
        key = f"usb:{usb.get('devnode')}"
        self.popups.close_key(key)
        if ev.get("removed"):
            return
        name = self.usb_name(usb)
        status = ev.get("status")
        message = self.msg(ev.get("msg_key", ""), ev.get("msg_params"))
        if status == "clean":
            self.popup("success", self.T("popup.usb.clean_title", name=name), message, timeout=15)
        elif status == "infected":
            self.popup("danger", self.T("popup.usb.infected_title", name=name), message,
                       buttons=[(self.T("popup.btn.quarantine"), "danger", lambda: self.show_tab("quarantine"))])
        else:
            self.popup("warning", self.T("popup.usb.done_title", name=name), message, timeout=15)
        if usb.get("private_mount") and status in ("clean", "infected"):
            # Le service a démonté la clé : la monter maintenant pour l'utilisateur et l'ouvrir
            threading.Thread(target=self.mount_for_user, args=(usb, True, False), daemon=True).start()

    def ask_usb(self, usb):
        key = f"usb:{usb.get('devnode')}"
        if self.popups.find(key):
            return
        name = self.usb_name(usb)
        body = self.T("popup.usb.ask_body", name=name, size=format_size(usb.get("size", 0)),
                      model=(usb.get("vendor", "") + " " + usb.get("model", "")).strip())
        self.popup("usb", self.T("popup.usb.ask_title"), body, key=key,
                   buttons=[(self.T("popup.btn.scan"), "primary", lambda: self.usb_decide(usb, True)),
                            (self.T("popup.btn.no_scan"), None, lambda: self.usb_decide(usb, False))])

    def usb_decide(self, usb, scan):
        DaemonClient.request("usb_decision", devnode=usb.get("devnode", ""))
        threading.Thread(target=self.mount_for_user, args=(usb, True, scan), daemon=True).start()

    def mount_for_user(self, usb, open_after=True, scan_after=False):
        """Monte le support via udisks (droits de l'utilisateur) et l'ouvre dans le gestionnaire de fichiers."""
        devnode = usb.get("devnode", "")
        mountpoint = None
        try:
            r = subprocess.run(["udisksctl", "mount", "-b", devnode], capture_output=True, text=True, timeout=60)
            out = (r.stdout or "") + (r.stderr or "")
            if " at " in out:
                mountpoint = out.rsplit(" at ", 1)[1].strip().rstrip(".")
        except Exception:  # noqa: BLE001
            pass
        if not mountpoint:
            try:
                r = subprocess.run(["findmnt", "-n", "-o", "TARGET", devnode], capture_output=True, text=True, timeout=10)
                lines = (r.stdout or "").strip().splitlines()
                mountpoint = lines[0].strip() if lines else None
            except Exception:  # noqa: BLE001
                mountpoint = None
        if not mountpoint:
            GLib.idle_add(self.popup, "warning", self.T("popup.usb.error_title"),
                          self.T("popup.usb.mount_failed", name=self.usb_name(usb)))
            return
        if open_after:
            try:
                subprocess.Popen(["xdg-open", mountpoint])
            except OSError:
                pass
        if scan_after:
            resp = DaemonClient.request("scan", path=mountpoint, usb_devnode=devnode)
            if not resp.get("ok"):
                GLib.idle_add(self.send_to_js, "operationResult",
                              {"status": "error", "message": self.daemon_error(resp)})

    def daemon_error(self, resp):
        err = resp.get("error", "")
        if err == "busy":
            busy = resp.get("busy") or {}
            return self.T("msg.busy_update") if busy.get("kind") == "update" else \
                self.T("msg.busy_scan", path=busy.get("path"))
        key = {"forbidden": "msg.forbidden", "not_found": "msg.not_found", "idle": "msg.idle",
               "restore_dest": "msg.restore_dest"}.get(err)
        if key:
            return self.T(key, path=resp.get("path", ""))
        return err or self.T("msg.daemon_unavailable")

    # ── Scan local (callbacks) ──────────────────────────────────────────
    def on_local_scan_event(self, event, data):
        if event == "progress":
            self.send_to_js("scanProgress", data)
        elif event == "line":
            self.send_to_js("scanLine", data)
        elif event == "done":
            self.local_scan = None
            self.scan_source = None
            self.tray.set_job(None)
            data["source"] = "local"
            data["message"] = self.msg(data.get("msg_key", ""), data.get("msg_params"))
            self.send_to_js("scanDone", data)
            self.notify_scan_result(data.get("status"), data["message"], data.get("summary", {}))
            self.send_status()
            self.tray.update_status()
        return False

    # ── Messages du frontend ────────────────────────────────────────────
    def on_message_from_js(self, ucm, result):
        try:
            data = json.loads(result.get_js_value().to_string())
            action = data.get("action")
            handler = getattr(self, f"act_{action}", None)
            if handler:
                handler(data)
            else:
                self.send_to_js("error", {"message": f"Unknown action: {action}"})
        except Exception as e:  # noqa: BLE001
            self.send_to_js("error", {"message": str(e)})

    def act_check_status(self, _data):
        st = DaemonClient.request("status")
        self.last_daemon_status = st if st.get("ok") else None
        self.send_status()

    def act_set_language(self, data):
        lang = data.get("lang")
        if lang not in LANGUAGES:
            return
        save_state({"language": lang})
        self.lang = lang
        self.tray.relabel()
        self.tray.update_status()
        self.run_js(f'if(typeof setLanguage==="function")setLanguage({json.dumps(self.lang)});')
        self.send_status()

    def act_install(self, _data):
        ClamAVBackend.install_clamav(self.operation_callback)

    def act_update(self, _data):
        if self.updating:
            return
        resp = DaemonClient.request("update")
        if resp.get("ok"):
            self.updating = True
            self.send_to_js("updateStarted", {"source": "daemon", "queued": resp.get("queued", False)})
            return
        if not resp.get("unavailable"):
            self.send_to_js("operationResult", {"status": "error", "message": self.daemon_error(resp), "op": "update"})
            return
        # Service absent : pkexec (mot de passe)
        self.updating = True
        self.send_to_js("updateStarted", {"source": "local"})
        ClamAVBackend.update_database_pkexec(self.operation_callback)

    def act_scan(self, data):
        path = os.path.normpath(data.get("path") or HOME_DIR)
        resume = bool(data.get("resume", False))
        full = path == "/"
        if self.scan_source or self.local_scan:
            self.send_to_js("operationResult", {"status": "error", "message": self.T("msg.scan_running")})
            return
        if not os.path.isdir(path):
            self.send_to_js("operationResult", {"status": "error", "message": self.T("msg.not_found", path=path)})
            return

        # 1) Service système (root, sans mot de passe)
        if daemon_can_scan(path):
            resp = DaemonClient.request("scan", path=path, resume=resume)
            if resp.get("ok"):
                return  # l'événement job_started déclenchera scanStarted
            if not resp.get("unavailable"):
                self.send_to_js("operationResult", {"status": "error", "message": self.daemon_error(resp)})
                return

        # 2) Repli local : pkexec pour le scan complet, sinon droits de l'utilisateur
        use_sudo = full
        self.scan_source = "local"
        self.local_scan = LocalScan(path, self.on_local_scan_event, resume=resume, use_sudo=use_sudo)
        self.tray.set_job(self.T("tray.scanning", path=path))
        self.send_to_js("scanStarted", {"source": "local", "path": path, "resume": resume,
                                        "auto": False, "started_at": self.local_scan.started_at,
                                        "needs_password": use_sudo})
        self.local_scan.start()

    def act_cancel_scan(self, _data):
        if self.local_scan:
            self.local_scan.cancel()
        elif self.scan_source == "daemon":
            resp = DaemonClient.request("cancel")
            if not resp.get("ok"):
                self.send_to_js("operationResult", {"status": "error", "message": self.daemon_error(resp)})
        else:
            self.send_to_js("operationResult", {"status": "info", "message": self.T("msg.idle")})

    def act_get_db_info(self, _data):
        self.send_to_js("dbInfo", {"files": db_files_info()})

    def act_get_log(self, data):
        scope = data.get("scope", "system")
        if scope == "system":
            resp = DaemonClient.request("get_log", lines=300)
            lines = resp.get("lines", []) if resp.get("ok") else []
            self.send_to_js("logContent", {"lines": lines, "scope": "system",
                                           "available": bool(resp.get("ok"))})
        else:
            try:
                with open(LOG_FILE) as f:
                    lines = f.readlines()[-300:]
            except FileNotFoundError:
                lines = []
            self.send_to_js("logContent", {"lines": lines, "scope": "user", "available": True})

    def act_clear_log(self, data):
        scope = data.get("scope", "system")
        if scope == "system":
            DaemonClient.request("clear_log")
        else:
            open(LOG_FILE, "w").close()
        self.act_get_log({"scope": scope})

    def act_get_quarantine(self, _data):
        self.send_to_js("quarantineList", {"files": self._merged_quarantine()})

    def _merged_quarantine(self):
        files = ClamAVBackend.get_quarantine_files()
        resp = DaemonClient.request("quarantine_list")
        if resp.get("ok"):
            files += resp.get("files", [])
        files.sort(key=lambda f: f.get("date", ""), reverse=True)
        return files

    def _quarantine_result(self, status, key, params):
        self.send_to_js("operationResult", {"status": status, "message": self.msg(key, params), "op": "quarantine"})
        self.send_to_js("quarantineList", {"files": self._merged_quarantine()})

    def _daemon_quarantine_result(self, resp):
        if resp.get("ok"):
            self._quarantine_result("success", resp.get("msg_key", ""), resp.get("msg_params"))
        else:
            self.send_to_js("operationResult", {"status": "error", "message": self.daemon_error(resp), "op": "quarantine"})

    def act_delete_quarantine(self, data):
        if data.get("scope") == "system":
            self._daemon_quarantine_result(DaemonClient.request("quarantine_delete", path=data.get("path", "")))
        else:
            self._quarantine_result(*ClamAVBackend.delete_quarantine_file(data.get("path", "")))

    def act_restore_quarantine(self, data):
        dest = data.get("dest") or HOME_DIR
        if data.get("scope") == "system":
            self._daemon_quarantine_result(DaemonClient.request("quarantine_restore", path=data.get("path", ""), dest=dest))
        else:
            self._quarantine_result(*ClamAVBackend.restore_quarantine_file(data.get("path", ""), dest))

    def act_empty_quarantine(self, _data):
        status, key, params = ClamAVBackend.empty_quarantine()
        message = self.msg(key, params)
        resp = DaemonClient.request("quarantine_empty")
        if resp.get("ok"):
            message += " · " + self.msg(resp.get("msg_key", ""), resp.get("msg_params"))
        self.send_to_js("operationResult", {"status": status, "message": message, "op": "quarantine"})
        self.send_to_js("quarantineList", {"files": self._merged_quarantine()})

    def act_pick_folder(self, data):
        """Sélecteur de dossier natif GTK (chemin personnalisé, restauration)."""
        purpose = data.get("purpose", "scan")
        dialog = Gtk.FileChooserDialog(
            title=self.T("dialog.choose_folder"), parent=self.window,
            action=Gtk.FileChooserAction.SELECT_FOLDER)
        dialog.add_buttons(self.T("dialog.cancel"), Gtk.ResponseType.CANCEL,
                           self.T("dialog.choose"), Gtk.ResponseType.OK)
        dialog.set_current_folder(data.get("start") or HOME_DIR)
        resp = dialog.run()
        path = dialog.get_filename() if resp == Gtk.ResponseType.OK else None
        dialog.destroy()
        self.send_to_js("folderPicked", {"path": path, "purpose": purpose,
                                         "extra": data.get("extra")})

    def act_get_system_status(self, data):
        resp = DaemonClient.request("system_status", refresh=bool(data.get("refresh")),
                                    force=bool(data.get("force")))
        if resp.get("ok"):
            self.send_to_js("systemStatus", {"status": resp.get("status"),
                                             "refreshing": bool(resp.get("refreshing")),
                                             "available": True})
        else:
            self.send_to_js("systemStatus", {"status": None, "refreshing": False, "available": False})

    def act_get_alerts(self, _data):
        resp = DaemonClient.request("alerts")
        self.send_to_js("alertsList", {"alerts": resp.get("alerts", []) if resp.get("ok") else [],
                                       "available": bool(resp.get("ok"))})

    def act_clear_alerts(self, _data):
        DaemonClient.request("clear_alerts")
        self.act_get_alerts({})

    def act_open_update_manager(self, _data):
        for cmd in (["mintupdate"], ["update-manager"], ["gnome-software", "--mode=updates"]):
            if shutil.which(cmd[0]):
                subprocess.Popen(cmd)
                return
        self.send_to_js("operationResult", {"status": "error", "message": self.T("msg.no_update_manager")})

    def act_open_url(self, data):
        url = data.get("url", "")
        if url.startswith(("https://", "http://")):
            subprocess.Popen(["xdg-open", url])

    def act_quit(self, _data):
        Gtk.main_quit()

    # ── Callbacks des opérations pkexec ─────────────────────────────────
    def operation_callback(self, status, key_or_text, params):
        if status == "progress":
            if self.updating:
                self.send_to_js("updateLine", {"text": key_or_text})
            else:
                self.send_to_js("operationResult", {"status": "progress", "message": key_or_text})
            return
        message = self.msg(key_or_text, params)
        if self.updating:
            self.updating = False
            self.send_to_js("operationResult", {"status": status, "message": message, "op": "update"})
            if status == "success":
                self.popup("success", self.T("popup.update.title"), message, timeout=12)
        else:
            self.send_to_js("operationResult", {"status": status, "message": message, "op": "install"})
        if status == "success":
            self.send_status()
            self.tray.update_status()

    # ── Statut global ───────────────────────────────────────────────────
    def send_status(self):
        ds = self.last_daemon_status if isinstance(self.last_daemon_status, dict) else None
        color, message = get_protection_status(self.lang, ds)
        installed = ClamAVBackend.is_installed()
        freshclam_installed = ClamAVBackend.is_freshclam_installed()
        state = load_state()
        dstate = (ds or {}).get("state") or {}

        resumable = (ds or {}).get("resumable")
        if not resumable and not self.local_scan:
            try:
                with open(SCAN_PROGRESS_FILE) as f:
                    prog = json.load(f)
                if prog.get("in_progress"):
                    resumable = {"path": prog.get("path"), "scanned": prog.get("scanned", 0),
                                 "total": prog.get("total", 0), "source": "local"}
            except Exception:
                pass

        history = list(state.get("history", [])) + list(dstate.get("history", []))
        history.sort(key=lambda e: e.get("date", ""), reverse=True)
        last_scan = history[0] if history else None
        if not last_scan and state.get("last_scan"):
            last_scan = {"date": state["last_scan"], "path": state.get("last_scan_path"),
                         "infected": state.get("last_scan_infected", 0), "source": "local"}

        last_update = effective_last_update(ds)
        next_update = systemd_next_elapse(UPDATE_TIMER_UNIT)

        self.send_to_js("statusUpdate", {
            "lang": self.lang,
            "color": color,
            "message": message,
            "installed": installed,
            "freshclam_installed": freshclam_installed,
            "fully_installed": installed and freshclam_installed,
            "daemon_active": systemd_is_active("clamav-freshclam"),
            "last_update": last_update.isoformat(timespec="seconds") if last_update else None,
            "last_scan": last_scan,
            "never_scanned": last_scan is None,
            "history": history[:10],
            "resumable": resumable,
            "scan_in_progress": bool(self.scan_source),
            "scan_job": (ds or {}).get("job") if ds else None,
            "daemon": {
                "available": ds is not None,
                "unit_active": systemd_is_active(DAEMON_UNIT),
                "version": (ds or {}).get("version"),
                "first_scan_pending": (ds or {}).get("first_scan_pending", False),
                "queue": (ds or {}).get("queue", []),
                "last_update_status": dstate.get("last_update_status"),
                "monitor_active": (ds or {}).get("monitor_active", False),
                "usb_active": (ds or {}).get("usb_active", False),
            },
            "alerts": (ds or {}).get("alerts", []),
            "system_status": (ds or {}).get("system_status"),
            "schedule": {
                "next_update": next_update.isoformat(timespec="seconds") if next_update else None,
                "timer_active": systemd_is_active(UPDATE_TIMER_UNIT),
            },
            "home": HOME_DIR,
            "version": VERSION,
        })


# ═══════════════════════════════════════════════════════════════════════════
# Instance unique
# ═══════════════════════════════════════════════════════════════════════════

def try_activate_existing():
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(1)
        sock.connect(INSTANCE_SOCKET)
        sock.sendall(b"show\n")
        sock.close()
        return True
    except (ConnectionRefusedError, FileNotFoundError, OSError):
        return False


def start_instance_server(app):
    try:
        os.unlink(INSTANCE_SOCKET)
    except FileNotFoundError:
        pass
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(INSTANCE_SOCKET)
    server.listen(1)
    server.settimeout(1)

    def listen():
        while True:
            try:
                conn, _ = server.accept()
                msg = conn.recv(16).decode().strip()
                conn.close()
                if msg == "show":
                    GLib.idle_add(app.window.present)
            except socket.timeout:
                continue
            except Exception:
                break

    threading.Thread(target=listen, daemon=True).start()
    return server


def main():
    if try_activate_existing():
        sys.exit(0)
    app = ClamAVAntivirusApp(start_hidden="--tray" in sys.argv)
    start_instance_server(app)
    Gtk.main()


if __name__ == "__main__":
    main()
