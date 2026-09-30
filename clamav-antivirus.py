#!/usr/bin/env python3
"""
ClamAV Antivirus GUI - ClamAV GUI for Linux Mint
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
    DEFAULT_SETTINGS, daemon_connect, daemon_request, find_command, is_noise_line,
    classify_line, db_last_update, db_files_info, systemd_next_elapse,
    systemd_is_active, load_i18n, pick_language, t as translate,
    quarantine_index_add, quarantine_enrich, parse_moved_line,
)

# Réglages propres à l'utilisateur (le reste est géré par le daemon)
import clamav_backup as backup   # sauvegarde des fichiers de l'utilisateur (droits utilisateur)
import clamav_extras as extras   # fuites, applications hors dépôts, coffre chiffré, bilan hebdomadaire

USER_DEFAULTS = {
    "view_mode": "simple",
    "popups": {"info": True, "upload": True, "scan": True, "update": True, "security": True, "tip": True},
}
DISCLAIMER_VERSION = 1
SECURITY_COMMANDS = ("firewall_set", "firewall_defaults", "firewall_rule_add", "firewall_rule_delete", "ssh_set", "firewall_profile",
                     "forget_network")
UNLOCK_HELPER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "clamav-antivirus-unlock")
OVERALL_ICON = {"green": "shield-green", "yellow": "shield-yellow", "blue": "shield-blue", "red": "shield-red"}

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


_AWARENESS = None


def load_awareness():
    """Leçons de sensibilisation (ui/awareness.js : window.AWARENESS = {...};)."""
    global _AWARENESS
    if _AWARENESS is None:
        try:
            with open(os.path.join(UI_DIR, "awareness.js"), encoding="utf-8") as f:
                raw = f.read()
            _AWARENESS = json.loads(raw[raw.index("{"):raw.rindex("}") + 1])
        except Exception:  # noqa: BLE001
            _AWARENESS = {}
    return _AWARENESS


def user_settings():
    state = load_state()
    popups = dict(USER_DEFAULTS["popups"])
    popups.update({k: bool(v) for k, v in (state.get("popups") or {}).items() if k in popups})
    mode = state.get("view_mode") if state.get("view_mode") in ("simple", "advanced") else USER_DEFAULTS["view_mode"]
    return {"view_mode": mode, "popups": popups, "language": state.get("language")}


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

    found_sigs = {}   # chemin infecté → signature (index de quarantaine utilisateur)

    def __init__(self, path, callback, resume=False, use_sudo=False):
        self.found_sigs = {}
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
                    self.found_sigs[path] = sig
                    write_log(line)
                    self.emit("line", {"kind": "found", "text": line})
                elif " moved to " in line:
                    moved = parse_moved_line(line)
                    if moved:
                        quarantine_index_add(QUARANTINE_DIR, moved[1], moved[0], self.found_sigs.get(moved[0], ""))
                    self.emit("line", {"kind": "info", "text": line})
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
        return quarantine_enrich(files, QUARANTINE_DIR)

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
.popup-card.tip     { border-color: rgba(34,197,94,0.45); }
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
    "warning": "shield-blue", "usb": "shield-blue", "tip": "logo",
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
            rows = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
            rows.set_margin_top(6)
            row = None
            for i, (label, style, callback) in enumerate(buttons):
                if i % 3 == 0:                      # 3 boutons par ligne au maximum
                    row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
                    rows.pack_start(row, False, False, 0)
                btn = Gtk.Button(label=label)
                btn.get_style_context().add_class("popup-btn")
                if style:
                    btn.get_style_context().add_class(style)
                btn.connect("clicked", self._on_button, callback)
                row.pack_start(btn, False, False, 0)
            col.pack_start(rows, False, False, 0)

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
        self.indicator.set_title("ClamAV Antivirus GUI")

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
        overall = self.app.overall_state()
        icon_color = overall.get("color") if overall else color
        reasons = [self.app.T(f"overall.reason.{r}") for r in (overall or {}).get("reasons", [])[:4]]
        bk = self.app.backup_summary()
        if self.app.backup_check_enabled() and bk.get("state") in ("none", "missing", "old"):
            if icon_color == "green":
                icon_color = "yellow"           # disponibilité (CIA) : fichiers non sauvegardés
            reasons.append(self.app.T(f"overall.reason.backup_{bk['state']}"))
        tooltip = message if not reasons else f"{message} — " + ", ".join(reasons)
        self.indicator.set_icon_full(os.path.join(ICONS_DIR, f"{OVERALL_ICON.get(icon_color, 'shield-green')}.svg"), tooltip)
        self.item_status.set_label(self.app.T("tray.status", message=tooltip if len(tooltip) < 90 else message))
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
        self.app.run_js('if(typeof startFullSystemScan==="function")startFullSystemScan(true);')

    def on_update(self, _):
        self.app.window.present()
        self.app.run_js('if(typeof triggerUpdate==="function")triggerUpdate();')

    def on_system(self, _):
        self.app.show_tab("system")

    def on_quit(self, _):
        self.app.request_quit()


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

        self.window = Gtk.Window(title="ClamAV Antivirus GUI")
        self.window.set_default_size(1040, 720)
        self.window.set_position(Gtk.WindowPosition.CENTER)
        self.window.set_icon_from_file(os.path.join(ICONS_DIR, "logo.svg"))
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
        GLib.timeout_add_seconds(25, self.show_daily_tip)
        self.backup_runner = None
        self.backup_progress = None
        GLib.timeout_add_seconds(120, self._backup_first_check)
        self.restore_runner = None
        GLib.timeout_add_seconds(90, self._weekly_first_check)

    # ── Conseil de sécurité du jour (sensibilisation) ───────────────────
    def show_daily_tip(self, force=False):
        state = load_state()
        if not force:
            if not self.popups_enabled("tip"):
                return False
            if state.get("tip_date") == datetime.now().strftime("%Y-%m-%d"):
                return False
        lessons = (load_awareness().get(self.lang) or load_awareness().get("en") or [])
        if not lessons:
            return False
        read = set(state.get("read_lessons") or [])
        unread = [l for l in lessons if l.get("id") not in read]
        if not unread and not force:
            return False                      # toutes les leçons sont lues : plus de popup
        pool = unread or lessons
        idx = int(state.get("tip_index", -1)) + 1
        if idx >= len(lessons):
            idx = 0
        # prochaine leçon (non lue) à partir de la position courante, en rotation
        rotation = lessons[idx:] + lessons[:idx]
        lesson = next((l for l in rotation if l in pool), pool[0])
        idx = next((i for i, l in enumerate(lessons) if l.get("id") == lesson.get("id")), 0)
        save_state({"tip_index": idx, "tip_date": datetime.now().strftime("%Y-%m-%d")})
        self.popup("tip", self.T("popup.tip.title", title=lesson.get("title", "")), lesson.get("summary", ""),
                   timeout=40, meta=self.T("popup.tip.meta"),
                   buttons=[(self.T("popup.btn.read_more"), "primary", lambda lid=lesson.get("id"): self.open_lesson(lid))],
                   on_activate=lambda lid=lesson.get("id"): self.open_lesson(lid))
        return False

    def open_lesson(self, lesson_id):
        self.window.present()
        self.run_js(f'if(typeof openLesson==="function")openLesson({json.dumps(lesson_id)});')

    # ── Traduction ──────────────────────────────────────────────────────
    def T(self, key, **params):
        return translate(self.lang, key, **params)

    def overall_state(self):
        ds = self.last_daemon_status if isinstance(self.last_daemon_status, dict) else None
        return (ds or {}).get("overall")

    # ── Session administrateur (pkexec → helper → daemon unlock) ────────
    def run_admin(self, cmd, params, on_result):
        """Envoie une commande ; si le daemon exige un administrateur, déverrouille via pkexec puis réessaie."""
        def worker():
            resp = daemon_request(cmd, timeout=600, **params)
            if resp.get("error") == "admin_required":
                GLib.idle_add(self.send_to_js, "operationResult", {"status": "info", "message": self.T("msg.admin_auth")})
                try:
                    r = subprocess.run(["pkexec", UNLOCK_HELPER], capture_output=True, text=True, timeout=300)
                    unlocked = r.returncode == 0
                except Exception:  # noqa: BLE001
                    unlocked = False
                if not unlocked:
                    resp = {"ok": False, "error": "auth_cancelled"}
                else:
                    resp = daemon_request(cmd, timeout=600, **params)
            GLib.idle_add(on_result, resp)
        threading.Thread(target=worker, daemon=True).start()

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

    def popups_enabled(self, kind):
        return user_settings()["popups"].get(kind, True)

    def process_action(self, pid, action):
        resp = DaemonClient.request("process_action", pid=pid, action=action)
        if resp.get("ok"):
            key = {"kill": "msg.process_killed", "continue": "msg.process_resumed", "quarantine": "msg.process_quarantined"}[action]
            self.send_to_js("operationResult", {"status": "success", "message": self.T(key)})
        else:
            self.send_to_js("operationResult", {"status": "error", "message": self.daemon_error(resp)})
        self.send_status()

    def show_alert(self, alert):
        T = self.T
        kind = alert.get("kind")
        if kind == "connection":
            if alert.get("severity") != "danger" and not self.popups_enabled("info"):
                return
            where = " · ".join(x for x in (alert.get("country"), alert.get("org")) if x)
            body = T("popup.connection.body", program=alert.get("comm") or "?", ip=alert.get("ip"), port=alert.get("port"),
                     where=where or "?")
            if alert.get("flagged"):
                buttons = [(T("popup.btn.kill"), "danger", lambda p=alert.get("pid"): self.process_action(p, "kill")),
                           (T("popup.btn.resume"), None, lambda p=alert.get("pid"): self.process_action(p, "continue"))] \
                    if alert.get("suspended") else [(T("popup.btn.details"), None, lambda: self.show_tab("system"))]
                self.popup("danger", T("popup.connection.danger_title"), body + "\n" + T("alert.reason.ip_blocklisted"),
                           meta=alert.get("exe") or None, buttons=buttons, on_activate=lambda: self.show_tab("system"))
            else:
                self.popup("warning", T("popup.connection.title"), body, timeout=16, meta=alert.get("exe") or None,
                           buttons=[(T("popup.btn.its_me"), "primary", lambda e=alert.get("exe"), c=alert.get("comm"): self.trust_program(e, c)),
                                    (T("popup.btn.details"), None, lambda: self.show_tab("system"))],
                           on_activate=lambda: self.show_tab("system"))
            return
        if kind == "timeshift":
            self.popup("warning", T("popup.timeshift.title"), T("popup.timeshift.body", free=alert.get("free_gb", 0)),
                       timeout=40, on_activate=lambda: self.show_tab("backup"),
                       buttons=[(T("popup.btn.details"), None, lambda: self.show_tab("backup"))])
            return
        if kind == "persistence":
            if not self.popups_enabled("info"):
                return
            self.popup("warning" if alert.get("severity") == "warn" else "info", T("popup.persistence.title"),
                       T("popup.persistence.body", name=alert.get("title", ""), detail=alert.get("detail", "")),
                       timeout=16, on_activate=lambda: self.show_tab("system"),
                       buttons=[(T("popup.btn.details"), None, lambda: self.show_tab("system"))])
            return
        if kind == "integrity":
            self.popup("danger" if alert.get("severity") == "danger" else "warning", T("popup.integrity.title"), T("popup.integrity.body", n=alert.get("title", "0"),
                       tools=alert.get("detail", "")), on_activate=lambda: self.show_tab("security"),
                       buttons=[(T("popup.btn.details"), None, lambda: self.show_tab("security"))])
            return
        if kind == "update":
            if not self.popups_enabled("update"):
                return
            upd = alert.get("update") or {}
            self.popup("info", T("popup.appupdate.title", version=upd.get("version", "")),
                       T("popup.appupdate.body", version=upd.get("version", ""), current=VERSION),
                       timeout=30, on_activate=lambda: self.show_tab("security"),
                       buttons=[(T("popup.btn.install"), "primary", lambda: self.act_install_update({})),
                                (T("popup.btn.details"), None, lambda: self.show_tab("security"))])
            return
        if kind == "upload":
            if not self.popups_enabled("upload"):
                return
            procs = ", ".join(f"{p['name']} ({p['connections']})" for p in (alert.get("processes") or [])[:4])
            self.popup("info", T("popup.upload.title"),
                       T("popup.upload.body", gb=alert.get("gb", 0), hours=alert.get("window_hours", 1),
                         threshold=alert.get("threshold_gb", 5)),
                       timeout=20, meta=(T("popup.upload.processes", list=procs) if procs else None),
                       buttons=[(T("popup.btn.details"), None, lambda: self.show_tab("system")),
                                (T("popup.btn.settings"), None, lambda: self.show_tab("settings"))],
                       on_activate=lambda: self.show_tab("system"))
            return
        severity = alert.get("severity", "info")
        if severity != "danger" and not self.popups_enabled("info"):
            return
        comm = alert.get("comm") or "?"
        count = alert.get("count", 0)
        top_dir = alert.get("top_dir") or "/"
        meta_parts = []
        if alert.get("exe"):
            meta_parts.append(alert["exe"])
        if alert.get("exe_replaced"):
            meta_parts.append(T("system.exe_replaced"))
        if alert.get("user"):
            meta_parts.append(T("popup.alert.user", user=alert["user"]))
        reasons = alert.get("reasons") or []
        reason_text = ", ".join(T(f"alert.reason.{r}") for r in reasons if r)
        if severity == "danger":
            body = T("popup.alert.danger_body", program=comm, count=count, dir=top_dir)
            if reason_text:
                body += f"\n{reason_text}"
            pid = alert.get("pid")
            its_me = (T("popup.btn.its_me"), None, lambda e=alert.get("exe"), c=comm: self.trust_program(e, c))
            if alert.get("suspended"):
                body += "\n" + T("popup.alert.suspended")
                buttons = [(T("popup.btn.kill"), "danger", lambda p=pid: self.process_action(p, "kill")),
                           (T("popup.btn.quarantine_exe"), "danger", lambda p=pid: self.process_action(p, "quarantine")),
                           (T("popup.btn.resume"), None, lambda p=pid: self.process_action(p, "continue")),
                           its_me]
            else:
                buttons = [(T("popup.btn.scan_folder"), "danger", lambda d=top_dir: self.request_scan(d)),
                           (T("popup.btn.details"), None, lambda: self.show_tab("system")), its_me]
            self.popup("danger", T("popup.alert.danger_title"), body, buttons=buttons,
                       meta=" · ".join(meta_parts) or None,
                       on_activate=lambda: self.show_tab("system"))
        else:
            body = T("popup.alert.body", program=comm, count=count, seconds=alert.get("window", 15), dir=top_dir)
            self.popup("info", T("popup.alert.info_title"), body, timeout=14,
                       meta=" · ".join(meta_parts) or None,
                       buttons=[(T("popup.btn.its_me"), None, lambda e=alert.get("exe"), c=comm: self.trust_program(e, c))] if alert.get("exe") else None,
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
            self.tray.update_status()   # couleur du tray dès la connexion (état global du service)
        elif et == "disconnected":
            self.last_daemon_status = None
            if self.scan_source == "daemon":
                self.scan_source = None
                self.send_to_js("scanDone", {"status": "error", "source": "daemon",
                                             "message": self.T("msg.daemon_lost")})
            self.send_status()
        elif et == "job_started":
            self._daemon_job_started(ev.get("job") or {}, resumed=bool(ev.get("resumed")))
        elif et == "job_paused":
            self.send_to_js("scanPaused", ev.get("job") or {})
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
        elif et == "usb_trusted":
            usb = ev.get("usb") or {}
            self.popup("usb", self.T("popup.usb.trusted_title", name=self.usb_name(usb)), self.T("popup.usb.trusted_body"), timeout=12,
                       buttons=[(self.T("popup.btn.scan_anyway"), "primary",
                                 lambda: threading.Thread(target=self.mount_for_user, args=(usb, False, True), daemon=True).start())])
            threading.Thread(target=self.mount_for_user, args=(usb, True, False), daemon=True).start()
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
        elif et == "system_upgrade_done":
            if ev.get("ok"):
                self.send_to_js("operationResult", {"status": "success", "op": "system", "message": self.T("msg.system_upgraded")})
                if self.popups_enabled("update"):
                    self.popup("success", self.T("popup.sysupgrade.title"), self.T("msg.system_upgraded"), timeout=12,
                               on_activate=lambda: self.show_tab("system"))
            else:
                self.send_to_js("operationResult", {"status": "error", "op": "system",
                                                    "message": self.T("msg.system_upgrade_failed", detail=(ev.get("detail") or "")[-160:])})
        elif et == "system_status_refreshing":
            self.send_to_js("systemStatus", {"status": None, "refreshing": True, "available": True})
        elif et == "security_status":
            if isinstance(self.last_daemon_status, dict):
                self.last_daemon_status["security"] = ev.get("security")
            self.send_to_js("securityStatus", {"security": ev.get("security"), "available": True})
        elif et == "settings":
            if isinstance(self.last_daemon_status, dict):
                self.last_daemon_status["settings"] = ev.get("settings")
            self.send_to_js("settingsData", {"system": ev.get("settings"), "user": user_settings(),
                                             "available": True})
        elif et == "overall":
            if isinstance(self.last_daemon_status, dict):
                self.last_daemon_status["overall"] = ev.get("overall")
            self.tray.update_status()
            self.send_to_js("overall", ev.get("overall") or {})
        elif et == "timeshift":
            if isinstance(self.last_daemon_status, dict):
                self.last_daemon_status["timeshift"] = ev.get("timeshift")
            self.send_to_js("backupTimeshift", ev.get("timeshift") or {})
        elif et == "timeshift_enable":
            self.timeshift_enable_result(ev.get("result") or {})
        elif et == "integrity_progress":
            self.send_to_js("integrityProgress", {k: v for k, v in ev.items() if k != "event"})
        elif et == "network_changed":
            T = self.T
            net = ev.get("network") or {}
            name = net.get("name") or "?"
            if ev.get("new"):
                self.popup("info", T("popup.network.new_title", name=name), T("popup.network.new_body"), timeout=45,
                           buttons=[(T("popup.network.change"), "primary", lambda: self.show_tab("firewall")),
                                    (T("popup.network.keep"), None, lambda: None)],
                           on_activate=lambda: self.show_tab("firewall"))
            elif ev.get("changed") and self.popups_enabled("info"):
                self.popup("info", T("popup.network.known_title", name=name),
                           T("popup.network.known_body", profile=T(f"firewall.profile.{ev.get('profile') or 'public'}")),
                           timeout=12, on_activate=lambda: self.show_tab("firewall"))
            self.act_get_security({"refresh": False})
            self.send_status()
        elif et == "hardening_done":
            T = self.T
            index = ev.get("index") if ev.get("index") is not None else "?"
            msg = T("msg.harden_reverted" if ev.get("revert") else "msg.harden_done",
                    ok=ev.get("ok", 0), failed=ev.get("failed", 0), index=index)
            self.send_to_js("operationResult", {"status": "success" if not ev.get("failed") else "error", "op": "security", "message": msg})
            if ev.get("auto") and ev.get("ok") and self.popups_enabled("info"):
                self.popup("success", T("popup.harden.title"), T("popup.harden.body", ok=ev.get("ok", 0), index=index),
                           timeout=20, on_activate=lambda: self.show_tab("security"))
            self.tray.update_status()
        elif et == "trusted":
            self.send_to_js("trustedList", {"programs": ev.get("programs") or [], "acknowledged": ev.get("acknowledged") or [],
                                            "available": True})
            self.act_get_alerts({})
        elif et == "integrity" and ev.get("after_scan"):
            # intégrité vérifiée au début d'une analyse complète : le bilan arrive avec la fin du scan
            self.send_to_js("securityData", {"type": "integrity", "data": ev.get("integrity") or {}, "available": True, "after_scan": True})
        elif et in ("vulns", "checklist", "integrity", "persistence", "app_update", "integrity_running", "suspended"):
            self.send_to_js("securityData", {"type": et, "data": ev.get(et) or ev.get("update") or {},
                                             "available": True})
            if et == "app_update" or et == "suspended":
                self.send_status()
        elif et in ("unlocked", "locked"):
            if et == "unlocked" and ev.get("uid") != os.getuid():
                return False
            if isinstance(self.last_daemon_status, dict):
                self.last_daemon_status["unlocked"] = et == "unlocked"
            self.send_status()
        return False

    def _daemon_job_started(self, job, resumed=False):
        self.daemon_job = job
        if job.get("kind") == "scan":
            self.scan_source = "daemon"
            self.tray.set_job(self.T("tray.scanning", path=job.get("path")))
            self.send_to_js("scanStarted", {"source": "daemon", "path": job.get("path"),
                                            "resume": job.get("resume"), "auto": job.get("auto"),
                                            "usb": job.get("usb"), "resumed": resumed,
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
                self.notify_scan_result(status, message, ev.get("summary", {}), integrity=bool(ev.get("integrity")),
                                        integrity_warnings=ev.get("integrity_warnings"), skipped=ev.get("skipped") or 0,
                                        cached=(ev.get("summary") or {}).get("cached") or 0)
        else:
            self.updating = False
            ok = status == "success"
            self.send_to_js("operationResult", {"status": "success" if ok else "error",
                                                "message": message, "op": "update"})
            if ok and self.popups_enabled("update"):
                self.popup("success", self.T("popup.update.title"), message, timeout=12,
                           on_activate=lambda: self.show_tab("update"))
        st = DaemonClient.request("status")
        if st.get("ok"):
            self.last_daemon_status = st
        self.send_status()
        self.tray.update_status()

    def notify_scan_result(self, status, message, summary, integrity=False, integrity_warnings=None, skipped=0, cached=0):
        T = self.T
        path = (summary or {}).get("path") or ""
        if status == "clean" and not self.popups_enabled("scan"):
            return
        if integrity and integrity_warnings is not None:
            message += "\n" + (T("popup.scan.integrity_warn", n=integrity_warnings) if integrity_warnings else T("popup.scan.integrity_ok"))
        if skipped:
            message += "\n" + T("scan.note.skipped", n=skipped)
        if cached:
            message += "\n" + T("scan.note.cached", n=cached)
        if status == "clean":
            self.popup("success", T("popup.integrity_ok.title") if integrity else T("popup.scan.clean_title"), message, timeout=12,
                       meta=path, on_activate=lambda: self.show_tab("scan"))
        elif status == "infected":
            self.popup("danger", T("popup.scan.infected_title"), message, meta=path,
                       buttons=[(T("popup.btn.quarantine"), "danger", lambda: self.show_tab("quarantine"))],
                       on_activate=lambda: self.show_tab("quarantine"))

    def maybe_notify_security(self, status):
        count = status.get("security") or 0
        previous = self.last_security_count
        self.last_security_count = count
        if count and count != previous and self.popups_enabled("security"):
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
                          on_activate=lambda: self.show_tab("scan"),
                          buttons=[(self.T("popup.btn.skip_scan"), None, lambda: self.usb_skip(usb, False)),
                                   (self.T("popup.btn.trust_usb"), None, lambda: self.usb_skip(usb, True))])

    def usb_skip(self, usb, trust=False):
        """« Continuer sans analyse » / « Faire confiance à cette clé » : la clé est remise tout de suite, sans mot de
        passe (sauf mode famille). Une clé de confiance n'est plus analysée à l'insertion (révocable dans Paramètres)."""
        def done(resp):
            if not resp.get("ok"):
                self.send_to_js("operationResult", {"status": "error", "message": self.daemon_error(resp)})
                return False
            self.popups.close_key(f"usb:{usb.get('devnode')}")
            name = self.usb_name(usb)
            self.popup("usb", self.T("popup.usb.skipped_title", name=name),
                       self.T("popup.usb.trusted_body") if resp.get("trusted") else self.T("popup.usb.skipped_body"), timeout=12)
            if resp.get("mount_now"):
                threading.Thread(target=self.mount_for_user, args=(usb, True, False), daemon=True).start()
            if resp.get("trusted"):
                self.act_get_trusted({})
            return False
        self.run_admin("usb_skip", {"devnode": usb.get("devnode", ""), "trust": bool(trust)}, done)

    def act_untrust_usb(self, data):
        def done(resp):
            if resp.get("ok"):
                self.send_to_js("operationResult", {"status": "success", "message": self.T("msg.usb_untrusted")})
                self.act_get_trusted({})
            else:
                self.send_to_js("operationResult", {"status": "error", "message": self.daemon_error(resp)})
            return False
        self.run_admin("untrust_usb", {"id": str(data.get("id") or "")}, done)

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
        if ev.get("skipped"):
            # « Continuer sans analyse » pendant l'analyse : montage privé libéré, la clé est montée pour l'utilisateur
            if usb.get("private_mount"):
                threading.Thread(target=self.mount_for_user, args=(usb, True, False), daemon=True).start()
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
                            (self.T("popup.btn.no_scan"), None, lambda: self.usb_decide(usb, False)),
                            (self.T("popup.btn.trust_usb"), None, lambda: self.usb_skip(usb, True))])

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
                mountpoint = out.rsplit(" at ", 1)[1].strip().rstrip(".").strip("`'\"")     # aussi « already mounted at `/media/…' »
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
               "restore_dest": "msg.restore_dest", "admin_required": "msg.admin_required",
               "auth_cancelled": "msg.auth_cancelled", "root_required": "msg.daemon_root_required",
               "command_failed": "msg.security_failed", "not_ready": "msg.update_not_ready",
               "sha256_mismatch": "msg.update_bad_hash", "not_suspended": "msg.process_gone",
               "nothing_phased": "msg.nothing_phased", "nothing_to_upgrade": "msg.nothing_to_upgrade",
               "busy_upgrade": "msg.system_upgrading", "busy_timeshift": "msg.timeshift_checking",
               "auto_updates_unavailable": "msg.auto_updates_unavailable", "busy_hardening": "msg.harden_busy",
               "nothing_to_harden": "msg.harden_nothing", "firewall_not_active": "msg.firewall_not_active"}.get(err)
        if key:
            return self.T(key, path=resp.get("path", ""), detail=str(resp.get("detail") or "")[:200])
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
            resp = DaemonClient.request("scan", path=path, resume=resume, integrity=bool(data.get("integrity")) and full)
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

    def act_accept_disclaimer(self, _data):
        save_state({"disclaimer_accepted": DISCLAIMER_VERSION, "disclaimer_date": now_iso()})
        self.send_status()

    # ── Télémétrie : consentement explicite à la première utilisation ──
    def act_telemetry_preview(self, _data):
        """Charge utile exacte que le service enverrait (sans envoi), pour la montrer avant de décider."""
        def worker():
            resp = daemon_request("telemetry_preview", timeout=30)
            GLib.idle_add(self.send_to_js, "telemetryPreview",
                          {"available": bool(resp.get("ok")), "payload": resp.get("payload"), "url": resp.get("url")})
        threading.Thread(target=worker, daemon=True).start()

    def act_telemetry_consent(self, data):
        """Réponse à la question posée en plein écran : oui/non, mémorisée pour ne plus la poser."""
        accepted = bool(data.get("accepted"))
        save_state({"telemetry_answered": now_iso(), "telemetry_consent": accepted})

        def done(resp):
            if not resp.get("ok"):
                self.send_to_js("operationResult", {"status": "error", "message": self.daemon_error(resp)})
            self.send_status()
            return False
        self.run_admin("set_settings", {"settings": {"telemetry": accepted}}, done)

    # ── « C'est moi » : programmes / entrées approuvés ─────────────────
    def trust_program(self, exe, comm=""):
        exe = (exe or "").replace(" (deleted)", "").strip()
        if not exe:
            return
        name = comm or os.path.basename(exe)

        def done(resp):
            if resp.get("ok"):
                self.send_to_js("operationResult", {"status": "success", "message": self.T("msg.program_trusted", program=name)})
                self.act_get_alerts({})
                self.act_get_trusted({})
            else:
                self.send_to_js("operationResult", {"status": "error", "message": self.daemon_error(resp)})
            self.send_status()
            return False
        self.run_admin("trust_program", {"exe": exe, "comm": name}, done)

    def act_trust_program(self, data):
        self.trust_program(data.get("exe"), data.get("comm") or "")

    def act_untrust_program(self, data):
        def done(resp):
            if resp.get("ok"):
                self.send_to_js("operationResult", {"status": "success", "message": self.T("msg.program_untrusted")})
                self.act_get_trusted({})
            else:
                self.send_to_js("operationResult", {"status": "error", "message": self.daemon_error(resp)})
            return False
        self.run_admin("untrust_program", {"exe": data.get("exe") or ""}, done)

    def act_get_trusted(self, _data):
        resp = DaemonClient.request("trusted_programs")
        self.send_to_js("trustedList", {"programs": resp.get("programs", []) if resp.get("ok") else [],
                                        "acknowledged": resp.get("acknowledged", []) if resp.get("ok") else [],
                                        "usb": resp.get("usb", []) if resp.get("ok") else [],
                                        "available": bool(resp.get("ok"))})

    def act_acknowledge_vuln(self, data):
        """« Ignorer » des failles sans correctif (ou les réafficher avec remove) : elles ne comptent plus dans l'état."""
        remove = bool(data.get("remove"))
        params = {"remove": remove}
        if data.get("all_open"):
            params["all_open"] = True
        else:
            cves = data.get("cves") if isinstance(data.get("cves"), list) else [data.get("cve")]
            params["cves"] = [str(c) for c in cves if c][:20000]

        def done(resp):
            if resp.get("ok"):
                self.send_to_js("operationResult", {"status": "success", "op": "security",
                                                    "message": self.T("msg.vuln_unacknowledged" if remove else "msg.vuln_acknowledged", n=resp.get("count") or 0)})
                self.act_get_security_data({"type": "vulns"})
            else:
                self.send_to_js("operationResult", {"status": "error", "op": "security", "message": self.daemon_error(resp)})
            return False
        self.run_admin("acknowledge_vuln", params, done)

    def act_acknowledge_integrity(self, data):
        """« C'est normal » sur un avertissement d'intégrité : approuvé (ou réactivé avec remove)."""
        remove = bool(data.get("remove"))

        def done(resp):
            if resp.get("ok"):
                self.send_to_js("operationResult", {"status": "success", "op": "security",
                                                    "message": self.T("msg.integrity_unacknowledged" if remove else "msg.integrity_acknowledged")})
                self.act_get_security_data({"type": "integrity"})
            else:
                self.send_to_js("operationResult", {"status": "error", "op": "security", "message": self.daemon_error(resp)})
            return False
        self.run_admin("acknowledge_integrity", {"tool": str(data.get("tool") or ""), "text": str(data.get("text") or ""), "remove": remove}, done)

    def act_acknowledge_port(self, data):
        """« Ignorer » un port joignable voulu (ou le réafficher avec remove) : la checklist ne le compte plus."""
        remove = bool(data.get("remove"))
        params = {"remove": remove}
        if data.get("all_reachable"):
            params["all_reachable"] = True
        else:
            keys = data.get("keys") if isinstance(data.get("keys"), list) else [data.get("key")]
            params["keys"] = [str(k) for k in keys if k][:200]

        def done(resp):
            if resp.get("ok"):
                self.send_to_js("operationResult", {"status": "success", "op": "security",
                                                    "message": self.T("msg.ports_unacknowledged" if remove else "msg.ports_acknowledged", n=resp.get("count") or 0)})
                if isinstance(resp.get("checklist"), dict):
                    self.send_to_js("securityData", {"type": "checklist", "data": resp["checklist"], "available": True})
                else:
                    self.act_get_security_data({"type": "checklist"})
            else:
                self.send_to_js("operationResult", {"status": "error", "op": "security", "message": self.daemon_error(resp)})
            return False
        self.run_admin("acknowledge_port", params, done)

    def act_acknowledge_persistence(self, data):
        remove = bool(data.get("remove"))

        def done(resp):
            if resp.get("ok"):
                self.send_to_js("operationResult", {"status": "success",
                                                    "message": self.T("msg.program_untrusted" if remove else "msg.persistence_acknowledged")})
                self.act_get_security_data({"type": "persistence"})
                self.act_get_alerts({})
                self.act_get_trusted({})
            else:
                self.send_to_js("operationResult", {"status": "error", "message": self.daemon_error(resp)})
            return False
        self.run_admin("acknowledge_persistence", {"key": data.get("key") or "", "remove": remove}, done)

    # ── Bonnes pratiques : leçons lues ──────────────────────────────────
    def act_lesson_read(self, data):
        lid = str(data.get("id") or "")
        read = [x for x in (load_state().get("read_lessons") or []) if x != lid]
        if lid:
            read.append(lid)
        save_state({"read_lessons": read})
        self.send_status()

    def act_lesson_unread(self, data):
        lid = str(data.get("id") or "")
        save_state({"read_lessons": [x for x in (load_state().get("read_lessons") or []) if x != lid]})
        self.send_status()

    # ── Sauvegardes (disponibilité) ────────────────────────────────────
    def backup_summary(self):
        try:
            return backup.summary(backup.load_state())
        except Exception:  # noqa: BLE001
            return {"state": "none", "last": None, "destinations": 0}

    def backup_check_enabled(self):
        ds = self.last_daemon_status if isinstance(self.last_daemon_status, dict) else {}
        settings = (ds or {}).get("settings") or {}
        return bool(settings.get("backup_check", True))

    def _backup_payload(self, drives=None):
        st = backup.load_state()
        drives = backup.detect_drives() if drives is None else drives
        ds = self.last_daemon_status if isinstance(self.last_daemon_status, dict) else {}
        dests = []
        for d in st["destinations"]:
            avail, target = backup.destination_available(d, drives)
            dests.append(dict(d, available=avail, target=target))
        return {"timeshift": (ds or {}).get("timeshift"), "user": backup.summary(st), "drives": drives,
                "destinations": dests, "sources": st["sources"], "excludes": st["excludes"], "retention": st["retention"],
                "schedule": st["schedule"], "history": st["history"][:20], "rclone": backup.rclone_path() is not None,
                "remotes": backup.rclone_remotes() if backup.rclone_path() else [], "running": self.backup_progress,
                "hostuser": backup._hostuser(), "timeshift_installed": shutil.which("timeshift") is not None}

    def act_backup_status(self, data):
        if data.get("refresh"):
            # Relevé complet (timeshift --list peut durer plus d'une minute) : hors du fil principal, délai large
            def worker():
                resp = daemon_request("backup_status", timeout=180, refresh=True)
                if resp.get("ok") and isinstance(self.last_daemon_status, dict):
                    self.last_daemon_status["timeshift"] = resp.get("timeshift")
                GLib.idle_add(lambda: self.send_to_js("backupStatus", self._backup_payload()) or False)
            threading.Thread(target=worker, daemon=True).start()
            return
        self.send_to_js("backupStatus", self._backup_payload())

    def _start_backup(self, dest, auto=False):
        if self.backup_runner and self.backup_runner.is_alive():
            self.send_to_js("operationResult", {"status": "error", "message": self.T("msg.backup_running")})
            return False
        st = backup.load_state()
        dest_id = dest.get("id")

        def progress(pct, text):
            GLib.idle_add(self._backup_progress_cb, dest_id, pct, text)

        def done(result):
            GLib.idle_add(self._backup_done, result)
        self.backup_runner = backup.BackupRunner(dest, st, on_progress=progress, on_done=done, auto=auto)
        self.backup_progress = {"dest_id": dest_id, "dest_label": dest.get("label", ""), "pct": 0, "text": "", "auto": auto}
        self.backup_runner.start()
        self.send_to_js("backupProgress", self.backup_progress)
        if auto and self.popups_enabled("info"):
            self.popup("info", self.T("popup.backup.start_title"), self.T("popup.backup.auto", dest=dest.get("label", "")), timeout=8)
        else:
            self.send_to_js("operationResult", {"status": "info", "message": self.T("msg.backup_started", dest=dest.get("label", ""))})
        self.send_status()
        return True

    def _backup_progress_cb(self, dest_id, pct, text):
        if self.backup_progress and self.backup_progress.get("dest_id") == dest_id:
            self.backup_progress.update({"pct": round(pct, 1), "text": text})
            self.send_to_js("backupProgress", self.backup_progress)
        return False

    def _backup_done(self, result):
        st = backup.load_state()
        backup.record_result(st, result)
        backup.save_state(st)
        self.backup_progress = None
        self.backup_runner = None
        self.send_to_js("backupDone", result)
        self.send_to_js("backupStatus", self._backup_payload())
        self.send_status()
        self.tray.update_status()
        T = self.T
        if result.get("ok"):
            msg = T("msg.backup_done", dest=result.get("dest_label", ""), files=result.get("files", 0),
                    size=backup.format_size(result.get("bytes", 0)))
            self.send_to_js("operationResult", {"status": "success", "message": msg})
            if self.popups_enabled("info"):
                self.popup("success", T("popup.backup.done_title"), msg, timeout=12, on_activate=lambda: self.show_tab("backup"))
        elif result.get("cancelled"):
            self.send_to_js("operationResult", {"status": "info", "message": T("msg.backup_cancelled")})
        else:
            err = result.get("error", "")
            key = {"destination_unavailable": "msg.backup_dest_unavailable", "no_sources": "msg.no_sources"}.get(err)
            detail = T(key) if key else f"{err} {result.get('detail', '')}".strip()
            msg = T("msg.backup_failed", error=detail[:200])
            self.send_to_js("operationResult", {"status": "error", "message": msg})
            self.popup("warning", T("popup.backup.failed_title"), msg, timeout=20, on_activate=lambda: self.show_tab("backup"))
        return False

    def act_backup_run(self, data):
        st = backup.load_state()
        dest = next((d for d in st["destinations"] if d.get("id") == data.get("dest_id")), None)
        if not dest:
            self.send_to_js("operationResult", {"status": "error", "message": self.T("msg.backup_no_dest")})
            return
        self._start_backup(dest, auto=False)

    def act_backup_quick(self, data):
        """Vue simple : sauvegarder sur un support détecté (ajouté comme destination s'il est nouveau)."""
        drive = data.get("drive") or {}
        st = backup.load_state()
        dest = next((d for d in st["destinations"] if d.get("type") == "local" and drive.get("uuid") and d.get("uuid") == drive.get("uuid")), None)
        if not dest:
            dest = backup.add_destination(st, {"type": "local", "label": drive.get("label") or drive.get("mountpoint", ""),
                                               "mountpoint": drive.get("mountpoint", ""), "uuid": drive.get("uuid", ""),
                                               "fstype": drive.get("fstype", ""), "devnode": drive.get("devnode", "")})
            backup.save_state(st)
        self._start_backup(dest, auto=False)

    def act_backup_cancel(self, _data):
        if self.backup_runner and self.backup_runner.is_alive():
            self.backup_runner.cancel()

    def act_backup_add_local(self, data):
        st = backup.load_state()
        if data.get("path"):
            p = os.path.expanduser(data["path"].strip())
            if not (os.path.isdir(p) and os.access(p, os.W_OK)):
                self.send_to_js("operationResult", {"status": "error", "message": self.T("msg.backup_dest_unavailable")})
                return
            dest = backup.add_destination(st, {"type": "path", "label": data.get("label") or os.path.basename(p.rstrip("/")) or p,
                                               "mountpoint": p})
        else:
            drive = data.get("drive") or {}
            dest = backup.add_destination(st, {"type": "local", "label": drive.get("label") or drive.get("mountpoint", ""),
                                               "mountpoint": drive.get("mountpoint", ""), "uuid": drive.get("uuid", ""),
                                               "fstype": drive.get("fstype", ""), "devnode": drive.get("devnode", "")})
        backup.save_state(st)
        self.send_to_js("operationResult", {"status": "success", "message": self.T("msg.backup_dest_added", label=dest["label"])})
        self.send_to_js("backupStatus", self._backup_payload())
        self.send_status()

    def act_backup_add_cloud(self, data):
        kind, name, params, remote = data.get("kind") or "", data.get("name") or "", data.get("params") or {}, (data.get("remote") or "").strip()

        def worker():
            if kind == "existing":
                ok, detail = (True, remote) if remote else (False, "no_remote")
            else:
                ok, detail = backup.cloud_configure(kind, name, params)
            target = detail if ok else ""
            if ok:
                ok, detail = backup.cloud_test(target)
            GLib.idle_add(finish, ok, detail, target)

        def finish(ok, detail, target):
            if not ok:
                key = "backup.cloud.rclone_missing" if detail == "rclone_missing" else None
                self.send_to_js("operationResult", {"status": "error", "message": self.T(key) if key else self.T("msg.backup_test_failed", detail=detail[:200])})
                return False
            st = backup.load_state()
            label = data.get("label") or (target.split(":")[0] + " (" + self.T(f"backup.cloud.{kind}" if kind != "existing" else "backup.cloud.existing") + ")")
            dest = backup.add_destination(st, {"type": "cloud", "label": label[:60], "remote": target, "provider": kind})
            backup.save_state(st)
            self.send_to_js("operationResult", {"status": "success", "message": self.T("msg.backup_dest_added", label=dest["label"])})
            self.send_to_js("backupStatus", self._backup_payload())
            self.send_status()
            return False
        self.send_to_js("operationResult", {"status": "info", "message": self.T("msg.backup_testing")})
        threading.Thread(target=worker, daemon=True).start()

    def act_backup_test(self, data):
        st = backup.load_state()
        dest = next((d for d in st["destinations"] if d.get("id") == data.get("dest_id")), None)
        if not dest:
            return

        def worker():
            if dest.get("type") == "cloud":
                ok, detail = backup.cloud_test(dest.get("remote", ""))
            else:
                ok, detail = backup.destination_available(dest)
                detail = "ok" if ok else "unavailable"
            GLib.idle_add(lambda: self.send_to_js("operationResult", {"status": "success" if ok else "error",
                          "message": self.T("msg.backup_test_ok") if ok else self.T("msg.backup_test_failed", detail=str(detail)[:200])}) or False)
        threading.Thread(target=worker, daemon=True).start()

    def act_backup_remove(self, data):
        st = backup.load_state()
        backup.remove_destination(st, data.get("dest_id"))
        backup.save_state(st)
        self.send_to_js("operationResult", {"status": "success", "message": self.T("msg.backup_dest_removed")})
        self.send_to_js("backupStatus", self._backup_payload())
        self.send_status()

    def act_backup_set(self, data):
        st = backup.load_state()
        if isinstance(data.get("sources"), list):
            st["sources"] = [os.path.expanduser(x.strip()) for x in data["sources"] if x and x.strip()][:50]
        if isinstance(data.get("excludes"), list):
            st["excludes"] = [x.strip() for x in data["excludes"] if x and x.strip()][:100]
        try:
            st["retention"] = max(1, min(100, int(data.get("retention", st["retention"]))))
        except (TypeError, ValueError):
            pass
        if data.get("schedule") in backup.SCHEDULE_DAYS:
            st["schedule"] = data["schedule"]
        backup.save_state(st)
        self.send_to_js("operationResult", {"status": "success", "message": self.T("msg.backup_saved")})
        self.send_to_js("backupStatus", self._backup_payload())
        self.send_status()

    def act_backup_open_folder(self, data):
        st = backup.load_state()
        dest = next((d for d in st["destinations"] if d.get("id") == data.get("dest_id")), None)
        if dest and dest.get("type") != "cloud":
            avail, target = backup.destination_available(dest)
            if avail:
                subprocess.Popen(["xdg-open", os.path.join(target, backup.BACKUP_DIRNAME, backup._hostuser())])

    def act_timeshift_enable(self, _data):
        """Activation (ou planification automatique) : hors du fil principal, délai large — la réponse est immédiate
        depuis 1.18.7 mais le service peut être occupé (mesure du système, instantané en cours)."""
        self.send_to_js("operationResult", {"status": "info", "message": self.T("msg.timeshift_enabling")})

        def worker():
            resp = daemon_request("timeshift_enable", timeout=120)
            GLib.idle_add(self._timeshift_enable_reply, resp)
        threading.Thread(target=worker, daemon=True).start()

    def _timeshift_enable_reply(self, resp):
        if resp.get("ok") and resp.get("pending"):
            self.send_to_js("operationResult", {"status": "info", "message": self.T("msg.timeshift_checking")})
            return False
        self.timeshift_enable_result(resp)
        return False

    def timeshift_enable_result(self, resp):
        """Résultat d'« Activer Timeshift » (immédiat, ou différé après la mesure du système par le service)."""
        T = self.T
        if resp.get("ok"):
            self.send_to_js("operationResult", {"status": "success", "message": T("msg.timeshift_enabled")})
            if self.popups_enabled("info"):
                self.popup("success", T("backup.timeshift.title"), T("msg.timeshift_enabled"), timeout=15)
        elif resp.get("error") == "timeshift_no_space":
            def gb(n):
                return round((n or 0) / 1e9)
            body = T("msg.timeshift_no_space", size=gb(resp.get("size")), needed=gb(resp.get("needed")), free=gb(resp.get("free")))
            self.send_to_js("operationResult", {"status": "error", "message": body})
            self.popup("warning", T("backup.timeshift.title"), body, timeout=40,
                       buttons=[(T("backup.open_timeshift"), "primary", lambda: self.act_backup_open_timeshift({}))],
                       on_activate=lambda: self.show_tab("backup"))
        else:
            key = "msg.timeshift_missing" if resp.get("error") == "timeshift_missing" else None
            self.send_to_js("operationResult", {"status": "error", "message": T(key) if key else self.daemon_error(resp)})
        self.act_backup_status({"refresh": True})
        GLib.timeout_add_seconds(90, lambda: self.act_backup_status({"refresh": True}) or False)

    IGNORABLE_CHECKS = {"timeshift_check": ("msg.timeshift_ignored", "msg.timeshift_unignored"),
                        "backup_check": ("msg.backup_ignored", "msg.backup_unignored")}

    def act_ignore_check(self, data):
        """« Ignorer » / « Réafficher » un contrôle de disponibilité (état de Timeshift, sauvegarde des fichiers) :
        réglage du service à False/True, sans mot de passe sauf en mode famille."""
        setting = str(data.get("setting") or "")
        if setting not in self.IGNORABLE_CHECKS:
            return
        ignore = bool(data.get("ignore", True))
        keys = self.IGNORABLE_CHECKS[setting]

        def done(resp):
            if resp.get("ok"):
                self.send_to_js("operationResult", {"status": "success", "message": self.T(keys[0] if ignore else keys[1])})
                self.refresh_daemon_status_now()
            else:
                self.send_to_js("operationResult", {"status": "error", "message": self.daemon_error(resp)})
            return False
        self.run_admin("ignore_check", {"setting": setting, "ignore": ignore}, done)

    def act_timeshift_ignore(self, data):
        self.act_ignore_check({"setting": "timeshift_check", "ignore": data.get("ignore", True)})

    def refresh_daemon_status_now(self):
        """Relit le statut du service (réglages, état global) et rafraîchit la vue et l'onglet Sauvegardes."""
        def worker():
            resp = DaemonClient.request("status")
            if resp.get("ok"):
                self.last_daemon_status = resp
            GLib.idle_add(self.send_status)
            GLib.idle_add(self.act_backup_status, {})
        threading.Thread(target=worker, daemon=True).start()

    def act_timeshift_disable(self, _data):
        def done(resp):
            if resp.get("ok"):
                self.send_to_js("operationResult", {"status": "success", "message": self.T("msg.timeshift_disabled")})
            else:
                self.send_to_js("operationResult", {"status": "error", "message": self.daemon_error(resp)})
            self.act_backup_status({"refresh": True})
            return False
        self.run_admin("timeshift_disable", {}, done)

    def act_backup_open_timeshift(self, _data):
        for cmd in (["timeshift-launcher"], ["pkexec", "timeshift-gtk"]):
            if shutil.which(cmd[0]) and (cmd[0] != "pkexec" or shutil.which("timeshift-gtk")):
                subprocess.Popen(cmd)
                return
        self.send_to_js("operationResult", {"status": "error", "message": self.T("msg.timeshift_missing")})

    def act_install_package(self, data):
        name = data.get("name")

        def done(resp):
            if resp.get("ok"):
                self.send_to_js("operationResult", {"status": "info", "message": self.T("msg.package_installing", name=name)})
            else:
                self.send_to_js("operationResult", {"status": "error", "message": self.daemon_error(resp)})
            return False
        self.run_admin("install_package", {"name": name}, done)

    def _backup_first_check(self):
        self.backup_scheduler()
        GLib.timeout_add_seconds(1800, self.backup_scheduler)
        return False

    def backup_scheduler(self):
        """Sauvegarde automatique (quotidienne/hebdomadaire/mensuelle) dès qu'une destination est disponible."""
        try:
            if self.backup_runner and self.backup_runner.is_alive():
                return True
            st = backup.load_state()
            if not backup.summary(st).get("due"):
                return True
            drives = backup.detect_drives()
            for dest in st["destinations"]:
                avail, _ = backup.destination_available(dest, drives)
                if avail:
                    self._start_backup(dest, auto=True)
                    break
        except Exception as e:  # noqa: BLE001
            print(f"backup scheduler: {e}", file=sys.stderr)
        return True

    # ── Bilan hebdomadaire ──────────────────────────────────────────────
    def _weekly_first_check(self):
        self.maybe_weekly_report()
        GLib.timeout_add_seconds(12 * 3600, self.maybe_weekly_report)
        return False

    def maybe_weekly_report(self, force=False):
        state = load_state()
        last = state.get("weekly_report_date") or ""
        try:
            due = not last or (datetime.now() - datetime.fromisoformat(last)).days >= 7
        except ValueError:
            due = True
        if not force and (not due or not self.popups_enabled("info")):
            return True
        threading.Thread(target=self._weekly_worker, args=(force,), daemon=True).start()
        return True

    def _weekly_worker(self, force):
        ds = self.last_daemon_status if isinstance(self.last_daemon_status, dict) else {}
        history = list(load_state().get("history", [])) + list(((ds or {}).get("state") or {}).get("history", []))
        alerts = DaemonClient.request("alerts").get("alerts") or []
        checklist = DaemonClient.request("checklist").get("checklist") or {}
        state = load_state()
        report = extras.weekly_report(history, alerts, checklist, self.backup_summary(), state.get("read_lessons"), state.get("weekly_prev_score"))
        GLib.idle_add(self._show_weekly_report, report)

    def _show_weekly_report(self, r):
        T = self.T
        lines = [T("report.scans", n=r["scans"], files=f"{r['files']:,}".replace(",", " "), threats=r["threats"]),
                 T("report.alerts", n=r["alerts"], danger=r["danger_alerts"])]
        if r.get("score") is not None:
            delta = ""
            if r.get("score_delta") is not None and r["score_delta"] != 0:
                delta = T("report.delta_up", d=r["score_delta"]) if r["score_delta"] > 0 else T("report.delta_down", d=r["score_delta"])
            lines.append(T("report.score", score=r["score"], grade=r.get("grade") or "", delta=delta).strip())
        lines.append(T("report.backup_ok", rel=self.relative(r["backup_last"])) if r.get("backup_last") else T("report.backup_none"))
        lines.append(T("report.lessons", n=r["lessons_read"]))
        kind = "danger" if r["threats"] or r["danger_alerts"] else ("warning" if r.get("backup_state") in ("none", "old", "missing") else "success")
        self.popup(kind, T("popup.report.title"), "\n".join(lines), timeout=45,
                   buttons=[(T("popup.btn.details"), "primary", lambda: self.show_tab("security"))],
                   on_activate=lambda: self.show_tab("security"))
        save_state({"weekly_report_date": datetime.now().isoformat(timespec="seconds"), "weekly_prev_score": r.get("score")})
        return False

    def relative(self, iso):
        """« il y a N j / N h » à partir d'une date ISO."""
        try:
            delta = datetime.now() - datetime.fromisoformat(str(iso)[:19])
        except ValueError:
            return str(iso)
        if delta.days >= 1:
            return self.T("rel.ago", t=self.T("rel.days", n=delta.days))
        return self.T("rel.ago", t=self.T("rel.hours", n=max(1, delta.seconds // 3600)))

    def act_show_report(self, _data):
        self.maybe_weekly_report(force=True)

    # ── Fuites de données (HIBP) ────────────────────────────────────────
    def act_hibp_password(self, data):
        pw = data.get("password") or ""

        def worker():
            count, err = extras.check_password(pw)
            GLib.idle_add(lambda: self.send_to_js("hibpResult", {"type": "password", "count": count, "error": err}) or False)
        threading.Thread(target=worker, daemon=True).start()

    def act_hibp_save(self, data):
        emails = [e.strip().lower() for e in (data.get("emails") or []) if e and e.strip()][:10]
        upd = {"hibp_emails": emails}
        if "api_key" in data:
            upd["hibp_api_key"] = "".join(ch for ch in str(data.get("api_key") or "") if ch.isalnum())[:64]
        save_state(upd)
        self.send_to_js("operationResult", {"status": "success", "message": self.T("msg.hibp_saved")})
        self.act_get_settings({})

    def act_hibp_check(self, data):
        state = load_state()
        emails = state.get("hibp_emails") or []
        key = state.get("hibp_api_key") or ""
        if not emails:
            self.send_to_js("hibpResult", {"type": "emails", "results": {}, "error": "no_emails"})
            return

        def worker():
            results, err_all = {}, ""
            for email in emails:
                breaches, err = extras.check_email(email, api_key=key)   # sans clé : base gratuite XposedOrNot (Dukiwi n'a pas de clé HIBP)
                results[email] = {"breaches": breaches, "error": err, "checked": now_iso()}
                if err and err != "":
                    err_all = err
            GLib.idle_add(self._hibp_done, results, err_all, bool(data.get("silent")))
        threading.Thread(target=worker, daemon=True).start()

    def _hibp_done(self, results, err_all, silent):
        state = load_state()
        previous = state.get("hibp_results") or {}
        new_breaches = []
        for email, r in results.items():
            if r.get("error"):
                continue
            known = {b["name"] for b in (previous.get(email) or {}).get("breaches") or []}
            for b in r["breaches"]:
                if b["name"] not in known and known is not None and previous.get(email):
                    new_breaches.append((email, b))
        merged = dict(previous)
        for email, r in results.items():
            if not r.get("error"):
                merged[email] = r
        save_state({"hibp_results": merged, "hibp_last": now_iso()})
        self.send_to_js("hibpResult", {"type": "emails", "results": results, "error": err_all})
        for email, b in new_breaches[:3]:
            self.popup("warning", self.T("popup.leak.title"), self.T("popup.leak.body", email=email, name=b.get("title") or b.get("name"), date=b.get("date", "")),
                       timeout=40, buttons=[(self.T("popup.btn.details"), "primary", lambda: self.show_tab("security"))])
        return False

    # ── Applications hors dépôts ────────────────────────────────────────
    def act_get_apps(self, _data):
        def worker():
            inv = extras.inventory_apps()
            GLib.idle_add(lambda: self.send_to_js("appsData", {"inventory": inv, "acknowledged": load_state().get("apps_ack") or []}) or False)
        threading.Thread(target=worker, daemon=True).start()

    def act_apps_ack(self, data):
        key = str(data.get("key") or "")
        ack = [k for k in (load_state().get("apps_ack") or []) if k != key]
        if key and not data.get("remove"):
            ack.append(key)
        save_state({"apps_ack": ack[:200]})
        self.send_to_js("operationResult", {"status": "success", "message": self.T("msg.persistence_acknowledged" if not data.get("remove") else "msg.program_untrusted")})
        self.act_get_apps({})

    # ── Coffre chiffré (gocryptfs) ──────────────────────────────────────
    def _password_dialog(self, title, confirm=False):
        dlg = Gtk.Dialog(title=title, transient_for=self.window, modal=True)
        dlg.add_button(Gtk.STOCK_CANCEL, Gtk.ResponseType.CANCEL)
        dlg.add_button(Gtk.STOCK_OK, Gtk.ResponseType.OK)
        dlg.set_default_response(Gtk.ResponseType.OK)
        box = dlg.get_content_area()
        box.set_spacing(8)
        box.set_margin_top(12); box.set_margin_bottom(12); box.set_margin_start(12); box.set_margin_end(12)
        lbl = Gtk.Label(label=self.T("vault.dialog.hint") if confirm else self.T("vault.dialog.password"))
        lbl.set_line_wrap(True); lbl.set_max_width_chars(48); lbl.set_xalign(0)
        box.pack_start(lbl, False, False, 0)
        e1 = Gtk.Entry(); e1.set_visibility(False); e1.set_placeholder_text(self.T("vault.dialog.password")); e1.set_activates_default(True)
        box.pack_start(e1, False, False, 0)
        e2 = None
        if confirm:
            e2 = Gtk.Entry(); e2.set_visibility(False); e2.set_placeholder_text(self.T("vault.dialog.confirm")); e2.set_activates_default(True)
            box.pack_start(e2, False, False, 0)
        dlg.show_all()
        resp = dlg.run()
        pw, pw2 = e1.get_text(), (e2.get_text() if e2 else None)
        dlg.destroy()
        if resp != Gtk.ResponseType.OK:
            return None
        if confirm and pw != pw2:
            self.send_to_js("operationResult", {"status": "error", "message": self.T("msg.vault_mismatch")})
            return None
        return pw

    def act_vault_status(self, _data):
        self.send_to_js("vaultStatus", extras.vault_status())

    def _vault_run(self, fn, ok_key):
        def worker():
            ok, detail = fn()
            GLib.idle_add(self._vault_done, ok, detail, ok_key)
        threading.Thread(target=worker, daemon=True).start()

    def _vault_done(self, ok, detail, ok_key):
        if ok:
            self.send_to_js("operationResult", {"status": "success", "message": self.T(ok_key)})
            st = extras.vault_status()
            if st.get("mounted") and ok_key in ("msg.vault_created", "msg.vault_opened"):
                subprocess.Popen(["xdg-open", st["mountpoint"]])
        else:
            key = {"bad_password": "msg.vault_bad_password", "password_short": "msg.vault_short", "gocryptfs_missing": "vault.missing"}.get(detail)
            self.send_to_js("operationResult", {"status": "error", "message": self.T(key) if key else self.T("msg.vault_error", detail=detail)})
        self.send_to_js("vaultStatus", extras.vault_status())
        self.send_status()
        return False

    def act_vault_create(self, _data):
        if not extras.vault_status()["available"]:
            self.send_to_js("operationResult", {"status": "error", "message": self.T("vault.missing")})
            return
        pw = self._password_dialog(self.T("vault.dialog.create_title"), confirm=True)
        if pw is None:
            return
        if len(pw) < 8:
            self.send_to_js("operationResult", {"status": "error", "message": self.T("msg.vault_short")})
            return
        st = backup.load_state()
        if extras.VAULT_CIPHER not in st["sources"]:
            st["sources"].append(extras.VAULT_CIPHER)       # le coffre chiffré fait partie des sauvegardes
            backup.save_state(st)
        self._vault_run(lambda: extras.vault_create(pw), "msg.vault_created")

    def act_vault_open(self, _data):
        st = extras.vault_status()
        if not st["exists"]:
            return self.act_vault_create({})
        if st["mounted"]:
            subprocess.Popen(["xdg-open", st["mountpoint"]])
            return
        pw = self._password_dialog(self.T("vault.dialog.open_title"))
        if pw is None:
            return
        self._vault_run(lambda: extras.vault_open(pw), "msg.vault_opened")

    def act_vault_close(self, _data):
        self._vault_run(extras.vault_close, "msg.vault_closed")

    def act_vault_toggle(self, _data):
        if extras.vault_status().get("mounted"):
            self.act_vault_close({})
        else:
            self.act_vault_open({})

    # ── Restauration guidée ─────────────────────────────────────────────
    def act_backup_snapshots(self, data):
        st = backup.load_state()
        dest = next((d for d in st["destinations"] if d.get("id") == data.get("dest_id")), None)
        if not dest:
            self.send_to_js("backupSnapshots", {"dest_id": data.get("dest_id"), "snapshots": [], "error": "no_dest"})
            return

        def worker():
            snaps, err = backup.list_snapshots(dest)
            GLib.idle_add(lambda: self.send_to_js("backupSnapshots", {"dest_id": dest["id"], "snapshots": snaps, "error": err}) or False)
        threading.Thread(target=worker, daemon=True).start()

    def act_backup_restore(self, data):
        if self.restore_runner and self.restore_runner.is_alive():
            self.send_to_js("operationResult", {"status": "error", "message": self.T("msg.backup_running")})
            return
        st = backup.load_state()
        dest = next((d for d in st["destinations"] if d.get("id") == data.get("dest_id")), None)
        if not dest:
            return

        def progress(pct, text):
            GLib.idle_add(lambda: self.send_to_js("restoreProgress", {"pct": round(pct, 1), "text": text}) or False)

        def done(result):
            GLib.idle_add(self._restore_done, result)
        self.restore_runner = backup.RestoreRunner(dest, data.get("snapshot") or "latest", data.get("folder") or "",
                                                   on_progress=progress, on_done=done)
        self.restore_runner.start()
        self.send_to_js("restoreProgress", {"pct": 0, "text": ""})

    def _restore_done(self, result):
        self.restore_runner = None
        self.send_to_js("restoreDone", result)
        if result.get("ok"):
            msg = self.T("backup.restore.done", path=result.get("path", ""), files=result.get("files", 0), size=backup.format_size(result.get("bytes", 0)))
            self.send_to_js("operationResult", {"status": "success", "message": msg})
            self.popup("success", self.T("backup.restore.card"), msg, timeout=20,
                       buttons=[(self.T("backup.restore.open"), "primary", lambda p=result.get("path", ""): subprocess.Popen(["xdg-open", p]))])
        elif not result.get("cancelled"):
            self.send_to_js("operationResult", {"status": "error", "message": self.T("msg.restore_failed", error=result.get("error", ""))})
        return False

    def act_backup_restore_cancel(self, _data):
        if self.restore_runner and self.restore_runner.is_alive():
            self.restore_runner.cancel()

    def act_backup_open_restore(self, _data):
        os.makedirs(backup.RESTORE_DIR, exist_ok=True)
        subprocess.Popen(["xdg-open", backup.RESTORE_DIR])

    # ── Mode voyage ─────────────────────────────────────────────────────
    def act_travel_mode(self, data):
        on = bool(data.get("on"))
        state = load_state()
        ds = self.last_daemon_status if isinstance(self.last_daemon_status, dict) else {}
        current = (((ds or {}).get("security") or {}).get("ufw") or {}).get("profile") or ""
        T = self.T
        if on:
            save_state({"travel_mode": True, "travel_prev_profile": current})
            resp = DaemonClient.request("firewall_profile", profile="public")
            if not resp.get("ok"):
                self.send_to_js("operationResult", {"status": "error", "message": self.daemon_error(resp)})
            # sauvegarde si un support est disponible
            st = backup.load_state()
            started = False
            drives = backup.detect_drives()
            for dest in st["destinations"]:
                avail, _ = backup.destination_available(dest, drives)
                if avail and not (self.backup_runner and self.backup_runner.is_alive()):
                    started = self._start_backup(dest, auto=True)
                    break
            # mises à jour
            sysst = (ds or {}).get("system_status") or {}
            if sysst.get("upgradable"):
                DaemonClient.request("system_upgrade")
            body = T("travel.on_body") + ("" if started else "\n" + T("travel.no_backup_dest"))
            self.popup("info", T("travel.on_title"), body, timeout=40,
                       buttons=[(T("popup.btn.read_more"), None, lambda: self.open_lesson("wifi"))])
        else:
            prev = state.get("travel_prev_profile") or "home"
            save_state({"travel_mode": False})

            def done(resp):
                if resp.get("ok"):
                    self.popup("success", T("travel.off_title"), T("travel.off_body", profile=T(f"firewall.profile.{prev}")), timeout=15)
                else:
                    self.send_to_js("operationResult", {"status": "error", "message": self.daemon_error(resp)})
                self.act_get_security({"refresh": True})
                self.send_status()
                return False
            if prev in ("home", "enterprise"):
                self.run_admin("firewall_profile", {"profile": prev}, done)
            else:
                done({"ok": True})
        self.act_get_security({"refresh": True})
        self.send_status()

    def act_show_tip(self, _data):
        self.show_daily_tip(force=True)

    def act_install_phased(self, _data):
        def done(resp):
            if resp.get("ok"):
                self.send_to_js("operationResult", {"status": "success", "op": "security",
                                                    "message": self.T("msg.phased_installing", n=len(resp.get("packages", [])))})
            else:
                self.send_to_js("operationResult", {"status": "error", "op": "security", "message": self.daemon_error(resp)})
            return False
        self.run_admin("install_phased", {}, done)

    def act_set_view_mode(self, data):
        mode = data.get("mode")
        if mode in ("simple", "advanced"):
            save_state({"view_mode": mode})
            self.send_status()

    def act_get_settings(self, _data):
        resp = DaemonClient.request("get_settings")
        self.send_to_js("settingsData", {"system": resp.get("settings") if resp.get("ok") else dict(DEFAULT_SETTINGS),
                                         "user": user_settings(), "available": bool(resp.get("ok")),
                                         "stats": resp.get("stats") if resp.get("ok") else None,
                                         "locked": resp.get("locked") or [], "policy": resp.get("policy"),
                                         "allowlist": resp.get("allowlist"), "telemetry_sent": resp.get("telemetry_sent"),
                                         "hibp": {"emails": load_state().get("hibp_emails") or [], "has_key": bool(load_state().get("hibp_api_key")),
                                                  "last": load_state().get("hibp_last"), "results": load_state().get("hibp_results") or {}}})

    def act_set_settings(self, data):
        user = data.get("user") or {}
        if "popups" in user and isinstance(user["popups"], dict):
            popups = user_settings()["popups"]
            popups.update({k: bool(v) for k, v in user["popups"].items() if k in popups})
            save_state({"popups": popups})
        if user.get("view_mode") in ("simple", "advanced"):
            save_state({"view_mode": user["view_mode"]})
        if user.get("language") in LANGUAGES and user["language"] != self.lang:
            self.act_set_language({"lang": user["language"]})
        system = data.get("system") or {}
        if not system:
            self.act_get_settings({})
            self.send_to_js("operationResult", {"status": "success", "op": "settings", "message": self.T("msg.settings_saved")})
            self.send_status()
            return

        def done(resp):
            errors = []
            if not resp.get("ok"):
                errors.append(self.daemon_error(resp))
            else:
                errors += resp.get("errors", [])
            self.act_get_settings({})
            if errors:
                self.send_to_js("operationResult", {"status": "error", "op": "settings",
                                                    "message": self.T("msg.settings_partial", errors=", ".join(errors))})
            else:
                self.send_to_js("operationResult", {"status": "success", "op": "settings", "message": self.T("msg.settings_saved")})
            self.send_status()
            return False
        self.run_admin("set_settings", {"settings": system}, done)

    def act_get_security(self, data):
        resp = DaemonClient.request("security_status", refresh=bool(data.get("refresh")))
        if resp.get("ok") and isinstance(self.last_daemon_status, dict):
            self.last_daemon_status["security"] = resp.get("security")
        self.send_to_js("securityStatus", {"security": resp.get("security") if resp.get("ok") else None,
                                           "available": bool(resp.get("ok"))})

    def act_security_action(self, data):
        cmd = data.get("cmd")
        if cmd not in SECURITY_COMMANDS:
            return
        params = {k: v for k, v in data.items() if k not in ("action", "cmd")}
        self.run_admin(cmd, params, lambda resp: self._security_result(cmd, params, resp))

    def _security_result(self, cmd, params, resp):
        if resp.get("ok"):
            if cmd == "firewall_profile":
                msg = self.T("msg.profile_applied", profile=self.T(f"firewall.profile.{params.get('profile', '')}"),
                             n=resp.get("rules", 0))
            else:
                key = {"firewall_set": "msg.firewall_enabled" if params.get("enabled") else "msg.firewall_disabled",
                       "ssh_set": "msg.ssh_enabled" if params.get("enabled") else "msg.ssh_disabled",
                       "forget_network": "msg.network_forgotten"}.get(cmd, "msg.security_applied")
                msg = self.T(key)
            self.send_to_js("operationResult", {"status": "success", "op": "security", "message": msg})
        else:
            self.send_to_js("operationResult", {"status": "error", "op": "security", "message": self.daemon_error(resp)})
        self.act_get_security({"refresh": True})
        self.send_status()
        return False

    def act_get_security_data(self, data):
        """Données du centre de sécurité : vulns, checklist, intégrité, persistance, connexions, mise à jour."""
        kind = data.get("type")
        cmd = {"vulns": "vulns", "checklist": "checklist", "integrity": "integrity", "persistence": "persistence",
               "connections": "connections", "app_update": "check_update"}.get(kind)
        if not cmd:
            return
        params = {}
        if data.get("refresh"):
            params["refresh"] = True
        if kind == "integrity" and data.get("run"):
            params["run"] = True
        if kind == "app_update" and not data.get("refresh"):
            ds = self.last_daemon_status if isinstance(self.last_daemon_status, dict) else {}
            self.send_to_js("securityData", {"type": "app_update", "data": ds.get("app_update") or {}, "available": ds != {}})
            return

        def worker():
            resp = daemon_request(cmd, timeout=900, **params)
            payload = resp.get(kind) or resp.get("update") or {}
            GLib.idle_add(self.send_to_js, "securityData",
                          {"type": kind, "data": payload, "available": bool(resp.get("ok")),
                           "refreshing": bool(resp.get("refreshing") or resp.get("running"))})
            if kind == "app_update":
                GLib.idle_add(self.send_status)
        threading.Thread(target=worker, daemon=True).start()

    def act_install_update(self, _data):
        def done(resp):
            if resp.get("ok"):
                self.send_to_js("operationResult", {"status": "success", "op": "security", "message": self.T("msg.update_installing")})
            else:
                self.send_to_js("operationResult", {"status": "error", "op": "security", "message": self.daemon_error(resp)})
            return False
        self.run_admin("install_update", {}, done)

    def act_install_tools(self, _data):
        def done(resp):
            if resp.get("ok"):
                self.send_to_js("operationResult", {"status": "success", "op": "security", "message": self.T("msg.tools_installing")})
            else:
                self.send_to_js("operationResult", {"status": "error", "op": "security", "message": self.daemon_error(resp)})
            return False
        self.run_admin("install_tools", {}, done)

    def act_process_action(self, data):
        try:
            self.process_action(int(data.get("pid")), data.get("action"))
        except (TypeError, ValueError):
            pass

    def act_unlock(self, _data):
        def worker():
            try:
                r = subprocess.run(["pkexec", UNLOCK_HELPER], capture_output=True, text=True, timeout=300)
                ok = r.returncode == 0
            except Exception:  # noqa: BLE001
                ok = False
            GLib.idle_add(self.send_to_js, "operationResult",
                          {"status": "success" if ok else "error", "op": "security",
                           "message": self.T("msg.unlocked") if ok else self.T("msg.auth_cancelled")})
            GLib.idle_add(self.act_check_status, {})
        threading.Thread(target=worker, daemon=True).start()

    def act_lock(self, _data):
        DaemonClient.request("lock")
        self.act_check_status({})

    def act_system_upgrade(self, _data):
        """« Mettre à jour » : apt update + apt upgrade par le service (les paquets décalés/retenus restent en attente)."""
        def done(resp):
            if resp.get("ok"):
                self.send_to_js("operationResult", {"status": "info", "op": "system", "message": self.T("msg.system_upgrading")})
            else:
                self.send_to_js("operationResult", {"status": "error", "op": "system", "message": self.daemon_error(resp)})
            return False
        self.run_admin("system_upgrade", {}, done)

    # ── Mises à jour automatiques : réglages utilisateur (Spices Cinnamon, Flatpak) ──
    MINT_UPDATES_SCHEMA = "com.linuxmint.updates"
    _auto_updates_cache = (0.0, None)

    def auto_updates_user(self, force=False):
        """Réglages utilisateur du Gestionnaire de mises à jour de Mint : {spices: bool|None, flatpak: bool|None}
        (None = outil absent), lus par gsettings et gardés 60 s."""
        ts, cached = self._auto_updates_cache
        if cached is not None and not force and time.time() - ts < 60:
            return cached
        result = {"spices": None, "flatpak": None}
        if shutil.which("gsettings"):
            for key, gkey, tool in (("spices", "auto-update-cinnamon-spices", "cinnamon-spice-updater"),
                                    ("flatpak", "auto-update-flatpaks", "flatpak")):
                if not shutil.which(tool):
                    continue
                try:
                    r = subprocess.run(["gsettings", "get", self.MINT_UPDATES_SCHEMA, gkey], capture_output=True, text=True, timeout=10)
                except Exception:  # noqa: BLE001
                    continue
                if r.returncode == 0:
                    result[key] = r.stdout.strip() == "true"
        self._auto_updates_cache = (time.time(), result)
        return result

    def enable_user_auto_updates(self):
        """Active les mises à jour automatiques des Spices Cinnamon et des Flatpak quand ces outils existent ;
        retourne les clés activées."""
        done = []
        current = self.auto_updates_user(force=True)
        for key, gkey in (("spices", "auto-update-cinnamon-spices"), ("flatpak", "auto-update-flatpaks")):
            if current.get(key) is None:
                continue
            try:
                r = subprocess.run(["gsettings", "set", self.MINT_UPDATES_SCHEMA, gkey, "true"], capture_output=True, text=True, timeout=10)
            except Exception:  # noqa: BLE001
                continue
            if r.returncode == 0:
                done.append(key)
        self.auto_updates_user(force=True)
        return done

    def act_auto_updates_enable(self, _data):
        """« Activer » : automatisation des mises à jour système par le service, puis Spices et Flatpak pour l'utilisateur."""
        def worker():
            resp = daemon_request("auto_updates_enable", timeout=120)
            GLib.idle_add(done, resp)

        def done(resp):
            T = self.T
            if resp.get("ok"):
                extras = self.enable_user_auto_updates()
                parts = [T("msg.auto_updates.system")] + [T(f"check.auto_updates.{k}") for k in extras]
                msg = T("msg.auto_updates_enabled", list=", ".join(parts))
                self.send_to_js("operationResult", {"status": "success", "message": msg})
                if self.popups_enabled("info"):
                    self.popup("success", T("check.auto_updates.title"), msg, timeout=15)
            else:
                self.send_to_js("operationResult", {"status": "error", "message": self.daemon_error(resp)})
            self.send_status()
            return False

        threading.Thread(target=worker, daemon=True).start()

    # ── Durcissement (recommandations Lynis) ──
    def act_harden_apply(self, data):
        """Application par le service en tâche de fond ; le résultat arrive par l'événement hardening_done."""
        params = {"tests": [str(t) for t in (data.get("tests") or [])], "all": bool(data.get("all"))}
        self.run_admin("harden_apply", params, self._harden_started)

    def act_harden_revert(self, data):
        self.run_admin("harden_revert", {"tests": [str(t) for t in (data.get("tests") or [])]}, self._harden_started)

    def _harden_started(self, resp):
        if resp.get("ok"):
            self.send_to_js("operationResult", {"status": "info", "op": "security",
                                                "message": self.T("msg.harden_started", n=len(resp.get("tests") or []))})
            self.act_get_security_data({"type": "integrity"})
        else:
            self.send_to_js("operationResult", {"status": "error", "op": "security", "message": self.daemon_error(resp)})
        return False

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
        self.request_quit()

    def request_quit(self):
        """Fermer le bouclier est réservé à un administrateur : authentification pkexec, puis arrêt propre du service
        utilisateur (sinon il serait relancé) et information du service système (pas de relance dans cette session)."""
        if getattr(self, "_quitting", False):
            return
        self._quitting = True

        def worker():
            try:
                r = subprocess.run(["pkexec", UNLOCK_HELPER], capture_output=True, text=True, timeout=300)
                ok = r.returncode == 0
            except Exception:  # noqa: BLE001
                ok = False
            GLib.idle_add(self._quit_done, ok)
        threading.Thread(target=worker, daemon=True).start()

    def _quit_done(self, ok):
        self._quitting = False
        if not ok:
            self.popup("warning", self.T("tray.quit_denied_title"), self.T("tray.quit_denied_body"), timeout=12)
            return False
        try:
            DaemonClient.request("tray_quit")
        except Exception:  # noqa: BLE001
            pass
        try:
            if subprocess.run(["systemctl", "--user", "is-active", "--quiet", "clamav-antivirus-tray.service"], timeout=10).returncode == 0:
                subprocess.Popen(["systemctl", "--user", "stop", "--no-block", "clamav-antivirus-tray.service"])
        except Exception:  # noqa: BLE001
            pass
        GLib.timeout_add(300, Gtk.main_quit)
        return False

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
            if status == "success" and self.popups_enabled("update"):
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
            "security": (ds or {}).get("security"),
            "settings": (ds or {}).get("settings"),
            "user_settings": user_settings(),
            "view_mode": user_settings()["view_mode"],
            "disclaimer_accepted": int(state.get("disclaimer_accepted") or 0) >= DISCLAIMER_VERSION,
            "telemetry_answered": bool(state.get("telemetry_answered")),
            "upload_gb": (ds or {}).get("upload_gb", 0),
            "overall": (ds or {}).get("overall"),
            "read_lessons": load_state().get("read_lessons") or [],
            "backup": {"timeshift": (ds or {}).get("timeshift"), "user": self.backup_summary(), "running": self.backup_progress},
            "travel_mode": bool(load_state().get("travel_mode")),
            "auto_updates_user": self.auto_updates_user(),
            "vault": extras.vault_status(),
            "unlocked": (ds or {}).get("unlocked", False),
            "family_mode": (ds or {}).get("family_mode", False),
            "admin_groups": (ds or {}).get("admin_groups", []),
            "suspended": (ds or {}).get("suspended", []),
            "app_update": (ds or {}).get("app_update"),
            "vulns_summary": (ds or {}).get("vulns_summary"),
            "checklist_summary": (ds or {}).get("checklist_summary"),
            "integrity_summary": (ds or {}).get("integrity_summary"),
            "persistence_summary": (ds or {}).get("persistence_summary"),
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
