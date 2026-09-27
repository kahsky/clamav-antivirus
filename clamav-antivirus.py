#!/usr/bin/env python3
"""
ClamAV Antivirus - ClamAV GUI for Linux Mint
A modern HTML/CSS/JS interface for ClamAV with system tray integration.

Les opérations privilégiées (scan complet du système, mise à jour des signatures)
sont déléguées au service système clamav-antivirus-daemon (root) via un socket
Unix : aucun mot de passe n'est demandé. Si le service est absent, l'application
se rabat sur pkexec (demande de mot de passe administrateur).

(c) 2026 Dukiwi SA - Estavayer-le-Lac
"""

import gi
gi.require_version('Gtk', '3.0')
gi.require_version('WebKit2', '4.1')
gi.require_version('AppIndicator3', '0.1')

from gi.repository import Gtk, WebKit2, GLib, AppIndicator3
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
    VERSION, DAEMON_ALLOWED_ROOTS, UPDATE_TIMER_UNIT, DAEMON_UNIT,
    daemon_connect, daemon_request, find_command, is_noise_line,
    classify_line, db_last_update, db_files_info, systemd_next_elapse,
    systemd_is_active,
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
        self.initial = None
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
            self.initial = initial
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
    if norm in DAEMON_ALLOWED_ROOTS:
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
            raise PermissionError("Authentification administrateur annulée ou refusée")
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
                write_log(f"▶ Scan de {self.path}")
                self.emit("line", {"kind": "info", "text": f"▶ Inventaire des fichiers de {self.path}…"})
                self.total = self._count()
                if self.cancel_event.is_set():
                    self._save_progress(False)
                    self.emit("done", {"status": "cancelled", "message": "Scan annulé pendant l'inventaire",
                                       "summary": self.summary()})
                    return
                self.scanned = 0
                self.infected = 0
                self._save_progress(True)
            else:
                self.scanned = start_idx
                self.emit("line", {"kind": "info",
                                   "text": f"▶ Reprise du scan à {start_idx:,} / {self.total:,} fichiers".replace(",", " ")})

            if self.total == 0:
                self._save_progress(False)
                self._record("clean")
                self.emit("done", {"status": "clean", "message": "Aucun fichier à analyser",
                                   "summary": self.summary()})
                return

            tmp_list = SCAN_FILES_CACHE + ".tmp"
            with open(SCAN_FILES_CACHE) as src, open(tmp_list, "w") as dst:
                for i, line in enumerate(src):
                    if i >= start_idx:
                        dst.write(line)

            self.phase = "scanning"
            self.emit("progress", self.progress())
            self.emit("line", {"kind": "info",
                               "text": f"▶ {self.total:,} fichier(s) à analyser — démarrage de clamscan…".replace(",", " ")})

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
                write_log(f"■ Scan interrompu à {self.scanned}/{self.total}")
                self.emit("done", {"status": "cancelled",
                                   "message": f"Scan interrompu à {self.scanned:,} / {self.total:,} fichiers — reprise possible".replace(",", " "),
                                   "summary": self.summary()})
                return

            self.scanned = self.total
            self.current_file = ""
            self._save_progress(False)
            try:
                os.remove(tmp_list)
            except OSError:
                pass
            if self.use_sudo and rc in (126, 127):
                raise PermissionError("Authentification administrateur annulée ou refusée")
            if rc not in (0, 1, 2):
                self._record("error")
                self.emit("done", {"status": "error", "message": f"clamscan a échoué (code {rc})",
                                   "summary": self.summary()})
                return
            status = "infected" if self.infected else "clean"
            self._record(status)
            if self.infected:
                msg = f"{self.infected} menace(s) détectée(s) — fichiers déplacés en quarantaine"
            else:
                msg = f"Aucune menace détectée sur {self.total:,} fichiers".replace(",", " ")
            write_log(f"■ Scan terminé : {msg}")
            self.emit("done", {"status": status, "message": msg, "summary": self.summary()})
        except Exception as e:
            self.emit("done", {"status": "error", "message": str(e), "summary": self.summary()})

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
                    GLib.idle_add(callback, "progress", line.strip())
                proc.wait()
                if proc.returncode == 0:
                    GLib.idle_add(callback, "success", "ClamAV installé avec succès !")
                else:
                    GLib.idle_add(callback, "error", f"Erreur d'installation (code {proc.returncode})")
            except Exception as e:
                GLib.idle_add(callback, "error", str(e))
        threading.Thread(target=run, daemon=True).start()

    @staticmethod
    def update_database_pkexec(callback):
        """Mise à jour via pkexec (mot de passe) — utilisée si le service est absent."""
        def run():
            try:
                update_script = (
                    "echo '→ Arrêt du service clamav-freshclam...' && "
                    "systemctl stop clamav-freshclam 2>/dev/null || true && "
                    "sleep 1 && "
                    "echo '→ Téléchargement des signatures...' && "
                    "freshclam --stdout 2>&1 ; "
                    "RETCODE=$? && "
                    "echo '→ Redémarrage du service clamav-freshclam...' && "
                    "systemctl start clamav-freshclam 2>/dev/null || true && "
                    "exit $RETCODE"
                )
                proc = subprocess.Popen(
                    ["pkexec", "bash", "-c", update_script],
                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
                )
                for line in proc.stdout:
                    GLib.idle_add(callback, "progress", line.strip())
                proc.wait()
                if proc.returncode == 0:
                    save_state({"last_update": now_iso()})
                    GLib.idle_add(callback, "success", "Base de données mise à jour !")
                elif proc.returncode in (126, 127):
                    GLib.idle_add(callback, "error", "Authentification administrateur annulée")
                else:
                    GLib.idle_add(callback, "error", f"Erreur de mise à jour (code {proc.returncode})")
            except Exception as e:
                GLib.idle_add(callback, "error", str(e))
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
            return "error", "Chemin non autorisé"
        os.remove(filepath)
        return "success", f"Fichier supprimé : {os.path.basename(filepath)}"

    @classmethod
    def restore_quarantine_file(cls, filepath, dest):
        if not cls._in_quarantine(filepath):
            return "error", "Chemin non autorisé"
        if not os.path.isdir(dest):
            return "error", "Dossier de destination introuvable"
        shutil.move(filepath, os.path.join(dest, os.path.basename(filepath)))
        return "success", f"Fichier restauré : {os.path.basename(filepath)}"

    @staticmethod
    def empty_quarantine():
        count = 0
        for f in Path(QUARANTINE_DIR).iterdir():
            if f.is_file() and not f.name.startswith(".clamav-quarantine-lock"):
                f.unlink()
                count += 1
        return "success", f"Quarantaine vidée — {count} fichier(s) supprimé(s)"


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


def get_protection_status(daemon_status=None):
    """
    - green : ClamAV installé + signatures < 1 jour
    - blue  : signatures entre 1 et 2 jours
    - red   : ClamAV absent, base absente ou signatures > 2 jours
    """
    if not ClamAVBackend.is_installed():
        return "red", "ClamAV non installé"
    last = effective_last_update(daemon_status)
    if not last:
        return "red", "Base de données introuvable"
    age = datetime.now() - last
    if age < timedelta(days=1):
        hours = int(age.total_seconds() // 3600)
        return "green", f"Protégé — signatures à jour ({hours} h)" if hours else "Protégé — signatures à jour"
    elif age < timedelta(days=2):
        return "blue", f"Mise à jour recommandée — signatures d'il y a {age.days} j"
    else:
        return "red", f"Non protégé — signatures d'il y a {age.days} j"


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
        item_show = Gtk.MenuItem(label="Ouvrir ClamAV Antivirus")
        item_show.connect("activate", self.on_show)
        menu.append(item_show)

        item_scan = Gtk.MenuItem(label="Scan complet du système")
        item_scan.connect("activate", self.on_full_scan)
        menu.append(item_scan)

        item_update = Gtk.MenuItem(label="Mettre à jour les signatures")
        item_update.connect("activate", self.on_update)
        menu.append(item_update)

        menu.append(Gtk.SeparatorMenuItem())
        self.item_status = Gtk.MenuItem(label="Statut : vérification...")
        self.item_status.set_sensitive(False)
        menu.append(self.item_status)
        self.item_job = Gtk.MenuItem(label="")
        self.item_job.set_sensitive(False)
        self.item_job.set_no_show_all(True)
        menu.append(self.item_job)
        menu.append(Gtk.SeparatorMenuItem())

        item_quit = Gtk.MenuItem(label="Quitter")
        item_quit.connect("activate", self.on_quit)
        menu.append(item_quit)

        menu.show_all()
        self.indicator.set_menu(menu)

        self.update_status()
        GLib.timeout_add_seconds(300, self.update_status)

    def update_status(self):
        color, message = get_protection_status(self.app.last_daemon_status)
        self.indicator.set_icon_full(os.path.join(ICONS_DIR, f"shield-{color}.svg"), message)
        self.item_status.set_label(f"Statut : {message}")
        if self.app.webview:
            js = f'if(typeof updateTrayStatus==="function")updateTrayStatus({json.dumps(color)},{json.dumps(message)});'
            self.app.webview.run_javascript(js, None, None, None)
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

    def on_quit(self, _):
        Gtk.main_quit()


def notify(title, body, icon="shield-green"):
    """Notification bureau (libnotify) — silencieuse si notify-send est absent."""
    if not shutil.which("notify-send"):
        return
    try:
        subprocess.Popen(["notify-send", "-a", "ClamAV Antivirus",
                          "-i", os.path.join(ICONS_DIR, f"{icon}.svg"), title, body])
    except OSError:
        pass


# ═══════════════════════════════════════════════════════════════════════════
# Application
# ═══════════════════════════════════════════════════════════════════════════

class ClamAVAntivirusApp:
    """Fenêtre principale (WebKit2) + tray + pont vers le service système."""

    def __init__(self, start_hidden=False):
        self.webview = None
        self.local_scan = None
        self.scan_source = None          # 'daemon' | 'local' | None
        self.updating = False
        self.last_daemon_status = None
        self.daemon_job = None

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
        self.webview.load_uri(f"file://{os.path.join(UI_DIR, 'index.html')}")
        self.window.add(self.webview)

        self.tray = TrayIcon(self)
        self.daemon = DaemonClient(self.on_daemon_event)

        self.window.show_all()
        if start_hidden:
            self.window.hide()
        else:
            self.window.present()

    # ── Fenêtre ─────────────────────────────────────────────────────────
    def on_close(self, widget, event):
        self.window.hide()
        return True

    def run_js(self, js):
        if self.webview:
            self.webview.run_javascript(js, None, None, None)

    def send_to_js(self, event, data):
        payload = json.dumps({"event": event, "data": data}, ensure_ascii=False)
        self.run_js(f'if(typeof onBackendMessage==="function")onBackendMessage({payload});')

    # ── Événements du service système ───────────────────────────────────
    def on_daemon_event(self, ev):
        et = ev.get("event")
        if et == "connected":
            self.last_daemon_status = ev.get("status") or {}
            job = self.last_daemon_status.get("job")
            if job:
                self._daemon_job_started(job)
            self.send_status()
        elif et == "disconnected":
            self.last_daemon_status = None
            if self.scan_source == "daemon":
                self.scan_source = None
                self.send_to_js("scanDone", {"status": "error", "source": "daemon",
                                             "message": "Connexion au service système perdue"})
            self.send_status()
        elif et == "job_started":
            self._daemon_job_started(ev.get("job") or {})
        elif et == "job_queued":
            if ev.get("waiting"):
                self.send_to_js("jobQueued", ev.get("job") or {})
        elif et == "progress":
            if ev.get("kind") == "scan":
                self.send_to_js("scanProgress", ev)
        elif et == "line":
            if self.daemon_job and self.daemon_job.get("kind") == "update":
                self.send_to_js("updateLine", {"text": ev.get("text", "")})
            else:
                self.send_to_js("scanLine", {"kind": ev.get("kind"), "text": ev.get("text", "")})
        elif et == "job_done":
            self._daemon_job_done(ev)
        return False

    def _daemon_job_started(self, job):
        self.daemon_job = job
        if job.get("kind") == "scan":
            self.scan_source = "daemon"
            self.tray.set_job(f"Scan en cours : {job.get('path')}")
            self.send_to_js("scanStarted", {"source": "daemon", "path": job.get("path"),
                                            "resume": job.get("resume"), "auto": job.get("auto"),
                                            "started_at": job.get("started_at"), "job": job})
        else:
            self.updating = True
            self.tray.set_job("Mise à jour des signatures…")
            self.send_to_js("updateStarted", {"source": "daemon", "auto": job.get("auto")})

    def _daemon_job_done(self, ev):
        self.daemon_job = None
        self.tray.set_job(None)
        status = ev.get("status")
        if ev.get("kind") == "scan":
            self.scan_source = None
            self.send_to_js("scanDone", {"status": status, "message": ev.get("message"),
                                         "summary": ev.get("summary", {}), "source": "daemon",
                                         "auto": ev.get("auto"), "path": ev.get("path")})
            if status == "infected":
                notify("Menaces détectées", ev.get("message", ""), "shield-red")
            elif status == "clean":
                notify("Analyse terminée", ev.get("message", ""), "shield-green")
        else:
            self.updating = False
            self.send_to_js("operationResult", {"status": "success" if status == "success" else "error",
                                                "message": ev.get("message"), "op": "update"})
        # Rafraîchir l'état global
        st = DaemonClient.request("status")
        if st.get("ok"):
            self.last_daemon_status = st
        self.send_status()
        self.tray.update_status()

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
            self.send_to_js("scanDone", data)
            if data.get("status") == "infected":
                notify("Menaces détectées", data.get("message", ""), "shield-red")
            elif data.get("status") == "clean":
                notify("Analyse terminée", data.get("message", ""), "shield-green")
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
                self.send_to_js("error", {"message": f"Action inconnue : {action}"})
        except Exception as e:
            self.send_to_js("error", {"message": str(e)})

    def act_check_status(self, _data):
        st = DaemonClient.request("status")
        self.last_daemon_status = st if st.get("ok") else None
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
            if resp.get("queued"):
                self.send_to_js("updateLine", {"text": "→ En attente de la fin de l'opération en cours…"})
            return
        if not resp.get("unavailable"):
            self.send_to_js("operationResult", {"status": "error", "message": resp.get("error"), "op": "update"})
            return
        # Service absent : pkexec (mot de passe)
        self.updating = True
        self.send_to_js("updateStarted", {"source": "local"})
        self.send_to_js("updateLine", {"text": "→ Service système indisponible : authentification administrateur requise"})
        ClamAVBackend.update_database_pkexec(self.operation_callback)

    def act_scan(self, data):
        path = os.path.normpath(data.get("path") or HOME_DIR)
        resume = bool(data.get("resume", False))
        full = path == "/"
        if self.scan_source or self.local_scan:
            self.send_to_js("operationResult", {"status": "error", "message": "Un scan est déjà en cours"})
            return
        if not os.path.isdir(path):
            self.send_to_js("operationResult", {"status": "error", "message": f"Répertoire introuvable : {path}"})
            return

        # 1) Service système (root, sans mot de passe)
        if daemon_can_scan(path):
            resp = DaemonClient.request("scan", path=path, resume=resume)
            if resp.get("ok"):
                return  # l'événement job_started déclenchera scanStarted
            if not resp.get("unavailable"):
                msg = resp.get("error", "Refusé par le service")
                if resp.get("busy"):
                    busy = resp["busy"]
                    msg = ("Le service exécute déjà une mise à jour" if busy.get("kind") == "update"
                           else f"Le service analyse déjà {busy.get('path')}")
                self.send_to_js("operationResult", {"status": "error", "message": msg})
                return

        # 2) Repli local : pkexec pour le scan complet, sinon droits de l'utilisateur
        use_sudo = full
        self.scan_source = "local"
        self.local_scan = LocalScan(path, self.on_local_scan_event, resume=resume, use_sudo=use_sudo)
        self.tray.set_job(f"Scan en cours : {path}")
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
                self.send_to_js("operationResult", {"status": "error", "message": resp.get("error")})
        else:
            self.send_to_js("operationResult", {"status": "info", "message": "Aucun scan en cours"})

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

    def _quarantine_result(self, status, message):
        self.send_to_js("operationResult", {"status": status, "message": message, "op": "quarantine"})
        self.send_to_js("quarantineList", {"files": self._merged_quarantine()})

    def act_delete_quarantine(self, data):
        if data.get("scope") == "system":
            resp = DaemonClient.request("quarantine_delete", path=data.get("path", ""))
            self._quarantine_result("success" if resp.get("ok") else "error",
                                    resp.get("message") or resp.get("error"))
        else:
            self._quarantine_result(*ClamAVBackend.delete_quarantine_file(data.get("path", "")))

    def act_restore_quarantine(self, data):
        dest = data.get("dest") or HOME_DIR
        if data.get("scope") == "system":
            resp = DaemonClient.request("quarantine_restore", path=data.get("path", ""), dest=dest)
            self._quarantine_result("success" if resp.get("ok") else "error",
                                    resp.get("message") or resp.get("error"))
        else:
            self._quarantine_result(*ClamAVBackend.restore_quarantine_file(data.get("path", ""), dest))

    def act_empty_quarantine(self, _data):
        status, message = ClamAVBackend.empty_quarantine()
        resp = DaemonClient.request("quarantine_empty")
        if resp.get("ok"):
            message += " · " + resp.get("message", "")
        self._quarantine_result(status, message)

    def act_pick_folder(self, data):
        """Sélecteur de dossier natif GTK (chemin personnalisé, restauration)."""
        purpose = data.get("purpose", "scan")
        dialog = Gtk.FileChooserDialog(
            title="Choisir un dossier", parent=self.window,
            action=Gtk.FileChooserAction.SELECT_FOLDER)
        dialog.add_buttons("Annuler", Gtk.ResponseType.CANCEL, "Choisir", Gtk.ResponseType.OK)
        dialog.set_current_folder(data.get("start") or HOME_DIR)
        resp = dialog.run()
        path = dialog.get_filename() if resp == Gtk.ResponseType.OK else None
        dialog.destroy()
        self.send_to_js("folderPicked", {"path": path, "purpose": purpose,
                                         "extra": data.get("extra")})

    def act_quit(self, _data):
        Gtk.main_quit()

    # ── Callbacks des opérations pkexec ─────────────────────────────────
    def operation_callback(self, status, message):
        if status == "progress":
            if self.updating:
                self.send_to_js("updateLine", {"text": message})
            else:
                self.send_to_js("operationResult", {"status": "progress", "message": message})
            return
        if self.updating:
            self.updating = False
            self.send_to_js("operationResult", {"status": status, "message": message, "op": "update"})
        else:
            self.send_to_js("operationResult", {"status": status, "message": message, "op": "install"})
        if status == "success":
            self.send_status()
            self.tray.update_status()

    # ── Statut global ───────────────────────────────────────────────────
    def send_status(self):
        ds = self.last_daemon_status if isinstance(self.last_daemon_status, dict) else None
        color, message = get_protection_status(ds)
        installed = ClamAVBackend.is_installed()
        freshclam_installed = ClamAVBackend.is_freshclam_installed()
        state = load_state()
        dstate = (ds or {}).get("state") or {}

        # Scan interrompu (local ou système) à proposer en reprise
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

        # Historique fusionné (local + système)
        history = list(state.get("history", [])) + list(dstate.get("history", []))
        history.sort(key=lambda e: e.get("date", ""), reverse=True)
        last_scan = history[0] if history else None
        if not last_scan and state.get("last_scan"):
            last_scan = {"date": state["last_scan"], "path": state.get("last_scan_path"),
                         "infected": state.get("last_scan_infected", 0), "source": "local"}

        last_update = effective_last_update(ds)
        next_update = systemd_next_elapse(UPDATE_TIMER_UNIT)

        self.send_to_js("statusUpdate", {
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
            },
            "schedule": {
                "next_update": next_update.isoformat(timespec="seconds") if next_update else None,
                "timer_active": systemd_is_active(UPDATE_TIMER_UNIT),
                "rule": "Tous les jours à 07:00 et 5 minutes après le démarrage",
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
