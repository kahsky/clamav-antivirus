#!/usr/bin/env python3
"""
ClamAV Antivirus - ClamAV GUI for Linux Mint
A modern HTML/CSS/JS interface for ClamAV with system tray integration.
(c) 2026 Dukiwi SA - Estavayer-le-Lac
"""

import gi
gi.require_version('Gtk', '3.0')
gi.require_version('WebKit2', '4.1')
gi.require_version('AppIndicator3', '0.1')

from gi.repository import Gtk, WebKit2, GLib, AppIndicator3, Gdk
import subprocess
import threading
import json
import os
import time
import sys
from pathlib import Path
from datetime import datetime, timedelta

# ─── Paths ───────────────────────────────────────────────────────────────────
APP_DIR = os.path.dirname(os.path.abspath(__file__))
UI_DIR = os.path.join(APP_DIR, "ui")
ICONS_DIR = os.path.join(APP_DIR, "icons")
LOG_FILE = os.path.expanduser("~/.local/share/clamav-antivirus/scan.log")
STATE_FILE = os.path.expanduser("~/.local/share/clamav-antivirus/state.json")
QUARANTINE_DIR = os.path.expanduser("~/.local/share/clamav-antivirus/quarantine")

os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
os.makedirs(QUARANTINE_DIR, exist_ok=True)


class ClamAVBackend:
    """Handles all ClamAV operations."""

    @staticmethod
    def is_installed():
        """Check if ClamAV is installed."""
        try:
            r = subprocess.run(["which", "clamscan"], capture_output=True, text=True)
            return r.returncode == 0
        except Exception:
            return False

    @staticmethod
    def is_freshclam_installed():
        """Check if freshclam is installed."""
        try:
            r = subprocess.run(["which", "freshclam"], capture_output=True, text=True)
            return r.returncode == 0
        except Exception:
            return False

    @staticmethod
    def install_clamav(callback):
        """Install ClamAV and freshclam via apt."""
        def run():
            try:
                proc = subprocess.Popen(
                    ["pkexec", "bash", "-c",
                     "apt-get update && apt-get install -y clamav clamav-daemon clamav-freshclam"],
                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
                )
                output = ""
                for line in proc.stdout:
                    output += line
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
    def update_database(callback):
        """Update ClamAV virus definitions."""
        def run():
            try:
                # Single pkexec call: stop daemon → freshclam → restart daemon
                update_script = (
                    "echo '→ Arrêt du service clamav-freshclam...' && "
                    "systemctl stop clamav-freshclam 2>/dev/null || true && "
                    "sleep 1 && "
                    "echo '→ Téléchargement des signatures...' && "
                    "freshclam --verbose 2>&1 ; "
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
                    save_state({"last_update": datetime.now().isoformat()})
                    GLib.idle_add(callback, "success", "Base de données mise à jour !")
                else:
                    GLib.idle_add(callback, "error", f"Erreur de mise à jour (code {proc.returncode})")
            except Exception as e:
                GLib.idle_add(callback, "error", str(e))
        threading.Thread(target=run, daemon=True).start()

    @staticmethod
    def scan_directory(path, callback):
        """Scan a directory with clamscan, quarantine infected files."""
        def run():
            try:
                proc = subprocess.Popen(
                    ["clamscan", "-r", "--bell", "--infected",
                     "--suppress-ok-results",
                     f"--move={QUARANTINE_DIR}", path],
                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
                )
                infected_count = 0
                for line in proc.stdout:
                    GLib.idle_add(callback, "progress", line.strip())
                    if "FOUND" in line:
                        infected_count += 1
                    with open(LOG_FILE, "a") as f:
                        f.write(f"[{datetime.now().isoformat()}] {line}")
                proc.wait()

                # Save scan timestamp
                save_state({
                    "last_scan": datetime.now().isoformat(),
                    "last_scan_path": path,
                    "last_scan_infected": infected_count
                })

                summary = f"Scan terminé — {infected_count} menace(s) détectée(s)"
                if infected_count > 0:
                    summary += f" — fichiers déplacés en quarantaine"
                if infected_count == 0:
                    GLib.idle_add(callback, "clean", summary)
                else:
                    GLib.idle_add(callback, "infected", summary)
            except Exception as e:
                GLib.idle_add(callback, "error", str(e))
        threading.Thread(target=run, daemon=True).start()

    @staticmethod
    def get_quarantine_files():
        """List files in quarantine directory."""
        files = []
        try:
            for f in sorted(Path(QUARANTINE_DIR).iterdir(), key=lambda x: x.stat().st_mtime, reverse=True):
                if f.is_file():
                    stat = f.stat()
                    files.append({
                        "name": f.name,
                        "path": str(f),
                        "size": stat.st_size,
                        "date": datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M")
                    })
        except Exception:
            pass
        return files

    @staticmethod
    def delete_quarantine_file(filepath, callback):
        """Permanently delete a quarantined file."""
        def run():
            try:
                p = Path(filepath)
                # Safety: only delete from quarantine dir
                if QUARANTINE_DIR in str(p.resolve()) and p.exists():
                    p.unlink()
                    GLib.idle_add(callback, "success", f"Fichier supprimé : {p.name}")
                else:
                    GLib.idle_add(callback, "error", "Chemin non autorisé")
            except Exception as e:
                GLib.idle_add(callback, "error", str(e))
        threading.Thread(target=run, daemon=True).start()

    @staticmethod
    def restore_quarantine_file(filepath, dest, callback):
        """Restore a quarantined file to its original location."""
        import shutil
        def run():
            try:
                p = Path(filepath)
                if QUARANTINE_DIR in str(p.resolve()) and p.exists():
                    shutil.move(str(p), dest)
                    GLib.idle_add(callback, "success", f"Fichier restauré : {p.name}")
                else:
                    GLib.idle_add(callback, "error", "Chemin non autorisé")
            except Exception as e:
                GLib.idle_add(callback, "error", str(e))
        threading.Thread(target=run, daemon=True).start()

    @staticmethod
    def empty_quarantine(callback):
        """Delete all files in quarantine."""
        def run():
            try:
                count = 0
                for f in Path(QUARANTINE_DIR).iterdir():
                    if f.is_file():
                        f.unlink()
                        count += 1
                GLib.idle_add(callback, "success", f"Quarantaine vidée — {count} fichier(s) supprimé(s)")
            except Exception as e:
                GLib.idle_add(callback, "error", str(e))
        threading.Thread(target=run, daemon=True).start()

    @staticmethod
    def get_db_info():
        """Get virus database info."""
        try:
            r = subprocess.run(
                ["bash", "-c", "ls -la /var/lib/clamav/*.cvd 2>/dev/null || ls -la /var/lib/clamav/*.cld 2>/dev/null"],
                capture_output=True, text=True, timeout=5
            )
            if r.returncode == 0:
                lines = r.stdout.strip().split("\n")
                files = []
                for line in lines:
                    parts = line.split()
                    if len(parts) >= 9:
                        files.append({
                            "name": parts[-1].split("/")[-1],
                            "size": parts[4],
                            "date": f"{parts[5]} {parts[6]} {parts[7]}"
                        })
                return files
            return []
        except Exception:
            return []


def load_state():
    """Load persistent state."""
    try:
        with open(STATE_FILE, "r") as f:
            return json.load(f)
    except Exception:
        return {}


def save_state(data):
    """Save persistent state (merges with existing)."""
    state = load_state()
    state.update(data)
    with open(STATE_FILE, "w") as f:
        json.dump(state, f, indent=2)


def get_protection_status():
    """
    Determine protection status:
    - green: ClamAV installed + DB updated within 2 days
    - blue: ClamAV installed + DB updated but older than today
    - red: ClamAV not installed or DB older than 2 days
    """
    if not ClamAVBackend.is_installed():
        return "red", "ClamAV non installé"

    state = load_state()
    last_update = state.get("last_update")

    if not last_update:
        # Check file modification time of DB files
        db_files = ClamAVBackend.get_db_info()
        if not db_files:
            return "red", "Base de données introuvable"
        return "blue", "Statut de mise à jour inconnu"

    try:
        last_dt = datetime.fromisoformat(last_update)
        age = datetime.now() - last_dt
        if age < timedelta(days=1):
            return "green", f"Protégé — MàJ il y a {int(age.total_seconds()//3600)}h"
        elif age < timedelta(days=2):
            return "blue", f"MàJ disponible — dernière il y a {age.days}j"
        else:
            return "red", f"Non protégé — MàJ il y a {age.days}j"
    except Exception:
        return "blue", "Statut inconnu"


class TrayIcon:
    """System tray shield icon with status colors."""

    def __init__(self, app):
        self.app = app
        self.indicator = AppIndicator3.Indicator.new(
            "clamav-antivirus",
            os.path.join(ICONS_DIR, "shield-green.svg"),
            AppIndicator3.IndicatorCategory.APPLICATION_STATUS
        )
        self.indicator.set_status(AppIndicator3.IndicatorStatus.ACTIVE)
        self.indicator.set_title("ClamAV Antivirus")

        # Build menu
        menu = Gtk.Menu()

        item_show = Gtk.MenuItem(label="Ouvrir ClamAV Antivirus")
        item_show.connect("activate", self.on_show)
        menu.append(item_show)

        item_update = Gtk.MenuItem(label="Mettre à jour les bases")
        item_update.connect("activate", self.on_update)
        menu.append(item_update)

        menu.append(Gtk.SeparatorMenuItem())

        self.item_status = Gtk.MenuItem(label="Statut : vérification...")
        self.item_status.set_sensitive(False)
        menu.append(self.item_status)

        menu.append(Gtk.SeparatorMenuItem())

        item_quit = Gtk.MenuItem(label="Quitter")
        item_quit.connect("activate", self.on_quit)
        menu.append(item_quit)

        menu.show_all()
        self.indicator.set_menu(menu)

        # Start status checker
        self.update_status()
        GLib.timeout_add_seconds(300, self.update_status)  # Check every 5 min

    def update_status(self):
        """Update tray icon color based on protection status."""
        color, message = get_protection_status()
        icon_path = os.path.join(ICONS_DIR, f"shield-{color}.svg")
        self.indicator.set_icon_full(icon_path, message)
        self.item_status.set_label(f"Statut : {message}")
        # Also notify the webview
        if hasattr(self.app, 'webview') and self.app.webview:
            js = f'if(typeof updateTrayStatus==="function")updateTrayStatus("{color}","{message}");'
            GLib.idle_add(self.app.webview.run_javascript, js, None, None, None)
        return True  # Keep the timeout active

    def on_show(self, _):
        self.app.window.present()

    def on_update(self, _):
        self.app.window.present()
        js = 'if(typeof triggerUpdate==="function")triggerUpdate();'
        self.app.webview.run_javascript(js, None, None, None)

    def on_quit(self, _):
        Gtk.main_quit()


class ClamAVAntivirusApp:
    """Main application window with WebKit2 webview."""

    def __init__(self):
        self.webview = None

        # ── Window ──
        self.window = Gtk.Window(title="ClamAV Antivirus")
        self.window.set_default_size(1000, 700)
        self.window.set_position(Gtk.WindowPosition.CENTER)
        self.window.set_icon_from_file(os.path.join(ICONS_DIR, "shield-green.svg"))
        self.window.connect("delete-event", self.on_close)

        # ── WebView ──
        ctx = WebKit2.WebContext.get_default()
        ctx.register_uri_scheme("app", self.on_uri_scheme)

        ucm = WebKit2.UserContentManager()
        ucm.register_script_message_handler("backend")
        ucm.connect("script-message-received::backend", self.on_message_from_js)

        self.webview = WebKit2.WebView.new_with_user_content_manager(ucm)
        settings = self.webview.get_settings()
        settings.set_enable_developer_extras(True)  # F12 inspector
        settings.set_javascript_can_access_clipboard(True)

        index_path = os.path.join(UI_DIR, "index.html")
        self.webview.load_uri(f"file://{index_path}")

        self.window.add(self.webview)

        # ── Tray ──
        self.tray = TrayIcon(self)

        self.window.show_all()

    def on_close(self, widget, event):
        """Minimize to tray instead of quitting."""
        self.window.hide()
        return True  # Prevent destruction

    def on_uri_scheme(self, request):
        """Handle app:// URI scheme requests."""
        uri = request.get_uri()
        # Could serve local files via app:// scheme if needed
        pass

    def on_message_from_js(self, ucm, result):
        """Handle messages sent from JavaScript via webkit.messageHandlers.backend."""
        try:
            data = json.loads(result.get_js_value().to_string())
            action = data.get("action")

            if action == "check_status":
                self.send_status()

            elif action == "install":
                ClamAVBackend.install_clamav(self.operation_callback)

            elif action == "update":
                ClamAVBackend.update_database(self.operation_callback)

            elif action == "scan":
                path = data.get("path", os.path.expanduser("~"))
                ClamAVBackend.scan_directory(path, self.operation_callback)

            elif action == "get_db_info":
                info = ClamAVBackend.get_db_info()
                self.send_to_js("dbInfo", {"files": info})

            elif action == "get_log":
                try:
                    with open(LOG_FILE, "r") as f:
                        lines = f.readlines()[-100:]  # Last 100 lines
                    self.send_to_js("logContent", {"lines": lines})
                except FileNotFoundError:
                    self.send_to_js("logContent", {"lines": []})

            elif action == "clear_log":
                open(LOG_FILE, "w").close()
                self.send_to_js("logContent", {"lines": []})

            elif action == "get_quarantine":
                files = ClamAVBackend.get_quarantine_files()
                self.send_to_js("quarantineList", {"files": files})

            elif action == "delete_quarantine":
                filepath = data.get("path", "")
                ClamAVBackend.delete_quarantine_file(filepath, self.quarantine_callback)

            elif action == "restore_quarantine":
                filepath = data.get("path", "")
                dest = data.get("dest", os.path.expanduser("~/"))
                ClamAVBackend.restore_quarantine_file(filepath, dest, self.quarantine_callback)

            elif action == "empty_quarantine":
                ClamAVBackend.empty_quarantine(self.quarantine_callback)

            elif action == "quit":
                Gtk.main_quit()

        except Exception as e:
            self.send_to_js("error", {"message": str(e)})

    def operation_callback(self, status, message):
        """Callback for async ClamAV operations."""
        self.send_to_js("operationResult", {"status": status, "message": message})
        if status in ("success", "clean", "infected"):
            self.tray.update_status()

    def quarantine_callback(self, status, message):
        """Callback for quarantine operations."""
        self.send_to_js("operationResult", {"status": status, "message": message})
        # Refresh quarantine list
        files = ClamAVBackend.get_quarantine_files()
        self.send_to_js("quarantineList", {"files": files})

    def send_status(self):
        """Send current protection status to JS."""
        color, message = get_protection_status()
        installed = ClamAVBackend.is_installed()
        freshclam_installed = ClamAVBackend.is_freshclam_installed()
        state = load_state()
        try:
            daemon = subprocess.run(
                ["systemctl", "is-active", "clamav-freshclam"],
                capture_output=True, text=True, timeout=5
            )
            daemon_active = daemon.stdout.strip() == "active"
        except Exception:
            daemon_active = False
        self.send_to_js("statusUpdate", {
            "color": color,
            "message": message,
            "installed": installed,
            "freshclam_installed": freshclam_installed,
            "daemon_active": daemon_active,
            "fully_installed": installed and freshclam_installed,
            "last_scan": state.get("last_scan"),
            "last_scan_path": state.get("last_scan_path"),
            "never_scanned": state.get("last_scan") is None
        })

    def send_to_js(self, event, data):
        """Send data to JavaScript frontend."""
        payload = json.dumps({"event": event, "data": data})
        js = f'if(typeof onBackendMessage==="function")onBackendMessage({payload});'
        self.webview.run_javascript(js, None, None, None)


def main():
    app = ClamAVAntivirusApp()
    Gtk.main()


if __name__ == "__main__":
    main()
