#!/usr/bin/env python3
"""
ClamAV Antivirus — module partagé entre le GUI et le daemon système.
Chemins, exclusions de scan, protocole socket (JSON par ligne) et utilitaires.
(c) 2026 Dukiwi SA - Estavayer-le-Lac
"""

import json
import os
import socket
import struct
import subprocess
from datetime import datetime

VERSION = "1.4.0"

# ─── Chemins système (daemon root) ───────────────────────────────────────────
# Surchargeables par variables d'environnement pour les tests sans root.
SYSTEM_STATE_DIR = os.environ.get("CLAMAV_ANTIVIRUS_STATE_DIR", "/var/lib/clamav-antivirus")
SYSTEM_LOG_DIR   = os.environ.get("CLAMAV_ANTIVIRUS_LOG_DIR",   "/var/log/clamav-antivirus")
DAEMON_SOCKET    = os.environ.get("CLAMAV_ANTIVIRUS_SOCKET",    "/run/clamav-antivirus/daemon.sock")

SYSTEM_STATE_FILE      = os.path.join(SYSTEM_STATE_DIR, "state.json")
SYSTEM_QUARANTINE_DIR  = os.path.join(SYSTEM_STATE_DIR, "quarantine")
SYSTEM_PROGRESS_FILE   = os.path.join(SYSTEM_STATE_DIR, "scan_progress.json")
SYSTEM_FILELIST_CACHE  = os.path.join(SYSTEM_STATE_DIR, "scan_filelist.txt")
FIRST_SCAN_FLAG        = os.path.join(SYSTEM_STATE_DIR, "first-scan-pending")
SYSTEM_LOG_FILE        = os.path.join(SYSTEM_LOG_DIR, "scan.log")

CLAMAV_DB_DIR = "/var/lib/clamav"

# Unités systemd
UPDATE_TIMER_UNIT  = "clamav-antivirus-update.timer"
DAEMON_UNIT        = "clamav-antivirus-daemon.service"

# ─── Chemins que le daemon accepte de scanner pour n'importe quel utilisateur ──
# (en plus du répertoire personnel de l'utilisateur qui fait la demande)
DAEMON_ALLOWED_ROOTS = ["/", "/home", "/etc", "/var", "/opt", "/usr", "/tmp", "/boot", "/root", "/srv"]

# ─── Répertoires exclus du scan (inutiles ou problématiques sur Linux Mint 22) ─
SCAN_EXCLUDE = [
    '/proc/*', '/sys/*', '/dev/*', '/run/*',           # systèmes de fichiers virtuels
    '/home/.ecryptfs/*',                               # vault eCryptFS (chiffré)
    '/snap/*', '/var/lib/snapd/*',                     # paquets snap (squashfs protégés)
    '/var/cache/apt/*', '/var/cache/debconf/*',        # cache paquets APT
    '/var/cache/man/*',                                # cache man pages
    '/var/lib/clamav/*',                               # bases virales (faux positifs garantis)
    '/var/lib/clamav-antivirus/quarantine/*',          # quarantaine système
    '/usr/share/doc/*', '/usr/share/man/*',            # documentation
    '/usr/share/info/*', '/usr/share/locale/*',        # données de locale
    '/usr/share/i18n/*', '/usr/share/fonts/*',         # polices
    '/usr/share/icons/*', '/usr/share/themes/*',       # icônes / thèmes
    '/usr/share/pixmaps/*', '/usr/share/backgrounds/*',# images décoratives
    '/home/*/.cache/*',                                # caches utilisateurs
    '/home/*/.local/share/Trash/*',                    # corbeilles
    '/home/*/.local/share/clamav-antivirus/*',         # quarantaine / logs utilisateur
    '/home/*/.thumbnails/*',                           # miniatures
    '/home/*/.mozilla/*/Cache*/*',                     # cache Firefox
    '/home/*/.config/google-chrome/*/Cache*/*',        # cache Chrome
    '/root/.cache/*',                                  # cache root
]

# Lignes de sortie clamscan --verbose qui sont du bruit (ne pas journaliser)
NOISE_PREFIXES = ("traverse_to:", "LibClamAV", "Scanning ")
NOISE_SUFFIXES = (": Empty file", ": No such file or directory", ": Excluded", ": Symbolic link")


def find_command(path, exclude=SCAN_EXCLUDE):
    """Commande find listant les fichiers réguliers à scanner sous `path`."""
    cmd = ['find', path, '-type', 'f']
    for excl in exclude:
        cmd += ['!', '-path', excl]
    return cmd


def is_noise_line(line):
    """True si la ligne clamscan n'apporte rien à l'utilisateur."""
    if not line:
        return True
    if line.startswith(NOISE_PREFIXES):
        return True
    return line.endswith(NOISE_SUFFIXES)


def classify_line(line):
    """Classe une ligne de sortie clamscan : 'found', 'denied', 'error', 'summary', 'info'."""
    if line.endswith(" FOUND"):
        return "found"
    if line.endswith(": Access denied") or line.endswith(": Permission denied"):
        return "denied"
    if line.startswith("-----------") or line.startswith("Known viruses") \
            or line.startswith("Engine version") or line.startswith("Scanned ") \
            or line.startswith("Infected files") or line.startswith("Data ") \
            or line.startswith("Time:") or line.startswith("Start Date") \
            or line.startswith("End Date") or line.startswith("Total errors"):
        return "summary"
    if "ERROR" in line or line.endswith(": Can't open file") or "Can't" in line:
        return "error"
    return "info"


def db_last_update():
    """Date (datetime) de la signature la plus récente dans /var/lib/clamav, ou None."""
    newest = None
    try:
        for name in os.listdir(CLAMAV_DB_DIR):
            if name.endswith((".cvd", ".cld")):
                mtime = os.stat(os.path.join(CLAMAV_DB_DIR, name)).st_mtime
                if newest is None or mtime > newest:
                    newest = mtime
    except OSError:
        return None
    return datetime.fromtimestamp(newest) if newest else None


def db_files_info():
    """Liste des fichiers de signatures avec taille et date."""
    files = []
    try:
        for name in sorted(os.listdir(CLAMAV_DB_DIR)):
            if name.endswith((".cvd", ".cld")):
                st = os.stat(os.path.join(CLAMAV_DB_DIR, name))
                files.append({
                    "name": name,
                    "size": str(st.st_size),
                    "date": datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M"),
                })
    except OSError:
        pass
    return files


def systemd_next_elapse(unit=UPDATE_TIMER_UNIT):
    """Prochaine exécution d'un timer systemd (datetime) ou None. Fonctionne sans root."""
    try:
        r = subprocess.run(
            ["systemctl", "show", unit, "-p", "NextElapseUSecRealtime", "--value"],
            capture_output=True, text=True, timeout=5,
        )
        value = r.stdout.strip()
        if not value or value in ("n/a", "infinity"):
            return None
        # Format : "Mon 2026-09-28 07:00:00 CEST"
        parts = value.split()
        if len(parts) >= 3:
            return datetime.strptime(f"{parts[1]} {parts[2]}", "%Y-%m-%d %H:%M:%S")
    except Exception:
        pass
    return None


def systemd_is_active(unit):
    """True si l'unité systemd est active. Fonctionne sans root."""
    try:
        r = subprocess.run(["systemctl", "is-active", unit],
                           capture_output=True, text=True, timeout=5)
        return r.stdout.strip() == "active"
    except Exception:
        return False


def format_duration(seconds):
    """Durée lisible : '1 h 12 min', '4 min 05 s', '32 s'."""
    seconds = int(max(0, seconds))
    h, rem = divmod(seconds, 3600)
    m, s = divmod(rem, 60)
    if h:
        return f"{h} h {m:02d} min"
    if m:
        return f"{m} min {s:02d} s"
    return f"{s} s"


# ─── Protocole socket : une ligne JSON par message ───────────────────────────

class LineSocket:
    """Enveloppe un socket Unix pour échanger des messages JSON ligne par ligne."""

    def __init__(self, sock):
        self.sock = sock
        self._buf = b""

    def send(self, obj):
        data = (json.dumps(obj, ensure_ascii=False) + "\n").encode("utf-8")
        self.sock.sendall(data)

    def recv(self):
        """Retourne le prochain objet JSON, ou None si la connexion est fermée."""
        while b"\n" not in self._buf:
            chunk = self.sock.recv(65536)
            if not chunk:
                return None
            self._buf += chunk
        line, _, self._buf = self._buf.partition(b"\n")
        line = line.strip()
        if not line:
            return self.recv()
        return json.loads(line.decode("utf-8"))

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


def peer_credentials(sock):
    """(pid, uid, gid) du processus connecté sur un socket Unix (SO_PEERCRED)."""
    creds = sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
    return struct.unpack("3i", creds)


def daemon_connect(timeout=2.0):
    """Ouvre une connexion vers le daemon. Lève OSError si indisponible."""
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    sock.connect(DAEMON_SOCKET)
    return LineSocket(sock)


def daemon_request(cmd, timeout=2.0, **kwargs):
    """Envoie une commande unique au daemon et retourne la réponse (dict).
    Retourne {"ok": False, "error": ..., "unavailable": True} si le daemon ne répond pas."""
    try:
        conn = daemon_connect(timeout=timeout)
    except OSError as e:
        return {"ok": False, "error": f"Service indisponible ({e})", "unavailable": True}
    try:
        conn.send(dict(cmd=cmd, **kwargs))
        resp = conn.recv()
        return resp if resp is not None else {"ok": False, "error": "Connexion fermée", "unavailable": True}
    except (OSError, ValueError) as e:
        return {"ok": False, "error": str(e), "unavailable": True}
    finally:
        conn.close()
