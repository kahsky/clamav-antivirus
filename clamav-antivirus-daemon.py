#!/usr/bin/env python3
"""
ClamAV Antivirus GUI — service système (root).

Tourne en permanence via systemd et écoute sur un socket Unix. Il permet à un
utilisateur sans droits administrateur de demander :
  - un scan complet du système (ou d'un répertoire système / de son home),
  - une mise à jour des signatures (freshclam),
sans saisir de mot de passe. Le GUI se rabat sur pkexec si le service est absent.

Il exécute aussi :
  - le scan complet automatique après la première installation,
  - les mises à jour planifiées (clamav-antivirus-update.timer : tous les jours
    à 07:00 et 5 minutes après le démarrage),
  - la surveillance des rafales d'écritures (fanotify) : un programme qui modifie
    beaucoup de fichiers est signalé (info), ou marqué "danger potentiel" s'il
    est inconnu du système, s'exécute depuis un dossier temporaire/personnel,
    ou si clamd reconnaît son exécutable,
  - l'analyse des supports USB avant leur mise à disposition (udev + montage
    privé) — les disques durs USB volumineux font l'objet d'une question,
  - le relevé de l'état du système : mises à jour de sécurité en attente et
    CVE corrigées par celles-ci (apt).

Usage :
  clamav-antivirus-daemon.py                 # mode daemon (root)
  clamav-antivirus-daemon.py --request update      # client : demander une MàJ et attendre
  clamav-antivirus-daemon.py --request scan [/chemin]
  clamav-antivirus-daemon.py --request status
  clamav-antivirus-daemon.py --request system-status

(c) 2026 Dukiwi SA - Estavayer-le-Lac
"""

import ctypes
import grp
import hashlib
import hmac
import ipaddress
import fnmatch
import glob
import json
import os
import pwd
import re
import shutil
import signal
import socket
import sqlite3
import struct
import subprocess
import sys
import threading
import time
import urllib.request
import uuid
import urllib.error
import urllib.parse
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import clamav_harden as harden  # noqa: E402
from clamav_common import (  # noqa: E402
    VERSION, SYSTEM_STATE_DIR, SYSTEM_LOG_DIR, DAEMON_SOCKET,
    SYSTEM_STATE_FILE, SYSTEM_QUARANTINE_DIR, SYSTEM_PROGRESS_FILE, SYSTEM_SCAN_CACHE_DB, SYSTEM_SECRET_FILE,
    quarantine_index_add, quarantine_enrich, parse_moved_line,
    SYSTEM_FILELIST_CACHE, FIRST_SCAN_FLAG, SYSTEM_LOG_FILE, USB_MOUNT_ROOT,
    SYSTEM_SETTINGS_FILE, DEFAULT_SETTINGS, DAEMON_ALLOWED_ROOTS,
    BURST_PID_COOLDOWN_SEC, BURST_GLOBAL_COOLDOWN, BURST_IGNORE_PREFIXES, BURST_IGNORE_PARTS,
    LineSocket, peer_credentials, daemon_connect, daemon_request, find_command,
    is_noise_line, classify_line, db_last_update, db_files_info, t,
    sanitize_settings, parse_ufw_verbose, parse_ufw_numbered, systemd_is_active,
)

APP_DIR = os.path.dirname(os.path.abspath(__file__))
KEYRING = os.path.join(APP_DIR, "keys", "dukiwi-clamav.gpg")
INTEGRITY_FILE = os.path.join(APP_DIR, "integrity.json")
MANIFEST_URL = os.environ.get("CLAMAV_ANTIVIRUS_MANIFEST_URL",
                              "https://www.dukiwi.com/repo/clamav-antivirus/manifest.json")
UPDATES_DIR = os.path.join(SYSTEM_STATE_DIR, "updates")
POLICY_DIR = "/etc/clamav-antivirus"
POLICY_FILE = os.path.join(POLICY_DIR, "policy.json")          # déployé par dukiwi-kit (root)
ALLOWLIST_URL = os.environ.get("CLAMAV_ANTIVIRUS_ALLOWLIST_URL", "https://www.dukiwi.com/repo/api/allowlist.json")
TELEMETRY_URL = os.environ.get("CLAMAV_ANTIVIRUS_TELEMETRY_URL", "https://www.dukiwi.com/repo/api/telemetry.php")
ALLOWLIST_FILE = os.path.join(SYSTEM_STATE_DIR, "allowlist.json")
BLOCKLIST_FILE = os.path.join(SYSTEM_STATE_DIR, "ip-blocklist.txt")
BLOCKLIST_URLS = {
    "feodo": "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
    "sslbl": "https://sslbl.abuse.ch/blacklist/sslipblacklist.txt",
}
OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/"
GEOIP_FIELDS = "status,country,countryCode,org,isp,query"
GEOIP_FREE_URL = "http://ip-api.com/batch?fields=" + GEOIP_FIELDS        # gratuit : HTTP seulement, 15 requêtes groupées/min
GEOIP_PRO_URL = "https://pro.ip-api.com/batch?key={key}&fields=" + GEOIP_FIELDS   # offre Pro : HTTPS, sans limite
GEOIP_MIN_INTERVAL = 5          # secondes entre deux requêtes groupées (≤ 12/min, sous la limite gratuite)
GEOIP_CACHE_MAX = 2000          # adresses gardées en cache (24 h), persistées dans l'état du service


def geoip_url(key):
    key = (key or "").strip()
    return GEOIP_PRO_URL.format(key=urllib.parse.quote(key, safe="")) if key else GEOIP_FREE_URL
UNLOCK_TTL = 900
ADMIN_GROUPS = ("sudo", "admin", "wheel")
USER_AGENT = f"clamav-antivirus/{VERSION}"
LOG_MAX_BYTES = 5 * 1024 * 1024
PROGRESS_INTERVAL = 0.25      # secondes entre deux événements de progression
PROGRESS_SAVE_INTERVAL = 2.0  # secondes entre deux sauvegardes du fichier de reprise
CLAMD_CONF = "/etc/clamav/clamd.conf"
USB_MANIFEST = ".clamav"       # manifeste caché à la racine d'un support amovible déjà analysé
SCAN_BATCH = 100               # fichiers par appel clamdscan (un worker = une connexion clamd)
SCAN_WORKERS_MAX = 8
MANIFEST_MAX_FILES = 200000
HISTORY_MAX = 20
ALERTS_MAX = 30
SYSTEM_STATUS_MIN_INTERVAL = 300   # secondes entre deux relevés apt à la demande
TEST_MODE = os.geteuid() != 0 and "CLAMAV_ANTIVIRUS_SOCKET" in os.environ

# Sorties d'outils analysées en anglais quelle que soit la langue du système : systemd donne au service la locale
# de /etc/default/locale (LANG=fr_CH.UTF-8 → « ufw status » répond « État : actif », « Partout »…) et l'analyse
# croyait alors le pare-feu inactif après une activation réussie. Les messages propres au programme sont traduits
# par l'interface, pas par la locale du service.
os.environ["LC_ALL"] = "C.UTF-8"
os.environ["LANG"] = "C.UTF-8"
os.environ.pop("LANGUAGE", None)


def now_iso():
    return datetime.now().isoformat(timespec="seconds")


def log(msg):
    """Journal du daemon (journald via stdout)."""
    print(f"[{now_iso()}] {msg}", flush=True)


def run_quiet(cmd, timeout=60):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except Exception as e:  # noqa: BLE001
        return subprocess.CompletedProcess(cmd, 1, "", str(e))


def http_get(url, timeout=60, data=None, headers=None):
    """GET/POST simple (urllib) avec User-Agent ; retourne bytes ; lève en cas d'erreur."""
    req = urllib.request.Request(url, data=data, headers={"User-Agent": USER_AGENT, **(headers or {})})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def gpg_verify(sig_path, data_path):
    """Vérifie une signature détachée avec la clé publique Dukiwi embarquée."""
    if not os.path.exists(KEYRING):
        return False, "no_keyring"
    if not shutil.which("gpgv"):
        return False, "no_gpgv"
    r = run_quiet(["gpgv", "--keyring", KEYRING, sig_path, data_path], timeout=30)
    return r.returncode == 0, ((r.stderr or "") + (r.stdout or "")).strip()[-300:]


def version_gt(a, b):
    r = run_quiet(["dpkg", "--compare-versions", str(a), "gt", str(b)], timeout=10)
    return r.returncode == 0


def uid_groups(uid):
    try:
        pw = pwd.getpwuid(uid)
    except KeyError:
        return []
    groups = [g.gr_name for g in grp.getgrall() if pw.pw_name in g.gr_mem]
    try:
        groups.append(grp.getgrgid(pw.pw_gid).gr_name)
    except KeyError:
        pass
    return groups


def is_public_ip(ip):
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast or addr.is_reserved)


def ubuntu_osv_ecosystem():
    codename = ""
    try:
        with open("/etc/os-release") as f:
            for line in f:
                if line.startswith("UBUNTU_CODENAME="):
                    codename = line.split("=", 1)[1].strip().strip('"')
    except OSError:
        pass
    return {"noble": "Ubuntu:24.04:LTS", "jammy": "Ubuntu:22.04:LTS", "focal": "Ubuntu:20.04:LTS",
            "questing": "Ubuntu:25.10", "plucky": "Ubuntu:25.04"}.get(codename, "Ubuntu:24.04:LTS")


# ═══════════════════════════════════════════════════════════════════════════
# État persistant
# ═══════════════════════════════════════════════════════════════════════════

class State:
    def __init__(self):
        self.lock = threading.Lock()
        self.data = self._load()

    def _load(self):
        try:
            with open(SYSTEM_STATE_FILE) as f:
                return json.load(f)
        except Exception:
            return {}

    def get(self, key, default=None):
        with self.lock:
            return self.data.get(key, default)

    def snapshot(self):
        with self.lock:
            return dict(self.data)

    def update(self, **kwargs):
        with self.lock:
            self.data.update(kwargs)
            self._save()

    def prepend(self, key, entry, limit):
        with self.lock:
            items = self.data.get(key, [])
            items.insert(0, entry)
            self.data[key] = items[:limit]
            self._save()

    def _save(self):
        tmp = SYSTEM_STATE_FILE + ".tmp"
        with open(tmp, "w") as f:
            json.dump(self.data, f, indent=2, ensure_ascii=False)
        os.chmod(tmp, 0o644)
        os.replace(tmp, SYSTEM_STATE_FILE)


class Settings:
    """Réglages système (page Paramètres), persistés dans settings.json."""

    def __init__(self):
        self.lock = threading.Lock()
        try:
            with open(SYSTEM_SETTINGS_FILE) as f:
                stored = json.load(f)
        except Exception:
            stored = {}
        self.data, _ = sanitize_settings({}, stored)

    def get(self, key):
        with self.lock:
            return self.data.get(key, DEFAULT_SETTINGS.get(key))

    def snapshot(self):
        with self.lock:
            return dict(self.data)

    def update(self, incoming):
        with self.lock:
            merged, errors = sanitize_settings(self.data, incoming)
            changed = {k: v for k, v in merged.items() if self.data.get(k) != v}
            self.data = merged
            tmp = SYSTEM_SETTINGS_FILE + ".tmp"
            with open(tmp, "w") as f:
                json.dump(self.data, f, indent=2)
            os.chmod(tmp, 0o644)
            os.replace(tmp, SYSTEM_SETTINGS_FILE)
        return changed, errors


# ═══════════════════════════════════════════════════════════════════════════
# Jobs
# ═══════════════════════════════════════════════════════════════════════════

# ── Moteur : clamd (base en mémoire, multi-thread) ───────────────────────
def clamd_socket_path():
    try:
        with open(CLAMD_CONF, encoding="utf-8", errors="replace") as f:
            for ln in f:
                ln = ln.strip()
                if ln.startswith("LocalSocket ") or ln.startswith("LocalSocket\t"):
                    return ln.split(None, 1)[1].strip()
    except OSError:
        pass
    return "/var/run/clamav/clamd.ctl"


def clamd_ping(timeout=5):
    """clamd répond-il sur son socket ? (PING → PONG)"""
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect(clamd_socket_path())
        s.sendall(b"zPING\0")
        data = s.recv(64)
        s.close()
        return b"PONG" in data
    except OSError:
        return False


def ensure_clamd(wait=90):
    """clamd garde la base de signatures en mémoire et analyse plusieurs fichiers en parallèle : c'est le moteur
    rapide. Démarré si nécessaire (clamscan recharge la base à chaque lancement)."""
    if clamd_ping():
        return True
    if os.geteuid() != 0 or not shutil.which("clamdscan"):
        return False
    run_quiet(["systemctl", "start", "clamav-daemon"], timeout=30)
    deadline = time.time() + wait
    while time.time() < deadline:
        if clamd_ping():
            return True
        time.sleep(2)
    return False


_DB_VERSION = {"v": "", "at": 0.0}


def signature_db_version():
    """Version de la base quotidienne (pour dater les manifestes), lue au plus toutes les 10 min."""
    if time.time() - _DB_VERSION["at"] < 600:
        return _DB_VERSION["v"]
    v = ""
    r = run_quiet(["clamscan", "--version"], timeout=30)
    m = re.search(r"/(\d+)/", r.stdout or "")
    if m:
        v = m.group(1)
    else:
        for name in ("daily.cld", "daily.cvd"):
            p = f"/var/lib/clamav/{name}"
            if os.path.exists(p):
                v = str(int(os.path.getmtime(p)))
                break
    _DB_VERSION.update(v=v, at=time.time())
    return v


def parse_find_line(line):
    """Ligne « chemin\ttaille\tmtime\tctime\tinode » (find -printf) → (chemin, taille, mtime_µs, ctime_µs, inode)."""
    parts = line.rstrip("\n").split("\t")
    if len(parts) < 5:
        return parts[0], 0, 0, 0, 0

    def micro(x):
        if "." not in x:                      # déjà en microsecondes (liste de travail relue)
            return int(x)
        s, _, f = x.partition(".")
        return int(s) * 1000000 + int((f + "000000")[:6])
    try:
        return parts[0], int(parts[1]), micro(parts[2]), micro(parts[3]), int(parts[4])
    except ValueError:
        return parts[0], 0, 0, 0, 0


class ScanCache:
    """Fichiers déjà vérifiés sains : empreinte (taille, mtime, ctime, inode) → pas relus tant qu'ils n'ont pas
    changé, pendant `days` jours. SQLite dans /var/lib/clamav-antivirus/scan-cache.db (des millions d'entrées)."""

    def __init__(self, path, days):
        self.days = int(days or 0)
        self.db = sqlite3.connect(path, check_same_thread=False, timeout=30)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=OFF")
        self.db.execute("CREATE TABLE IF NOT EXISTS files (path TEXT PRIMARY KEY, size INTEGER, mtime INTEGER, "
                        "ctime INTEGER, ino INTEGER, scanned_at INTEGER)")
        self.lock = threading.Lock()

    def lookup(self, entries):
        """Chemins de `entries` (tuples find) connus sains, inchangés et assez récents."""
        if not self.days or not entries:
            return set()
        since = int(time.time()) - self.days * 86400
        out = set()
        with self.lock:
            for i in range(0, len(entries), 500):
                chunk = entries[i:i + 500]
                marks = ",".join("?" * len(chunk))
                rows = self.db.execute(f"SELECT path,size,mtime,ctime,ino,scanned_at FROM files WHERE path IN ({marks})",
                                       [e[0] for e in chunk]).fetchall()
                known = {r[0]: r for r in rows}
                for e in chunk:
                    r = known.get(e[0])
                    if r and r[5] >= since and (r[1], r[2], r[3], r[4]) == (e[1], e[2], e[3], e[4]):
                        out.add(e[0])
        return out

    def record(self, entries):
        if not entries:
            return
        now = int(time.time())
        with self.lock:
            self.db.executemany("INSERT OR REPLACE INTO files(path,size,mtime,ctime,ino,scanned_at) VALUES (?,?,?,?,?,?)",
                                [(e[0], e[1], e[2], e[3], e[4], now) for e in entries])
            self.db.commit()

    def purge(self, keep_days=90):
        with self.lock:
            self.db.execute("DELETE FROM files WHERE scanned_at < ?", (int(time.time()) - keep_days * 86400,))
            self.db.commit()

    def count(self):
        with self.lock:
            return self.db.execute("SELECT COUNT(*) FROM files").fetchone()[0]

    def close(self):
        with self.lock:
            try:
                self.db.commit()
                self.db.close()
            except sqlite3.Error:
                pass


# ── Manifeste .clamav d'un support amovible ───────────────────────────────
def usb_secret():
    """Secret HMAC de l'installation (jamais copié sur la clé) : un manifeste forgé par la clé est ignoré."""
    try:
        with open(SYSTEM_SECRET_FILE, "rb") as f:
            s = f.read()
        if len(s) >= 32:
            return s
    except OSError:
        pass
    s = os.urandom(32)
    try:
        fd = os.open(SYSTEM_SECRET_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        os.write(fd, s)
        os.close(fd)
    except OSError:
        pass
    return s


def manifest_sign(data):
    body = json.dumps({k: v for k, v in data.items() if k != "hmac"}, sort_keys=True, separators=(",", ":")).encode()
    return hmac.new(usb_secret(), body, hashlib.sha256).hexdigest()


def usb_manifest_read(mountpoint):
    """Manifeste .clamav d'un support déjà analysé ; None s'il manque, s'il est illisible ou s'il n'est pas signé
    par cette installation."""
    path = os.path.join(mountpoint, USB_MANIFEST)
    try:
        if os.path.getsize(path) > 64 * 2 ** 20:
            return None
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict) or data.get("format") != 1 or not isinstance(data.get("files"), dict):
        return None
    if not hmac.compare_digest(str(data.get("hmac") or ""), manifest_sign(data)):
        return None
    return data


def manifest_fresh(manifest, days):
    try:
        age = time.time() - datetime.fromisoformat(manifest.get("scanned_at", "")).timestamp()
    except (TypeError, ValueError):
        return False
    return days > 0 and age < days * 86400


def usb_manifest_write(mountpoint, files, db_version, infected):
    """Écrit .clamav (caché) à la racine : fichiers sains {chemin relatif: [taille, mtime_µs]}, signés."""
    data = {"format": 1, "app": "clamav-antivirus", "version": VERSION, "scanned_at": now_iso(), "db": db_version,
            "files": files, "infected": sorted(infected)[:1000]}
    data["hmac"] = manifest_sign(data)
    path = os.path.join(mountpoint, USB_MANIFEST)
    tmp = path + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, separators=(",", ":"))
        os.replace(tmp, path)
        return True
    except OSError as e:
        log(f"Manifeste USB non écrit ({mountpoint}) : {e}")
        try:
            os.remove(tmp)
        except OSError:
            pass
        return False


class Job:
    _counter = 0
    _counter_lock = threading.Lock()

    def __init__(self, kind, path=None, resume=False, auto=False, requested_by=None, usb=None, integrity=False, use_cache=True):
        with Job._counter_lock:
            Job._counter += 1
            self.id = Job._counter
        self.kind = kind            # 'scan' | 'update'
        self.path = path
        self.resume = resume
        self.auto = auto            # lancé par le système (première installation, reprise)
        self.usb = usb              # dict décrivant le support USB analysé, ou None
        self.integrity = integrity  # analyse complète : vérification d'intégrité (rootkits, paquets) AVANT le scan
        self.skipped = 0            # fichiers système vérifiés par debsums, ignorés par l'antivirus
        self.cached = 0             # fichiers inchangés déjà vérifiés sains (cache ou manifeste .clamav), non relus
        self.use_cache = use_cache
        self.engine = ""            # clamd | clamscan
        self.paused = False         # mis en pause pour analyser une clé USB, reprise ensuite
        self.pause_event = threading.Event()
        self.procs = []             # workers clamdscan en cours
        self.count_lock = threading.Lock()
        self.manifest_keep = {}     # support amovible : fichiers sains {relatif: [taille, mtime]}
        self.usb_infected = set()
        self.found_sigs = {}        # chemin infecté → signature (pour l'index de quarantaine)
        self.integrity_warnings = None
        self.requested_by = requested_by
        self.created_at = time.time()
        self.started_at = None
        self.cancel_event = threading.Event()
        self.cancelled_by_user = False
        self.result = None          # (status, msg_key, msg_params) une fois terminé
        self.proc = None
        self.proc_lock = threading.Lock()
        # progression
        self.phase = "queued"       # queued | prepare | counting | scanning | updating | done
        self.scanned = 0
        self.total = 0
        self.found = 0              # fichiers trouvés pendant l'inventaire
        self.infected = 0
        self.denied = 0
        self.errors = 0
        self.current_file = ""
        self.threats = []

    def public(self):
        return {
            "id": self.id,
            "kind": self.kind,
            "path": self.path,
            "resume": self.resume,
            "auto": self.auto,
            "usb": self.usb,
            "integrity": self.integrity,
            "skipped": self.skipped,
            "cached": self.cached,
            "engine": self.engine,
            "paused": self.paused,
            "integrity_warnings": self.integrity_warnings,
            "phase": self.phase,
            "scanned": self.scanned,
            "total": self.total,
            "found": self.found,
            "infected": self.infected,
            "denied": self.denied,
            "errors": self.errors,
            "file": self.current_file,
            "threats": self.threats[-50:],
            "started_at": self.started_at,
            "elapsed": (time.time() - self.started_at) if self.started_at else 0,
            "source": "daemon",
        }

    def _signal_procs(self, sig):
        with self.proc_lock:
            for p in [self.proc] + list(self.procs):
                if p and p.poll() is None:
                    try:
                        os.kill(p.pid, sig)
                    except OSError:
                        pass

    def pause(self):
        """Clé USB insérée : le scan en cours s'arrête (workers suspendus), reprend après l'analyse de la clé."""
        self.paused = True
        self.pause_event.set()
        self._signal_procs(signal.SIGSTOP)

    def unpause(self):
        self.paused = False
        self.pause_event.clear()
        self._signal_procs(signal.SIGCONT)

    def cancel(self, by_user=False):
        self.cancelled_by_user = self.cancelled_by_user or by_user
        self.cancel_event.set()
        if self.paused:
            self.unpause()
        with self.proc_lock:
            for p in [self.proc] + list(self.procs):
                if p and p.poll() is None:
                    try:
                        p.terminate()
                    except OSError:
                        pass


# ═══════════════════════════════════════════════════════════════════════════
# Moniteur d'activité (fanotify) — rafales d'écritures par processus
# ═══════════════════════════════════════════════════════════════════════════

FAN_CLOEXEC = 0x01
FAN_CLASS_NOTIF = 0x00
FAN_UNLIMITED_QUEUE = 0x10
FAN_MARK_ADD = 0x01
FAN_MARK_FILESYSTEM = 0x100
FAN_CLOSE_WRITE = 0x08
AT_FDCWD = -100
O_LARGEFILE = 0o100000
FAN_EVENT = struct.Struct("=IBBHQii")   # event_len, vers, reserved, metadata_len, mask, fd, pid

TRUSTED_EXE_PREFIXES = ("/usr/", "/bin/", "/sbin/", "/lib", "/opt/", "/snap/", "/var/lib/flatpak/", "/app/")
UNTRUSTED_EXE_PREFIXES = ("/tmp/", "/var/tmp/", "/dev/shm/", "/run/user/", "/home/", "/root/", "/media/", "/mnt/")


def load_policy():
    """Politique d'entreprise (/etc/clamav-antivirus/policy.json) : fichier root, non modifiable par les autres,
    signature détachée facultative (policy.json.sig, clé policy-key.gpg du même dossier ou clé Dukiwi)."""
    try:
        st = os.stat(POLICY_FILE)
    except OSError:
        return {}
    if st.st_uid != 0 or (st.st_mode & 0o022):
        log("Politique ignorée : policy.json doit appartenir à root et ne pas être modifiable par d'autres")
        return {}
    try:
        with open(POLICY_FILE, encoding="utf-8") as f:
            policy = json.load(f)
    except (OSError, ValueError) as e:
        log(f"Politique illisible : {e}")
        return {}
    if not isinstance(policy, dict):
        return {}
    sig = POLICY_FILE + ".sig"
    if os.path.exists(sig):
        keyring = os.path.join(POLICY_DIR, "policy-key.gpg")
        r = run_quiet(["gpgv", "--keyring", keyring if os.path.exists(keyring) else KEYRING, sig, POLICY_FILE], timeout=30)
        if r.returncode != 0:
            log("Politique ignorée : signature invalide")
            return {}
        policy["_signed"] = True
    policy["_mtime"] = st.st_mtime
    return policy


def anonymize_path(path):
    return re.sub(r"^/home/[^/]+", "/home/~", str(path or ""))


def normalize_exe(exe):
    """Chemin de l'exécutable sans le suffixe « (deleted) » (binaire remplacé par une mise à jour pendant l'exécution)."""
    exe = (exe or "").strip()
    if exe.endswith(" (deleted)"):
        exe = exe[:-len(" (deleted)")]
    return exe


class ActivityMonitor(threading.Thread):
    """Détecte les processus qui modifient beaucoup de fichiers en peu de temps."""

    def __init__(self, daemon):
        super().__init__(daemon=True, name="activity-monitor")
        self.daemon_ref = daemon
        self.fd = None
        self.active = False
        self.tracks = {}            # pid -> dict
        self.reported = {}          # pid -> timestamp du dernier signalement
        self.last_report = 0
        self.dpkg_cache = {}
        self.self_pid = os.getpid()

    # ── fanotify ─────────────────────────────────────────────────────────
    def _init_fanotify(self):
        libc = ctypes.CDLL(None, use_errno=True)
        libc.fanotify_init.argtypes = [ctypes.c_uint, ctypes.c_uint]
        libc.fanotify_mark.argtypes = [ctypes.c_int, ctypes.c_uint, ctypes.c_uint64,
                                       ctypes.c_int, ctypes.c_char_p]
        fd = libc.fanotify_init(FAN_CLASS_NOTIF | FAN_CLOEXEC | FAN_UNLIMITED_QUEUE,
                                os.O_RDONLY | O_LARGEFILE | os.O_CLOEXEC)
        if fd < 0:
            raise OSError(ctypes.get_errno(), "fanotify_init")
        marked = 0
        for path in ("/", "/home"):
            if not os.path.isdir(path):
                continue
            rc = libc.fanotify_mark(fd, FAN_MARK_ADD | FAN_MARK_FILESYSTEM, FAN_CLOSE_WRITE,
                                    AT_FDCWD, path.encode())
            if rc == 0:
                marked += 1
        if not marked:
            os.close(fd)
            raise OSError(ctypes.get_errno(), "fanotify_mark")
        return fd

    def run(self):
        try:
            self.fd = self._init_fanotify()
        except OSError as e:
            log(f"Moniteur d'activité indisponible ({e}) — surveillance des rafales désactivée")
            return
        self.active = True
        log("Moniteur d'activité (fanotify) actif")
        while not self.daemon_ref.shutdown.is_set():
            try:
                buf = os.read(self.fd, 65536)
            except OSError:
                break
            off = 0
            while off + FAN_EVENT.size <= len(buf):
                event_len, _v, _r, _ml, mask, fd, pid = FAN_EVENT.unpack_from(buf, off)
                if event_len < FAN_EVENT.size:
                    break
                off += event_len
                if fd < 0:
                    continue
                try:
                    if pid != self.self_pid and mask & FAN_CLOSE_WRITE:
                        try:
                            path = os.readlink(f"/proc/self/fd/{fd}")
                        except OSError:
                            path = None
                        if path:
                            self.record(pid, path)
                finally:
                    try:
                        os.close(fd)
                    except OSError:
                        pass
        self.active = False

    def stop(self):
        if self.fd is not None:
            try:
                os.close(self.fd)
            except OSError:
                pass

    # ── Suivi ────────────────────────────────────────────────────────────
    @staticmethod
    def ignored(path):
        if path.startswith(BURST_IGNORE_PREFIXES):
            return True
        return any(part in path for part in BURST_IGNORE_PARTS)

    def record(self, pid, path):
        if self.ignored(path) or not self.daemon_ref.settings.get("burst_monitor"):
            return
        now = time.time()
        window = self.daemon_ref.settings.get("burst_window_sec")
        track = self.tracks.get(pid)
        if track is None or now - track["first"] > window:
            track = {"first": now, "paths": set(), "home": 0, "count": 0}
            self.tracks[pid] = track
            if len(self.tracks) > 2000:      # limiter la mémoire : purger les vieux suivis
                cutoff = now - window
                self.tracks = {p: tr for p, tr in self.tracks.items() if tr["first"] >= cutoff}
        if path in track["paths"]:
            return
        if len(track["paths"]) < 400:
            track["paths"].add(path)
        track["count"] += 1
        if path.startswith("/home/") or path.startswith("/root/"):
            track["home"] += 1
        info_th = self.daemon_ref.settings.get("burst_info_threshold")
        danger_th = self.daemon_ref.settings.get("burst_danger_threshold")
        if track["count"] in (danger_th, info_th, 150, 500, 2000):
            self.evaluate(pid, track, now)

    # ── Évaluation ───────────────────────────────────────────────────────
    def process_info(self, pid):
        info = {"pid": pid, "comm": "?", "exe": "", "cmdline": "", "uid": None, "user": ""}
        try:
            with open(f"/proc/{pid}/comm") as f:
                info["comm"] = f.read().strip()
        except OSError:
            pass
        try:
            info["exe"] = os.readlink(f"/proc/{pid}/exe")
        except OSError:
            pass
        try:
            with open(f"/proc/{pid}/cmdline", "rb") as f:
                info["cmdline"] = f.read().replace(b"\0", b" ").decode(errors="replace").strip()[:300]
        except OSError:
            pass
        try:
            with open(f"/proc/{pid}/status") as f:
                for line in f:
                    if line.startswith("Uid:"):
                        info["uid"] = int(line.split()[1])
                        break
            if info["uid"] is not None:
                info["user"] = pwd.getpwuid(info["uid"]).pw_name
        except (OSError, KeyError, ValueError):
            pass
        return info

    def exe_trusted(self, exe):
        """Exécutable connu du système (paquet dpkg / emplacement système) ou approuvé par l'utilisateur (« C'est moi ») ?"""
        exe = normalize_exe(exe)
        if not exe:
            return False
        if exe in self.daemon_ref.user_trusted() or self.daemon_ref.central_trusted(exe):
            return True
        if exe.startswith(UNTRUSTED_EXE_PREFIXES):
            return False
        if not exe.startswith(TRUSTED_EXE_PREFIXES):
            return False
        if exe.startswith(("/snap/", "/var/lib/flatpak/", "/app/", "/opt/")):
            return True
        if exe in self.dpkg_cache:
            return self.dpkg_cache[exe]
        r = run_quiet(["dpkg", "-S", exe], timeout=15)
        owned = r.returncode == 0
        if len(self.dpkg_cache) > 500:
            self.dpkg_cache.clear()
        self.dpkg_cache[exe] = owned
        return owned

    @staticmethod
    def clamd_check(paths):
        """Analyse rapide via clamd (clamdscan --fdpass). Retourne la liste des FOUND."""
        found = []
        if not shutil.which("clamdscan") or not paths:
            return found
        r = run_quiet(["clamdscan", "--fdpass", "--no-summary", "--infected"] + list(paths), timeout=60)
        for line in (r.stdout or "").splitlines():
            if line.endswith(" FOUND"):
                found.append(line)
        return found

    def evaluate(self, pid, track, now):
        if now - self.reported.get(pid, 0) < BURST_PID_COOLDOWN_SEC:
            return
        info = self.process_info(pid)
        if info["comm"] in ("clamscan", "clamd", "clamdscan", "freshclam", "find") and \
                info["exe"].startswith("/usr/"):
            return
        exe_path = normalize_exe(info["exe"])
        if exe_path and exe_path in self.daemon_ref.user_trusted():
            self.reported[pid] = now          # programme approuvé : plus aucune alerte
            return
        trusted = self.exe_trusted(info["exe"])
        infected_exe = self.clamd_check([exe_path]) if exe_path and os.path.exists(exe_path) else []
        sample = sorted(track["paths"])[:200]
        infected_files = self.clamd_check(sample[:12])
        severity = "info"
        reasons = []
        if infected_exe:
            severity = "danger"
            reasons.append("exe_infected")
        if infected_files:
            severity = "danger"
            reasons.append("files_infected")
        if not trusted and track["home"] >= self.daemon_ref.settings.get("burst_danger_threshold"):
            severity = "danger"
            reasons.append("untrusted_home_burst")
        if not trusted and exe_path.startswith(("/tmp/", "/var/tmp/", "/dev/shm/")):
            severity = "danger"
            reasons.append("exe_in_temp")
        if severity == "info" and track["count"] < self.daemon_ref.settings.get("burst_info_threshold"):
            return
        if severity == "info" and now - self.last_report < BURST_GLOBAL_COOLDOWN:
            return
        self.reported[pid] = now
        self.last_report = now
        # Dossier le plus touché (pour proposer une analyse ciblée)
        dirs = {}
        for p in sample:
            d = os.path.dirname(p)
            dirs[d] = dirs.get(d, 0) + 1
        top_dir = max(dirs, key=dirs.get) if dirs else "/"
        alert = {
            "kind": "burst",
            "time": now_iso(), "severity": severity, "reasons": reasons,
            "pid": pid, "comm": info["comm"], "exe": info["exe"], "cmdline": info["cmdline"],
            "user": info["user"], "trusted": trusted, "exe_replaced": info["exe"].endswith(" (deleted)"),
            "count": track["count"], "home_count": track["home"],
            "window": self.daemon_ref.settings.get("burst_window_sec"),
            "sample": sample[:8], "top_dir": top_dir,
            "infected_exe": infected_exe, "infected_files": infected_files,
        }
        self.daemon_ref.publish_alert(alert)


# ═══════════════════════════════════════════════════════════════════════════
# Surveillance du volume envoyé vers Internet (/proc/net/dev)
# ═══════════════════════════════════════════════════════════════════════════

IGNORED_IFACE_PREFIXES = ("lo", "docker", "veth", "br-", "virbr", "vboxnet", "lxc", "lxdbr", "cni")


def read_tx_bytes():
    """Octets transmis, cumulés sur les interfaces physiques/VPN (hors loopback et ponts locaux)."""
    total = 0
    per_iface = {}
    try:
        with open("/proc/net/dev") as f:
            for line in f.readlines()[2:]:
                name, _, rest = line.partition(":")
                name = name.strip()
                if name.startswith(IGNORED_IFACE_PREFIXES):
                    continue
                fields = rest.split()
                if len(fields) >= 9:
                    tx = int(fields[8])
                    per_iface[name] = tx
                    total += tx
    except (OSError, ValueError):
        pass
    return total, per_iface


def outbound_processes(limit=8):
    """Processus ayant des connexions sortantes établies (via ss)."""
    procs = {}
    r = run_quiet(["ss", "-Htnp", "state", "established"], timeout=10)
    for line in (r.stdout or "").splitlines():
        for m in re.finditer(r'\("([^"]+)",pid=(\d+)', line):
            name, pid = m.group(1), int(m.group(2))
            entry = procs.setdefault((name, pid), {"name": name, "pid": pid, "connections": 0})
            entry["connections"] += 1
    return sorted(procs.values(), key=lambda p: -p["connections"])[:limit]


class NetworkMonitor(threading.Thread):
    """Alerte quand le volume envoyé dépasse le seuil configuré dans la fenêtre configurée."""

    INTERVAL = 15

    def __init__(self, daemon):
        super().__init__(daemon=True, name="network-monitor")
        self.daemon_ref = daemon
        self.samples = deque()      # (timestamp, tx_total)
        self.last_alert = 0
        self.active = False
        self.current_gb = 0.0

    def run(self):
        self.active = True
        while not self.daemon_ref.shutdown.is_set():
            try:
                self.tick()
            except Exception as e:  # noqa: BLE001
                log(f"Réseau : {e}")
            self.daemon_ref.shutdown.wait(self.INTERVAL)
        self.active = False

    def tick(self):
        settings = self.daemon_ref.settings
        now = time.time()
        total, per_iface = read_tx_bytes()
        window = float(settings.get("upload_window_hours")) * 3600
        self.samples.append((now, total))
        while len(self.samples) > 1 and now - self.samples[0][0] > window:
            self.samples.popleft()
        oldest_t, oldest_tx = self.samples[0]
        sent = max(0, total - oldest_tx)       # un compteur qui repart (reboot) donne 0
        self.current_gb = sent / 1e9
        if not settings.get("upload_monitor"):
            return
        threshold = float(settings.get("upload_alert_gb")) * 1e9
        if sent >= threshold and now - self.last_alert > window:
            self.last_alert = now
            alert = {
                "kind": "upload", "severity": "info", "time": now_iso(),
                "bytes": sent, "gb": round(sent / 1e9, 2), "window_hours": settings.get("upload_window_hours"),
                "threshold_gb": settings.get("upload_alert_gb"),
                "since": datetime.fromtimestamp(oldest_t).isoformat(timespec="seconds"),
                "processes": outbound_processes(), "ifaces": per_iface,
                "comm": "", "pid": 0, "count": 0, "top_dir": "", "reasons": [], "sample": [],
            }
            self.daemon_ref.publish_alert(alert)


# ═══════════════════════════════════════════════════════════════════════════
# Sécurité réseau : pare-feu UFW et service SSH
# ═══════════════════════════════════════════════════════════════════════════

def ssh_port():
    try:
        with open("/etc/ssh/sshd_config") as f:
            for line in f:
                line = line.strip()
                if line.lower().startswith("port ") and not line.startswith("#"):
                    return int(line.split()[1])
    except (OSError, ValueError, IndexError):
        pass
    return 22


TIMESHIFT_CONF = "/etc/timeshift/timeshift.json"
TIMESHIFT_CRON = "/etc/cron.d/timeshift-hourly"


def timeshift_best_practice_config(existing=None):
    """Configuration Timeshift recommandée : instantanés du système sur le disque principal, quotidiens (5),
    hebdomadaires (3), mensuels (2) ; mode btrfs si la racine est un sous-volume @, sinon rsync en excluant tout le
    contenu des dossiers personnels (réglage par défaut de Timeshift : les données cachées — Flatpak, Steam,
    navigateurs — pèsent des dizaines de Go). Les documents relèvent de la sauvegarde."""
    r = run_quiet(["findmnt", "-no", "FSTYPE,UUID,OPTIONS", "/"], timeout=10)
    parts = (r.stdout or "").split()
    fstype, uuid_root, options = (parts + ["", "", ""])[:3]
    btrfs = fstype == "btrfs" and "subvol=/@" in options
    cfg = dict(existing or {})
    cfg.update({
        "backup_device_uuid": uuid_root, "parent_device_uuid": "", "do_first_run": "false",
        "btrfs_mode": "true" if btrfs else "false", "include_btrfs_home": "false", "stop_cron_emails": "true",
        "schedule_monthly": "true", "schedule_weekly": "true", "schedule_daily": "true", "schedule_hourly": "false", "schedule_boot": "false",
        "count_monthly": "2", "count_weekly": "3", "count_daily": "5", "count_hourly": "6", "count_boot": "5",
        "exclude": [] if btrfs else ["/root/**", "/home/*/**"],
        "exclude-apps": cfg.get("exclude-apps") or [],
    })
    return cfg, btrfs


def timeshift_write_config(cfg):
    os.makedirs(os.path.dirname(TIMESHIFT_CONF), exist_ok=True)
    tmp = TIMESHIFT_CONF + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)
    os.chmod(tmp, 0o644)
    os.replace(tmp, TIMESHIFT_CONF)


TIMESHIFT_MIN_FREE = 10 * 1024 ** 3        # sous ce seuil, les instantanés planifiés sont suspendus
TIMESHIFT_GUARD_CRON = ("SHELL=/bin/sh\nPATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin\n"
                        "# ClamAV Antivirus GUI : instantane planifie seulement s'il reste au moins 10 Go sur le disque principal\n"
                        "@hourly root a=$(df -k --output=avail / | tail -n1 | tr -d ' '); [ \"${a:-0}\" -ge 10485760 ] && timeshift --check\n")
DU_EXCLUDES = ["/home", "/root", "/timeshift", "/timeshift-btrfs", "/dev", "/proc", "/sys", "/run", "/tmp", "/media", "/mnt",
               "/var/lib/docker", "/var/lib/schroot", "/snap", "/var/cache/apt/archives", "/var/log", "/swapfile", "/lost+found"]


def estimate_system_size(timeout=900):
    """Taille du système tel que Timeshift le copie en mode rsync (sans les dossiers personnels), en octets ;
    None si du échoue. Une à deux minutes sur un gros système, en priorité basse."""
    cmd = []
    if shutil.which("nice"):
        cmd += ["nice", "-n", "19"]
    if shutil.which("ionice"):
        cmd += ["ionice", "-c", "3"]
    cmd += ["du", "-sxB1"] + [f"--exclude={p}" for p in DU_EXCLUDES] + ["/"]
    r = run_quiet(cmd, timeout=timeout)
    m = re.match(r"\s*(\d+)", r.stdout or "")
    return int(m.group(1)) if m else None


def timeshift_space_needed(size, btrfs=False):
    """Espace libre exigé avant d'activer : 1,2 × le système + 10 Go (première copie complète, puis incréments) ;
    en btrfs les instantanés ne copient rien, seul le seuil minimal s'applique."""
    return TIMESHIFT_MIN_FREE if btrfs else int(size * 1.2) + TIMESHIFT_MIN_FREE


def timeshift_free_bytes(cfg=None):
    """Espace libre (et point de montage) du disque qui reçoit les instantanés : le périphérique configuré s'il est
    monté, le disque principal sinon ; (None, "") si le disque configuré est un disque dédié non monté."""
    uuid = (cfg or {}).get("backup_device_uuid") or ""
    path = "/"
    if uuid:
        r = run_quiet(["findmnt", "-rno", "TARGET", "-S", f"UUID={uuid}"], timeout=10)
        lines = [x.strip() for x in (r.stdout or "").splitlines() if x.strip()]
        if lines:
            path = lines[0]
        else:
            return None, ""
    try:
        st = os.statvfs(path)
        return st.f_bavail * st.f_frsize, path
    except OSError:
        return None, path


def collect_timeshift_status(list_snapshots=True):
    """Instantanés système Timeshift : installé, configuré, planification, dernier instantané (lecture root)."""
    ts = {"checked_at": now_iso(), "installed": shutil.which("timeshift") is not None, "configured": False,
          "schedule": [], "mode": "", "device": "", "snapshots": None, "last": None, "error": ""}
    if not ts["installed"]:
        return ts
    cfg = {}
    try:
        with open(TIMESHIFT_CONF, encoding="utf-8") as f:
            cfg = json.load(f)
        ts["configured"] = True
        ts["mode"] = "btrfs" if str(cfg.get("btrfs_mode", "")).lower() == "true" else "rsync"
        ts["device"] = cfg.get("backup_device_uuid", "") or ""
        ts["schedule"] = [k for k in ("boot", "hourly", "daily", "weekly", "monthly")
                          if str(cfg.get(f"schedule_{k}", "")).lower() == "true"]
    except (OSError, ValueError):
        ts["configured"] = False
    free, _path = timeshift_free_bytes(cfg)
    ts["free_bytes"] = free
    ts["low_space"] = free is not None and free < TIMESHIFT_MIN_FREE
    if ts["configured"] and list_snapshots and os.geteuid() == 0:
        r = run_quiet(["timeshift", "--list", "--scripted"], timeout=120)
        names = sorted(set(re.findall(r"\b(\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2})\b", (r.stdout or ""))))
        if r.returncode == 0 or names:
            ts["snapshots"] = len(names)
            if names:
                ts["last"] = datetime.strptime(names[-1], "%Y-%m-%d_%H-%M-%S").isoformat(timespec="seconds")
        else:
            ts["error"] = ((r.stderr or "") + (r.stdout or "")).strip()[-200:]
    return ts


def collect_security_status():
    """État du pare-feu UFW et du service SSH."""
    ufw = {"installed": shutil.which("ufw") is not None, "active": False, "enabled": False,
           "default_incoming": "", "default_outgoing": "", "rules": [], "error": ""}
    if ufw["installed"]:
        try:
            with open("/etc/ufw/ufw.conf") as f:
                ufw["enabled"] = any(line.strip() == "ENABLED=yes" for line in f)
        except OSError:
            pass
        ufw["active"] = ufw["enabled"] and systemd_is_active("ufw")
        if os.geteuid() == 0:
            r = run_quiet(["ufw", "status", "verbose"], timeout=20)
            if r.returncode == 0:
                ufw.update(parse_ufw_verbose(r.stdout))
                r2 = run_quiet(["ufw", "status", "numbered"], timeout=20)
                ufw["rules"] = parse_ufw_numbered(r2.stdout) if r2.returncode == 0 else []
            else:
                ufw["error"] = (r.stderr or r.stdout or "").strip()[:200]
            if not ufw["active"] and ufw["enabled"] and ufw_chains_loaded():
                ufw["active"] = True                    # sortie de ufw non analysable : les chaînes font foi
            ufw["conflicts"] = firewall_conflicts()
            ufw["unit_enabled"] = unit_enabled("ufw")
        else:
            ufw["error"] = "root_required"
    ssh_installed = shutil.which("sshd") is not None or os.path.exists("/usr/sbin/sshd")
    ssh = {"installed": ssh_installed, "active": False, "enabled": False, "port": ssh_port(),
           "allowed_by_firewall": False}
    if ssh_installed:
        ssh["active"] = systemd_is_active("ssh") or systemd_is_active("sshd")
        r = run_quiet(["systemctl", "is-enabled", "ssh"], timeout=10)
        ssh["enabled"] = (r.stdout or "").strip() == "enabled"
    port = str(ssh["port"])
    ssh["allowed_by_firewall"] = any(
        rule["action"].startswith("ALLOW") and (rule["to"].startswith(port) or "OpenSSH" in rule["to"])
        for rule in ufw["rules"])
    return {"ufw": ufw, "ssh": ssh, "checked_at": now_iso()}


VALID_PROTO = ("tcp", "udp", "any")
FIREWALL_PROFILES = ("home", "public", "enterprise")
PROFILE_TAG = "cav-profile"                     # commentaire des règles gérées par le profil réseau
PROFILE_PRIVATE_NETS = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fe80::/10"]


def unit_active(name):
    r = run_quiet(["systemctl", "is-active", name], timeout=10)
    return (r.stdout or "").strip() == "active"


def unit_enabled(name):
    r = run_quiet(["systemctl", "is-enabled", name], timeout=10)
    return (r.stdout or "").strip() == "enabled"


MINT_AUTOMATION = "/usr/bin/mintupdate-automation"                                  # Linux Mint
MINT_AUTO_UPGRADE_FLAG = "/var/lib/linuxmint/mintupdate-automatic-upgrades-enabled"  # témoin lu par le Gestionnaire
APT_AUTO_CONF = "/etc/apt/apt.conf.d/20auto-upgrades"                                # unattended-upgrades (autres Debian/Ubuntu)


def local_subnets():
    """Sous-réseaux IPv4 directement connectés (ip -j route, scope link), hors interfaces virtuelles."""
    r = run_quiet(["ip", "-j", "route"], timeout=10)
    nets = set()
    try:
        for rt in json.loads(r.stdout or "[]"):
            dst, dev = rt.get("dst", ""), rt.get("dev", "")
            if rt.get("scope") == "link" and "/" in dst and not dev.startswith(("lo", "docker", "br-", "veth", "virbr", "tun", "tap")):
                nets.add(dst)
    except ValueError:
        pass
    return sorted(nets)


def profile_services(profile):
    """Services autorisés depuis le réseau local par le profil, selon ce qui est installé sur la machine."""
    if profile == "public":
        return []
    svc = []
    if unit_active("ssh") or unit_active("sshd"):
        svc.append("ssh")
    if shutil.which("cupsd") or os.path.exists("/usr/sbin/cupsd"):
        svc.append("cups")
    if shutil.which("smbd") or os.path.exists("/usr/sbin/smbd"):
        svc.append("samba")
    if profile == "home":
        svc.append("mdns")
        if shutil.which("kdeconnectd") or glob.glob("/usr/lib/*/libexec/kdeconnectd") or glob.glob("/usr/libexec/kdeconnectd") \
                or glob.glob("/home/*/.local/share/gnome-shell/extensions/gsconnect*"):
            svc.append("kdeconnect")
    return svc


def profile_nets(profile):
    if profile == "public":
        return []
    if profile == "enterprise":
        return (local_subnets() or PROFILE_PRIVATE_NETS[:3]) + ["fe80::/10"]
    return list(PROFILE_PRIVATE_NETS)


def profile_rules(profile):
    """Arguments ufw des règles du profil : autorisations limitées au réseau local, taguées PROFILE_TAG."""
    ports = {"ssh": [(str(ssh_port()), "tcp")], "cups": [("631", "tcp")], "samba": [("139,445", "tcp"), ("137,138", "udp")],
             "mdns": [("5353", "udp")], "kdeconnect": [("1714:1764", "tcp"), ("1714:1764", "udp")]}
    rules = []
    nets = profile_nets(profile)
    for name in profile_services(profile):
        for port, proto in ports[name]:
            for net in nets:
                rules.append(["allow", "from", net, "to", "any", "port", port, "proto", proto, "comment", f"{PROFILE_TAG} {name}"])
    return rules
VALID_ACTION = ("allow", "deny", "reject", "limit")
VALID_POLICY = ("allow", "deny", "reject")
NETWORK_SKIP_TYPES = ("loopback", "vpn", "wireguard", "tun", "tap", "bridge", "dummy", "ip-tunnel")


TRAY_LAUNCHER = "/opt/clamav-antivirus/clamav-antivirus-tray"


def graphical_sessions():
    """Sessions graphiques locales actives : [{id, user, uid, type}] (loginctl)."""
    out = []
    r = run_quiet(["loginctl", "list-sessions", "--no-legend"], timeout=10)
    for ln in (r.stdout or "").splitlines():
        parts = ln.split()
        if not parts:
            continue
        sid = parts[0]
        s = run_quiet(["loginctl", "show-session", sid, "-p", "Type", "-p", "State", "-p", "Name", "-p", "Remote", "-p", "Class"], timeout=10)
        props = dict(kv.split("=", 1) for kv in (s.stdout or "").splitlines() if "=" in kv)
        if props.get("State") != "active" or props.get("Type") not in ("x11", "wayland") or props.get("Remote") == "yes" \
                or props.get("Class", "user") != "user":
            continue
        try:
            uid = pwd.getpwnam(props.get("Name", "")).pw_uid
        except KeyError:
            continue
        if uid >= 1000:
            out.append({"id": sid, "user": props.get("Name"), "uid": uid, "type": props.get("Type")})
    return out


def network_identity():
    """Réseau courant : {key, name, type, device}. Clé stable = connexion NetworkManager qui porte la route par défaut
    (uuid), sinon adresse MAC de la passerelle. None hors ligne."""
    r = run_quiet(["ip", "-j", "route", "show", "default"], timeout=10)
    try:
        routes = json.loads(r.stdout or "[]")
    except ValueError:
        routes = []
    routes = [x for x in routes if x.get("dev")]
    if not routes:
        return None
    routes.sort(key=lambda x: x.get("metric", 0))
    dev, gw = routes[0]["dev"], routes[0].get("gateway", "")
    if shutil.which("nmcli"):
        r = run_quiet(["nmcli", "-t", "-f", "UUID,NAME,TYPE,DEVICE", "connection", "show", "--active"], timeout=10)
        for ln in (r.stdout or "").splitlines():
            parts = [x.replace("\\:", ":") for x in re.split(r"(?<!\\):", ln.strip())]
            if len(parts) < 4 or parts[3] != dev or parts[2] in NETWORK_SKIP_TYPES:
                continue
            kind = "wifi" if "wireless" in parts[2] else "ethernet" if "ethernet" in parts[2] else "other"
            return {"key": f"nm:{parts[0]}", "name": parts[1] or dev, "type": kind, "device": dev}
    mac = ""
    if gw:
        r = run_quiet(["ip", "-j", "neigh", "show", gw], timeout=10)
        try:
            mac = next((x.get("lladdr", "") for x in json.loads(r.stdout or "[]") if x.get("lladdr")), "")
        except ValueError:
            pass
    return {"key": f"gw:{mac or gw or dev}", "name": gw or dev, "type": "ethernet", "device": dev}


UFW_RULE_COMMANDS = ("allow", "deny", "reject", "limit", "insert", "prepend")


UFW_INIT = os.environ.get("CLAMAV_ANTIVIRUS_UFW_INIT") or next((p for p in ("/lib/ufw/ufw-init", "/usr/lib/ufw/ufw-init") if os.path.exists(p)), "/lib/ufw/ufw-init")


def ufw_chains_loaded():
    """Les chaînes UFW existent dans le noyau (même test que ufw-init : « Firewall already started »),
    indépendant de la langue et de ufw.conf. Root seulement ; False si iptables est absent."""
    if os.geteuid() != 0 and not os.environ.get("CLAMAV_ANTIVIRUS_UFW_INIT"):
        return False
    r = run_quiet(["iptables", "-L", "ufw-user-input", "-n"], timeout=15)
    return r.returncode == 0


def firewall_running():
    """True si les chaînes UFW sont réellement chargées : « Status: active », ou chaînes présentes (secours si la
    sortie de ufw n'est pas analysable)."""
    r = run_quiet(["ufw", "status"], timeout=20)
    if r.returncode == 0 and parse_ufw_verbose(r.stdout).get("active"):
        return True
    return ufw_chains_loaded()


def firewall_conflicts():
    """Autres gestionnaires de pare-feu susceptibles d'effacer les règles UFW (au démarrage ou à la volée)."""
    out = []
    if systemd_is_active("firewalld"):
        out.append("firewalld")
    if systemd_is_active("nftables"):
        try:
            with open("/etc/nftables.conf", encoding="utf-8", errors="replace") as f:
                if "flush ruleset" in f.read():
                    out.append("nftables")
        except OSError:
            out.append("nftables")
    if systemd_is_active("netfilter-persistent"):
        out.append("netfilter-persistent")
    return out


def firewall_unit_persist(log_fn):
    """ufw.service démasquée, activée et démarrée : les règles sont rechargées au démarrage et
    « systemctl is-active ufw » reflète l'état réel."""
    if TEST_MODE and not os.environ.get("CLAMAV_ANTIVIRUS_UFW_INIT"):
        return
    r = run_quiet(["systemctl", "is-enabled", "ufw"], timeout=10)
    st = (r.stdout or "").strip()
    if st == "masked":
        run_quiet(["systemctl", "unmask", "ufw"], timeout=30)
    if st != "enabled":
        run_quiet(["systemctl", "enable", "ufw"], timeout=30)
        log_fn(f"ufw.service was {st or 'unknown'}: enabled at boot")
    if not systemd_is_active("ufw"):
        run_quiet(["systemctl", "start", "ufw"], timeout=60)       # ufw-init start quiet : sans effet si déjà chargé


def firewall_enable_checked(ufw, log_fn):
    """« Activer le pare-feu » vérifié. `ufw enable` répond 0 avec « Firewall is active » même quand ufw-init échoue,
    dès que ufw.conf disait déjà ENABLED=yes (frontend.set_enabled ne remonte l'erreur que si l'état a changé) :
    le pare-feu paraît activé mais reste inactif. On contrôle donc l'état réel ; s'il n'est pas chargé, on force
    disable → enable (l'erreur réelle apparaît), puis ufw-init start, et on rend l'erreur à l'utilisateur."""
    ok, text = ufw("enable")
    if ok and firewall_running():
        firewall_unit_persist(log_fn)
        return True, text
    ufw("disable")
    ok2, text2 = ufw("enable")
    if ok2 and firewall_running():
        firewall_unit_persist(log_fn)
        return True, text2
    init = run_quiet([UFW_INIT, "start"], timeout=60)
    init_out = ((init.stdout or "") + (init.stderr or "")).strip()
    if firewall_running():
        firewall_unit_persist(log_fn)
        log_fn(f"firewall loaded by ufw-init after a silent ufw enable: {init_out[:160]}")
        return True, init_out or "loaded by ufw-init"
    parts = [x.strip() for x in ((text2 if not ok2 else ""), init_out) if x and x.strip()]
    detail = " | ".join(dict.fromkeys(parts)) or "firewall not active after enable"
    conflicts = firewall_conflicts()
    log_fn(f"firewall enable failed: {detail[:300]}" + (f" (conflicts: {', '.join(conflicts)})" if conflicts else ""))
    return False, detail[:300]


def ufw_args(args):
    """Arguments complets d'un appel ufw. ufw n'insère le mot-clé implicite « rule » que si la commande est en
    première position : « ufw --force allow … » répond « Invalid syntax » (frontend.parse_command). On écrit donc
    « rule » explicitement pour les commandes de règle ; « delete N » (par numéro) reste tel quel."""
    args = [str(a) for a in args]
    if args and (args[0] in UFW_RULE_COMMANDS or (args[0] == "delete" and len(args) > 1 and not args[1].isdigit())):
        args = ["rule"] + args
    return ["ufw", "--force"] + args


# ═══════════════════════════════════════════════════════════════════════════
# Surveillance des supports USB (udev)
# ═══════════════════════════════════════════════════════════════════════════

class UsbWatcher(threading.Thread):
    """Analyse les clés USB avant leur montage ; demande pour les disques durs USB."""

    def __init__(self, daemon):
        super().__init__(daemon=True, name="usb-watcher")
        self.daemon_ref = daemon
        self.active = False
        self.pending = {}           # devnode -> info (disques volumineux en attente de décision)
        self.mounted = {}           # devnode -> mountpoint (montages privés du daemon)
        self.lock = threading.Lock()

    def run(self):
        try:
            import pyudev
        except ImportError:
            log("pyudev absent — surveillance USB désactivée")
            return
        try:
            ctx = pyudev.Context()
            monitor = pyudev.Monitor.from_netlink(ctx)
            monitor.filter_by("block")
            monitor.start()
        except Exception as e:  # noqa: BLE001
            log(f"Surveillance USB indisponible ({e})")
            return
        self.active = True
        log("Surveillance USB (udev) active")
        while not self.daemon_ref.shutdown.is_set():
            device = monitor.poll(timeout=1)
            if device is None:
                continue
            try:
                self.handle(device)
            except Exception as e:  # noqa: BLE001
                log(f"USB : {e}")
        self.active = False

    def describe(self, device):
        """Informations utiles sur une partition/un disque USB portant un système de fichiers."""
        settings = self.daemon_ref.settings
        max_bytes = int(settings.get("usb_auto_scan_max_gib")) * 1024 ** 3
        auto = bool(settings.get("usb_auto_scan"))
        bus = device.get("ID_BUS")
        parent = device.find_parent("block", "disk") if device.get("DEVTYPE") == "partition" else None
        if bus != "usb" and (parent is None or parent.get("ID_BUS") != "usb"):
            return None
        fstype = device.get("ID_FS_TYPE") or ""
        if not fstype or fstype in ("swap", "LVM2_member", "crypto_LUKS", "linux_raid_member"):
            return None
        try:
            size = int(device.attributes.asstring("size")) * 512
        except Exception:  # noqa: BLE001
            size = 0
        src = parent if parent is not None else device
        try:
            removable = src.attributes.asstring("removable") == "1"
        except Exception:  # noqa: BLE001
            removable = False
        return {
            "devnode": device.device_node,
            "label": device.get("ID_FS_LABEL") or "",
            "fstype": fstype,
            "size": size,
            "vendor": (device.get("ID_VENDOR") or src.get("ID_VENDOR") or "").replace("_", " ").strip(),
            "model": (device.get("ID_MODEL") or src.get("ID_MODEL") or "").replace("_", " ").strip(),
            "serial": device.get("ID_SERIAL_SHORT") or src.get("ID_SERIAL_SHORT") or "",
            "removable": removable,
            "kind": "key" if (auto and size <= max_bytes) else "hdd",
        }

    def handle(self, device):
        action = device.action
        devnode = device.device_node
        if action == "add":
            info = self.describe(device)
            if not info:
                return
            log(f"USB détecté : {devnode} ({info['label'] or info['model']}, "
                f"{info['size'] // 2**20} MiB, {info['kind']})")
            self.daemon_ref.broadcast({"event": "usb_added", "usb": info})
            if info["kind"] == "key":
                self.daemon_ref.start_usb_scan(info)
            else:
                with self.lock:
                    self.pending[devnode] = info
                self.daemon_ref.broadcast({"event": "usb_ask", "usb": info})
        elif action == "remove":
            with self.lock:
                info = self.pending.pop(devnode, None)
            job = self.daemon_ref.current_job()
            if job and job.usb and job.usb.get("devnode") == devnode:
                log(f"USB retiré pendant l'analyse : {devnode}")
                job.usb["removed"] = True
                job.cancel(by_user=True)
            self.unmount(devnode)
            self.daemon_ref.broadcast({"event": "usb_removed", "devnode": devnode, "usb": info})

    # ── Montage privé ────────────────────────────────────────────────────
    def mount(self, info):
        devnode = info["devnode"]
        mountpoint = os.path.join(USB_MOUNT_ROOT, os.path.basename(devnode))
        os.makedirs(mountpoint, exist_ok=True)
        opts = "nosuid,nodev,noexec"
        if info["fstype"] in ("vfat", "exfat", "ntfs"):
            opts += ",umask=077"
        r = run_quiet(["mount", "-o", opts, devnode, mountpoint], timeout=60)
        if r.returncode != 0:
            r = run_quiet(["mount", "-o", "nosuid,nodev,noexec", devnode, mountpoint], timeout=60)
        if r.returncode != 0:
            try:
                os.rmdir(mountpoint)
            except OSError:
                pass
            raise OSError(f"mount {devnode}: {(r.stderr or '').strip()}")
        with self.lock:
            self.mounted[devnode] = mountpoint
        return mountpoint

    def unmount(self, devnode):
        with self.lock:
            mountpoint = self.mounted.pop(devnode, None)
        if not mountpoint:
            return
        for _ in range(5):
            r = run_quiet(["umount", mountpoint], timeout=60)
            if r.returncode == 0:
                break
            time.sleep(1)
        else:
            run_quiet(["umount", "-l", mountpoint], timeout=60)
        try:
            os.rmdir(mountpoint)
        except OSError:
            pass

    def take_pending(self, devnode):
        with self.lock:
            return self.pending.pop(devnode, None)

    def pending_list(self):
        with self.lock:
            return list(self.pending.values())


# ═══════════════════════════════════════════════════════════════════════════
# État du système : mises à jour de sécurité et CVE (apt)
# ═══════════════════════════════════════════════════════════════════════════

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}")
CHANGELOG_HEADER_RE = re.compile(r"^(\S+) \(([^)]+)\) ([^;]+); urgency=", re.M)


def parse_changelog_cves(text, installed_version, compare):
    """CVE mentionnées dans les entrées de changelog plus récentes que la version installée.
    Retourne {cve: titre}."""
    cves = {}
    entries = list(CHANGELOG_HEADER_RE.finditer(text))
    for i, m in enumerate(entries):
        version = m.group(2)
        if installed_version and compare(version, installed_version) <= 0:
            break
        body = text[m.end(): entries[i + 1].start() if i + 1 < len(entries) else len(text)]
        title = ""
        in_title = False
        for line in body.splitlines():
            stripped = line.strip()
            if stripped.startswith("* "):
                title = stripped[2:].strip()
                if title.upper().startswith("SECURITY UPDATE:"):
                    title = title.split(":", 1)[1].strip()
                in_title = True
            elif in_title and stripped and not stripped.startswith("- "):
                title = f"{title} {stripped}"          # suite du titre sur la ligne suivante
            else:
                in_title = False
            for cve in CVE_RE.findall(stripped):
                if cve not in cves or not cves[cve]:
                    cves[cve] = title.rstrip(" .:")
    return cves


def collect_system_status(previous=None):
    """Relevé de l'état du système : paquets à mettre à jour, sécurité, CVE, redémarrage."""
    status = {
        "checked_at": now_iso(), "ok": True, "error": "",
        "os": "", "kernel": "", "reboot_required": False, "reboot_pkgs": [],
        "lists_updated": None, "upgradable": 0, "security": 0,
        "packages": [], "cves": [], "cve_count": 0, "changelog_errors": 0,
    }
    try:
        with open("/etc/os-release") as f:
            for line in f:
                if line.startswith("PRETTY_NAME="):
                    status["os"] = line.split("=", 1)[1].strip().strip('"')
    except OSError:
        pass
    status["kernel"] = os.uname().release
    status["reboot_required"] = os.path.exists("/var/run/reboot-required")
    try:
        with open("/var/run/reboot-required.pkgs") as f:
            status["reboot_pkgs"] = sorted({line.strip() for line in f if line.strip()})
    except OSError:
        pass
    try:
        newest = max(os.stat(os.path.join("/var/lib/apt/lists", n)).st_mtime
                     for n in os.listdir("/var/lib/apt/lists") if n.endswith("Release"))
        status["lists_updated"] = datetime.fromtimestamp(newest).isoformat(timespec="seconds")
    except (OSError, ValueError):
        pass

    try:
        import apt
        import apt_pkg
        cache = apt.Cache()
        compare = apt_pkg.version_compare
    except Exception as e:  # noqa: BLE001
        status["ok"] = False
        status["error"] = f"python3-apt: {e}"
        return status
    try:
        cache.upgrade(dist_upgrade=False)   # simulation en mémoire (rien n'est installé) : ce qu'« apt upgrade » installerait vraiment
        sim_ok = True
    except Exception:  # noqa: BLE001
        sim_ok = False

    packages = []
    for pkg in cache:
        try:
            if not pkg.installed:
                continue
            if pkg.is_upgradable:
                cand = pkg.candidate
                origins = cand.origins if cand else []
                security = any((o.archive or "").endswith("-security") or (o.label or "") == "Debian-Security"
                               for o in origins)
                phase = cand.record.get("Phased-Update-Percentage") if cand else None
                # « apt upgrade » ne l'installerait pas : décalé (phasing) ou retenu (dépendances, « kept back »)
                held = sim_ok and not pkg.marked_upgrade
                category = "security" if security else "recommended"
                if held:
                    category = "phased" if phase is not None else "held"
                packages.append({
                    "name": pkg.name, "installed": pkg.installed.version if pkg.installed else "",
                    "candidate": cand.version if cand else "", "security": security,
                    "category": category, "phase": phase if category == "phased" else None,
                    "archive": origins[0].archive if origins else "", "cves": {},
                })
                continue
            # Mise à jour "décalée" (phased) : une version plus récente existe mais apt la retient
            for ver in pkg.versions:
                if ver > pkg.installed and ver != pkg.candidate and ver.record.get("Phased-Update-Percentage") is not None:
                    origins = ver.origins
                    packages.append({
                        "name": pkg.name, "installed": pkg.installed.version, "candidate": ver.version,
                        "security": any((o.archive or "").endswith("-security") for o in origins),
                        "category": "phased", "phase": ver.record.get("Phased-Update-Percentage"),
                        "archive": origins[0].archive if origins else "", "cves": {},
                    })
                    break
        except Exception:  # noqa: BLE001
            continue
    status["upgradable"] = sum(1 for p in packages if p["category"] in ("security", "recommended"))   # installables maintenant
    status["security"] = sum(1 for p in packages if p["security"] and p["category"] != "phased")       # y compris retenus (à surveiller)
    status["recommended"] = sum(1 for p in packages if p["category"] == "recommended")
    status["phased"] = sum(1 for p in packages if p["category"] == "phased")
    status["held"] = sum(1 for p in packages if p["category"] == "held")

    # CVE : changelog des paquets de sécurité (et du noyau), limité pour rester raisonnable
    prev_pkgs = {p["name"]: p for p in ((previous or {}).get("packages") or [])}
    targets = [p for p in packages if p["security"] or p["name"].startswith("linux-image")][:40]
    env = dict(os.environ, APT_PAGER="cat", LC_ALL="C")
    for p in targets:
        prev = prev_pkgs.get(p["name"])
        if prev and prev.get("candidate") == p["candidate"] and prev.get("cves"):
            p["cves"] = prev["cves"]
            continue
        try:
            r = subprocess.run(["apt-get", "changelog", "-qq", p["name"]], capture_output=True,
                               text=True, timeout=40, env=env)
            if r.returncode == 0 and r.stdout:
                p["cves"] = parse_changelog_cves(r.stdout, p["installed"], compare)
            else:
                status["changelog_errors"] += 1
        except Exception:  # noqa: BLE001
            status["changelog_errors"] += 1
    cves = []
    for p in packages:
        for cve, title in sorted(p["cves"].items(), reverse=True):
            cves.append({"id": cve, "package": p["name"], "candidate": p["candidate"],
                         "installed": p["installed"], "title": title,
                         "url": f"https://ubuntu.com/security/{cve}"})
    status["packages"] = sorted(packages, key=lambda p: ({"security": 0, "recommended": 1, "phased": 2, "held": 3}.get(p["category"], 4), p["name"]))
    status["cves"] = cves
    status["cve_count"] = len(cves)
    return status


# ═══════════════════════════════════════════════════════════════════════════
# Mises à jour de l'application (manifeste signé) et intégrité des fichiers
# ═══════════════════════════════════════════════════════════════════════════

class UpdateChecker:
    def __init__(self, daemon):
        self.daemon_ref = daemon
        self.lock = threading.Lock()

    def check(self, force=False):
        """Télécharge manifest.json + .sig, vérifie la signature, prépare le .deb si plus récent."""
        with self.lock:
            os.makedirs(UPDATES_DIR, exist_ok=True)
            info = {"checked_at": now_iso(), "current": VERSION, "available": False, "verified": False,
                    "downloaded": False, "version": "", "path": "", "sha256": "", "url": "", "error": "",
                    "date": "", "size": 0}
            if not self.daemon_ref.settings.get("app_update_check") and not force:
                info["error"] = "disabled"
                return info
            manifest_path = os.path.join(UPDATES_DIR, "manifest.json")
            sig_path = manifest_path + ".sig"
            try:
                with open(manifest_path, "wb") as f:
                    f.write(http_get(MANIFEST_URL, timeout=30))
                with open(sig_path, "wb") as f:
                    f.write(http_get(MANIFEST_URL + ".sig", timeout=30))
            except Exception as e:  # noqa: BLE001
                info["error"] = f"download:{e}"
                return info
            ok, detail = gpg_verify(sig_path, manifest_path)
            if not ok:
                info["error"] = f"signature:{detail}"
                self.daemon_ref.write_log(f"⚠ update manifest signature INVALID: {detail}")
                return info
            info["verified"] = True
            try:
                with open(manifest_path) as f:
                    manifest = json.load(f)
            except Exception as e:  # noqa: BLE001
                info["error"] = f"manifest:{e}"
                return info
            info.update({k: manifest.get(k, "") for k in ("version", "url", "sha256", "date")})
            info["size"] = int(manifest.get("size") or 0)
            if manifest.get("package") != "clamav-antivirus" or not info["version"]:
                info["error"] = "manifest:invalid"
                return info
            if not version_gt(info["version"], VERSION):
                return info
            info["available"] = True
            deb_path = os.path.join(UPDATES_DIR, os.path.basename(manifest.get("deb") or f"clamav-antivirus_{info['version']}_all.deb"))
            if not (os.path.exists(deb_path) and sha256_file(deb_path) == info["sha256"]):
                try:
                    with open(deb_path + ".part", "wb") as f:
                        f.write(http_get(info["url"], timeout=300))
                    if sha256_file(deb_path + ".part") != info["sha256"]:
                        os.remove(deb_path + ".part")
                        info["error"] = "sha256_mismatch"
                        self.daemon_ref.write_log("⚠ update .deb sha256 MISMATCH — refusé")
                        return info
                    os.replace(deb_path + ".part", deb_path)
                except Exception as e:  # noqa: BLE001
                    info["error"] = f"download_deb:{e}"
                    return info
            info["downloaded"] = True
            info["path"] = deb_path
            return info

    def install(self, info):
        """Installe le .deb vérifié dans une unité transitoire (survit au redémarrage du daemon)."""
        path = info.get("path", "")
        if not (info.get("available") and info.get("verified") and path and os.path.exists(path)):
            return False, "not_ready"
        if sha256_file(path) != info.get("sha256"):
            return False, "sha256_mismatch"
        if TEST_MODE:
            return True, "test_mode"
        unit = f"clamav-antivirus-upgrade-{int(time.time())}"
        r = run_quiet(["systemd-run", "--unit", unit, "--collect", "--quiet",
                       "-p", "Environment=DEBIAN_FRONTEND=noninteractive",
                       "/bin/sh", "-c", f"apt-get install -y --allow-downgrades '{path}'"], timeout=30)
        return r.returncode == 0, ((r.stderr or "") + (r.stdout or "")).strip()[-200:]


def app_integrity():
    """Compare les fichiers installés au manifeste d'intégrité livré dans le paquet."""
    result = {"checked_at": now_iso(), "available": os.path.exists(INTEGRITY_FILE), "signed": False,
              "verified": False, "modified": [], "missing": [], "count": 0, "version": ""}
    if not result["available"]:
        return result
    sig = INTEGRITY_FILE + ".sig"
    if os.path.exists(sig):
        result["signed"] = True
        result["verified"], _ = gpg_verify(sig, INTEGRITY_FILE)
    try:
        with open(INTEGRITY_FILE) as f:
            manifest = json.load(f)
    except Exception:  # noqa: BLE001
        result["available"] = False
        return result
    result["version"] = manifest.get("version", "")
    files = manifest.get("files") or {}
    result["count"] = len(files)
    for rel, digest in files.items():
        full = "/" + rel
        if not os.path.exists(full):
            result["missing"].append(full)
        elif sha256_file(full) != digest:
            result["modified"].append(full)
    return result


# ═══════════════════════════════════════════════════════════════════════════
# Inventaire des failles ouvertes (OSV.dev, écosystème Ubuntu) + Flatpak/Snap
# ═══════════════════════════════════════════════════════════════════════════

PRIORITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "negligible": 4, "untriaged": 5, "": 6}


def installed_sources():
    """{source_package: {"version": source_version, "binaries": [...]}} des paquets installés."""
    r = run_quiet(["dpkg-query", "-W", "-f", "${Package}\t${source:Package}\t${source:Version}\t${Version}\t${db:Status-Status}\n"], timeout=60)
    sources = {}
    for line in (r.stdout or "").splitlines():
        parts = line.split("\t")
        if len(parts) < 5 or parts[4] != "installed":
            continue
        binary, source, sversion, version = parts[0], parts[1] or parts[0], parts[2] or parts[3], parts[3]
        entry = sources.setdefault(source, {"version": sversion, "binaries": []})
        entry["binaries"].append(binary)
        # Plusieurs versions d'une même source peuvent coexister (noyaux linux-image-6.8.0-101/-139…) :
        # la version qui compte est la plus récente, sinon des failles déjà corrigées ressortent.
        if sversion != entry["version"] and version_gt(sversion, entry["version"]):
            entry["version"] = sversion
    return sources


def running_kernel_source(sources):
    """Paquet source du noyau en cours d'exécution (uname -r), ex. linux (6.8 GA) ou linux-hwe-7.0."""
    release = os.uname().release
    r = run_quiet(["dpkg-query", "-W", "-f", "${source:Package}", f"linux-image-{release}"], timeout=15)
    src = (r.stdout or "").strip()
    if not src:
        r = run_quiet(["dpkg-query", "-W", "-f", "${source:Package}", f"linux-image-unsigned-{release}"], timeout=15)
        src = (r.stdout or "").strip()
    if not src:
        for name, info in sources.items():
            if f"linux-image-{release}" in info.get("binaries", []) or f"linux-image-unsigned-{release}" in info.get("binaries", []):
                src = name
                break
    return src.replace("linux-signed", "linux") if src else "", release


def osv_query(sources, ecosystem, skip=()):
    """Interroge OSV par lots, avec pagination (un noyau dépasse les 1000 fiches d'une page) ; {source: [ids]}."""
    names = sorted(n for n in sources if n not in skip)
    found = {}
    for i in range(0, len(names), 1000):
        chunk = names[i:i + 1000]
        pending = [(n, {"package": {"name": n, "ecosystem": ecosystem}, "version": sources[n]["version"]}) for n in chunk]
        for _page in range(8):
            payload = {"queries": [q for _, q in pending]}
            data = http_get(OSV_BATCH_URL, timeout=120, data=json.dumps(payload).encode(),
                            headers={"Content-Type": "application/json"})
            results = json.loads(data).get("results", [])
            nxt = []
            for (name, q), res in zip(pending, results):
                ids = [v["id"] for v in (res or {}).get("vulns", []) if v.get("id")]
                if ids:
                    found.setdefault(name, []).extend(ids)
                token = (res or {}).get("next_page_token")
                if token:
                    nxt.append((name, dict(q, page_token=token)))
            pending = nxt
            if not pending:
                break
    return {n: sorted(set(ids)) for n, ids in found.items()}


def osv_details(ids, cache, ecosystem, max_workers=8):
    """Détails OSV (mis en cache par id). Retourne {id: detail_simplifié}."""
    def fetch(vid):
        try:
            d = json.loads(http_get(OSV_VULN_URL + vid, timeout=30))
        except Exception:  # noqa: BLE001
            return vid, None
        priority, cvss = "", ""
        for sev in d.get("severity") or []:
            if sev.get("type") == "Ubuntu":
                priority = str(sev.get("score", "")).lower()
            elif sev.get("type", "").startswith("CVSS") and not cvss:
                cvss = sev.get("score", "")
        # Une fiche OSV Ubuntu couvre plusieurs paquets sources (linux, linux-aws, linux-hwe-6.11…) :
        # la version corrigée et la disponibilité (Ubuntu Pro) se lisent PAR PAQUET, jamais globalement.
        fixed_by_pkg, pro_by_pkg = {}, {}
        for aff in d.get("affected") or []:
            pkg = aff.get("package", {})
            if pkg.get("ecosystem") != ecosystem:
                continue
            name = pkg.get("name", "")
            fixed_by_pkg.setdefault(name, "")
            for rng in aff.get("ranges") or []:
                for ev in rng.get("events") or []:
                    if ev.get("fixed"):
                        fixed_by_pkg[name] = ev["fixed"]
            if "Ubuntu Pro" in (aff.get("ecosystem_specific") or {}).get("availability", ""):
                pro_by_pkg[name] = True
        summary = d.get("summary") or (d.get("details") or "").strip().split("\n")[0]
        cve = ""
        for alias in [d.get("id", "")] + list(d.get("aliases") or []) + list(d.get("upstream") or []):
            if alias.startswith("CVE-"):
                cve = alias
                break
        if not cve and d.get("id", "").startswith("UBUNTU-CVE-"):
            cve = d["id"][7:]
        return vid, {"id": d.get("id", vid), "cve": cve, "modified": d.get("modified", ""),
                     "published": d.get("published", ""), "priority": priority, "cvss": cvss,
                     "fixed_by_pkg": fixed_by_pkg, "pro_by_pkg": pro_by_pkg, "summary": summary[:240]}

    usable = lambda vid: vid in cache and "fixed_by_pkg" in cache[vid]      # anciens caches (< 1.8.4) : re-téléchargés
    todo = [vid for vid in ids if not usable(vid)]
    out = {vid: cache[vid] for vid in ids if usable(vid)}
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        for vid, detail in pool.map(fetch, todo[:3000]):
            if detail:
                out[vid] = detail
    return out


EMBEDDED_ENGINE_RE = re.compile(r"^mozjs\d*$")          # SpiderMonkey extrait de Firefox ESR (cjs, gjs, polkit)
ENGINE_TERMS = re.compile(r"\b(SpiderMonkey|JavaScript engine|JS engine|JIT|garbage collect\w*|WebAssembly|wasm|"
                          r"typed array|ArrayBuffer|regular expression|regex|JSON|BigInt|Intl)\b", re.I)


def embedded_engine_users(binaries):
    """Paquets installés qui dépendent du moteur (apt-cache rdepends), pour l'explication à l'utilisateur."""
    def rdepends(pkg):
        r = run_quiet(["apt-cache", "rdepends", "--installed", pkg], timeout=30)
        return {ln.strip().lstrip("|").strip() for ln in (r.stdout or "").splitlines()[2:]
                if ln.strip() and ":" not in ln and not ln.strip().lstrip("|").strip().startswith("libmozjs")}
    direct = set()
    for b in binaries:
        if b.startswith("libmozjs"):
            direct |= rdepends(b)
    users = {u for u in direct if not u.startswith("lib")}
    for lib in [u for u in direct if u.startswith("lib")]:      # libcjs0 → cjs, cinnamon… (un niveau de plus)
        users |= {u for u in rdepends(lib) if not u.startswith("lib")}
    return sorted(users or direct)[:12]


# Failles célèbres sans correctif possible (défaut de conception) : explication intégrée, usage réel vérifié
CVE_KNOWLEDGE = {"CVE-2024-3661": "tunnelvision"}


def vpn_connections():
    """Connexions VPN configurées dans NetworkManager (noms), pour dire si TunnelVision concerne cet ordinateur."""
    r = run_quiet(["nmcli", "-t", "-f", "NAME,TYPE", "connection", "show"], timeout=15)
    out = []
    for ln in (r.stdout or "").splitlines():
        parts = re.split(r"(?<!\\):", ln.strip())
        if len(parts) >= 2 and parts[1] in ("vpn", "wireguard", "tun", "ip-tunnel"):
            out.append(parts[0].replace("\\:", ":"))
    return out[:10]


def annotate_vulns(vulns):
    """Notes intégrées par CVE (clé de traduction) et contexte machine (VPN configurés)."""
    for it in vulns.get("items") or []:
        note = CVE_KNOWLEDGE.get(it.get("cve") or "")
        if note:
            it["note"] = note
    vulns["context"] = {"vpn_connections": vpn_connections()}
    return vulns


VULN_ACK_STATUSES = ("unfixed", "pro_only")
VULN_ACK_MAX = 20000


def apply_vuln_acks(vulns, acks):
    """« Ignorer » : les CVE approuvées par l'utilisateur ne comptent plus (tray, score, vue simple) mais restent
    listées dans une section repliée. Recalcule les compteurs et la répartition par priorité à partir des éléments."""
    out = dict(vulns or {})
    acks = acks or {}
    items = []
    counts = dict(out.get("counts") or {})
    for k in ("unfixed", "pro_only", "fix_available", "acknowledged"):
        counts[k] = 0
    by_priority = {}
    acked_cves = set()
    for it in out.get("items") or []:
        it = dict(it)
        acked = it.get("status") in VULN_ACK_STATUSES and (it.get("cve") or it.get("id")) in acks
        it["acknowledged"] = acked
        if acked:
            it["acknowledged_at"] = (acks.get(it.get("cve") or it.get("id")) or {}).get("at")
            acked_cves.add(it.get("cve") or it.get("id"))
        else:
            it.pop("acknowledged_at", None)
        items.append(it)
        if it.get("dormant"):
            continue
        if acked:
            counts["acknowledged"] += 1
            continue
        st = it.get("status")
        if st in ("unfixed", "pro_only", "fix_available"):
            counts[st] += 1
        if st not in ("kernel_pending", "not_applicable"):
            pr = it.get("priority") or "untriaged"
            by_priority[pr] = by_priority.get(pr, 0) + 1
    counts["acknowledged_cves"] = len(acked_cves)
    out.update(items=items, counts=counts, by_priority=by_priority)
    return out


def reclassify_vulns(vulns):
    """Relevé enregistré par une version précédente : applique la classification « non applicable » (moteur intégré)
    sans réseau, au démarrage, pour que l'affichage soit juste tout de suite."""
    out = dict(vulns or {})
    counts = dict(out.get("counts") or {})
    counts.setdefault("not_applicable", 0)
    embedded = dict(out.get("embedded") or {})
    vendor = dict(out.get("vendor") or {})
    by_priority, items = {}, []
    r = run_quiet(["dpkg-query", "-W", "-f", "${Package}\n", "libmozjs*"], timeout=30)
    mozjs_bins = [ln.strip() for ln in (r.stdout or "").splitlines() if ln.strip()]
    for it in out.get("items") or []:
        it = dict(it)
        if it.get("status") == "unfixed" and EMBEDDED_ENGINE_RE.match(it.get("package") or "") \
                and not ENGINE_TERMS.search(it.get("summary") or ""):
            it["status"] = "not_applicable"
            counts["unfixed"] = max(0, int(counts.get("unfixed") or 0) - 1)
            counts["not_applicable"] += 1
            if it["package"] not in embedded:
                embedded[it["package"]] = {"users": embedded_engine_users(mozjs_bins)}
        elif it.get("status") == "unfixed" and "linuxmint" in (it.get("installed") or ""):
            it["status"] = "not_applicable"
            counts["unfixed"] = max(0, int(counts.get("unfixed") or 0) - 1)
            counts["not_applicable"] += 1
            vendor[it["package"]] = it.get("installed") or ""
        if it.get("status") not in ("kernel_pending", "not_applicable") and not it.get("dormant"):
            pr = it.get("priority") or "untriaged"
            by_priority[pr] = by_priority.get(pr, 0) + 1
        items.append(it)
    counts["na_embedded"] = sum(1 for it in items if it.get("status") == "not_applicable" and it.get("package") in embedded)
    counts["na_vendor"] = sum(1 for it in items if it.get("status") == "not_applicable" and it.get("package") in vendor)
    out.update(items=items, counts=counts, by_priority=by_priority, embedded=embedded, vendor=vendor)
    return annotate_vulns(out)


def collect_vulnerabilities(previous=None):
    """Failles connues affectant les paquets installés : sans correctif, correctif Pro, ou correctif disponible."""
    ecosystem = ubuntu_osv_ecosystem()
    result = {"checked_at": now_iso(), "ok": True, "error": "", "ecosystem": ecosystem,
              "sources": 0, "items": [], "counts": {"unfixed": 0, "pro_only": 0, "fix_available": 0, "kernel_pending": 0, "not_applicable": 0, "na_embedded": 0, "na_vendor": 0,
                         "kernel_hwe_fixed": 0, "dormant": 0},
              "embedded": {}, "vendor": {},
              "running_kernel": {}, "dormant_kernels": [],
              "by_priority": {}, "flatpak": [], "snap": [], "cache": {}}
    try:
        sources = installed_sources()
        result["sources"] = len(sources)
        # Noyaux installés mais non démarrés (ex. linux 6.8 GA alors que linux-hwe-7.0 tourne) : leurs failles
        # ne concernent pas le système en cours ; ils ne sont ni interrogés, ni comptés, ni affichés.
        running_src, release = running_kernel_source(sources)
        def kernel_family(name):              # linux-signed-hwe-7.0 et linux-hwe-7.0 : même noyau
            return "linux" + name[len("linux-signed"):] if name.startswith("linux-signed") else name
        kernel_sources = {n for n, info in sources.items() if n.startswith("linux")
                          and any(re.match(r"linux-(image|modules)(-unsigned)?-\d", b) for b in info.get("binaries", []))}
        dormant = {n for n in kernel_sources if running_src and kernel_family(n) != kernel_family(running_src)}
        result["running_kernel"] = {"release": release, "source": running_src}
        result["dormant_kernels"] = sorted(dormant)
        found = osv_query(sources, ecosystem, skip=dormant)
        ids = sorted({vid for lst in found.values() for vid in lst})
        cache = (previous or {}).get("cache") or {}
        details = osv_details(ids, cache, ecosystem)
        result["cache"] = details
        for source, vids in found.items():
            installed = sources[source]["version"]
            for vid in vids:
                d = details.get(vid)
                if not d:
                    continue
                fixed = (d.get("fixed_by_pkg") or {}).get(source, "")
                if fixed and not version_gt(fixed, installed):
                    continue                    # déjà corrigée dans la version installée : ne pas l'afficher
                if (d.get("pro_by_pkg") or {}).get(source):
                    status = "pro_only"         # correctif réservé à Ubuntu Pro (esm)
                elif fixed:
                    status = "fix_available"    # une mise à jour l'installe
                else:
                    status = "unfixed"          # aucun correctif publié par Ubuntu pour ce paquet
                if status == "unfixed" and running_src and kernel_family(source) == kernel_family(running_src):
                    status = "kernel_pending"   # noyau en cours : correctif attendu d'Ubuntu, livré par les mises à jour
                elif status == "unfixed" and EMBEDDED_ENGINE_RE.match(source) and not ENGINE_TERMS.search(d.get("summary") or ""):
                    # Moteur JavaScript extrait de Firefox : Ubuntu y rattache toutes les failles du navigateur (« needed »)
                    # sans jamais les corriger ; celles qui décrivent le navigateur (contenu web, médias, onglets…) ne
                    # s'appliquent pas au moteur seul. Les failles propres au moteur (JIT, wasm, GC) restent « unfixed ».
                    status = "not_applicable"
                    result["counts"]["na_embedded"] += 1
                    if source not in result["embedded"]:
                        result["embedded"][source] = {"users": embedded_engine_users(sources[source].get("binaries", []))}
                elif status == "unfixed" and "linuxmint" in installed:
                    # Paquet construit par Linux Mint (Firefox, Thunderbird…) : le suivi CVE d'Ubuntu vise SA version,
                    # pas celle-ci ; Mint livre les versions Mozilla à jour.
                    status = "not_applicable"
                    result["counts"]["na_vendor"] += 1
                    result["vendor"][source] = installed
                is_dormant = source in dormant
                if is_dormant:
                    result["counts"]["dormant"] += 1
                else:
                    result["counts"][status] += 1
                # Noyau GA (linux 6.8) : la faille est souvent déjà corrigée dans un noyau HWE plus récent
                hwe = ""
                if status in ("unfixed", "kernel_pending") and source == "linux" and not is_dormant:
                    fixed_hwe = {k: v for k, v in (d.get("fixed_by_pkg") or {}).items() if k.startswith("linux-hwe-") and v}
                    if fixed_hwe:
                        k = sorted(fixed_hwe)[0]
                        hwe = f"{k} {fixed_hwe[k]}"
                        result["counts"]["kernel_hwe_fixed"] += 1
                pr = d["priority"] or "untriaged"
                if status not in ("kernel_pending", "not_applicable"):
                    result["by_priority"][pr] = result["by_priority"].get(pr, 0) + 1
                result["items"].append({"id": d["id"], "cve": d["cve"] or d["id"], "package": source,
                                        "installed": installed, "fixed": fixed, "status": status, "hwe_fixed": hwe, "dormant": is_dormant,
                                        "priority": pr, "cvss": d["cvss"], "summary": d["summary"],
                                        "url": f"https://ubuntu.com/security/{d['cve']}" if d["cve"] else f"https://osv.dev/vulnerability/{d['id']}"})
        result["items"].sort(key=lambda it: (PRIORITY_RANK.get(it["priority"], 6), it["status"] != "unfixed", it["package"]))
        annotate_vulns(result)
    except Exception as e:  # noqa: BLE001
        result["ok"] = False
        result["error"] = str(e)[:200]
    # Flatpak / Snap : mises à jour disponibles
    if shutil.which("flatpak"):
        r = run_quiet(["flatpak", "remote-ls", "--updates", "--app", "--columns=application,version,name"], timeout=120)
        for line in (r.stdout or "").splitlines():
            parts = line.split("\t")
            if parts and parts[0].strip():
                result["flatpak"].append({"id": parts[0].strip(), "version": parts[1].strip() if len(parts) > 1 else "",
                                          "name": parts[2].strip() if len(parts) > 2 else parts[0].strip()})
    if shutil.which("snap"):
        r = run_quiet(["snap", "refresh", "--list"], timeout=120)
        for line in (r.stdout or "").splitlines()[1:]:
            parts = line.split()
            if parts:
                result["snap"].append({"id": parts[0], "version": parts[1] if len(parts) > 1 else "", "name": parts[0]})
    return result


# ═══════════════════════════════════════════════════════════════════════════
# Checklist de sécurité et score
# ═══════════════════════════════════════════════════════════════════════════

KNOWN_PORTS = {22: "ssh", 25: "smtp", 53: "dns", 67: "dhcp", 68: "dhcp", 80: "http", 110: "pop3", 111: "rpcbind", 139: "samba", 143: "imap", 443: "https", 465: "smtps", 587: "submission", 993: "imaps",
               445: "samba", 546: "dhcpv6", 631: "cups", 1716: "kdeconnect", 3306: "mysql", 3389: "rdp",
               5353: "mdns", 5432: "postgresql", 5900: "vnc", 5901: "vnc", 6000: "x11", 8000: "dev-server",
               8080: "http-alt", 8443: "https-alt", 9050: "tor", 27017: "mongodb", 32400: "plex"}


def sudoers_file_origin(path):
    """(paquet, modifié) pour un fichier sudoers : livré par un paquet dpkg (mintupdate, mintdrivers, mintsystem…)
    et, en root, vérifié inchangé par rapport au paquet (dpkg -V)."""
    r = run_quiet(["dpkg", "-S", path], timeout=15)
    if r.returncode != 0 or ":" not in (r.stdout or ""):
        return "", False
    pkg = (r.stdout or "").split(":", 1)[0].strip()
    modified = False
    if os.geteuid() == 0:
        v = run_quiet(["dpkg", "-V", pkg], timeout=120)
        for ln in (v.stdout or "").splitlines():
            parts = ln.split()
            if len(parts) >= 2 and parts[-1] == path and "5" in parts[0]:
                modified = True
    return pkg, modified


def ufw_port_allowed(rules, port, proto):
    """Une règle ALLOW IN couvre-t-elle ce port ? (« 22/tcp », « 80,443/tcp », « 8000:8100/udp », « 22 », « Anywhere »)."""
    for r in rules:
        action = (r.get("action") or "").upper()
        if not action.startswith("ALLOW") or "OUT" in action:
            continue
        to = (r.get("to") or "").strip()
        spec = to.split()[-1] if to else ""          # « 192.168.1.5 22/tcp » → « 22/tcp »
        if spec.lower() in ("anywhere", "anywhere (v6)", ""):
            return True
        if "/" in spec:
            ports_part, rproto = spec.rsplit("/", 1)
            if rproto.lower() not in (proto.lower(), "any"):
                continue
        else:
            ports_part = spec
        for chunk in ports_part.split(","):
            chunk = chunk.strip()
            try:
                if ":" in chunk:
                    lo, hi = chunk.split(":", 1)
                    if int(lo) <= port <= int(hi):
                        return True
                elif int(chunk) == port:
                    return True
            except ValueError:
                continue
    return False


def port_key(p):
    """Clé d'un port à l'écoute pour « Ignorer » : port, protocole et programme (un autre programme sur le même port
    est de nouveau signalé)."""
    return f"{p.get('port')}/{p.get('proto')}:{p.get('process') or p.get('service') or ''}"


def listening_ports():
    r = run_quiet(["ss", "-tulnpH"], timeout=15)
    ports = []
    for line in (r.stdout or "").splitlines():
        parts = line.split()
        if len(parts) < 5:
            continue
        proto, local = parts[0], parts[4]
        addr, _, port = local.rpartition(":")
        addr = addr.split("%")[0].strip("[]")
        try:
            port = int(port)
        except ValueError:
            continue
        proc = ""
        m = re.search(r'users:\(\("([^"]+)"', line)
        if m:
            proc = m.group(1)
        if addr in ("0.0.0.0", "::", "*", ""):
            exposed = True
        else:
            try:
                ip = ipaddress.ip_address(addr)
                exposed = not (ip.is_loopback or ip.is_link_local)
            except ValueError:
                exposed = False
        ports.append({"proto": proto, "addr": addr or "*", "port": port, "process": proc,
                      "service": KNOWN_PORTS.get(port, ""), "exposed": bool(exposed)})
    ports.sort(key=lambda p: (not p["exposed"], p["port"]))
    return ports


def collect_checklist(daemon):
    """Liste de contrôles pondérés → score 0-100."""
    items = []
    settings = daemon.settings
    sec = daemon.security or {}
    ufw, ssh = sec.get("ufw", {}), sec.get("ssh", {})
    sysst = daemon.state.get("system_status") or {}
    vulns = daemon.state.get("vulns") or {}
    persistence = daemon.state.get("persistence") or {}

    def add(key, status, weight, detail=""):
        items.append({"key": key, "status": status, "weight": weight, "detail": str(detail)[:200]})

    add("firewall", "ok" if ufw.get("active") else ("fail" if ufw.get("installed") else "warn"), 15,
        f"{ufw.get('default_incoming', '')}/{ufw.get('default_outgoing', '')}" if ufw.get("active") else "")
    if ssh.get("installed") and ssh.get("active"):
        add("ssh", "ok" if (ufw.get("active") and ssh.get("allowed_by_firewall")) else "warn", 6, f"port {ssh.get('port')}")
    else:
        add("ssh", "ok", 6, "off")
    # Chiffrement du disque
    r = run_quiet(["lsblk", "-rno", "TYPE,FSTYPE"], timeout=10)
    encrypted = any("crypt" in line or "LUKS" in line for line in (r.stdout or "").splitlines())
    if not encrypted:
        encrypted = os.path.isdir("/home/.ecryptfs") and any(os.scandir("/home/.ecryptfs")) if os.path.isdir("/home/.ecryptfs") else False
    add("disk_encryption", "ok" if encrypted else "warn", 8)
    # Secure Boot
    sb = "unknown"
    if shutil.which("mokutil"):
        r = run_quiet(["mokutil", "--sb-state"], timeout=10)
        out = (r.stdout or "").lower()
        sb = "ok" if "enabled" in out and "disabled" not in out else ("warn" if out else "unknown")
    elif not os.path.isdir("/sys/firmware/efi"):
        sb = "na"
    add("secure_boot", sb, 5)
    # AppArmor
    try:
        with open("/sys/module/apparmor/parameters/enabled") as f:
            aa = f.read().strip() == "Y"
    except OSError:
        aa = False
    add("apparmor", "ok" if aa else "warn", 6)
    # Mises à jour automatiques
    auto = False
    try:
        with open("/etc/apt/apt.conf.d/20auto-upgrades") as f:
            auto = 'Unattended-Upgrade "1"' in f.read()
    except OSError:
        pass
    # Linux Mint : automatisation du Gestionnaire de mises à jour (timer systemd + fichier témoin)
    auto = auto or unit_enabled("mintupdate-automation-upgrade.timer") or os.path.exists(MINT_AUTO_UPGRADE_FLAG)
    add("auto_updates", "ok" if auto else "warn", 6)
    add("security_updates", "ok" if not sysst.get("security") else "fail", 12, sysst.get("security", 0))
    add("reboot", "ok" if not sysst.get("reboot_required") else "warn", 3)
    # Comptes sans mot de passe / sudo sans mot de passe (root uniquement)
    if os.geteuid() == 0:
        empty = []
        try:
            with open("/etc/shadow") as f:
                for line in f:
                    parts = line.split(":")
                    if len(parts) > 1 and parts[1] == "":
                        empty.append(parts[0])
        except OSError:
            pass
        add("empty_passwords", "fail" if empty else "ok", 10, ", ".join(empty))
        nopass, mint_ok = [], []
        for path in ["/etc/sudoers"] + sorted(str(p) for p in Path("/etc/sudoers.d").glob("*") if p.is_file()):
            try:
                with open(path) as f:
                    has_rule = any("NOPASSWD" in line and not line.strip().startswith("#") for line in f)
            except OSError:
                continue
            if not has_rule:
                continue
            # Fichier déployé par le système (paquet dpkg : mintupdate, mintdrivers…) et inchangé : normal.
            # Fichier ajouté à la main, ou modifié depuis le paquet : risque à signaler.
            pkg, modified = sudoers_file_origin(path) if path != "/etc/sudoers" else ("", False)
            if pkg and not modified:
                mint_ok.append(f"{os.path.basename(path)} ({pkg})")
            else:
                nopass.append(os.path.basename(path) + (" (modifié)" if modified else ""))
        nopass, mint_ok = sorted(set(nopass)), sorted(set(mint_ok))
        add("nopasswd_sudo", "warn" if nopass else "ok", 5, ", ".join(nopass))
        if not nopass and mint_ok:
            items[-1].update(detail_key="check.nopasswd_sudo.mint", detail_params={"files": ", ".join(mint_ok)})
    else:
        add("empty_passwords", "unknown", 10)
        add("nopasswd_sudo", "unknown", 5)
    # Ports exposés
    ports = listening_ports()
    filtering = bool(ufw.get("active")) and (ufw.get("default_incoming") or "").lower().startswith("deny")
    for p in ports:
        if not p["exposed"]:
            p["verdict"] = "local"
        elif filtering and not ufw_port_allowed(ufw.get("rules") or [], p["port"], p["proto"]):
            p["verdict"] = "filtered"           # à l'écoute, mais bloqué par le pare-feu : injoignable depuis le réseau
        else:
            p["verdict"] = "reachable"
    acks = daemon.state.get("acknowledged_ports") or {}
    for p in ports:
        p["key"] = port_key(p)
        p["acknowledged"] = p["verdict"] == "reachable" and p["key"] in acks     # « Ignorer » : port voulu (développement web…)
    exposed = [p for p in ports if p["verdict"] == "reachable" and not p["acknowledged"] and p["port"] not in (5353, 68, 546, 67)]
    acknowledged = [p for p in ports if p["acknowledged"]]
    filtered = [p for p in ports if p["verdict"] == "filtered"]
    add("open_ports", "ok" if not exposed else ("warn" if ufw.get("active") else "fail"), 8,
        ", ".join(f"{p['port']}/{p['proto']} {p['process'] or p['service']}".strip() for p in exposed[:8]))
    if not exposed and acknowledged:
        items[-1].update(detail_key="check.open_ports.acknowledged", detail_params={"n": len(acknowledged)})
    elif not exposed and filtered:
        items[-1].update(detail_key="check.open_ports.filtered", detail_params={"n": len(filtered)})
    # Services exposés courants (joignables)
    exposed_services = sorted({p["service"] or p["process"] for p in exposed if p["port"] in (139, 445, 631, 5900, 5901, 3389, 3306, 5432, 27017)})
    add("exposed_services", "ok" if not exposed_services else "warn", 5, ", ".join(exposed_services))
    # ld.so.preload (persistance de rootkit)
    add("ld_preload", "fail" if os.path.exists("/etc/ld.so.preload") and os.path.getsize("/etc/ld.so.preload") > 0 else "ok", 8)
    # Antivirus
    db = db_last_update()
    age_days = (datetime.now() - db).days if db else 99
    add("signatures", "ok" if age_days < 1 else ("warn" if age_days < 2 else "fail"), 8, f"{age_days} d")
    add("realtime", "ok" if daemon.monitor.active else "warn", 6)
    add("weekly_scan", "ok" if settings.get("weekly_scan") else "warn", 3)
    last_scan = daemon.state.get("last_scan")
    try:
        scan_age = (datetime.now() - datetime.fromisoformat(last_scan)).days if last_scan else 99
    except ValueError:
        scan_age = 99
    add("recent_scan", "ok" if scan_age <= 7 else ("warn" if scan_age <= 30 else "fail"), 4, f"{scan_age} d")
    # Failles ouvertes
    counts = vulns.get("counts") or {}
    high = len({it.get("cve") or it.get("id") for it in vulns.get("items", [])
                if it.get("status") == "unfixed" and it.get("priority") in ("critical", "high")
                and not it.get("acknowledged")})   # CVE distinctes, hors failles ignorées par l'utilisateur
    add("open_vulns", "unknown" if not vulns else ("ok" if not high else "warn"), 6,
        f"{counts.get('unfixed', 0)} unfixed, {high} high/critical")
    # Persistance inconnue
    unknown = [it for it in persistence.get("items", []) if not it.get("trusted")]
    add("persistence", "ok" if not unknown else "warn", 4, f"{len(unknown)}")
    # Durcissement du système (indice Lynis 0-100, relevé lors de la vérification d'intégrité)
    lynis = (daemon.state.get("integrity") or {}).get("lynis") or {}
    idx = lynis.get("index")
    add("hardening", "unknown" if idx is None else ("ok" if idx >= 65 else ("warn" if idx >= 45 else "fail")), 5,
        f"{idx}/100" if idx is not None else "")
    # Noyau GA : failles déjà corrigées dans un noyau HWE (indication seulement, la distribution gère le déploiement)
    hwe_fixed = ((vulns or {}).get("counts") or {}).get("kernel_hwe_fixed") or 0
    add("kernel_hwe", "unknown" if not vulns else ("warn" if hwe_fixed else "ok"), 3, f"{hwe_fixed}" if hwe_fixed else "")
    # Réponse automatique
    add("auto_response", "ok" if settings.get("auto_response") else "warn", 2)

    applicable = [it for it in items if it["status"] in ("ok", "warn", "fail")]
    total = sum(it["weight"] for it in applicable) or 1
    earned = sum(it["weight"] for it in applicable if it["status"] == "ok") + \
        sum(it["weight"] * 0.5 for it in applicable if it["status"] == "warn")
    score = int(round(100 * earned / total))
    grade = "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 60 else "D" if score >= 40 else "E"
    return {"checked_at": now_iso(), "score": score, "grade": grade, "items": items, "ports": ports[:40]}


# ═══════════════════════════════════════════════════════════════════════════
# Connexions sortantes : programmes inconnus, IP malveillantes, géolocalisation
# ═══════════════════════════════════════════════════════════════════════════

class ConnectionMonitor(threading.Thread):
    INTERVAL = 20

    def __init__(self, daemon):
        super().__init__(daemon=True, name="connection-monitor")
        self.daemon_ref = daemon
        self.active = False
        self.seen = {}             # (pid, ip) -> first seen
        self.reported = {}         # pid -> last alert time
        self.blocklist = set()
        self.blocklist_loaded = 0
        self.geo = {ip: v for ip, v in (daemon.state.get("geo_cache") or {}).items()
                    if isinstance(v, dict) and time.time() - v.get("ts", 0) < 86400}   # ip -> {country, countryCode, org, ts}
        self.geo_requests = []     # horodatages des requêtes (24 h glissantes)
        self.geo_last_request = 0.0
        self.geo_backoff_until = 0.0
        self.geo_last_error = ""
        self.geo_last_saved = time.time()
        self.current = {"checked_at": None, "processes": []}
        self.lock = threading.Lock()

    def load_blocklist(self, refresh=False):
        try:
            age = time.time() - os.path.getmtime(BLOCKLIST_FILE) if os.path.exists(BLOCKLIST_FILE) else 1e9
        except OSError:
            age = 1e9
        if refresh or age > 86400:
            ips = set()
            for name, url in BLOCKLIST_URLS.items():
                try:
                    text = http_get(url, timeout=60).decode(errors="replace")
                    for line in text.splitlines():
                        line = line.strip()
                        if line and not line.startswith("#"):
                            ip = line.split(",")[0].strip()
                            try:
                                ipaddress.ip_address(ip)
                                ips.add(ip)
                            except ValueError:
                                pass
                except Exception as e:  # noqa: BLE001
                    log(f"Liste {name} indisponible : {e}")
            if ips:
                with open(BLOCKLIST_FILE, "w") as f:
                    f.write("\n".join(sorted(ips)))
        try:
            with open(BLOCKLIST_FILE) as f:
                self.blocklist = {line.strip() for line in f if line.strip()}
            self.blocklist_loaded = time.time()
        except OSError:
            self.blocklist = set()

    def geolocate(self, ips):
        if not self.daemon_ref.settings.get("geoip_lookup"):
            return
        now = time.time()
        todo = [ip for ip in ips if is_public_ip(ip) and (ip not in self.geo or now - self.geo[ip]["ts"] > 86400)]
        if not todo or now < self.geo_backoff_until or now - self.geo_last_request < GEOIP_MIN_INTERVAL:
            return                      # les adresses restantes seront traitées au prochain passage
        self.geo_last_request = now
        self.geo_requests = [t for t in self.geo_requests if now - t < 86400] + [now]
        try:
            data = json.dumps([{"query": ip} for ip in todo[:100]]).encode()
            for entry in json.loads(http_get(geoip_url(self.daemon_ref.settings.get("geoip_api_key")), timeout=20, data=data,
                                             headers={"Content-Type": "application/json"})):
                if entry.get("status") == "success":
                    self.geo[entry["query"]] = {"country": entry.get("country", ""), "countryCode": entry.get("countryCode", ""),
                                                "org": entry.get("org") or entry.get("isp", ""), "ts": now}
            self.geo_last_error = ""
        except urllib.error.HTTPError as e:
            self.geo_last_error = f"HTTP {e.code}"
            self.geo_backoff_until = now + (300 if e.code in (401, 403) else 60)   # 429 : quota dépassé → pause 1 min
            log(f"GeoIP : HTTP {e.code} (pause)")
        except Exception as e:  # noqa: BLE001
            self.geo_last_error = str(e)[:120]
            log(f"GeoIP : {e}")
        if len(self.geo) > GEOIP_CACHE_MAX:
            for ip in sorted(self.geo, key=lambda k: self.geo[k]["ts"])[:len(self.geo) - GEOIP_CACHE_MAX]:
                self.geo.pop(ip, None)
        if now - self.geo_last_saved > 300:     # cache persisté (survit au redémarrage du service)
            self.geo_last_saved = now
            self.daemon_ref.state.update(geo_cache=self.geo)

    def geoip_stats(self):
        now = time.time()
        return {"requests_24h": sum(1 for t in self.geo_requests if now - t < 86400), "cached": len(self.geo),
                "provider": "pro" if (self.daemon_ref.settings.get("geoip_api_key") or "").strip() else "free",
                "last_error": self.geo_last_error, "paused": now < self.geo_backoff_until}

    @staticmethod
    def parse_ss():
        r = run_quiet(["ss", "-Htnp", "state", "established"], timeout=15)
        conns = []
        for line in (r.stdout or "").splitlines():
            parts = line.split()
            if len(parts) < 4:
                continue
            peer = parts[3]
            host, _, port = peer.rpartition(":")
            host = host.strip("[]").split("%")[0]
            for m in re.finditer(r'\("([^"]+)",pid=(\d+)', line):
                conns.append({"comm": m.group(1), "pid": int(m.group(2)), "ip": host, "port": port})
        return conns

    def run(self):
        self.active = True
        try:
            self.load_blocklist()
        except Exception as e:  # noqa: BLE001
            log(f"Blocklist : {e}")
        while not self.daemon_ref.shutdown.is_set():
            try:
                if self.daemon_ref.settings.get("connection_monitor"):
                    self.tick()
            except Exception as e:  # noqa: BLE001
                log(f"Connexions : {e}")
            self.daemon_ref.shutdown.wait(self.INTERVAL)
        self.active = False

    def tick(self):
        if time.time() - self.blocklist_loaded > 86400:
            self.load_blocklist()
        conns = self.parse_ss()
        now = time.time()
        procs = {}
        new_pairs = []
        for c in conns:
            if not is_public_ip(c["ip"]):
                continue
            key = (c["pid"], c["ip"])
            if key not in self.seen:
                self.seen[key] = now
                new_pairs.append(c)
            p = procs.setdefault(c["pid"], {"pid": c["pid"], "comm": c["comm"], "exe": "", "trusted": None, "remotes": {}})
            p["remotes"].setdefault(c["ip"], {"ip": c["ip"], "ports": set(), "flagged": c["ip"] in self.blocklist})
            p["remotes"][c["ip"]]["ports"].add(c["port"])
        if len(self.seen) > 5000:
            cutoff = now - 3600
            self.seen = {k: v for k, v in self.seen.items() if v >= cutoff}
        self.geolocate([c["ip"] for c in new_pairs])
        monitor = self.daemon_ref.monitor
        for p in procs.values():
            info = monitor.process_info(p["pid"])
            p["exe"] = info["exe"]
            p["user"] = info["user"]
            p["trusted"] = monitor.exe_trusted(info["exe"]) if info["exe"] else None
            p["exe_replaced"] = info["exe"].endswith(" (deleted)")
            for r in p["remotes"].values():
                r["ports"] = sorted(r["ports"])[:6]
                g = self.geo.get(r["ip"], {})
                r["country"] = g.get("countryCode", "")
                r["org"] = g.get("org", "")
        with self.lock:
            self.current = {"checked_at": now_iso(), "processes": sorted(procs.values(), key=lambda p: (p["trusted"] is not False, p["comm"]))}
        # Alertes : programme inconnu qui se connecte, ou IP malveillante
        for c in new_pairs:
            p = procs.get(c["pid"])
            if not p:
                continue
            flagged = c["ip"] in self.blocklist
            if not flagged and p["trusted"] is not False:
                continue
            if now - self.reported.get(c["pid"], 0) < 600 and not flagged:
                continue
            self.reported[c["pid"]] = now
            g = self.geo.get(c["ip"], {})
            alert = {"kind": "connection", "severity": "danger" if flagged else "warn", "time": now_iso(),
                     "pid": c["pid"], "comm": c["comm"], "exe": p["exe"], "user": p.get("user", ""),
                     "trusted": bool(p["trusted"]), "exe_replaced": bool(p.get("exe_replaced")), "ip": c["ip"], "port": c["port"], "flagged": flagged,
                     "country": g.get("country", ""), "org": g.get("org", ""),
                     "reasons": ["ip_blocklisted"] if flagged else ["untrusted_connection"],
                     "count": 0, "top_dir": os.path.dirname(p["exe"]) if p["exe"] else "", "sample": [], "cmdline": ""}
            self.daemon_ref.publish_alert(alert)

    def mark_trusted(self, exe):
        """Marque immédiatement comme approuvé un programme de la liste courante."""
        with self.lock:
            for p in (self.current.get("processes") or []):
                if normalize_exe(p.get("exe")) == exe:
                    p["trusted"] = True

    def snapshot(self):
        with self.lock:
            return dict(self.current, blocklist_size=len(self.blocklist))


# ═══════════════════════════════════════════════════════════════════════════
# Persistance (démarrages automatiques, cron, unités) et extensions de navigateur
# ═══════════════════════════════════════════════════════════════════════════

def dpkg_owners(paths):
    """{path: paquet} pour une liste de chemins, en un seul appel dpkg -S par lot."""
    owners = {}
    paths = [p for p in dict.fromkeys(paths)]
    for i in range(0, len(paths), 150):
        chunk = paths[i:i + 150]
        r = run_quiet(["dpkg", "-S"] + chunk, timeout=120)
        for line in (r.stdout or "").splitlines():
            if ": " not in line:
                continue
            pkgs, _, path = line.partition(": ")
            path = path.strip()
            if path in chunk and path not in owners:
                owners[path] = pkgs.split(",")[0].split(":")[0].strip()
    return owners


def desktop_exec(path):
    try:
        with open(path, errors="replace") as f:
            for line in f:
                if line.startswith("Exec="):
                    return line[5:].strip()
    except OSError:
        pass
    return ""


def user_homes():
    homes = []
    for pw in pwd.getpwall():
        if (pw.pw_uid >= 1000 or pw.pw_uid == 0) and pw.pw_dir.startswith(("/home/", "/root")) and os.path.isdir(pw.pw_dir):
            homes.append((pw.pw_name, pw.pw_dir))
    return homes


def collect_persistence():
    items = []

    def add(kind, path, name, exec_line="", user="", trusted=None):
        items.append({"kind": kind, "path": path, "name": name, "exec": exec_line[:200], "user": user,
                      "trusted": trusted, "owner": "", "key": f"{kind}:{path}"})

    for p in sorted(Path("/etc/xdg/autostart").glob("*.desktop")):
        add("autostart", str(p), p.stem, desktop_exec(str(p)))
    def safe_glob(base, pattern):
        try:
            return sorted(Path(base).glob(pattern))
        except OSError:
            return []

    for user, home in user_homes():
        for p in safe_glob(Path(home, ".config/autostart"), "*.desktop"):
            add("autostart", str(p), p.stem, desktop_exec(str(p)), user, trusted=False)
        for p in safe_glob(Path(home, ".config/systemd/user"), "*.service"):
            add("user_unit", str(p), p.stem, "", user, trusted=False)
        cron = Path("/var/spool/cron/crontabs", user)
        try:
            lines = [ln for ln in cron.read_text(errors="replace").splitlines() if ln.strip() and not ln.startswith("#")] if cron.exists() else []
        except OSError:
            lines = []
        if lines:
            add("crontab", str(cron), user, " | ".join(lines)[:200], user, trusted=False)
    for d in ("/etc/cron.d", "/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.monthly"):
        for p in safe_glob(d, "*"):
            if p.is_file() and not p.name.startswith("."):
                add("cron", str(p), p.name)
    for p in safe_glob("/etc/systemd/system", "*.service"):
        if p.is_file() and not p.is_symlink():
            add("system_unit", str(p), p.stem)
    for p in safe_glob("/etc/profile.d", "*.sh"):
        add("profile", str(p), p.name)
    for path in ("/etc/rc.local", "/etc/ld.so.preload"):
        if os.path.exists(path) and os.path.getsize(path) > 0:
            add("rc", path, os.path.basename(path), trusted=False)

    owners = dpkg_owners([it["path"] for it in items if it["trusted"] is None])
    for it in items:
        if it["trusted"] is None:
            it["owner"] = owners.get(it["path"], "")
            it["trusted"] = bool(it["owner"])

    extensions = []
    for user, home in user_homes():
        for browser, sub in (("chrome", ".config/google-chrome"), ("chromium", ".config/chromium"),
                             ("brave", ".config/BraveSoftware/Brave-Browser"), ("edge", ".config/microsoft-edge")):
            base = Path(home, sub)
            try:
                if not base.is_dir():
                    continue
            except OSError:
                continue
            for profile in safe_glob(base, "Default") + safe_glob(base, "Profile *"):
                prefs = {}
                for pref_name in ("Secure Preferences", "Preferences"):
                    try:
                        with open(profile / pref_name, errors="replace") as f:
                            prefs.update((json.load(f).get("extensions") or {}).get("settings") or {})
                    except Exception:  # noqa: BLE001
                        pass
                for ext_dir in safe_glob(profile / "Extensions", "*"):
                    if not ext_dir.is_dir():
                        continue
                    versions = sorted(ext_dir.glob("*"))
                    if not versions:
                        continue
                    manifest_path = versions[-1] / "manifest.json"
                    name, version = ext_dir.name, versions[-1].name
                    try:
                        with open(manifest_path, errors="replace") as f:
                            man = json.load(f)
                        name = man.get("name", name)
                        version = man.get("version", version)
                        if name.startswith("__MSG_"):
                            key = name[6:-2]
                            locales = [man.get("default_locale", "en"), "en", "en_US", "en_GB", "fr", "de", "it"]
                            locales += [d.name for d in safe_glob(versions[-1] / "_locales", "*")]
                            for loc in locales:
                                msg_file = versions[-1] / "_locales" / str(loc) / "messages.json"
                                if msg_file.exists():
                                    with open(msg_file, errors="replace") as f:
                                        msgs = json.load(f)
                                    entry = msgs.get(key) or msgs.get(key.lower()) or {}
                                    if entry.get("message"):
                                        name = entry["message"]
                                        break
                    except Exception:  # noqa: BLE001
                        pass
                    pref = prefs.get(ext_dir.name) or {}
                    extensions.append({"browser": browser, "user": user, "profile": profile.name, "id": ext_dir.name,
                                       "name": str(name)[:80], "version": str(version), "from_store": bool(pref.get("from_webstore", True)),
                                       "enabled": pref.get("state", 1) == 1, "key": f"{browser}:{user}:{ext_dir.name}"})
        for ext_json in safe_glob(Path(home, ".mozilla/firefox"), "*/extensions.json"):
            try:
                with open(ext_json, errors="replace") as f:
                    addons = json.load(f).get("addons") or []
            except Exception:  # noqa: BLE001
                continue
            for a in addons:
                if a.get("type") != "extension" or a.get("location") == "app-builtin":
                    continue
                extensions.append({"browser": "firefox", "user": user, "profile": ext_json.parent.name, "id": a.get("id", ""),
                                   "name": str(a.get("defaultLocale", {}).get("name") or a.get("id", ""))[:80],
                                   "version": str(a.get("version", "")), "from_store": a.get("signedState", 0) not in (0, None) or a.get("location") == "app-system-defaults",
                                   "enabled": bool(a.get("active")), "key": f"firefox:{user}:{a.get('id', '')}"})
    return {"checked_at": now_iso(), "items": items, "extensions": extensions,
            "counts": {"items": len(items), "untrusted": sum(1 for it in items if not it["trusted"]),
                       "extensions": len(extensions), "ext_outside_store": sum(1 for e in extensions if not e["from_store"])}}


# ═══════════════════════════════════════════════════════════════════════════
# Intégrité : Lynis, unhide, chkrootkit, debsums + fichiers de l'application
# ═══════════════════════════════════════════════════════════════════════════

def debsums_verified_paths(failed_lines):
    """Empreintes (hash) des fichiers de paquets dont debsums a confirmé l'intégrité :
    entrées de /var/lib/dpkg/info/*.md5sums, moins les conffiles (non vérifiés sans -a) et les fichiers signalés."""
    failed = set()
    for ln in failed_lines or []:
        for m in re.finditer(r"(/[^\s]+)", ln):
            failed.add(m.group(1))
    conffiles = set()
    info = "/var/lib/dpkg/info"
    try:
        names = os.listdir(info)
    except OSError:
        return set()
    for n in names:
        if n.endswith(".conffiles"):
            try:
                with open(os.path.join(info, n), encoding="utf-8", errors="replace") as f:
                    conffiles.update(ln.strip() for ln in f if ln.strip())
            except OSError:
                pass
    verified = set()
    for n in names:
        if not n.endswith(".md5sums"):
            continue
        try:
            with open(os.path.join(info, n), encoding="utf-8", errors="replace") as f:
                for ln in f:
                    parts = ln.rstrip("\n").split("  ", 1)
                    if len(parts) == 2:
                        path = "/" + parts[1]
                        if path not in conffiles and path not in failed:
                            verified.add(hash(path))
        except OSError:
            continue
    return verified


INTEGRITY_TOOLS = {"lynis": "lynis", "unhide": "unhide", "unhide-tcp": "unhide-tcp", "chkrootkit": "chkrootkit", "debsums": "debsums"}


def integrity_tools_now():
    """Disponibilité actuelle des outils d'intégrité (indépendante du dernier relevé mémorisé)."""
    return {name: shutil.which(cmd) is not None for name, cmd in INTEGRITY_TOOLS.items()}


def with_tools_now(integrity):
    out = dict(integrity or {})
    out["tools_now"] = integrity_tools_now()
    return out


HARDEN_CATALOG = harden.catalog_public()       # test Lynis → kind/caution/no_revert/action (pour l'interface)


def parse_lynis_report(path="/var/log/lynis-report.dat", log_path="/var/log/lynis.log"):
    """Rapport Lynis : indice de durcissement (0-100), avertissements, suggestions (dédoublonnées par test, avec
    détails) et, depuis le journal, les clés sysctl et permissions relevées (absentes du rapport)."""
    rep = {"index": None, "warnings": [], "suggestions": 0, "items": [], "tests": None, "version": "",
           "sysctl_diffs": [], "file_perms": []}
    seen = {}
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            for ln in f:
                ln = ln.strip()
                if ln.startswith("hardening_index="):
                    rep["index"] = int(ln.split("=", 1)[1].strip() or 0)
                elif ln.startswith("warning[]="):
                    parts = ln.split("=", 1)[1].split("|")
                    rep["warnings"].append(f"{parts[0]}: {parts[1]}" if len(parts) > 1 and parts[1] else parts[0])
                elif ln.startswith("suggestion[]="):
                    parts = (ln.split("=", 1)[1] + "|||").split("|")
                    test, text, details = parts[0].strip(), parts[1].strip(), parts[2].strip()
                    details = "" if details == "-" else details
                    if not test:
                        continue
                    if test in seen:
                        seen[test]["count"] += 1
                        if details and details not in seen[test]["details"]:
                            seen[test]["details"] = "; ".join(x for x in (seen[test]["details"], details) if x)
                    else:
                        seen[test] = {"test": test, "text": text, "details": details, "count": 1}
                        rep["items"].append(seen[test])
                elif ln.startswith(("lynis_tests_done=", "tests_executed=")):
                    rep["tests"] = ln.split("=", 1)[1].strip()
                elif ln.startswith("lynis_version="):
                    rep["version"] = ln.split("=", 1)[1].strip()
    except (OSError, ValueError):
        pass
    rep["suggestions"] = len(rep["items"])
    diffs, perms = {}, {}
    try:
        with open(log_path, encoding="utf-8", errors="replace") as f:
            for ln in f:
                m = re.search(r"sysctl key (\S+) has a different value than expected in scan profile\. Expected=(\S+), Real=(\S+)", ln)
                if m:
                    diffs[m.group(1)] = {"key": m.group(1), "expected": m.group(2), "current": m.group(3)}
                    continue
                m = re.search(r"permissions of file (\S+) are not matching expected value \((\d+) != (\d+)\)", ln)
                if m:
                    perms[m.group(1)] = {"path": m.group(1), "current": m.group(2), "expected": m.group(3)}
    except OSError:
        pass
    rep["sysctl_diffs"], rep["file_perms"] = list(diffs.values()), list(perms.values())
    for it in rep["items"]:
        if it["test"] == "KRNL-6000" and diffs:
            it["details"] = ", ".join(f"{x['key']} {x['current']}→{x['expected']}" for x in rep["sysctl_diffs"][:40])
        elif it["test"] == "FILE-7524" and perms:
            it["details"] = ", ".join(f"{x['path']} ({x['current']}→{x['expected']})" for x in rep["file_perms"][:40])
    return rep


CHK_RULES_VERSION = 4              # règles de classification intégrées ; un relevé plus ancien est refait au démarrage
CHK_NOISE = ("RTNETLINK answers", "ip: ", "ifconfig:", "ls: ", "find: ", "grep: ", "netstat:", "ss: ", "Usage:",
             "/usr/sbin/chkrootkit:", "chkrootkit:", "chkproc:", "chkdirs:", "chkutmp:", "eth", "wlan")   # messages d'outils, pas des constats
CHK_NOISE = tuple(x for x in CHK_NOISE if x not in ("eth", "wlan"))
LYNIS_SECTIONS = 44                # sections « [+] » d'un audit complet (progression)
CHK_TESTS = 108                    # « Searching for … » + « Checking `bin'… » d'un passage chkrootkit


def _md5sums_entries():
    """Nombre de fichiers que debsums va vérifier (lignes des *.md5sums), pour la progression."""
    total = 0
    try:
        for n in os.listdir("/var/lib/dpkg/info"):
            if n.endswith(".md5sums"):
                with open(os.path.join("/var/lib/dpkg/info", n), "rb") as f:
                    total += sum(1 for _ in f)
    except OSError:
        pass
    return total or 500000


def _stream_tool(name, cmd, cancel_event, tick):
    """Lance un outil d'intégrité en lisant sa sortie au fil de l'eau ; tick(pourcentage, étape) selon ses repères.
    Retourne (lignes utiles, code retour). Pour debsums, seules les anomalies sont gardées (une ligne par fichier sinon)."""
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1, errors="replace")
    except OSError as e:
        return [f"{name}: {e}"], 1
    totals = {"lynis": LYNIS_SECTIONS, "chkrootkit": CHK_TESTS, "unhide": 3, "unhide-tcp": 2}
    total = _md5sums_entries() if name == "debsums" else totals.get(name, 1)
    out, done, detail, last_tick = [], 0, "", 0.0
    for raw in proc.stdout:
        if cancel_event is not None and cancel_event.is_set():
            proc.terminate()
            break
        line = raw.rstrip("\n")
        if name == "debsums":
            done += 1
            if line and not line.endswith(" OK"):
                out.append(line)
        else:
            out.append(line)
            s = line.strip()
            if name == "lynis" and s.startswith("[+] "):
                done += 1
                detail = s[4:].strip()[:60]
            elif name == "chkrootkit" and (s.startswith("Checking `") or s.startswith("Searching for ")):
                done += 1
                detail = (s.split("`", 1)[1].split("'", 1)[0] if s.startswith("Checking `") else s[14:].split("...", 1)[0]).strip()[:60]
            elif name in ("unhide", "unhide-tcp") and s.startswith("[*]"):
                done += 1
                detail = s[3:].strip()[:60]
            else:
                continue
        now = time.time()
        if now - last_tick >= 0.4:
            last_tick = now
            tick(min(97, int(done * 100 / max(1, total))), detail)
    proc.wait()
    return out, proc.returncode
NETMGR_NAMES = {"NetworkManager", "wpa_supplicant", "iwd", "dhclient", "dhcpcd", "avahi-daemon", "systemd-networkd",
                "dnsmasq", "libvirtd", "dockerd", "tcpdump", "dumpcap", "wireshark", "nmap", "arp-scan", "lldpd",
                "connmand", "hostapd", "NetworkManager-dispatcher"}


def parse_chkrootkit(out):
    """Sortie de chkrootkit -q → constats. Un « WARNING: … : » est suivi des chemins concernés sur les lignes
    suivantes (fichiers cachés, etc.) : ils restent attachés au constat au lieu d'être perdus."""
    findings, cur, prev_blank = [], [], True
    for raw in out:
        s = raw.strip()
        if not s:
            prev_blank = True
            continue
        if s.startswith("ROOTDIR") or s.lower().startswith(("not tested", "not infected", "not found", "nothing found")) \
                or s.startswith(CHK_NOISE):
            prev_blank = False
            continue
        m = re.match(r"^(?:Checking `[^']*'\.\.\.|Searching for .*?\.\.\.)\s*(.*)$", s)
        if m:                                       # mode verbeux : le résultat du test suit sur la même ligne
            rest = m.group(1).strip().lower()
            if not rest or rest.startswith(("not infected", "not found", "not tested", "nothing", "ok", "warning", "no ", "started", "finished")) \
                    or "nothing detected" in rest or "nothing deleted" in rest or rest.startswith(tuple(x.lower() for x in CHK_NOISE)):
                prev_blank = False
                continue                            # test sans constat (un WARNING détaillé suit sur ses propres lignes)
            if cur:                                 # résultat non anodin (ex. « Checking `ls'... INFECTED ») : constat entier
                findings.append("\n".join(cur))
                cur = []
            cur.append(s)
            prev_blank = False
            continue
        # Se rattache au constat en cours : chemin ou ligne de tableau, ou en-tête terminé par « : » (liste annoncée)
        attach = s.startswith(("/", "!")) or (bool(cur) and cur[0].rstrip().endswith(":"))
        if cur and (s.startswith(("WARNING", "INFECTED", "Possible", "Checking")) or prev_blank or not attach):
            findings.append("\n".join(cur))
            cur = []
        cur.append(s)
        prev_blank = False
    if cur:
        findings.append("\n".join(cur))
    return findings[:80]


# Noms cachés légitimes dans /usr/lib et /lib (chkrootkit signale tout nom commençant par un point)
HIDDEN_KNOWN = {
    "debug": {".build-id", ".dwz"},                                   # symboles de débogage, vdso du noyau
    "perl": {".packlist"},                                            # modules Perl
    "devfile": {".gitignore", ".gitkeep", ".gitattributes", ".keep", ".placeholder", ".dirstamp", ".mkdir",
                ".npmignore", ".npmrc", ".yarnrc", ".editorconfig", ".babelrc", ".eslintrc", ".eslintrc.js",
                ".eslintrc.json", ".eslintignore", ".prettierrc", ".prettierignore", ".jshintrc", ".nycrc",
                ".travis.yml", ".mailmap", ".flake8", ".pylintrc", ".coveragerc", ".dockerignore"},
}
HIDDEN_KNOWN_BY_NAME = {n: cat for cat, names in HIDDEN_KNOWN.items() for n in names}
MODULE_TREES = ("/usr/lib/node_modules/", "/usr/lib/python3/dist-packages/", "/usr/lib/python3.", "/usr/local/lib/python3.",
                "/usr/local/lib/node_modules/")


def dpkg_owners(paths):
    """{chemin: 'paquet, paquet'} pour les chemins livrés par un paquet installé (dpkg -S par lots)."""
    owners = {}
    paths = [p for p in paths if p.startswith("/")]
    for i in range(0, len(paths), 200):
        r = run_quiet(["dpkg", "-S"] + paths[i:i + 200], timeout=120)
        for ln in (r.stdout or "").splitlines():
            if ": " not in ln or ln.startswith("diversion"):
                continue
            pkgs, _, path = ln.rpartition(": ")
            if path in paths and pkgs:
                owners[path] = pkgs
    return owners


def _module_file(p):
    """Petit fichier caché à l'intérieur d'un arbre de modules npm/Python (installé hors dpkg)."""
    try:
        return any(p.startswith(t) for t in MODULE_TREES) and os.path.isfile(p) and os.path.getsize(p) < 1_000_000
    except OSError:
        return False


def classify_hidden_paths(paths):
    """Verdict intégré pour chaque chemin caché signalé par chkrootkit : benign (livré par un paquet, nom connu,
    fichier d'un module npm/Python) ou unknown (à vérifier). Le savoir est dans le programme, pas chez l'utilisateur."""
    owners = dpkg_owners(paths)
    notes = []
    for p in paths:
        name = os.path.basename(p.rstrip("/"))
        if p in owners:
            notes.append({"path": p, "verdict": "benign", "reason": "dpkg", "package": owners[p].split(", ")[0]})
        elif name in HIDDEN_KNOWN_BY_NAME:
            notes.append({"path": p, "verdict": "benign", "reason": HIDDEN_KNOWN_BY_NAME[name]})
        elif _module_file(p):
            notes.append({"path": p, "verdict": "benign", "reason": "module"})
        else:
            notes.append({"path": p, "verdict": "unknown", "reason": "unknown"})
    return notes


TMP_KNOWN = (
    ("/tmp/scoped_dir", "chrome"),        # installation d'extensions Chrome/Chromium (CRX_INSTALL/manifest.json)
    ("/tmp/timeshift-", "timeshift"),     # scripts temporaires de Timeshift
    ("/tmp/pip-", "build_tmp"), ("/tmp/cargo", "build_tmp"), ("/tmp/rustc", "build_tmp"), ("/tmp/go-build", "build_tmp"),
    ("/tmp/tmp", "build_tmp"), ("/tmp/npm-", "build_tmp"), ("/tmp/yarn-", "build_tmp"),
)


def classify_tmp_paths(paths):
    """Verdict intégré pour « Linux.Xor.DDoS » : chkrootkit y liste simplement tout fichier exécutable de /tmp.
    Le vrai Xor.DDoS dépose des binaires ELF aux noms aléatoires : un fichier texte ou script, une installation
    d'extension Chrome, un script Timeshift ou un dossier de compilation ne sont pas des rootkits."""
    notes = []
    for p in paths:
        if not os.path.exists(p):
            notes.append({"path": p, "verdict": "benign", "reason": "tmp_gone"})
            continue
        known = next((reason for prefix, reason in TMP_KNOWN if p.startswith(prefix)), None)
        if known:
            notes.append({"path": p, "verdict": "benign", "reason": known})
            continue
        try:
            with open(p, "rb") as f:
                head = f.read(4)
        except OSError:
            head = b""
        if head != b"\x7fELF":
            notes.append({"path": p, "verdict": "benign", "reason": "tmp_text"})
        else:
            notes.append({"path": p, "verdict": "unknown", "reason": "elf_tmp"})
    return notes


def classify_promisc(lines):
    """Verdict intégré pour « Output from ifpromisc » : une interface Wi-Fi gérée par NetworkManager/wpa_supplicant
    apparaît en PACKET SNIFFER (socket brute légitime). Processus connu ou livré par un paquet → bénin ; sinon à vérifier."""
    notes, exes = [], []
    for ln in lines:
        s = ln.strip()
        m = re.search(r"PACKET SNIFFER\((.*)\)", s)
        if m:
            for part in m.group(1).split(","):
                exe = part.strip().split("[", 1)[0].strip()
                if exe:
                    exes.append(exe)
        elif s.endswith(": PROMISC") or " PROMISC" in s:
            notes.append({"path": s.split(":", 1)[0], "verdict": "unknown", "reason": "promisc"})
    owners = dpkg_owners(exes)
    for exe in exes:
        if os.path.basename(exe) in NETMGR_NAMES:
            notes.append({"path": exe, "verdict": "benign", "reason": "netmgr"})
        elif exe in owners:
            notes.append({"path": exe, "verdict": "benign", "reason": "dpkg", "package": owners[exe].split(", ")[0]})
        else:
            notes.append({"path": exe, "verdict": "unknown", "reason": "sniffer"})
    return notes


def chkrootkit_analysis(out):
    """Sortie de chkrootkit -q → {warnings, benign, notes} : les constats « suspicious files » dont tous les chemins
    sont bénins deviennent des faux positifs connus (non comptés) ; les autres gardent une note par chemin."""
    warnings, benign, notes = [], [], {}
    for text in parse_chkrootkit(out):
        lines = text.splitlines()
        head = lines[0].lower()
        verdicts = None
        if len(lines) > 1:
            paths = [ln.strip() for ln in lines[1:] if ln.strip().startswith("/")]
            if "suspicious files" in head:
                verdicts = classify_hidden_paths(paths)
            elif "xor.ddos" in head:
                verdicts = classify_tmp_paths(paths)
            elif "ifpromisc" in head:
                verdicts = classify_promisc(lines[1:])
        if verdicts is not None:
            if verdicts and all(n["verdict"] == "benign" for n in verdicts):
                benign.append({"text": text, "notes": verdicts})
                continue
            notes[text] = verdicts
        warnings.append(text)
    return {"warnings": warnings[:80], "benign": benign[:40], "notes": notes}


DEBSUMS_RULES_VERSION = 1
MINT_ADJUST_DIRS = ("/usr/share/linuxmint/adjustments", "/etc/linuxmint/adjustments")
_MINT_ADJ = {"at": 0.0, "patterns": [], "paths": set()}


def mint_adjustments():
    """Fichiers que Linux Mint remplace ou modifie lui-même à chaque démarrage (mintsystem « adjustments ») :
    motifs de destination des .overwrite (glob) et chemins cités par les .execute/.menu. Cache 10 min."""
    if time.time() - _MINT_ADJ["at"] < 600:
        return _MINT_ADJ["patterns"], _MINT_ADJ["paths"]
    patterns, paths = [], set()
    for base in MINT_ADJUST_DIRS:
        try:
            names = sorted(os.listdir(base))
        except OSError:
            continue
        for n in names:
            full = os.path.join(base, n)
            try:
                with open(full, encoding="utf-8", errors="replace") as f:
                    for ln in f:
                        ln = ln.strip()
                        if not ln or ln.startswith("#"):
                            continue
                        if n.endswith(".overwrite"):
                            parts = ln.split()
                            if len(parts) >= 2 and parts[1].startswith("/"):
                                patterns.append(parts[1])
                        else:
                            paths.update(m.group(1) for m in re.finditer(r"(/usr/[^\s'\"]+)", ln))
            except OSError:
                pass
    _MINT_ADJ.update(at=time.time(), patterns=patterns, paths=paths)
    return patterns, paths


def dpkg_diversions():
    r = run_quiet(["dpkg-divert", "--list"], timeout=30)
    return set(re.findall(r"^diversion of (\S+) to ", r.stdout or "", flags=re.M))


def classify_debsums(lines):
    """Verdict intégré pour chaque fichier signalé par debsums : remplacé par les ajustements Mint, détourné par
    dpkg-divert (bénins), sinon modifié depuis l'installation (à vérifier)."""
    patterns, mentioned = mint_adjustments()
    diverted = dpkg_diversions()
    notes = []
    for ln in lines:
        path = ln.split()[0] if ln.strip() else ""
        if not path.startswith("/"):
            notes.append({"path": ln[:120], "verdict": "unknown", "reason": "modified"})
            continue
        if path in mentioned or any(fnmatch.fnmatch(path, p) for p in patterns):
            notes.append({"path": path, "verdict": "benign", "reason": "mint_adjustment"})
        elif path in diverted:
            notes.append({"path": path, "verdict": "benign", "reason": "diverted"})
        else:
            notes.append({"path": path, "verdict": "unknown", "reason": "modified"})
    return notes


def debsums_analysis(lines):
    """Lignes debsums (FAILED/REPLACED/missing) → {warnings, benign, notes} comme pour chkrootkit et Lynis."""
    out, benign, notes = [], [], {}
    for ln, note in zip(lines, classify_debsums(lines)):
        if note["verdict"] == "benign":
            benign.append({"text": ln, "notes": [note]})
        else:
            notes[ln] = [note]
            out.append(ln)
    return {"warnings": out[:80], "benign": benign[:80], "notes": notes}


def integrity_ack_key(tool, text):
    """Clé d'un avertissement approuvé (« C'est normal ») : outil + empreinte du texte normalisé."""
    return f"{tool}:{hashlib.sha1(re.sub(r'\s+', ' ', (text or '').strip()).encode()).hexdigest()[:16]}"


LYNIS_RULES_VERSION = 1


def classify_lynis_warning(test, text):
    """Verdict intégré pour un avertissement Lynis connu (l'état réel est vérifié) ; None si inconnu."""
    if test == "TIME-3185":
        # Lynis exige un fichier témoin touché il y a moins de 2048 s ; systemd-timesyncd espace ses alignements
        # jusqu'à exactement 2048 s une fois l'heure stable → faux positif fréquent. L'état réel fait foi.
        r = run_quiet(["timedatectl", "show", "-p", "NTP", "-p", "NTPSynchronized", "--value"], timeout=15)
        vals = (r.stdout or "").split()
        ntp_on, synced = (vals + ["", ""])[0] == "yes", (vals + ["", ""])[1] == "yes"
        if synced:
            return {"path": test, "verdict": "benign", "reason": "time_synced"}
        if not ntp_on:
            return {"path": test, "verdict": "unknown", "reason": "ntp_off", "fix": "TIME-3104"}
        return {"path": test, "verdict": "unknown", "reason": "time_stale", "fix": "TIME-3185"}
    if test == "KRNL-5788":
        return {"path": test, "verdict": "unknown", "reason": "reboot"}
    return None


def lynis_analysis(warnings):
    """Avertissements Lynis « TEST: texte » → {warnings, benign, notes} comme pour chkrootkit."""
    out, benign, notes = [], [], {}
    for w in warnings or []:
        test = w.split(":", 1)[0].strip() if ":" in w else ""
        note = classify_lynis_warning(test, w) if re.fullmatch(r"[A-Z]{3,5}-\d{4}", test) else None
        if note and note["verdict"] == "benign":
            benign.append({"text": w, "notes": [note]})
            continue
        if note:
            notes[w] = [note]
        out.append(w)
    return {"warnings": out[:80], "benign": benign[:40], "notes": notes}


def run_integrity_checks(collect_verified=False, cancel_event=None, progress=None):
    """Lynis (audit de durcissement), unhide (processus et ports cachés), chkrootkit, debsums et fichiers de
    l'application. Avec collect_verified, retourne aussi l'ensemble (hashes) des fichiers système vérifiés
    par debsums, que l'antivirus peut ignorer. `progress(outil, pourcentage, étape, état, avertissements)`
    est appelé au fil de l'eau (sortie des outils lue en continu) pour l'affichage."""
    result = {"checked_at": now_iso(), "tools": {}, "app": app_integrity(), "warnings": 0, "verified_files": 0}
    verified = set()
    tools = {"lynis": ["lynis", "audit", "system", "--quick", "--no-colors"],
             "unhide": ["unhide", "quick"],
             "unhide-tcp": ["unhide-tcp"],
             "chkrootkit": ["chkrootkit"],
             "debsums": ["debsums"]}

    def report(name, percent, detail="", state="running", warnings=None):
        if progress is not None:
            try:
                progress(name, percent, detail, state, warnings)
            except Exception as e:  # noqa: BLE001
                log(f"Progression intégrité : {e}")

    for name, cmd in tools.items():
        entry = {"installed": shutil.which(cmd[0]) is not None, "ran": False, "warnings": [], "rc": None}
        if cancel_event is not None and cancel_event.is_set():
            result["tools"][name] = entry
            continue
        if not (entry["installed"] and os.geteuid() == 0):
            report(name, 100, "", "skipped")
        if entry["installed"] and os.geteuid() == 0:
            report(name, 0, "", "running")
            out, rc = _stream_tool(name, cmd, cancel_event, lambda pct, det, _n=name: report(_n, pct, det))
            entry["ran"] = True
            entry["rc"] = rc
            lines = [ln.strip() for ln in out if ln.strip()]
            if name == "lynis":
                rep = parse_lynis_report()
                result["lynis"] = rep
                la = lynis_analysis(rep.get("warnings") or [])
                lines = la["warnings"]
                entry["benign"], entry["notes"], entry["rules"] = la["benign"], la["notes"], LYNIS_RULES_VERSION
            elif name in ("unhide", "unhide-tcp"):
                lines = [ln for ln in lines if "HIDDEN" in ln.upper() and "Found" in ln]
            elif name == "chkrootkit":
                chk = chkrootkit_analysis(out)
                lines = chk["warnings"]
                entry["benign"], entry["notes"], entry["rules"] = chk["benign"], chk["notes"], CHK_RULES_VERSION
            elif name == "debsums":
                lines = [ln for ln in lines if "FAILED" in ln or "REPLACED" in ln or "missing file" in ln][:160]
                if collect_verified:
                    verified = debsums_verified_paths(lines)      # tout fichier signalé reste à analyser, bénin ou non
                    result["verified_files"] = len(verified)
                da = debsums_analysis(lines)
                lines = da["warnings"]
                entry["benign"], entry["notes"], entry["rules"] = da["benign"], da["notes"], DEBSUMS_RULES_VERSION
            entry["warnings"] = lines[:80]
            report(name, 100, "", "done", len(entry["warnings"]))
        result["tools"][name] = entry
        result["warnings"] += len(entry["warnings"])
    result["warnings"] += len(result["app"]["modified"]) + len(result["app"]["missing"])
    return (result, verified) if collect_verified else result


# ═══════════════════════════════════════════════════════════════════════════
# Daemon
# ═══════════════════════════════════════════════════════════════════════════

class Daemon:
    def __init__(self):
        self.state = State()
        self.subscribers = []
        self.sub_lock = threading.Lock()
        self.queue = deque()
        self.queue_lock = threading.Condition()
        self.current = None
        self.shutdown = threading.Event()
        self.server = None
        self.last_first_scan_attempt = 0
        self.settings = Settings()
        self.monitor = ActivityMonitor(self)
        self.network = NetworkMonitor(self)
        self.connections = ConnectionMonitor(self)
        self.updater = UpdateChecker(self)
        self.usb = UsbWatcher(self)
        self.unlocked = {}          # uid -> expiry (session administrateur)
        self.suspended = {}         # pid -> info (processus suspendus par la réponse automatique)
        self._trusted_set = {t.get("exe") for t in (self.state.get("trusted_programs") or []) if t.get("exe")}
        self.policy = {}
        self.locked_settings = set()
        self.central_patterns = []
        self.load_central_allowlist()
        try:
            stored_vulns = self.state.get("vulns") or {}
            if stored_vulns.get("items") and ("na_vendor" not in (stored_vulns.get("counts") or {}) or "context" not in stored_vulns):
                stored_vulns = reclassify_vulns(stored_vulns)
                log("Failles : relevé reclassé (moteur JavaScript intégré)")
            if stored_vulns.get("items") and (self.state.get("acknowledged_vulns") or "acknowledged" not in (stored_vulns.get("counts") or {})):
                stored_vulns = apply_vuln_acks(stored_vulns, self.state.get("acknowledged_vulns") or {})
            if stored_vulns is not (self.state.get("vulns") or {}):
                self.state.update(vulns=stored_vulns)
        except Exception as e:  # noqa: BLE001
            log(f"Reclassement des failles : {e}")
        self.apply_policy(startup=True)
        self.last_daily = 0
        self.timeshift_enabling = False
        self.hardening_running = False
        self.integrity_progress = None         # {"tools": {outil: {percent, detail, state, warnings}}, "current", "started_at"}
        self.tray_stopped = {}                 # uid → {ids de sessions} où l'administrateur a quitté le bouclier
        self.tray_launched = {}                # uid → dernier lancement (anti-rafale)
        self.last_tray_check = 0.0
        self.last_integrity_emit = 0.0
        self.current_network = None            # réseau courant {key, name, type, device}, None hors ligne
        self.network_lock = threading.Lock()
        self.last_integrity = 0
        self.integrity_running = False
        self.daily_running = False
        self.overall = {"color": "green", "reasons": []}
        self.security = None
        self.security_lock = threading.Lock()
        self.last_security = 0
        self.last_weekly_check = 0
        self.system_status_lock = threading.Lock()
        self.system_status_running = False
        self.system_upgrade_running = False
        self.last_system_status = 0

    def current_job(self):
        with self.queue_lock:
            return self.current

    # ── Diffusion aux abonnés ────────────────────────────────────────────
    def broadcast(self, event):
        with self.sub_lock:
            dead = []
            for sub in self.subscribers:
                try:
                    sub.send(event)
                except (OSError, socket.timeout):
                    dead.append(sub)
            for sub in dead:
                self.subscribers.remove(sub)
                sub.close()

    def emit_line(self, kind, text):
        self.broadcast({"event": "line", "kind": kind, "text": text})

    def emit_progress(self, job):
        payload = job.public()
        if job.phase == "integrity" and self.integrity_progress:
            payload["integrity_progress"] = self.integrity_progress
        self.broadcast({"event": "progress", **payload})

    def integrity_progress_cb(self, name, percent, detail, state, warnings):
        """Callback des outils d'intégrité : état par outil diffusé (au plus toutes les 0,4 s, sauf changement d'état)."""
        if self.integrity_progress is None:
            self.integrity_progress = {"tools": {}, "current": None, "started_at": now_iso()}
        prev = self.integrity_progress["tools"].get(name) or {}
        self.integrity_progress["tools"][name] = {"percent": percent, "detail": detail, "state": state, "warnings": warnings}
        self.integrity_progress["current"] = name if state == "running" else self.integrity_progress.get("current")
        now = time.time()
        if state != prev.get("state") or now - self.last_integrity_emit >= 0.4:
            self.last_integrity_emit = now
            self.broadcast({"event": "integrity_progress", **self.integrity_progress})

    def publish_alert(self, alert):
        pid = alert.get("pid") or 0
        if alert.get("severity") == "danger" and pid > 1 and pid != os.getpid() \
                and self.settings.get("auto_response") and alert.get("kind") in ("burst", "connection"):
            try:
                os.kill(pid, signal.SIGSTOP)
                alert["suspended"] = True
                self.suspended[pid] = {"pid": pid, "comm": alert.get("comm"), "exe": alert.get("exe"),
                                       "time": now_iso(), "kind": alert.get("kind")}
                self.write_log(f"⏸ suspended pid {pid} ({alert.get('comm')})")
            except OSError:
                alert["suspended"] = False
        self.state.prepend("alerts", alert, ALERTS_MAX)
        if alert.get("kind") == "upload":
            self.write_log(f"⚠ upload: {alert.get('gb')} GB sent in {alert.get('window_hours')} h "
                           f"(threshold {alert.get('threshold_gb')} GB)")
            log(f"Alerte envoi Internet : {alert.get('gb')} Go en {alert.get('window_hours')} h")
        elif alert.get("kind") == "connection":
            self.write_log(f"⚠ connection {alert['severity']}: {alert.get('comm')} (pid {alert.get('pid')}) → {alert.get('ip')}:{alert.get('port')} {alert.get('country', '')}")
        elif alert.get("kind") in ("persistence", "integrity", "update", "timeshift"):
            self.write_log(f"⚠ {alert.get('kind')}: {alert.get('title', '')} {alert.get('detail', '')}")
        else:
            self.write_log(f"⚠ {alert['severity']}: {alert['comm']} (pid {alert['pid']}, {alert.get('exe')}) "
                           f"modified {alert['count']} files in {alert['window']} s — {alert['top_dir']}")
            log(f"Alerte {alert['severity']} : {alert['comm']} pid {alert['pid']} {alert['count']} fichiers")
        self.broadcast({"event": "alert", "alert": alert})
        self.refresh_overall()

    # ── Journal ──────────────────────────────────────────────────────────
    def write_log(self, text):
        try:
            with open(SYSTEM_LOG_FILE, "a") as f:
                f.write(f"[{now_iso()}] {text}\n")
        except OSError:
            pass

    def rotate_log(self):
        try:
            if os.path.getsize(SYSTEM_LOG_FILE) > LOG_MAX_BYTES:
                with open(SYSTEM_LOG_FILE) as f:
                    lines = f.readlines()[-2000:]
                with open(SYSTEM_LOG_FILE, "w") as f:
                    f.writelines(lines)
        except OSError:
            pass

    # ── File d'attente ───────────────────────────────────────────────────
    def enqueue(self, job):
        with self.queue_lock:
            waiting = self.current is not None or len(self.queue) > 0
            self.queue.append(job)
            self.queue_lock.notify()
        self.broadcast({"event": "job_queued", "job": job.public(), "waiting": waiting})
        return job

    def worker(self):
        while not self.shutdown.is_set():
            with self.queue_lock:
                while not self.queue and not self.shutdown.is_set():
                    self.queue_lock.wait(timeout=1)
                if self.shutdown.is_set():
                    return
                job = self.queue.popleft()
                self.current = job
            try:
                job.started_at = time.time()
                job.phase = "prepare"
                self.broadcast({"event": "job_started", "job": job.public()})
                if job.kind == "scan":
                    self.run_scan(job)
                else:
                    self.run_update(job)
            except Exception as e:  # noqa: BLE001
                log(f"Erreur job {job.kind}: {e}")
                self.finish(job, "error", "msg.scan.internal", {"error": str(e)})
            finally:
                with self.queue_lock:
                    self.current = None
                self._after_job(job)

    def _after_job(self, job):
        """Support amovible : démontage du montage privé et événement usb_done (popup de résultat)."""
        if job.usb:
            if job.usb.get("private_mount"):
                self.usb.unmount(job.usb["devnode"])
            status, key, params = job.result or ("error", "msg.scan.internal", {})
            self.broadcast({
                "event": "usb_done", "usb": job.usb, "status": status,
                "msg_key": key, "msg_params": params, "infected": job.infected,
                "files": job.total + job.cached, "cached": job.cached, "threats": job.threats[-50:],
                "removed": bool(job.usb.get("removed")),
            })

    def _run_priority(self, job, paused):
        """Clé USB pendant un scan : le scan est mis en pause, la clé est analysée tout de suite, puis reprise."""
        paused.pause()
        self.write_log(f"⏸ paused {paused.path} for USB {job.usb.get('label') or job.usb.get('devnode')}")
        self.emit_line("info", f"⏸ paused for USB {job.usb.get('label') or job.usb.get('devnode')}")
        self.broadcast({"event": "job_paused", "job": paused.public()})
        try:
            job.started_at = time.time()
            job.phase = "prepare"
            self.broadcast({"event": "job_started", "job": job.public()})
            self.run_scan(job)
        except Exception as e:  # noqa: BLE001
            log(f"Erreur job USB : {e}")
            self.finish(job, "error", "msg.scan.internal", {"error": str(e)})
        finally:
            try:
                self._after_job(job)
            except Exception as e:  # noqa: BLE001
                log(f"Fin du job USB : {e}")
            paused.unpause()
            self.write_log(f"▶ resumed {paused.path}")
            self.emit_line("info", "▶ resumed")
            self.broadcast({"event": "job_started", "job": paused.public(), "resumed": True})

    def finish(self, job, status, key, params=None, summary=None):
        job.phase = "done"
        params = params or {}
        job.result = (status, key, params)
        self.broadcast({
            "event": "job_done", "id": job.id, "kind": job.kind, "path": job.path,
            "status": status, "msg_key": key, "msg_params": params,
            "message": t("en", key, **params), "summary": summary or {},
            "auto": job.auto, "usb": job.usb, "integrity": getattr(job, "integrity", False),
            "integrity_warnings": getattr(job, "integrity_warnings", None), "skipped": getattr(job, "skipped", 0),
            "elapsed": time.time() - (job.started_at or time.time()),
        })

    # ── Scan ─────────────────────────────────────────────────────────────
    def _save_progress(self, job, in_progress=True):
        if job.usb:
            return   # pas de reprise pour un support amovible
        try:
            tmp = SYSTEM_PROGRESS_FILE + ".tmp"
            with open(tmp, "w") as f:
                json.dump({
                    "path": job.path, "total": job.total, "scanned": job.scanned,
                    "last_file": job.current_file, "in_progress": in_progress,
                    "auto": job.auto, "infected": job.infected,
                }, f)
            os.chmod(tmp, 0o644)
            os.replace(tmp, SYSTEM_PROGRESS_FILE)
        except OSError:
            pass

    def load_progress(self):
        try:
            with open(SYSTEM_PROGRESS_FILE) as f:
                return json.load(f)
        except Exception:
            return {}

    def _count_files(self, job, cache, skip=None, scache=None, manifest=None):
        """Phase inventaire : find (avec empreintes) → fichier cache, en streaming.
        `skip` : hashes des fichiers système vérifiés par debsums. `scache` : cache des fichiers sains (disque) ;
        `manifest` : manifeste .clamav du support amovible. Les fichiers inchangés déjà vérifiés ne sont pas relus."""
        job.phase = "counting"
        job.found = 0
        job.cached = 0
        self.emit_progress(job)
        cmd = find_command(job.path, exclude=[], stat=True) if job.usb else find_command(job.path, stat=True)
        with job.proc_lock:
            job.proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                        stderr=subprocess.DEVNULL, text=True, bufsize=1)
        last_emit = time.time()
        batch = []
        mf_files = (manifest or {}).get("files") or {}
        root = job.path.rstrip("/") + "/"

        def flush(out):
            nonlocal batch
            if not batch:
                return
            keep, batch = batch, []
            clean = set()
            if scache is not None and job.use_cache:
                try:
                    clean = scache.lookup(keep)
                except Exception as e:  # noqa: BLE001
                    log(f"Cache de scan : {e}")
            for e in keep:
                if e[0] in clean:
                    job.cached += 1
                    continue
                out.write("\t".join(str(x) for x in e) + "\n")
                job.found += 1

        with open(cache, "w") as out:
            for line in job.proc.stdout:
                if job.cancel_event.is_set():
                    break
                if not line.strip():
                    continue
                e = parse_find_line(line)
                if skip and hash(e[0]) in skip:
                    job.skipped += 1
                    continue
                if job.usb:
                    rel = e[0][len(root):] if e[0].startswith(root) else os.path.relpath(e[0], job.path)
                    if rel in (USB_MANIFEST, USB_MANIFEST + ".tmp"):
                        continue                                  # le manifeste lui-même
                    m = mf_files.get(rel)
                    if m and len(m) >= 2 and m[0] == e[1] and m[1] == e[2]:
                        job.cached += 1                           # inchangé depuis la dernière analyse
                        job.manifest_keep[rel] = [e[1], e[2]]
                        continue
                batch.append(e)
                if len(batch) >= 500:
                    flush(out)
                if time.time() - last_emit >= PROGRESS_INTERVAL:
                    self.emit_progress(job)
                    last_emit = time.time()
            flush(out)
        job.proc.wait()
        return job.found

    def _resume_offset(self, job):
        """Index de reprise dans le cache, ou None si reprise impossible."""
        prog = self.load_progress()
        if not (prog.get("in_progress") and prog.get("path") == job.path):
            return None
        if not os.path.exists(SYSTEM_FILELIST_CACHE):
            return None
        last_file = prog.get("last_file") or ""
        total = 0
        idx = None
        with open(SYSTEM_FILELIST_CACHE) as f:
            for i, line in enumerate(f):
                total += 1
                if idx is None and last_file and line.split("\t", 1)[0] == last_file:
                    idx = i + 1
        job.total = total
        job.infected = int(prog.get("infected", 0) or 0)
        return idx if idx is not None else 0

    def run_scan(self, job):
        self.rotate_log()
        start_idx = 0
        resumed = False
        cache = SYSTEM_FILELIST_CACHE + (".usb" if job.usb else "")
        days = int(self.settings.get("scan_cache_days") or 0)
        scache = None
        manifest = None
        if job.usb:
            manifest = usb_manifest_read(job.path) if job.use_cache else None
            if manifest and not manifest_fresh(manifest, days):
                manifest = None
        else:
            try:
                scache = ScanCache(SYSTEM_SCAN_CACHE_DB, days)
            except Exception as e:  # noqa: BLE001
                log(f"Cache de scan indisponible : {e}")

        if job.resume and not job.usb:
            idx = self._resume_offset(job)
            if idx is not None:
                start_idx, resumed = idx, True
            else:
                job.resume = False

        skip = None
        if not resumed:
            label = "usb " if job.usb else ("auto " if job.auto else "")
            self.write_log(f"▶ scan {label}{job.path}" + ("" if job.use_cache else " (cache ignored)")
                           + (" (manifest)" if manifest else ""))
            self.emit_line("info", f"▶ {job.path}")
            if job.integrity and not job.usb:
                # Analyse complète : intégrité d'abord (rootkits, paquets, fichiers de l'application) ;
                # les fichiers système confirmés intacts par debsums sont ensuite ignorés par l'antivirus.
                job.phase = "integrity"
                self.emit_progress(job)
                self.emit_line("info", "▶ integrity (Lynis, unhide, chkrootkit, debsums)")
                self.integrity_progress = None
                result, skip = run_integrity_checks(collect_verified=True, cancel_event=job.cancel_event,
                                                    progress=self.integrity_progress_cb)
                self.integrity_progress = None
                if not job.cancel_event.is_set():
                    self._store_integrity(result, after_scan=True)
                    job.integrity_warnings = result.get("warnings", 0)
                    self.write_log(f"integrity: {result.get('warnings', 0)} warning(s), {len(skip)} verified system files")
                    self.emit_line("info", f"✓ integrity: {result.get('warnings', 0)} warning(s), {len(skip)} verified files skipped")
            total = self._count_files(job, cache, skip, scache=scache, manifest=manifest)
            skip = None
            if job.cancel_event.is_set():
                if job.cancelled_by_user:
                    self._forget_auto(job)
                self._save_progress(job, in_progress=False)
                self._close_cache(scache)
                self.finish(job, "cancelled", "msg.scan.cancelled_counting", {}, self._summary(job))
                return
            job.total = total
            job.infected = 0
            job.scanned = 0
            self._save_progress(job, in_progress=True)
        else:
            job.scanned = start_idx
            self.write_log(f"▶ resume {job.path} ({start_idx}/{job.total})")
            self.emit_line("info", f"▶ {start_idx} / {job.total}")

        if job.total == 0:
            self._save_progress(job, in_progress=False)
            self._record_scan(job, "clean")
            if job.usb:
                self._write_usb_manifest(job)
            self._close_cache(scache)
            if job.cached:
                key, params = "msg.scan.clean_cached", {"files": job.cached, "cached": job.cached}
            else:
                key, params = "msg.scan.nofiles", {}
            self.write_log(f"■ done: nothing to scan ({job.cached} cached)")
            self.finish(job, "clean", key, params, self._summary(job))
            return

        # Liste des fichiers restants (copie en streaming)
        tmp_list = cache + ".tmp"
        with open(cache) as src, open(tmp_list, "w") as dst:
            for i, line in enumerate(src):
                if i >= start_idx:
                    dst.write(line)

        job.phase = "scanning"
        self.emit_progress(job)
        use_clamd = shutil.which("clamdscan") is not None and not os.environ.get("CLAMAV_ANTIVIRUS_NO_CLAMD") \
            and (clamd_ping() if TEST_MODE else ensure_clamd())
        job.engine = "clamd" if use_clamd else "clamscan"
        self.emit_line("info", f"▶ {job.engine} × {job.total}"
                       + (f" · {job.cached} unchanged (already verified)" if job.cached else "")
                       + (f" · {job.skipped} verified by debsums" if job.skipped else ""))
        if use_clamd:
            rc = self._scan_with_clamd(job, tmp_list, scache)
        else:
            rc = self._scan_with_clamscan(job, tmp_list, scache)

        if job.cancel_event.is_set():
            if job.cancelled_by_user:
                self._forget_auto(job)
            self._save_progress(job, in_progress=True)
            self._close_cache(scache)
            self.write_log(f"■ interrupted {job.scanned}/{job.total}")
            self.finish(job, "cancelled", "msg.scan.cancelled",
                        {"scanned": job.scanned, "total": job.total}, self._summary(job))
            return

        job.scanned = job.total
        job.current_file = ""
        self._save_progress(job, in_progress=False)
        for p in (tmp_list, tmp_list + ".paths"):
            try:
                os.remove(p)
            except OSError:
                pass

        if rc not in (0, 1, 2):
            self._record_scan(job, "error")
            self._close_cache(scache)
            self.finish(job, "error", "msg.scan.failed", {"code": rc}, self._summary(job))
            return

        status = "infected" if job.infected > 0 else "clean"
        self._record_scan(job, status)
        if job.usb:
            self._write_usb_manifest(job)
        if scache is not None:
            try:
                scache.purge(max(90, days * 3))
            except Exception:  # noqa: BLE001
                pass
        self._close_cache(scache)
        if job.infected:
            key, params = "msg.scan.infected", {"count": job.infected}
        elif job.cached:
            key, params = "msg.scan.clean_cached", {"files": job.total + job.cached, "cached": job.cached}
        else:
            key, params = "msg.scan.clean", {"files": job.total}
        self.write_log(f"■ done: {job.infected} infected / {job.total} files ({job.engine}, {job.cached} cached, "
                       f"{round(time.time() - (job.started_at or time.time()))} s)")
        self.finish(job, status, key, params, self._summary(job))

    @staticmethod
    def _close_cache(scache):
        if scache is not None:
            try:
                scache.close()
            except Exception:  # noqa: BLE001
                pass

    def _write_usb_manifest(self, job):
        """Manifeste .clamav à la racine du support : fichiers sains (empreintes) pour un scan rapide la prochaine fois."""
        files = dict(job.manifest_keep)
        if len(files) > MANIFEST_MAX_FILES:
            self.write_log(f"usb manifest skipped ({len(files)} files)")
            return
        ok = usb_manifest_write(job.path, files, signature_db_version(), job.usb_infected)
        self.write_log(f"usb manifest {'written' if ok else 'not written'}: {len(files)} clean file(s)")

    def _record_clean(self, job, clean, scache):
        """Fichiers sains d'un lot : cache disque (empreinte relevée à l'inventaire) ou manifeste du support."""
        if not clean:
            return
        if job.usb:
            root = job.path.rstrip("/") + "/"
            with job.count_lock:
                for e in clean:
                    rel = e[0][len(root):] if e[0].startswith(root) else os.path.relpath(e[0], job.path)
                    job.manifest_keep[rel] = [e[1], e[2]]
        elif scache is not None:
            try:
                scache.record(clean)
            except Exception as e:  # noqa: BLE001
                log(f"Cache de scan : {e}")

    def _scan_line(self, job, line, by_path, clean):
        """Une ligne de clamdscan : « chemin: OK », « chemin: Signature FOUND », « chemin: … ERROR »."""
        if line.endswith(": OK"):
            path = line[:-4]
            with job.count_lock:
                job.scanned += 1
                job.current_file = path
            e = by_path.get(path)
            if e:
                clean.append(e)
            return True
        if line.endswith(" FOUND"):
            path, _, sig = line[:-6].rpartition(": ")
            with job.count_lock:
                job.scanned += 1
                job.infected += 1
                job.current_file = path
                job.threats.append({"path": path, "signature": sig, "time": now_iso()})
                job.found_sigs[path] = sig
                if job.usb:
                    job.usb_infected.add(os.path.relpath(path, job.path))
            self.write_log(line)
            self.emit_line("found", line)
            return True
        if line.endswith(" ERROR"):
            path, _, msg = line[:-6].rpartition(": ")
            denied = "denied" in msg.lower() or "permission" in msg.lower()
            with job.count_lock:
                if path in by_path:
                    job.scanned += 1
                    job.current_file = path
                if denied:
                    job.denied += 1
                else:
                    job.errors += 1
            self.write_log(line)
            self.emit_line("denied" if denied else "error", line)
            return True
        if " moved to " in line:
            moved = parse_moved_line(line)
            if moved:
                quarantine_index_add(SYSTEM_QUARANTINE_DIR, moved[1], moved[0], job.found_sigs.get(moved[0], ""))
            self.emit_line("info", line)
            return False
        if not is_noise_line(line):
            self.emit_line(classify_line(line), line)
        return False

    def _scan_with_clamd(self, job, tmp_list, scache):
        """clamd garde la base en mémoire : plusieurs clamdscan --fdpass en parallèle, chacun sur un lot de fichiers
        (le descripteur est transmis à clamd, qui lit les fichiers avec les droits du service)."""
        cpu = os.cpu_count() or 2
        workers = max(2, min(SCAN_WORKERS_MAX, cpu // 2))
        if job.usb:
            workers = min(workers, 3)              # le débit d'une clé vient du support, pas du CPU
        prefix = ["nice", "-n", "15", "ionice", "-c", "2", "-n", "7"] if job.auto else ["nice", "-n", "5", "ionice", "-c", "2", "-n", "4"]
        if not shutil.which("ionice"):
            prefix = prefix[:2]
        src = open(tmp_list)
        src_lock = threading.Lock()
        state = {"rc": 0, "fatal": False, "fallbacks": 0, "fallback_lock": threading.Lock(),
                 "last_emit": time.time(), "last_save": time.time()}
        emit_lock = threading.Lock()

        def next_batch():
            with src_lock:
                batch = []
                for line in src:
                    if line.strip():
                        batch.append(parse_find_line(line))
                        if len(batch) >= SCAN_BATCH:
                            break
                return batch

        def tick():
            now = time.time()
            with emit_lock:
                if now - state["last_emit"] >= PROGRESS_INTERVAL:
                    state["last_emit"] = now
                    self.emit_progress(job)
                if now - state["last_save"] >= PROGRESS_SAVE_INTERVAL:
                    state["last_save"] = now
                    self._save_progress(job, in_progress=True)

        def worker(idx):
            list_path = f"{tmp_list}.w{idx}"
            while not job.cancel_event.is_set() and not state["fatal"]:
                while job.pause_event.is_set() and not job.cancel_event.is_set():
                    time.sleep(0.5)
                batch = next_batch()
                if not batch:
                    break
                by_path = {e[0]: e for e in batch}
                with open(list_path, "w") as f:
                    f.write("".join(e[0] + "\n" for e in batch))
                cmd = prefix + ["clamdscan", "--fdpass", "--no-summary", "--stdout",
                                f"--move={SYSTEM_QUARANTINE_DIR}", f"--file-list={list_path}"]
                clean, seen, rc_b, tail = self._run_clamdscan_batch(job, cmd, by_path, tick)
                if rc_b == 2 and seen == 0 and not job.cancel_event.is_set():
                    # Lot refusé sans qu'aucun fichier ne soit traité (clamd injoignable, descripteur refusé…) :
                    # attendre clamd et réessayer une fois, sinon ce lot passe par clamscan ; au 5e lot en échec,
                    # le reste du scan bascule sur clamscan au lieu d'échouer.
                    self.write_log(f"clamdscan batch failed (rc 2, {len(batch)} files): {tail[:200]}")
                    if ensure_clamd(wait=60):
                        clean, seen, rc_b, tail = self._run_clamdscan_batch(job, cmd, by_path, tick)
                    if rc_b == 2 and seen == 0 and not job.cancel_event.is_set():
                        state["fallbacks"] += 1
                        with state["fallback_lock"]:
                            rc_b = self._scan_batch_with_clamscan(job, batch, list_path + ".fb", scache)
                        clean = []
                        if state["fallbacks"] >= 5:
                            state["fatal"] = True
                if rc_b not in (0, 1, 2):
                    state["rc"] = rc_b
                self._record_clean(job, clean, scache)
            try:
                os.remove(list_path)
            except OSError:
                pass

        threads = [threading.Thread(target=worker, args=(i,), daemon=True, name=f"scan-{i}") for i in range(workers)]
        for th in threads:
            th.start()
        for th in threads:
            th.join()
        if state["fatal"] and not job.cancel_event.is_set():
            # clamd hors service : le reste de la liste par clamscan (plus lent, mais le scan aboutit)
            rest, n = tmp_list + ".rest", 0
            with open(rest, "w") as f:
                for line in src:
                    if line.strip():
                        f.write(line)
                        n += 1
            src.close()
            self.write_log(f"clamd engine unavailable: {n} remaining file(s) scanned with clamscan")
            self.emit_line("info", f"▶ clamscan × {n} (clamd unavailable)")
            job.engine = "clamscan"
            rc = self._scan_with_clamscan(job, rest, scache) if n else 0
            for p in (rest, rest + ".paths"):
                try:
                    os.remove(p)
                except OSError:
                    pass
            return 1 if job.infected else rc
        src.close()
        return 1 if job.infected else state["rc"]

    def _run_clamdscan_batch(self, job, cmd, by_path, tick):
        """Un lot par clamdscan : (fichiers sains, fichiers traités, code retour, dernières lignes hors fichiers)."""
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
        except OSError as e:
            return [], 0, 2, str(e)
        with job.proc_lock:
            job.procs.append(proc)
        clean, seen, tail = [], 0, []
        for raw in proc.stdout:
            line = raw.rstrip("\n")
            if not line:
                continue
            if self._scan_line(job, line, by_path, clean):
                seen += 1
                tick()
            else:
                tail.append(line)
        proc.wait()
        with job.proc_lock:
            if proc in job.procs:
                job.procs.remove(proc)
        return clean, seen, proc.returncode, " | ".join(tail[-3:])

    def _scan_batch_with_clamscan(self, job, batch, list_path, scache):
        """Repli pour un lot que clamd n'a pas pu traiter."""
        with open(list_path, "w") as f:
            f.write("".join("\t".join(str(x) for x in e) + "\n" for e in batch))
        try:
            return self._scan_with_clamscan(job, list_path, scache)
        finally:
            for p in (list_path, list_path + ".paths"):
                try:
                    os.remove(p)
                except OSError:
                    pass

    def _scan_with_clamscan(self, job, tmp_list, scache):
        """Repli sans clamd : un seul clamscan sur la liste (base chargée une fois), mono-thread."""
        paths_list = tmp_list + ".paths"
        with open(tmp_list) as src, open(paths_list, "w") as dst:
            for line in src:
                if line.strip():
                    dst.write(line.split("\t", 1)[0] + "\n")
        prefix = ["nice", "-n", "15", "ionice", "-c", "2", "-n", "7"] if job.auto else ["nice", "-n", "5", "ionice", "-c", "2", "-n", "4"]
        if not shutil.which("ionice"):
            prefix = prefix[:2]
        cmd = prefix + ["clamscan", "--verbose", "--suppress-ok-results",
                        f"--move={SYSTEM_QUARANTINE_DIR}", f"--file-list={paths_list}"]
        with job.proc_lock:
            job.proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                        stderr=subprocess.STDOUT, text=True, bufsize=1)
        entries = open(tmp_list)            # lecture en parallèle de la liste : empreinte du fichier courant
        cur, cur_dirty, clean = None, False, []

        def advance_to(path):
            for _ in range(5000):
                line = entries.readline()
                if not line:
                    return None
                e = parse_find_line(line)
                if e[0] == path:
                    return e
            return None

        last_emit = last_save = time.time()
        for raw in job.proc.stdout:
            line = raw.rstrip("\n")
            if not line:
                continue
            counted = False
            if line.startswith("Scanning "):
                if cur and not cur_dirty:
                    clean.append(cur)
                    if len(clean) >= 500:
                        self._record_clean(job, clean, scache)
                        clean = []
                job.current_file = line[9:]
                cur, cur_dirty = advance_to(line[9:]), False
                counted = True
            elif line.endswith((": Empty file", ": No such file or directory", ": Excluded")):
                job.current_file = line.rsplit(": ", 1)[0]
                cur_dirty = True
                counted = True
            elif line.endswith(" FOUND"):
                cur_dirty = True
                job.infected += 1
                path, _, sig = line[:-6].rpartition(": ")
                job.threats.append({"path": path, "signature": sig, "time": now_iso()})
                job.found_sigs[path] = sig
                if job.usb:
                    job.usb_infected.add(os.path.relpath(path, job.path))
                self.write_log(line)
                self.emit_line("found", line)
            elif " moved to " in line:
                moved = parse_moved_line(line)
                if moved:
                    quarantine_index_add(SYSTEM_QUARANTINE_DIR, moved[1], moved[0], job.found_sigs.get(moved[0], ""))
                self.emit_line("info", line)
            elif not is_noise_line(line):
                kind = classify_line(line)
                if kind == "denied":
                    job.denied += 1
                    cur_dirty = True
                elif kind == "error":
                    job.errors += 1
                    cur_dirty = True
                if kind in ("error", "summary", "denied"):
                    self.write_log(line)
                self.emit_line(kind, line)

            if counted:
                job.scanned += 1
                now = time.time()
                if now - last_emit >= PROGRESS_INTERVAL:
                    self.emit_progress(job)
                    last_emit = now
                if now - last_save >= PROGRESS_SAVE_INTERVAL:
                    self._save_progress(job, in_progress=True)
                    last_save = now
        rc = job.proc.wait()
        if cur and not cur_dirty and rc in (0, 1):
            clean.append(cur)
        self._record_clean(job, clean, scache)
        entries.close()
        return rc

    def _forget_auto(self, job):
        """L'utilisateur a annulé un scan automatique : ne pas le relancer tout seul."""
        job.auto = False
        try:
            os.remove(FIRST_SCAN_FLAG)
        except OSError:
            pass

    def _summary(self, job):
        return {
            "path": job.path, "files": job.total, "infected": job.infected,
            "denied": job.denied, "errors": job.errors,
            "duration": time.time() - (job.started_at or time.time()),
            "threats": job.threats[-50:], "auto": job.auto, "usb": job.usb,
            "skipped": job.skipped, "integrity_warnings": job.integrity_warnings,
            "cached": job.cached, "engine": job.engine,
        }

    def _record_scan(self, job, status):
        duration = time.time() - (job.started_at or time.time())
        entry = {
            "date": now_iso(), "path": job.path, "files": job.total,
            "infected": job.infected, "duration": round(duration),
            "status": status, "source": "daemon", "auto": job.auto,
            "usb": {k: job.usb.get(k) for k in ("label", "model", "size", "devnode")} if job.usb else None,
            "cached": job.cached, "skipped": job.skipped, "engine": job.engine,
        }
        self.state.update(last_scan=entry["date"], last_scan_path=job.path,
                          last_scan_infected=job.infected, last_scan_files=job.total,
                          last_scan_duration=round(duration), last_scan_status=status)
        self.state.prepend("history", entry, HISTORY_MAX)
        if job.auto and os.path.exists(FIRST_SCAN_FLAG):
            try:
                os.remove(FIRST_SCAN_FLAG)
            except OSError:
                pass
            self.state.update(first_scan_done=entry["date"])

    # ── USB ──────────────────────────────────────────────────────────────
    def start_usb_scan(self, info):
        """Clé USB : montage privé, analyse, puis remise à l'utilisateur (événement job_done)."""
        try:
            mountpoint = self.usb.mount(info)
        except OSError as e:
            log(f"USB : {e}")
            self.broadcast({"event": "usb_error", "usb": info, "error": str(e)})
            return
        usb = dict(info, private_mount=True, mountpoint=mountpoint)
        self._start_usb_job(Job("scan", path=mountpoint, usb=usb, requested_by="system"))

    def _start_usb_job(self, job):
        """Une clé passe devant : si un scan (disque) est en cours, il est mis en pause le temps de la clé."""
        with self.queue_lock:
            cur = self.current
        if cur and cur.kind == "scan" and not cur.usb and not cur.paused \
                and cur.phase in ("counting", "scanning", "integrity") and not cur.cancel_event.is_set():
            threading.Thread(target=self._run_priority, args=(job, cur), daemon=True, name="usb-priority").start()
        else:
            self.enqueue(job)

    # ── Mise à jour des signatures ───────────────────────────────────────
    def run_update(self, job):
        job.phase = "updating"
        self.emit_progress(job)
        self.write_log("▶ update")
        self.emit_line("info", "→ systemctl stop clamav-freshclam")
        run_quiet(["systemctl", "stop", "clamav-freshclam"], timeout=60)
        output = []
        try:
            self.emit_line("info", "→ freshclam")
            with job.proc_lock:
                job.proc = subprocess.Popen(["freshclam", "--stdout"],
                                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                            text=True, bufsize=1)
            for raw in job.proc.stdout:
                line = raw.strip()
                if line:
                    output.append(line)
                    self.emit_line("info", line)
            rc = job.proc.wait()
        finally:
            self.emit_line("info", "→ systemctl start clamav-freshclam")
            run_quiet(["systemctl", "start", "clamav-freshclam"], timeout=60)

        if job.cancel_event.is_set():
            self.finish(job, "cancelled", "msg.update.cancelled")
            return
        db = db_last_update()
        if rc == 0:
            changed = any("updated (" in line or "Testing database" in line for line in output)
            self.state.update(last_update=now_iso(), last_update_status="success",
                              last_update_db=db.isoformat(timespec="seconds") if db else None)
            self.write_log("■ signatures up to date")
            key = "msg.update.updated" if changed else "msg.update.uptodate"
            self.finish(job, "success", key, {"date": db.strftime("%d.%m.%Y %H:%M") if db else ""},
                        {"db_files": db_files_info(), "changed": changed})
            threading.Thread(target=self.refresh_system_status, daemon=True).start()
        else:
            self.state.update(last_update_attempt=now_iso(), last_update_status="error")
            self.write_log(f"■ update failed ({rc})")
            self.finish(job, "error", "msg.update.failed", {"code": rc})

    # ── État du système (apt / CVE) ──────────────────────────────────────
    def _system_upgrade_worker(self, unit):
        ok, detail = True, "test_mode"
        try:
            if unit:
                r = run_quiet(["systemd-run", "--unit", unit, "--collect", "--quiet", "--wait", "--pipe",
                               "-p", "Environment=DEBIAN_FRONTEND=noninteractive",
                               "/bin/sh", "-c", "apt-get update -q && apt-get upgrade -y -q "
                               "-o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold"], timeout=3600)
                ok, detail = r.returncode == 0, ((r.stderr or "") + (r.stdout or "")).strip()[-300:]
            else:
                time.sleep(2)
            self.write_log(f"system upgrade → {'ok' if ok else 'FAILED'} {detail[-120:]}")
        except Exception as e:  # noqa: BLE001
            ok, detail = False, str(e)
        finally:
            with self.system_status_lock:
                self.system_upgrade_running = False
        self.refresh_system_status(force=True)
        self.broadcast({"event": "system_upgrade_done", "ok": ok, "detail": detail})
        self.refresh_overall()

    def refresh_system_status(self, force=False):
        with self.system_status_lock:
            if self.system_status_running:
                return False
            if not force and time.time() - self.last_system_status < SYSTEM_STATUS_MIN_INTERVAL:
                return False
            self.system_status_running = True
        try:
            self.broadcast({"event": "system_status_refreshing"})
            status = collect_system_status(self.state.get("system_status"))
            self.state.update(system_status=status)
            self.last_system_status = time.time()
            log(f"État du système : {status['upgradable']} MàJ ({status['security']} sécurité), "
                f"{status['cve_count']} CVE, redémarrage={'oui' if status['reboot_required'] else 'non'}")
            self.broadcast({"event": "system_status", "status": status})
            return True
        except Exception as e:  # noqa: BLE001
            log(f"État du système : {e}")
            return False
        finally:
            with self.system_status_lock:
                self.system_status_running = False

    # ── Sécurité réseau (UFW / SSH) ──────────────────────────────────────
    def _timeshift_first_snapshot(self):
        """Premier instantané juste après l'activation (quelques minutes), puis état rafraîchi."""
        r = run_quiet(["timeshift", "--check", "--scripted"], timeout=1800)
        if r.returncode != 0 or "snapshot" not in ((r.stdout or "") + (r.stderr or "")).lower():
            r = run_quiet(["timeshift", "--create", "--scripted", "--tags", "D", "--comments", "ClamAV Antivirus GUI"], timeout=1800)
        self.write_log(f"timeshift first snapshot → {r.returncode}")
        self.refresh_backup(force=True)
        self.refresh_overall()

    def cached_system_size(self, max_age=7 * 86400):
        info = self.state.get("system_size") or {}
        try:
            age = time.time() - datetime.fromisoformat(info.get("checked_at", "")).timestamp()
        except ValueError:
            return None
        return info.get("bytes") if age < max_age and info.get("bytes") else None

    def refresh_system_size(self, force=False):
        """Taille du système (garde-fou Timeshift), mesurée au plus une fois par semaine ; None si indisponible."""
        size = None if force else self.cached_system_size()
        if size is not None:
            return size
        size = estimate_system_size()
        if size is None:   # du indisponible : occupation du disque principal, majorant prudent
            try:
                st = os.statvfs("/")
                size = (st.f_blocks - st.f_bfree) * st.f_frsize
            except OSError:
                return None
        self.state.update(system_size={"bytes": size, "checked_at": now_iso()})
        log(f"Taille du système : {size // 10**9} Go")
        return size

    def _timeshift_enable_now(self, existing, size):
        """Garde-fou puis activation : refus si l'espace libre est inférieur à 1,2 × le système + 10 Go."""
        cfg, btrfs = timeshift_best_practice_config(existing)
        free, path = timeshift_free_bytes(None)
        needed = timeshift_space_needed(size, btrfs)
        if free is not None and free < needed:
            self.write_log(f"timeshift refused: {free // 10**9} GB free on {path}, {needed // 10**9} GB needed "
                           f"(system {size // 10**9} GB)")
            return {"ok": False, "error": "timeshift_no_space", "free": free, "needed": needed, "size": size, "path": path}
        timeshift_write_config(cfg)
        with open(TIMESHIFT_CRON, "w") as f:
            f.write(TIMESHIFT_GUARD_CRON)
        os.chmod(TIMESHIFT_CRON, 0o644)
        self.state.update(timeshift_suspended=None)
        self.write_log(f"timeshift enabled ({'btrfs' if btrfs else 'rsync'}, daily 5 / weekly 3 / monthly 2, "
                       f"{'?' if free is None else free // 10**9} GB free for a {size // 10**9} GB system)")
        threading.Thread(target=self._timeshift_first_snapshot, daemon=True).start()
        self.refresh_backup(force=True)
        return {"ok": True, "mode": "btrfs" if btrfs else "rsync", "started": True, "free": free, "size": size}

    def _timeshift_enable_worker(self, existing):
        """Activation différée : mesure du système (une à deux minutes), garde-fou, activation ; résultat diffusé."""
        try:
            size = self.refresh_system_size(force=True)
            result = self._timeshift_enable_now(existing, size) if size is not None \
                else {"ok": False, "error": "command_failed", "detail": "du"}
        except Exception as e:  # noqa: BLE001
            log(f"Timeshift : {e}")
            result = {"ok": False, "error": "command_failed", "detail": str(e)[:200]}
        finally:
            self.timeshift_enabling = False
        self.broadcast({"event": "timeshift_enable", "result": result})

    def _timeshift_suspend(self, ts):
        """Garde-fou : disque presque plein → planifications Timeshift coupées (les instantanés existants restent)
        et alerte. À réactiver depuis l'onglet Sauvegardes une fois de la place libérée."""
        try:
            with open(TIMESHIFT_CONF, encoding="utf-8") as f:
                cfg = json.load(f)
            for k in ("schedule_monthly", "schedule_weekly", "schedule_daily", "schedule_hourly", "schedule_boot"):
                cfg[k] = "false"
            timeshift_write_config(cfg)
        except (OSError, ValueError) as e:
            log(f"Timeshift : suspension impossible : {e}")
            return ts
        try:
            os.remove(TIMESHIFT_CRON)
        except OSError:
            pass
        free_gb = round((ts.get("free_bytes") or 0) / 1e9, 1)
        self.state.update(timeshift_suspended={"at": now_iso(), "free_bytes": ts.get("free_bytes")})
        self.write_log(f"timeshift schedules suspended: only {free_gb} GB free")
        if self.settings.get("timeshift_check") is not False:          # état Timeshift ignoré par l'utilisateur : pas d'alerte
            self.publish_alert({"kind": "timeshift", "severity": "warn", "time": now_iso(), "title": "low_space",
                                "detail": f"{free_gb} GB free", "free_gb": free_gb})
        new = collect_timeshift_status(list_snapshots=False)
        new["snapshots"], new["last"] = ts.get("snapshots"), ts.get("last")
        return new

    def refresh_backup(self, force=False):
        """État Timeshift, au plus une fois par heure (timeshift --list peut monter le disque de sauvegarde)."""
        with self.security_lock:
            cached = self.state.get("timeshift") or {}
            try:
                age = time.time() - datetime.fromisoformat(cached.get("checked_at", "")).timestamp()
            except ValueError:
                age = 1e9
            if not force and cached and age < 3600:
                return cached
        ts = collect_timeshift_status()
        if ts.get("low_space") and ts.get("schedule") and os.geteuid() == 0:
            ts = self._timeshift_suspend(ts)
        ts["suspended"] = self.state.get("timeshift_suspended") or None
        self.state.update(timeshift=ts)
        self.broadcast({"event": "timeshift", "timeshift": ts})
        return ts

    def refresh_security(self, force=False, broadcast=True):
        with self.security_lock:
            if not force and self.security and time.time() - self.last_security < 60:
                return self.security
            self.security = collect_security_status()
            try:
                self.security["ufw"]["profile"] = self.settings.get("firewall_profile") or ""
                self.security["ufw"]["profiles"] = {p: {"services": profile_services(p), "nets": profile_nets(p)} for p in FIREWALL_PROFILES}
                self.security["network"] = self.network_info()
            except Exception as e:  # noqa: BLE001
                log(f"Profil pare-feu : {e}")
            self.last_security = time.time()
            result = self.security
        if broadcast:
            self.broadcast({"event": "security_status", "security": result})
        return result

    # ── Réseau courant et profil mémorisé par réseau ──────────────────────
    def network_loop(self):
        """Surveille le réseau courant (route par défaut, connexion NetworkManager) toutes les 10 s,
        et le bouclier (tray) de chaque session graphique toutes les 20 s."""
        time.sleep(8)
        while not self.shutdown.is_set():
            try:
                self.check_network()
            except Exception as e:  # noqa: BLE001
                log(f"Réseau : {e}")
            try:
                if time.time() - self.last_tray_check >= 20:
                    self.last_tray_check = time.time()
                    self.check_tray()
            except Exception as e:  # noqa: BLE001
                log(f"Tray : {e}")
            self.shutdown.wait(10)

    def check_tray(self):
        """Le bouclier doit être présent dans chaque session graphique active : s'il a été tué, il est relancé
        dans la session (service utilisateur transitoire), sauf si un administrateur l'a quitté dans cette session."""
        if os.geteuid() != 0 or TEST_MODE or not os.path.exists(TRAY_LAUNCHER):
            return
        for s in graphical_sessions():
            uid = s["uid"]
            if s["id"] in (self.tray_stopped.get(uid) or set()):
                continue
            r = run_quiet(["pgrep", "-u", str(uid), "-f", "clamav-antivirus.py"], timeout=10)
            if r.returncode == 0:
                continue
            if time.time() - self.tray_launched.get(uid, 0) < 30:
                continue
            self.tray_launched[uid] = time.time()
            env = {"XDG_RUNTIME_DIR": f"/run/user/{uid}", "DBUS_SESSION_BUS_ADDRESS": f"unix:path=/run/user/{uid}/bus", "HOME": pwd.getpwuid(uid).pw_dir}
            cmd = ["runuser", "-u", s["user"], "--", "env"] + [f"{k}={v}" for k, v in env.items()] + [TRAY_LAUNCHER]
            rr = run_quiet(cmd, timeout=30)
            self.write_log(f"tray relaunched for {s['user']} (session {s['id']}) → {rr.returncode}")

    def network_info(self):
        known = self.state.get("network_profiles") or {}
        return {"current": self.current_network,
                "known": sorted(({"key": k, **v} for k, v in known.items()), key=lambda x: x.get("last_seen") or "", reverse=True)[:30]}

    def remember_network_profile(self, profile):
        """Le profil choisi par l'utilisateur est mémorisé pour le réseau courant."""
        net = self.current_network
        if not net:
            return
        known = dict(self.state.get("network_profiles") or {})
        entry = dict(known.get(net["key"]) or {"first_seen": now_iso()})
        entry.update({"profile": profile, "name": net["name"], "type": net["type"], "last_seen": now_iso()})
        known[net["key"]] = entry
        self.state.update(network_profiles=known)

    def check_network(self, force=False):
        """Réseau connu : son profil mémorisé est appliqué. Réseau inconnu : Public d'office, mémorisé, et l'utilisateur
        est prévenu (popup avec « Changer »). Première fois après mise à jour : le réseau courant hérite du profil déjà choisi."""
        net = network_identity()
        with self.network_lock:
            prev_key = (self.current_network or {}).get("key")
            if net and net["key"] == prev_key and not force:
                return
            self.current_network = net
            if not net:
                if prev_key:
                    self.write_log("network: offline")
                return
            known = dict(self.state.get("network_profiles") or {})
            current_profile = self.settings.get("firewall_profile") or ""
            migrate = not self.state.get("network_profiles_init")      # première fois (mise à jour) : héritage du profil choisi
            entry = known.get(net["key"])
            new = entry is None
            if new:
                inherit = bool(migrate and current_profile)
                profile = current_profile if inherit else "public"
                entry = {"profile": profile, "name": net["name"], "type": net["type"], "first_seen": now_iso()}
                new = not inherit                                          # héritage silencieux, sinon popup « nouveau réseau »
            else:
                profile = entry.get("profile") or "public"
            if migrate:
                self.state.update(network_profiles_init=True)
            entry.update({"name": net["name"], "type": net["type"], "last_seen": now_iso()})
            known[net["key"]] = entry
            self.state.update(network_profiles=known)
            changed = profile != current_profile
            if changed or new:
                if os.geteuid() == 0 and not TEST_MODE:
                    ok, text = self.apply_firewall_profile(profile)
                    if not ok:
                        self.write_log(f"network {net['name']}: profile {profile} failed: {text[:120]}")
                self.settings.update({"firewall_profile": profile})
            self.write_log(f"network {net['name']} [{net['type']}] ({net['key']}): profile {profile}"
                           + (" — new network → public" if new else ""))
        if changed or new or force:
            self.refresh_security(force=True)
            self.refresh_overall()
        self.broadcast({"event": "network_changed", "network": net, "profile": profile, "new": new, "changed": changed})

    def apply_firewall_profile(self, profile):
        """Retire les anciennes règles du profil, applique les politiques, ajoute les règles du profil, active UFW."""
        r = run_quiet(["ufw", "status", "numbered"], timeout=30)
        for rule in sorted(parse_ufw_numbered(r.stdout or ""), key=lambda x: -x["number"]):
            if PROFILE_TAG in (rule.get("comment") or "") or PROFILE_TAG in (rule.get("raw") or ""):
                self.ufw("delete", str(rule["number"]))
        self.ufw("default", "deny", "incoming")
        self.ufw("default", "allow", "outgoing")
        errors = []
        rules = profile_rules(profile)
        for args in rules:
            ok, text = self.ufw(*args)
            if not ok:
                errors.append(text[:80])
        self.ufw("logging", "medium" if profile == "enterprise" else "low")
        ok, text = self.ufw("enable")
        self.write_log(f"firewall profile {profile}: {len(rules)} rule(s), {len(errors)} error(s)")
        return ok and not errors, ("; ".join(errors) or text)[:300]

    def ufw(self, *args):
        cmd = ufw_args(args)
        r = run_quiet(cmd, timeout=60)
        text = ((r.stdout or "") + (r.stderr or "")).strip()
        self.write_log(f"{' '.join(cmd[1:])} → {r.returncode}" + (f" : {text[:160]}" if r.returncode != 0 else ""))
        return r.returncode == 0, text[:300]

    # ── Application des réglages ─────────────────────────────────────────
    def apply_settings(self, changed):
        applied = []
        if "update_hour" in changed or "update_minute" in changed:
            hour, minute = int(self.settings.get("update_hour")), int(self.settings.get("update_minute"))
            if not TEST_MODE:
                dropin_dir = "/etc/systemd/system/clamav-antivirus-update.timer.d"
                try:
                    os.makedirs(dropin_dir, exist_ok=True)
                    with open(os.path.join(dropin_dir, "override.conf"), "w") as f:
                        f.write("[Timer]\nOnCalendar=\n"
                                f"OnCalendar=*-*-* {hour:02d}:{minute:02d}:00\nOnBootSec=5min\n")
                    run_quiet(["systemctl", "daemon-reload"], timeout=60)
                    run_quiet(["systemctl", "restart", "clamav-antivirus-update.timer"], timeout=60)
                    applied.append("update_time")
                except OSError as e:
                    log(f"Réglage heure de MàJ : {e}")
            else:
                applied.append("update_time")
        if "upload_window_hours" in changed:
            self.network.samples.clear()
            applied.append("upload_window")
        return applied

    def check_weekly_scan(self):
        if not self.settings.get("weekly_scan"):
            return
        now = datetime.now()
        if now.weekday() != int(self.settings.get("weekly_scan_day")) or now.hour != int(self.settings.get("weekly_scan_hour")):
            return
        last = self.state.get("last_weekly_scan")
        if last:
            try:
                if (now - datetime.fromisoformat(last)).days < 6:
                    return
            except ValueError:
                pass
        with self.queue_lock:
            busy = self.current is not None or bool(self.queue)
        if busy:
            return
        self.state.update(last_weekly_scan=now.isoformat(timespec="seconds"))
        log("Scan complet hebdomadaire planifié")
        self.enqueue(Job("scan", path="/", auto=True, requested_by="system"))

    # ── Tâches quotidiennes : failles, persistance, mise à jour de l'app, checklist ───
    def daily_tasks(self, force=False):
        if self.daily_running:
            return
        self.daily_running = True
        try:
            self.last_daily = time.time()
            # Instantanés système (Timeshift)
            try:
                self.refresh_backup(force=True)
            except Exception as e:  # noqa: BLE001
                log(f"Timeshift : {e}")
            if shutil.which("timeshift") and not TEST_MODE:
                try:
                    self.refresh_system_size()
                except Exception as e:  # noqa: BLE001
                    log(f"Taille du système : {e}")
            # Failles ouvertes
            vulns = apply_vuln_acks(collect_vulnerabilities(self.state.get("vulns")), self.state.get("acknowledged_vulns") or {})
            self.state.update(vulns=vulns)
            self.broadcast({"event": "vulns", "vulns": self.public_vulns(vulns)})
            log(f"Failles : {vulns['counts']} ({vulns['sources']} paquets sources)")
            # Persistance & extensions
            prev = self.state.get("persistence") or {}
            prev_keys = {it["key"] for it in prev.get("items", [])} | {e["key"] for e in prev.get("extensions", [])}
            pers = self.apply_acknowledged(collect_persistence())
            self.state.update(persistence=pers)
            if prev_keys:
                for it in pers["items"]:
                    if it["key"] not in prev_keys:
                        self.publish_alert({"kind": "persistence", "severity": "warn" if not it["trusted"] else "info",
                                            "time": now_iso(), "title": it["name"], "detail": it["path"],
                                            "item": it, "pid": 0, "comm": it["name"], "exe": it["path"], "count": 0,
                                            "top_dir": os.path.dirname(it["path"]), "reasons": [], "sample": []})
                for e in pers["extensions"]:
                    if e["key"] not in prev_keys:
                        self.publish_alert({"kind": "persistence", "severity": "warn" if not e["from_store"] else "info",
                                            "time": now_iso(), "title": e["name"], "detail": f"{e['browser']} · {e['id']}",
                                            "extension": e, "pid": 0, "comm": e["name"], "exe": "", "count": 0,
                                            "top_dir": "", "reasons": [], "sample": []})
            self.broadcast({"event": "persistence", "persistence": pers})
            # Listes d'IP malveillantes
            try:
                self.connections.load_blocklist(refresh=True)
            except Exception as e:  # noqa: BLE001
                log(f"Blocklist : {e}")
            # Vérification d'intégrité : jamais faite, ou faite avec une autre liste d'outils (mise à jour de l'application)
            stored = self.state.get("integrity") or {}
            if os.geteuid() == 0 and not self.integrity_running and set((stored.get("tools") or {}).keys()) != set(INTEGRITY_TOOLS):
                log("Vérification d'intégrité relancée (outils modifiés)")
                threading.Thread(target=self.run_integrity, daemon=True).start()
            else:
                # Avertissements Lynis d'un relevé antérieur : reclassés sur place (état réel vérifié), sans relancer l'audit
                ly = (stored.get("tools") or {}).get("lynis") or {}
                if ly.get("ran") and ly.get("rules") != LYNIS_RULES_VERSION:
                    try:
                        la = lynis_analysis(ly.get("all_warnings") or ly.get("warnings") or [])
                        integ = dict(stored)
                        tools = dict(integ.get("tools") or {})
                        tools["lynis"] = dict(ly, all_warnings=list(la["warnings"]), warnings=list(la["warnings"]),
                                              benign=la["benign"], notes=la["notes"], rules=LYNIS_RULES_VERSION)
                        integ["tools"] = tools
                        self.apply_integrity_acks(integ)
                        self.state.update(integrity=integ)
                        stored = integ
                        self.broadcast({"event": "integrity", "integrity": self.integrity_payload()})
                        self.refresh_overall()
                        log(f"Avertissements Lynis reclassés : {len(la['benign'])} faux positif(s) connu(s)")
                    except Exception as e:  # noqa: BLE001
                        log(f"Reclassement Lynis : {e}")
                # Fichiers debsums d'un relevé antérieur : reclassés sur place (ajustements Mint, détournements)
                ds = (stored.get("tools") or {}).get("debsums") or {}
                if ds.get("ran") and ds.get("rules") != DEBSUMS_RULES_VERSION:
                    try:
                        src = list(ds.get("all_warnings") or ds.get("warnings") or []) + [b.get("text") for b in (ds.get("benign") or [])]
                        da = debsums_analysis([x for x in src if x])
                        integ = dict(stored)
                        tools = dict(integ.get("tools") or {})
                        tools["debsums"] = dict(ds, all_warnings=list(da["warnings"]), warnings=list(da["warnings"]),
                                                benign=da["benign"], notes=da["notes"], rules=DEBSUMS_RULES_VERSION)
                        integ["tools"] = tools
                        self.apply_integrity_acks(integ)
                        self.state.update(integrity=integ)
                        stored = integ
                        self.broadcast({"event": "integrity", "integrity": self.integrity_payload()})
                        self.refresh_overall()
                        log(f"Fichiers debsums reclassés : {len(da['benign'])} bénin(s), {len(da['warnings'])} à vérifier")
                    except Exception as e:  # noqa: BLE001
                        log(f"Reclassement debsums : {e}")
                # Relevé chkrootkit incomplet (en-tête sans ses chemins, versions < 1.12.1) ou sans classification
                chk = (stored.get("tools") or {}).get("chkrootkit") or {}
                old_style = any(str(w).rstrip().endswith(":") for w in (chk.get("all_warnings") or chk.get("warnings") or []))
                if os.geteuid() == 0 and not self.integrity_running and chk.get("ran") \
                        and (old_style or chk.get("rules") != CHK_RULES_VERSION):
                    log("chkrootkit relancé (relevé incomplet)")
                    threading.Thread(target=self._chkrootkit_rescan, daemon=True).start()
            # Liste blanche centrale (signée), politique d'entreprise, télémétrie opt-in
            try:
                self.refresh_central_allowlist()
                self.apply_policy()
                self.send_telemetry()
            except Exception as e:  # noqa: BLE001
                log(f"Liste blanche / politique / télémétrie : {e}")
            # Mise à jour de l'application
            self.check_app_update()
            # Checklist
            self.refresh_checklist()
        except Exception as e:  # noqa: BLE001
            log(f"Tâches quotidiennes : {e}")
        finally:
            self.daily_running = False

    def check_app_update(self, force=False):
        info = self.updater.check(force=force)
        prev = self.state.get("app_update") or {}
        self.state.update(app_update=info)
        if info.get("available") and info.get("verified") and info.get("version") != prev.get("version"):
            self.publish_alert({"kind": "update", "severity": "info", "time": now_iso(),
                                "title": info["version"], "detail": info.get("date", ""), "update": info,
                                "pid": 0, "comm": "", "exe": "", "count": 0, "top_dir": "", "reasons": [], "sample": []})
            if self.settings.get("app_update_auto"):
                ok, detail = self.updater.install(info)
                self.write_log(f"auto-update {info['version']}: {ok} {detail}")
        self.broadcast({"event": "app_update", "update": info})
        self.refresh_overall()
        return info

    def refresh_checklist_async(self):
        """Checklist et score recalculés en arrière-plan (ss, sudoers… quelques secondes) après une action de sécurité."""
        th = getattr(self, "_checklist_thread", None)
        if th and th.is_alive():
            return

        def run():
            try:
                self.refresh_checklist()
            except Exception as e:  # noqa: BLE001
                log(f"Checklist : {e}")
        self._checklist_thread = threading.Thread(target=run, daemon=True)
        self._checklist_thread.start()

    def refresh_checklist(self):
        checklist = collect_checklist(self)
        self.state.update(checklist=checklist)
        self.broadcast({"event": "checklist", "checklist": checklist})
        self.refresh_overall()
        return checklist

    # ── Durcissement (recommandations Lynis) ─────────────────────────────
    def integrity_payload(self):
        """Résultat d'intégrité + disponibilité actuelle des outils + état du durcissement (pour l'interface)."""
        out = with_tools_now(self.state.get("integrity"))
        h = dict(self.state.get("hardening") or {})
        h.pop("prev", None)
        h["running"] = self.hardening_running
        h["catalog"] = HARDEN_CATALOG
        out["hardening"] = h
        return out

    def pending_safe_hardening(self, integrity):
        """Tests Lynis relevés, applicables sans risque, ni appliqués ni échoués depuis moins de 7 jours."""
        h = self.state.get("hardening") or {}
        applied, failed = h.get("applied") or {}, h.get("failed") or {}
        out = []
        for it in ((integrity or {}).get("lynis") or {}).get("items") or []:
            test = it.get("test")
            if not harden.is_safe(test) or test in applied:
                continue
            try:
                if test in failed and time.time() - datetime.fromisoformat(failed[test]["at"]).timestamp() < 7 * 86400:
                    continue
            except (KeyError, ValueError, TypeError):
                pass
            out.append(test)
        return out

    def start_hardening(self, tests, revert=False, auto=False):
        with self.security_lock:
            if self.hardening_running:
                return False
            self.hardening_running = True
        threading.Thread(target=self._harden_worker, args=(tests, revert, auto), daemon=True).start()
        return True

    def _harden_worker(self, tests, revert, auto):
        """Applique (ou annule) chaque recommandation, note le résultat, relance Lynis, puis diffuse."""
        h = dict(self.state.get("hardening") or {})
        for k in ("applied", "prev", "failed"):
            h[k] = dict(h.get(k) or {})
        ctx = {"file_perms": ((self.state.get("integrity") or {}).get("lynis") or {}).get("file_perms") or []}
        ok = fail = 0
        done_fns = set()
        try:
            for test in tests:
                fn = (harden.CATALOG.get(test) or {}).get("fn")
                if not fn or fn in done_fns:
                    continue
                done_fns.add(fn)
                same = harden.tests_sharing(test)
                try:
                    if TEST_MODE:
                        detail, prev = "test_mode", {}
                    elif revert:
                        detail, prev = harden.revert(fn, h["prev"].get(fn) or {}), None
                    else:
                        detail, prev = harden.apply(fn, ctx)
                except Exception as e:  # noqa: BLE001
                    fail += 1
                    for t in same:
                        h["failed"][t] = {"at": now_iso(), "detail": str(e)[:300], "revert": revert}
                    self.write_log(f"hardening {'revert' if revert else 'apply'} {test} failed: {str(e)[:200]}")
                    continue
                ok += 1
                for t in same:
                    h["failed"].pop(t, None)
                    if revert:
                        h["applied"].pop(t, None)
                    else:
                        h["applied"][t] = {"at": now_iso(), "detail": detail, "fn": fn}
                if revert:
                    h["prev"].pop(fn, None)
                else:
                    h["prev"][fn] = prev or {}
                self.write_log(f"hardening {'reverted' if revert else 'applied'} {test}: {detail}")
            h["last"] = now_iso()
            self.state.update(hardening=h)
            if ok and not TEST_MODE and shutil.which("lynis"):
                self._lynis_rescan()
                self.refresh_checklist()
        except Exception as e:  # noqa: BLE001
            log(f"Durcissement : {e}")
        finally:
            self.hardening_running = False
        index = ((self.state.get("integrity") or {}).get("lynis") or {}).get("index")
        self.broadcast({"event": "integrity", "integrity": self.integrity_payload()})
        self.broadcast({"event": "hardening_done", "ok": ok, "failed": fail, "revert": revert, "auto": auto, "index": index})

    def _lynis_rescan(self):
        """Nouvel audit Lynis seul (une à deux minutes) après un durcissement : indice et suggestions à jour sans
        relancer toute la vérification d'intégrité."""
        if self.integrity_running:
            return
        r = run_quiet(["lynis", "audit", "system", "--quick", "--no-colors", "--quiet"], timeout=1800)
        rep = parse_lynis_report()
        integ = dict(self.state.get("integrity") or {})
        if not integ:
            return
        tools = dict(integ.get("tools") or {})
        la = lynis_analysis(rep.get("warnings") or [])
        tools["lynis"] = {"installed": True, "ran": True, "rc": r.returncode, "warnings": list(la["warnings"]),
                          "all_warnings": list(la["warnings"]), "benign": la["benign"], "notes": la["notes"],
                          "rules": LYNIS_RULES_VERSION}
        integ["tools"], integ["lynis"] = tools, rep
        self.apply_integrity_acks(integ)
        self.state.update(integrity=integ)
        self.write_log(f"lynis rescan → index {rep.get('index')}")

    def apply_integrity_acks(self, result):
        """Avertissements d'intégrité approuvés par l'utilisateur (« C'est normal ») : mis à part, non comptés."""
        if not result:
            return result
        acks = set(self.state.get("acknowledged_integrity") or [])
        total = 0
        for name, entry in (result.get("tools") or {}).items():
            allw = entry.get("all_warnings")
            if allw is None:
                allw = entry["all_warnings"] = list(entry.get("warnings") or [])
            entry["warnings"] = [w for w in allw if integrity_ack_key(name, w) not in acks]
            entry["ignored"] = [w for w in allw if integrity_ack_key(name, w) in acks]
            total += len(entry["warnings"])
        app = result.get("app") or {}
        result["warnings"] = total + len(app.get("modified") or []) + len(app.get("missing") or [])
        return result

    def _chkrootkit_rescan(self):
        """chkrootkit seul (moins d'une minute) quand le relevé stocké est incomplet ; classification intégrée."""
        if self.integrity_running or not shutil.which("chkrootkit"):
            return
        r = run_quiet(["chkrootkit", "-q"], timeout=1800)
        out = ((r.stdout or "") + (r.stderr or "")).strip().splitlines()
        chk = chkrootkit_analysis(out)
        integ = dict(self.state.get("integrity") or {})
        if not integ:
            return
        tools = dict(integ.get("tools") or {})
        tools["chkrootkit"] = {"installed": True, "ran": True, "rc": r.returncode, "warnings": list(chk["warnings"]),
                               "all_warnings": list(chk["warnings"]), "benign": chk["benign"], "notes": chk["notes"],
                               "rules": CHK_RULES_VERSION}
        integ["tools"] = tools
        self.apply_integrity_acks(integ)
        self.state.update(integrity=integ)
        self.write_log(f"chkrootkit rescan → {len(chk['warnings'])} warning(s), {len(chk['benign'])} known false positive(s)")
        self.broadcast({"event": "integrity", "integrity": self.integrity_payload()})
        self.refresh_overall()

    def _store_integrity(self, result, after_scan=False):
        self.apply_integrity_acks(result)
        self.last_integrity = time.time()
        self.state.update(integrity=result, last_integrity=now_iso())
        if result["warnings"]:
            self.publish_alert({"kind": "integrity", "severity": "warn", "time": now_iso(),
                                "title": str(result["warnings"]), "detail": ", ".join(
                                    [n for n, t in result["tools"].items() if t["warnings"]] +
                                    (["app"] if result["app"]["modified"] or result["app"]["missing"] else [])),
                                "pid": 0, "comm": "", "exe": "", "count": 0, "top_dir": "", "reasons": [], "sample": []})
        self.broadcast({"event": "integrity", "integrity": self.integrity_payload(), "after_scan": after_scan})
        self.refresh_overall()
        # Durcissement automatique (réglage) : recommandations Lynis sans risque pas encore appliquées
        if self.settings.get("auto_harden") and not TEST_MODE:
            tests = self.pending_safe_hardening(result)
            if tests and self.start_hardening(tests, auto=True):
                self.write_log("auto hardening: " + ", ".join(tests))

    def run_integrity(self, after_scan=False):
        if self.integrity_running:
            return False
        self.integrity_running = True
        try:
            self.broadcast({"event": "integrity_running"})
            self.integrity_progress = None
            self._store_integrity(run_integrity_checks(progress=self.integrity_progress_cb), after_scan=after_scan)
            return True
        finally:
            self.integrity_running = False
            self.integrity_progress = None

    def check_weekly_integrity(self):
        if not self.settings.get("integrity_weekly"):
            return
        now = datetime.now()
        if now.weekday() != int(self.settings.get("integrity_day")) or now.hour != int(self.settings.get("integrity_hour")):
            return
        last = self.state.get("last_integrity")
        try:
            if last and (now - datetime.fromisoformat(last)).days < 6:
                return
        except ValueError:
            pass
        threading.Thread(target=self.run_integrity, daemon=True).start()

    @staticmethod
    def public_vulns(vulns):
        return {k: v for k, v in (vulns or {}).items() if k != "cache"}

    # ── Couleur globale (icône du tray, vue simple) ──────────────────────
    def user_trusted(self):
        """Exécutables approuvés par l'utilisateur (« C'est moi ») : plus jamais d'alerte pour eux."""
        return self._trusted_set

    def central_trusted(self, exe):
        """Liste blanche centrale Dukiwi (signée) + programmes de confiance de la politique d'entreprise."""
        for pat in self.central_patterns:
            if fnmatch.fnmatch(exe, pat):
                return True
        return False

    def load_central_allowlist(self):
        """Charge allowlist.json (déjà vérifiée) et les programmes de la politique."""
        patterns = []
        try:
            with open(ALLOWLIST_FILE, encoding="utf-8") as f:
                data = json.load(f)
            for pat in data.get("programs") or []:
                pat = str(pat)
                patterns.append(pat.replace("~/", "/home/*/") if pat.startswith("~/") else pat)
            self.state.update(allowlist_version=data.get("version"), allowlist_updated=data.get("updated"))
        except (OSError, ValueError):
            pass
        for pat in (self.policy or {}).get("trusted_programs") or []:
            patterns.append(str(pat))
        self.central_patterns = patterns

    def refresh_central_allowlist(self):
        """Télécharge allowlist.json + .sig, vérifie la signature Dukiwi, remplace le fichier local."""
        tmp = ALLOWLIST_FILE + ".new"
        try:
            data = http_get(ALLOWLIST_URL, timeout=30)
            sig = http_get(ALLOWLIST_URL + ".sig", timeout=30)
            with open(tmp, "wb") as f:
                f.write(data)
            with open(tmp + ".sig", "wb") as f:
                f.write(sig)
            ok, detail = gpg_verify(tmp + ".sig", tmp)
            if not ok:
                log(f"Liste blanche : signature refusée ({detail})")
                return False
            json.loads(data.decode("utf-8"))
            os.replace(tmp, ALLOWLIST_FILE)
            os.replace(tmp + ".sig", ALLOWLIST_FILE + ".sig")
            self.load_central_allowlist()
            self.monitor.dpkg_cache.clear()
            log(f"Liste blanche centrale : {len(self.central_patterns)} motif(s)")
            return True
        except Exception as e:  # noqa: BLE001
            log(f"Liste blanche : {e}")
            return False
        finally:
            for p in (tmp, tmp + ".sig"):
                try:
                    os.remove(p)
                except OSError:
                    pass

    def apply_policy(self, startup=False):
        """Applique la politique d'entreprise : réglages imposés (verrouillés), profil pare-feu, programmes de confiance."""
        policy = load_policy()
        if not policy:
            if self.policy:
                self.policy, self.locked_settings = {}, set()
                self.load_central_allowlist()
            return
        if policy.get("_mtime") == (self.policy or {}).get("_mtime") and not startup:
            return
        self.policy = policy
        settings = policy.get("settings") or {}
        if isinstance(settings, dict) and settings:
            changed, errors = self.settings.update(settings)
            if changed and not startup:
                self.apply_settings(changed)
            if errors:
                log(f"Politique : réglages ignorés {errors}")
        locked = set(policy.get("locked") or [])
        if policy.get("lock_all"):
            locked |= set(settings.keys())
        self.locked_settings = {k for k in locked if k in DEFAULT_SETTINGS}
        self.load_central_allowlist()
        profile = policy.get("firewall_profile")
        if profile in FIREWALL_PROFILES and os.geteuid() == 0 and self.settings.get("firewall_profile") != profile:
            ok, text = self.apply_firewall_profile(profile)
            if ok:
                self.settings.update({"firewall_profile": profile})
        log(f"Politique d'entreprise appliquée : {policy.get('name', 'sans nom')}, {len(self.locked_settings)} réglage(s) verrouillé(s)"
            + (" (signée)" if policy.get("_signed") else ""))
        self.write_log(f"policy applied: {policy.get('name', '')}")

    def telemetry_extra(self):
        """Champs de télémétrie qui alimentent les règles intégrées et la mesure des performances (sans identifiant) :
        avertissements d'intégrité approuvés, classifications bénignes, dernier scan, durcissement, paquets à failles hautes."""
        integ = self.state.get("integrity") or {}
        tools = integ.get("tools") or {}
        acked, benign = [], {}
        for name, t in tools.items():
            for w in (t.get("ignored") or [])[:10]:
                acked.append({"tool": name, "text": anonymize_path(str(w).splitlines()[0])[:160]})
            for b in t.get("benign") or []:
                for n in b.get("notes") or []:
                    key = f"{name}:{n.get('reason', '?')}"
                    benign[key] = benign.get(key, 0) + 1
        vulns = self.state.get("vulns") or {}
        high = {}
        for it in vulns.get("items") or []:
            if it.get("status") == "unfixed" and it.get("priority") in ("critical", "high") and not it.get("acknowledged"):
                high[it.get("package") or "?"] = high.get(it.get("package") or "?", 0) + 1
        history = self.state.get("history") or []
        last = next((h for h in history if not h.get("usb")), None) or {}
        cutoff = (datetime.now().timestamp() - 30 * 86400)
        usb30 = 0
        for h in history:
            try:
                if h.get("usb") and datetime.fromisoformat(h.get("date", "")).timestamp() >= cutoff:
                    usb30 += 1
            except ValueError:
                pass
        hard = self.state.get("hardening") or {}
        return {
            "acknowledged_integrity": acked[:30],
            "benign_findings": benign,
            "integrity_tools": {n: len(t.get("warnings") or []) for n, t in tools.items()},
            "lynis_index": (integ.get("lynis") or {}).get("index"),
            "hardening": {"applied": sorted(hard.get("applied") or {})[:40], "failed": len(hard.get("failed") or {})},
            "vulns_high": dict(sorted(high.items(), key=lambda kv: -kv[1])[:20]),
            "vulns_acknowledged": (vulns.get("counts") or {}).get("acknowledged_cves") or 0,
            "scan": {k: last.get(k) for k in ("duration", "files", "cached", "skipped", "engine", "infected", "status", "auto")} if last else None,
            "usb_scans_30d": usb30,
            "known_networks": len(self.state.get("network_profiles") or {}),
        }

    def send_telemetry(self):
        """Télémétrie anonyme, opt-in, une fois par semaine : version, système, score, faux positifs approuvés (chemins anonymisés)."""
        if not self.settings.get("telemetry"):
            return False
        last = self.state.get("telemetry_sent") or ""
        try:
            if last and (time.time() - datetime.fromisoformat(last).timestamp()) < 7 * 86400:
                return False
        except ValueError:
            pass
        payload = self.build_telemetry_payload()
        try:
            http_get(TELEMETRY_URL, timeout=30, data=json.dumps(payload).encode(), headers={"Content-Type": "application/json"})
            self.state.update(telemetry_sent=now_iso())
            self.write_log("telemetry sent (opt-in)")
            return True
        except Exception as e:  # noqa: BLE001
            log(f"Télémétrie : {e}")
            return False

    def build_telemetry_payload(self):
        """Exactement ce qui serait envoyé (aussi montré à l'utilisateur avant qu'il ne décide)."""
        install_id = self.state.get("install_id")
        if not install_id:
            install_id = uuid.uuid4().hex
            self.state.update(install_id=install_id)
        pretty = ""
        try:
            with open("/etc/os-release") as f:
                for line in f:
                    if line.startswith("PRETTY_NAME="):
                        pretty = line.split("=", 1)[1].strip().strip('"')
        except OSError:
            pass
        cutoff = time.time() - 7 * 86400
        alerts = []
        for a in self.state.get("alerts") or []:
            try:
                if datetime.fromisoformat(a.get("time", "")).timestamp() >= cutoff:
                    alerts.append(a.get("kind", "?"))
            except ValueError:
                continue
        checklist = self.state.get("checklist") or {}
        vulns = (self.state.get("vulns") or {}).get("counts") or {}
        payload = {
            "install_id": install_id, "version": VERSION, "os": pretty, "kernel": os.uname().release, "arch": os.uname().machine,
            "settings": {k: self.settings.get(k) for k in ("family_mode", "firewall_profile", "backup_check", "timeshift_check", "auto_response", "connection_monitor",
                                                             "auto_harden", "scan_cache_days", "integrity_weekly", "weekly_scan")},
            "checklist": {"score": checklist.get("score"), "grade": checklist.get("grade"),
                          "fail": [i["key"] for i in checklist.get("items", []) if i.get("status") == "fail"],
                          "warn": [i["key"] for i in checklist.get("items", []) if i.get("status") == "warn"]},
            "alerts_7d": {k: alerts.count(k) for k in set(alerts)},
            "trusted_programs": [anonymize_path(t.get("exe")) for t in (self.state.get("trusted_programs") or [])][:50],
            "acknowledged_persistence": [anonymize_path(k) for k in (self.state.get("acknowledged_persistence") or [])][:50],
            "vulns": {k: vulns.get(k) for k in ("unfixed", "fix_available", "pro_only", "kernel_pending", "not_applicable", "na_embedded", "na_vendor", "kernel_hwe_fixed")},
            "integrity_warnings": (self.state.get("integrity") or {}).get("warnings"),
            "timeshift": bool((self.state.get("timeshift") or {}).get("schedule")),
            "policy": bool(self.policy),
        }
        try:
            payload.update(self.telemetry_extra())
        except Exception as e:  # noqa: BLE001
            log(f"Télémétrie (champs) : {e}")
        return payload

    def apply_acknowledged(self, pers):
        """Applique les entrées de persistance approuvées par l'utilisateur et recalcule les compteurs."""
        if not pers:
            return pers
        ack = set(self.state.get("acknowledged_persistence") or [])
        items, exts = pers.get("items") or [], pers.get("extensions") or []
        for it in items:
            base = it.get("trusted_base", it.get("trusted"))   # confiance dpkg d'origine, conservée pour pouvoir retirer l'approbation
            it["trusted_base"] = base
            it["approved"] = it.get("key") in ack
            it["trusted"] = bool(base) or it["approved"]
        for e in exts:
            e["approved"] = e.get("key") in ack
        pers["counts"] = {"items": len(items), "untrusted": sum(1 for it in items if not it.get("trusted")),
                          "extensions": len(exts),
                          "ext_outside_store": sum(1 for e in exts if not e.get("from_store") and not e.get("approved"))}
        return pers

    def compute_overall(self):
        reasons = []
        color = "green"

        def raise_to(level, reason):
            nonlocal color
            order = {"green": 0, "yellow": 1, "blue": 2, "red": 3}
            if order[level] > order[color]:
                color = level
            reasons.append(reason)

        db = db_last_update()
        age_days = (datetime.now() - db).days if db else 99
        if age_days >= 2:
            raise_to("red", "signatures_old")
        elif age_days >= 1:
            raise_to("blue", "signatures_stale")
        sysst = self.state.get("system_status") or {}
        if sysst.get("security"):
            raise_to("red", "security_updates")
        elif sysst.get("upgradable"):
            raise_to("yellow", "updates")
        if sysst.get("reboot_required"):
            raise_to("yellow", "reboot")
        sec = self.security or {}
        ufw, ssh = sec.get("ufw", {}), sec.get("ssh", {})
        if ufw.get("installed") and not ufw.get("active"):
            raise_to("red", "firewall_off")
        elif not ufw.get("installed"):
            raise_to("red", "firewall_missing")
        if ssh.get("active"):
            raise_to("red" if not ufw.get("active") else "yellow", "ssh_exposed" if not ufw.get("active") else "ssh_active")
        cutoff = time.time() - 86400
        for a in (self.state.get("alerts") or [])[:20]:
            try:
                ts = datetime.fromisoformat(a.get("time", "")).timestamp()
            except ValueError:
                continue
            if ts < cutoff:
                continue
            if a.get("severity") == "danger":
                raise_to("red", "danger_alert")
                break
        if self.suspended:
            raise_to("red", "suspended_process")
        integ = self.state.get("integrity") or {}
        app = integ.get("app") or {}
        rootkit_warns = sum(len(t.get("warnings") or []) for name, t in (integ.get("tools") or {}).items() if name != "lynis") \
            + len(app.get("modified") or []) + len(app.get("missing") or [])
        if rootkit_warns:
            raise_to("red", "integrity_warnings")          # rootkits, fichiers de paquets ou de l'application modifiés
        elif integ.get("warnings"):
            raise_to("yellow", "hardening_warnings")       # avertissements Lynis seuls (durcissement) : pas une compromission
        vulns = self.state.get("vulns") or {}
        counts = vulns.get("counts") or {}
        if counts.get("unfixed") or counts.get("pro_only"):
            raise_to("blue", "open_vulns")
        if vulns.get("flatpak") or vulns.get("snap"):
            raise_to("yellow", "app_store_updates")
        upd = self.state.get("app_update") or {}
        if upd.get("available") and upd.get("verified"):
            raise_to("yellow", "app_update")
        pers = self.state.get("persistence") or {}
        if (pers.get("counts") or {}).get("untrusted"):
            raise_to("yellow", "unknown_persistence")
        if not self.monitor.active and not TEST_MODE:
            raise_to("yellow", "monitor_inactive")
        # Disponibilité (CIA) : instantanés système Timeshift
        ts = self.state.get("timeshift") or {}
        if self.settings.get("timeshift_check") is not False and ts.get("checked_at"):     # backup_check = fichiers seulement
            if not ts.get("installed") or not ts.get("configured") or not ts.get("schedule"):
                raise_to("yellow", "timeshift_off")
            elif ts.get("last"):
                try:
                    if (time.time() - datetime.fromisoformat(ts["last"]).timestamp()) > 30 * 86400:
                        raise_to("yellow", "timeshift_old")
                except ValueError:
                    pass
        return {"color": color, "reasons": reasons}

    def refresh_overall(self):
        new = self.compute_overall()
        if new != self.overall:
            self.overall = new
            self.broadcast({"event": "overall", "overall": new})
        return new

    # ── Sessions administrateur ──────────────────────────────────────────
    def is_unlocked(self, uid):
        if uid == 0:
            return True
        exp = self.unlocked.get(uid, 0)
        if exp and exp > time.time():
            return True
        self.unlocked.pop(uid, None)
        return False

    def admin_required(self, cmd, req, uid):
        """Actions réservées à un administrateur authentifié (pkexec → unlock)."""
        if cmd == "firewall_set":
            return not req.get("enabled")
        if cmd == "firewall_profile":
            # L'utilisateur sait sur quel réseau il est : le service applique le profil sans mot de passe
            # (sauf en mode famille, où les actions sensibles restent réservées à un administrateur).
            return bool(self.settings.get("family_mode"))
        if cmd in ("timeshift_disable", "harden_revert"):
            return True
        if cmd == "ssh_set":
            return bool(req.get("enabled"))
        if cmd in ("firewall_defaults", "firewall_rule_add", "firewall_rule_delete", "install_update", "install_tools",
                   "install_phased", "install_package"):
            return True
        if cmd in ("set_settings", "trust_program", "untrust_program", "acknowledge_persistence", "acknowledge_integrity",
                   "acknowledge_vuln", "acknowledge_port", "system_upgrade", "harden_apply", "forget_network"):
            return bool(self.settings.get("family_mode"))
        return False

    # ── Première installation / reprise automatique ──────────────────────
    def check_first_scan(self):
        """Programme le scan complet initial (et une MàJ avant si les bases manquent)."""
        if self.shutdown.is_set():
            return
        with self.queue_lock:
            busy = self.current is not None or bool(self.queue)
        if busy:
            return
        prog = self.load_progress()
        if prog.get("in_progress") and prog.get("auto"):
            log(f"Reprise du scan automatique interrompu de {prog.get('path')}")
            self.enqueue(Job("scan", path=prog.get("path", "/"), resume=True, auto=True,
                             requested_by="system"))
            return
        if not os.path.exists(FIRST_SCAN_FLAG):
            return
        if time.time() - self.last_first_scan_attempt < 600:
            return
        self.last_first_scan_attempt = time.time()
        if db_last_update() is None:
            log("Bases virales absentes : mise à jour avant le scan initial")
            self.enqueue(Job("update", auto=True, requested_by="system"))
        log("Scan complet initial du système (première installation)")
        self.enqueue(Job("scan", path="/", auto=True, requested_by="system"))

    def maintenance_loop(self):
        time.sleep(15)  # laisser le système finir de démarrer
        first_status_done = False
        while not self.shutdown.is_set():
            try:
                self.check_first_scan()
                self.check_weekly_scan()
                if not first_status_done:
                    first_status_done = True
                    threading.Thread(target=self.refresh_system_status, daemon=True).start()
                if time.time() - self.last_security > 300:
                    self.refresh_security(force=True)
                    self.refresh_overall()
                if time.time() - self.last_daily > 86400 and not self.daily_running:
                    threading.Thread(target=self.daily_tasks, daemon=True).start()
                self.check_weekly_integrity()
                for uid, exp in list(self.unlocked.items()):
                    if exp < time.time():
                        self.unlocked.pop(uid, None)
            except Exception as e:  # noqa: BLE001
                log(f"Maintenance : {e}")
            self.shutdown.wait(60)

    # ── Statut ───────────────────────────────────────────────────────────
    def status(self, uid=-1):
        with self.queue_lock:
            job = self.current.public() if self.current else None
            queue = [j.public() for j in self.queue]
        if job and job.get("phase") == "integrity" and self.integrity_progress:
            job["integrity_progress"] = self.integrity_progress
        prog = self.load_progress()
        resumable = None
        if prog.get("in_progress") and not job:
            resumable = {"path": prog.get("path"), "scanned": prog.get("scanned", 0),
                         "total": prog.get("total", 0), "auto": prog.get("auto", False)}
        db = db_last_update()
        state = self.state.snapshot()
        sys_status = state.get("system_status") or {}
        return {
            "ok": True, "version": VERSION, "job": job, "queue": queue,
            "state": {k: v for k, v in state.items() if k not in ("system_status", "alerts", "vulns", "checklist", "integrity", "persistence", "app_update", "trusted_programs", "acknowledged_persistence")},
            "resumable": resumable,
            "first_scan_pending": os.path.exists(FIRST_SCAN_FLAG),
            "db_last_update": db.isoformat(timespec="seconds") if db else None,
            "db_files": db_files_info(),
            "monitor_active": self.monitor.active,
            "network_active": self.network.active,
            "upload_gb": round(self.network.current_gb, 2),
            "usb_active": self.usb.active,
            "usb_pending": self.usb.pending_list(),
            "settings": self.settings.snapshot(),
            "security": self.security or self.refresh_security(broadcast=False),
            "timeshift": self.state.get("timeshift"),
            "overall": self.overall,
            "unlocked": self.is_unlocked(uid) if uid >= 0 else False,
            "family_mode": bool(self.settings.get("family_mode")),
            "admin_groups": [g for g in uid_groups(uid) if g in ADMIN_GROUPS] if uid > 0 else [],
            "suspended": list(self.suspended.values()),
            "app_update": {k: v for k, v in (state.get("app_update") or {}).items() if k != "path"},
            "vulns_summary": {k: (state.get("vulns") or {}).get(k) for k in ("checked_at", "counts", "by_priority", "ok", "error")}
                              | {"flatpak": len((state.get("vulns") or {}).get("flatpak", [])), "snap": len((state.get("vulns") or {}).get("snap", []))}
                              if state.get("vulns") else None,
            "checklist_summary": dict({k: (state.get("checklist") or {}).get(k) for k in ("checked_at", "score", "grade")},
                                      todo=sum(1 for i in (state.get("checklist") or {}).get("items", []) if i.get("status") in ("warn", "fail")))
            if state.get("checklist") else None,
            "integrity_summary": {"checked_at": (state.get("integrity") or {}).get("checked_at"),
                                  "warnings": (state.get("integrity") or {}).get("warnings")} if state.get("integrity") else None,
            "persistence_summary": (state.get("persistence") or {}).get("counts"),
            "connections_active": self.connections.active,
            "alerts": (state.get("alerts") or [])[:10],
            "system_status": {k: sys_status.get(k) for k in
                              ("checked_at", "ok", "upgradable", "security", "recommended", "phased", "held", "cve_count",
                               "reboot_required", "os", "kernel", "lists_updated")} if sys_status else None,
        }

    # ── Quarantaine système ──────────────────────────────────────────────
    def quarantine_list(self):
        files = []
        try:
            for f in sorted(Path(SYSTEM_QUARANTINE_DIR).iterdir(),
                            key=lambda x: x.stat().st_mtime, reverse=True):
                if f.is_file() and not f.name.startswith(".clamav-quarantine-lock"):
                    st = f.stat()
                    files.append({
                        "name": f.name, "path": str(f), "size": st.st_size,
                        "date": datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M"),
                        "scope": "system",
                    })
        except OSError:
            pass
        return quarantine_enrich(files, SYSTEM_QUARANTINE_DIR)

    @staticmethod
    def _in_quarantine(path):
        try:
            p = Path(path).resolve()
            return p.parent == Path(SYSTEM_QUARANTINE_DIR).resolve() and p.is_file()
        except OSError:
            return False

    # ── Autorisations ────────────────────────────────────────────────────
    @staticmethod
    def _home_of(uid):
        try:
            return pwd.getpwuid(uid).pw_dir
        except KeyError:
            return None

    def _scan_path_allowed(self, path, uid):
        if uid == 0:
            return True
        norm = os.path.normpath(path)
        if norm in DAEMON_ALLOWED_ROOTS:
            return True
        if norm.startswith(("/media/", "/mnt/")):
            return True          # supports amovibles montés
        home = self._home_of(uid)
        if home and home != "/" and (norm == home or norm.startswith(home.rstrip("/") + "/")):
            return True
        return False

    def _dest_allowed(self, dest, uid):
        if uid == 0:
            return True
        home = self._home_of(uid)
        norm = os.path.normpath(dest)
        return bool(home and home != "/" and (norm == home or norm.startswith(home.rstrip("/") + "/")))

    # ── Traitement des commandes ─────────────────────────────────────────
    def handle(self, req, uid):
        cmd = req.get("cmd")

        if cmd == "ping":
            return {"ok": True, "version": VERSION}

        if cmd == "status":
            return self.status(uid)

        if cmd == "unlock":
            target = int(req.get("uid", -1))
            if uid != 0 and not TEST_MODE:
                return {"ok": False, "error": "forbidden"}
            if target < 0:
                return {"ok": False, "error": "invalid_uid"}
            self.unlocked[target] = time.time() + UNLOCK_TTL
            self.write_log(f"admin unlock uid {target}")
            self.broadcast({"event": "unlocked", "uid": target, "ttl": UNLOCK_TTL})
            return {"ok": True, "ttl": UNLOCK_TTL}

        if cmd == "lock":
            self.unlocked.pop(uid, None)
            self.broadcast({"event": "locked", "uid": uid})
            return {"ok": True}

        if cmd == "auth_status":
            return {"ok": True, "unlocked": self.is_unlocked(uid), "family_mode": bool(self.settings.get("family_mode")),
                    "admin_groups": [g for g in uid_groups(uid) if g in ADMIN_GROUPS] if uid > 0 else []}

        if self.admin_required(cmd, req, uid) and not self.is_unlocked(uid):
            return {"ok": False, "error": "admin_required"}

        if cmd == "overall":
            return {"ok": True, "overall": self.refresh_overall()}

        if cmd == "check_update":
            info = self.check_app_update(force=True)
            return {"ok": True, "update": {k: v for k, v in info.items() if k != "path"}}

        if cmd == "install_update":
            info = self.state.get("app_update") or {}
            ok, detail = self.updater.install(info)
            self.write_log(f"install update {info.get('version')}: {ok} {detail}")
            return {"ok": ok, "error": "" if ok else "command_failed", "detail": detail}

        if cmd == "app_integrity":
            return {"ok": True, "integrity": app_integrity()}

        if cmd == "vulns":
            if req.get("refresh") and not self.daily_running:
                threading.Thread(target=self.daily_tasks, kwargs={"force": True}, daemon=True).start()
                return {"ok": True, "refreshing": True, "vulns": self.public_vulns(self.state.get("vulns"))}
            return {"ok": True, "refreshing": self.daily_running, "vulns": self.public_vulns(self.state.get("vulns"))}

        if cmd == "checklist":
            if req.get("refresh"):
                self.refresh_security(force=True, broadcast=False)
                return {"ok": True, "checklist": self.refresh_checklist()}
            return {"ok": True, "checklist": self.state.get("checklist")}

        if cmd == "connections":
            return {"ok": True, "connections": self.connections.snapshot()}

        if cmd == "persistence":
            if req.get("refresh"):
                pers = self.apply_acknowledged(collect_persistence())
                self.state.update(persistence=pers)
                return {"ok": True, "persistence": pers}
            return {"ok": True, "persistence": self.state.get("persistence")}

        if cmd == "integrity":
            if req.get("run"):
                started = not self.integrity_running
                if started:
                    threading.Thread(target=self.run_integrity, daemon=True).start()
                return {"ok": True, "running": True, "started": started, "integrity": self.integrity_payload()}
            return {"ok": True, "running": self.integrity_running, "integrity": self.integrity_payload()}

        if cmd == "backup_status":
            return {"ok": True, "timeshift": self.refresh_backup(force=bool(req.get("refresh")))}

        if cmd in ("timeshift_enable", "timeshift_disable"):
            # Activer : sans mot de passe (protège le système). Désactiver : administrateur (voir admin_required).
            if os.geteuid() != 0:
                return {"ok": False, "error": "root_required"}
            if not shutil.which("timeshift"):
                return {"ok": False, "error": "timeshift_missing"}
            try:
                with open(TIMESHIFT_CONF, encoding="utf-8") as f:
                    existing = json.load(f)
            except (OSError, ValueError):
                existing = {}
            if cmd == "timeshift_enable":
                # Garde-fou : jamais sans avoir mesuré la place (la première copie rsync, c'est tout le système)
                if self.timeshift_enabling:
                    return {"ok": False, "error": "busy_timeshift"}
                size = self.cached_system_size()
                if size is None:
                    self.timeshift_enabling = True
                    threading.Thread(target=self._timeshift_enable_worker, args=(existing,), daemon=True).start()
                    return {"ok": True, "pending": True}
                return self._timeshift_enable_now(existing, size)
            for k in ("schedule_monthly", "schedule_weekly", "schedule_daily", "schedule_hourly", "schedule_boot"):
                existing[k] = "false"
            timeshift_write_config(existing)
            try:
                os.remove(TIMESHIFT_CRON)
            except OSError:
                pass
            self.state.update(timeshift_suspended=None)
            self.write_log("timeshift schedules disabled")
            self.refresh_backup(force=True)
            self.refresh_overall()
            return {"ok": True}

        if cmd in ("harden_apply", "harden_revert"):
            # Recommandations Lynis : appliquer (sans mot de passe, protège le système ; mode famille : administrateur)
            # ou annuler (administrateur). Tâche de fond ; résultat diffusé par l'événement hardening_done.
            revert = cmd == "harden_revert"
            tests = [str(t) for t in (req.get("tests") or []) if (harden.CATALOG.get(str(t)) or {}).get("kind") == "apply"]
            if req.get("all") and not revert:
                tests = self.pending_safe_hardening(self.state.get("integrity"))
            if not tests:
                return {"ok": False, "error": "nothing_to_harden"}
            if os.geteuid() != 0 and not TEST_MODE:
                return {"ok": False, "error": "root_required"}
            if not self.start_hardening(tests, revert=revert):
                return {"ok": False, "error": "busy_hardening"}
            return {"ok": True, "started": True, "tests": tests}

        if cmd == "auto_updates_enable":
            # « Activer » (sans mot de passe : protège le système) : automatisation du Gestionnaire de mises à jour de
            # Linux Mint, sinon unattended-upgrades. Les réglages utilisateur (Spices, Flatpak) sont faits par l'interface.
            if TEST_MODE:
                return {"ok": True, "method": "test"}
            if os.geteuid() != 0:
                return {"ok": False, "error": "root_required"}
            if os.path.exists(MINT_AUTOMATION):
                r = run_quiet([MINT_AUTOMATION, "upgrade", "enable"], timeout=120)
                ok = r.returncode == 0 and (unit_enabled("mintupdate-automation-upgrade.timer")
                                            or os.path.exists(MINT_AUTO_UPGRADE_FLAG))
                method, detail = "mintupdate", ((r.stderr or "") + (r.stdout or "")).strip()[-200:]
            elif os.path.exists("/usr/bin/unattended-upgrade"):
                try:
                    with open(APT_AUTO_CONF, "w") as f:
                        f.write('APT::Periodic::Update-Package-Lists "1";\nAPT::Periodic::Unattended-Upgrade "1";\n')
                    ok, method, detail = True, "unattended", ""
                except OSError as e:
                    ok, method, detail = False, "unattended", str(e)
            else:
                return {"ok": False, "error": "auto_updates_unavailable"}
            self.write_log(f"automatic updates enable ({method}) → {'ok' if ok else 'failed'} {detail}")
            if ok:
                threading.Thread(target=self.refresh_checklist, daemon=True).start()
            return {"ok": ok, "error": "" if ok else "command_failed", "method": method, "detail": detail}

        if cmd == "install_package":
            name = str(req.get("name") or "")
            if name not in ("rclone", "timeshift", "gocryptfs"):
                return {"ok": False, "error": "forbidden", "forbidden": True}
            if TEST_MODE:
                return {"ok": True, "detail": "test_mode"}
            r = run_quiet(["systemd-run", "--unit", f"clamav-antivirus-pkg-{int(time.time())}", "--collect", "--quiet",
                           "-p", "Environment=DEBIAN_FRONTEND=noninteractive",
                           "/bin/sh", "-c", f"apt-get install -y {name}"], timeout=30)
            return {"ok": r.returncode == 0, "error": "" if r.returncode == 0 else "command_failed",
                    "detail": ((r.stderr or "") + (r.stdout or "")).strip()[-200:]}

        if cmd == "install_tools":
            if TEST_MODE:
                return {"ok": True, "detail": "test_mode"}
            r = run_quiet(["systemd-run", "--unit", f"clamav-antivirus-tools-{int(time.time())}", "--collect", "--quiet",
                           "-p", "Environment=DEBIAN_FRONTEND=noninteractive",
                           "/bin/sh", "-c", "apt-get install -y lynis unhide chkrootkit debsums"], timeout=30)
            return {"ok": r.returncode == 0, "error": "" if r.returncode == 0 else "command_failed",
                    "detail": ((r.stderr or "") + (r.stdout or "")).strip()[-200:]}

        if cmd == "system_upgrade":
            # « Mettre à jour » : apt-get update && apt-get upgrade dans une unité transitoire, puis nouvel état du système
            sysst = self.state.get("system_status") or {}
            if not sysst.get("upgradable") and not req.get("force"):
                return {"ok": False, "error": "nothing_to_upgrade"}
            with self.system_status_lock:
                if self.system_upgrade_running:
                    return {"ok": False, "error": "busy_upgrade"}
                self.system_upgrade_running = True
            unit = None if TEST_MODE else f"clamav-antivirus-sysupgrade-{int(time.time())}"
            threading.Thread(target=self._system_upgrade_worker, args=(unit,), daemon=True).start()
            self.write_log("system upgrade requested" + (" (test mode)" if TEST_MODE else ""))
            return {"ok": True, "detail": "test_mode" if TEST_MODE else ""}

        if cmd == "install_phased":
            sysst = self.state.get("system_status") or {}
            names = sorted({p["name"] for p in sysst.get("packages", []) if p.get("category") == "phased"})
            if not names:
                return {"ok": False, "error": "nothing_phased"}
            if TEST_MODE:
                return {"ok": True, "detail": "test_mode", "packages": names}
            r = run_quiet(["systemd-run", "--unit", f"clamav-antivirus-phased-{int(time.time())}", "--collect", "--quiet",
                           "-p", "Environment=DEBIAN_FRONTEND=noninteractive",
                           "/bin/sh", "-c", "apt-get install -y -o APT::Get::Always-Include-Phased-Updates=true " + " ".join(names)], timeout=30)
            self.write_log(f"install phased: {names} → {r.returncode}")
            return {"ok": r.returncode == 0, "error": "" if r.returncode == 0 else "command_failed",
                    "detail": ((r.stderr or "") + (r.stdout or "")).strip()[-200:], "packages": names}

        if cmd == "process_action":
            try:
                pid = int(req.get("pid"))
            except (TypeError, ValueError):
                return {"ok": False, "error": "invalid_pid"}
            info = self.suspended.get(pid)
            if not info:
                return {"ok": False, "error": "not_suspended"}
            action = req.get("action")
            try:
                if action == "continue":
                    os.kill(pid, signal.SIGCONT)
                elif action in ("kill", "quarantine"):
                    os.kill(pid, signal.SIGKILL)
                    if action == "quarantine":
                        exe = (info.get("exe") or "").replace(" (deleted)", "")
                        if exe and os.path.isfile(exe) and not exe.startswith(("/usr/", "/bin/", "/sbin/", "/lib")):
                            target = os.path.join(SYSTEM_QUARANTINE_DIR, os.path.basename(exe))
                            shutil.move(exe, target)
                            os.chmod(target, 0o600)
                else:
                    return {"ok": False, "error": "invalid_action"}
            except OSError as e:
                return {"ok": False, "error": "command_failed", "detail": str(e)}
            self.suspended.pop(pid, None)
            self.write_log(f"process {pid} ({info.get('comm')}): {action}")
            self.broadcast({"event": "suspended", "suspended": list(self.suspended.values())})
            self.refresh_overall()
            return {"ok": True}

        if cmd == "scan":
            path = req.get("path", "/")
            if not os.path.isabs(path) or not os.path.isdir(path):
                return {"ok": False, "error": "not_found", "path": path}
            if not self._scan_path_allowed(path, uid):
                return {"ok": False, "error": "forbidden", "forbidden": True}
            with self.queue_lock:
                if self.current or self.queue:
                    busy = (self.current or self.queue[0]).public()
                    return {"ok": False, "error": "busy", "busy": busy}
            usb = None
            if req.get("usb_devnode"):
                usb = self.usb.take_pending(req["usb_devnode"]) or {"devnode": req["usb_devnode"]}
                usb = dict(usb, private_mount=False, mountpoint=os.path.normpath(path))
            job = self.enqueue(Job("scan", path=os.path.normpath(path),
                                   resume=bool(req.get("resume")), requested_by=uid, usb=usb,
                                   integrity=bool(req.get("integrity")), use_cache=not bool(req.get("nocache"))))
            return {"ok": True, "job_id": job.id, "queued": False}

        if cmd == "update":
            with self.queue_lock:
                if any(j.kind == "update" for j in self.queue) or \
                        (self.current and self.current.kind == "update"):
                    return {"ok": True, "job_id": self.current.id if self.current else None,
                            "queued": True, "already": True}
                queued = self.current is not None or bool(self.queue)
            job = self.enqueue(Job("update", requested_by=uid))
            return {"ok": True, "job_id": job.id, "queued": queued}

        if cmd == "cancel":
            with self.queue_lock:
                job = self.current
                self.queue.clear()
            if job:
                job.cancel(by_user=True)
                return {"ok": True}
            return {"ok": False, "error": "idle"}

        if cmd == "usb_decision":
            info = self.usb.take_pending(req.get("devnode", ""))
            return {"ok": True, "usb": info}

        if cmd == "usb_pending":
            return {"ok": True, "pending": self.usb.pending_list()}

        if cmd == "system_status":
            if req.get("refresh"):
                started = self.refresh_system_status(force=bool(req.get("force")))
                return {"ok": True, "refreshing": started, "status": self.state.get("system_status")}
            return {"ok": True, "status": self.state.get("system_status")}

        if cmd == "get_settings":
            return {"ok": True, "settings": self.settings.snapshot(), "stats": {"geoip": self.connections.geoip_stats()},
                    "locked": sorted(self.locked_settings),
                    "policy": {"name": self.policy.get("name", ""), "signed": bool(self.policy.get("_signed"))} if self.policy else None,
                    "allowlist": {"version": self.state.get("allowlist_version"), "updated": self.state.get("allowlist_updated"),
                                  "patterns": len(self.central_patterns)},
                    "telemetry_sent": self.state.get("telemetry_sent")}

        if cmd == "set_settings":
            incoming = dict(req.get("settings") or {})
            locked = [k for k in incoming if k in self.locked_settings]
            for k in locked:
                incoming.pop(k, None)
            changed, errors = self.settings.update(incoming)
            errors = list(errors) + [f"locked:{k}" for k in locked]
            applied = self.apply_settings(changed)
            if changed:
                self.write_log(f"settings: {', '.join(f'{k}={v}' for k, v in changed.items())}")
                self.broadcast({"event": "settings", "settings": self.settings.snapshot()})
                self.refresh_overall()
            return {"ok": True, "settings": self.settings.snapshot(), "changed": changed,
                    "applied": applied, "errors": errors}

        if cmd == "security_status":
            return {"ok": True, "security": self.refresh_security(force=bool(req.get("refresh")), broadcast=False)}

        if cmd == "firewall_profile":
            profile = str(req.get("profile") or "")
            if profile not in FIREWALL_PROFILES:
                return {"ok": False, "error": "invalid_profile"}
            if os.geteuid() != 0:
                return {"ok": False, "error": "root_required"}
            if uid not in (0,) and uid < 1000:
                return {"ok": False, "error": "forbidden"}
            ok, text = self.apply_firewall_profile(profile)
            if ok:
                self.settings.update({"firewall_profile": profile})
                self.remember_network_profile(profile)
            self.refresh_security(force=True)
            self.refresh_overall()
            return {"ok": ok, "error": "" if ok else "command_failed", "detail": text, "profile": profile,
                    "rules": len(profile_rules(profile))}

        if cmd in ("firewall_set", "firewall_defaults", "firewall_rule_add", "firewall_rule_delete", "ssh_set"):
            if os.geteuid() != 0:
                return {"ok": False, "error": "root_required"}
            if uid not in (0,) and uid < 1000:
                return {"ok": False, "error": "forbidden"}
            ok, text = self.security_command(cmd, req)
            sec = self.refresh_security(force=True)
            self.refresh_overall()
            self.refresh_checklist_async()                      # score, « Pare-feu » et badge suivent tout de suite
            ufw_now = (sec or {}).get("ufw") or {}
            enabling = cmd == "firewall_set" and bool(req.get("enabled"))
            if enabling and ok and not ufw_now.get("active"):
                ok, text = False, text or "firewall not active after enable"
            err = "" if ok else ("firewall_not_active" if enabling else "command_failed")
            return {"ok": ok, "error": err, "detail": text, "conflicts": ufw_now.get("conflicts") or []}

        if cmd == "alerts":
            return {"ok": True, "alerts": self.state.get("alerts", [])}

        if cmd == "trusted_programs":
            return {"ok": True, "programs": self.state.get("trusted_programs") or [],
                    "acknowledged": self.state.get("acknowledged_persistence") or []}

        if cmd == "trust_program":
            # « C'est moi » : le programme ne déclenche plus d'alerte (rafale, connexion), même s'il est inconnu de dpkg
            exe = normalize_exe(req.get("exe"))
            if not exe or not os.path.isabs(exe):
                return {"ok": False, "error": "invalid_path"}
            try:
                who = pwd.getpwuid(uid).pw_name
            except KeyError:
                who = str(uid)
            programs = [p for p in (self.state.get("trusted_programs") or []) if p.get("exe") != exe]
            programs.insert(0, {"exe": exe, "comm": str(req.get("comm") or os.path.basename(exe))[:64],
                                "added": now_iso(), "by": who})
            programs = programs[:200]
            self.state.update(trusted_programs=programs)
            self._trusted_set = {p["exe"] for p in programs}
            alerts = [a for a in (self.state.get("alerts") or [])
                      if not (a.get("kind") in ("burst", "connection") and normalize_exe(a.get("exe")) == exe)]
            self.state.update(alerts=alerts)
            for spid, info in list(self.suspended.items()):
                if normalize_exe(info.get("exe")) == exe:
                    try:
                        os.kill(spid, signal.SIGCONT)
                    except OSError:
                        pass
                    self.suspended.pop(spid, None)
            self.connections.mark_trusted(exe)
            self.write_log(f"✔ trusted program: {exe} (by {who})")
            self.broadcast({"event": "trusted", "programs": programs, "acknowledged": self.state.get("acknowledged_persistence") or []})
            self.broadcast({"event": "suspended", "suspended": list(self.suspended.values())})
            self.refresh_overall()
            return {"ok": True, "programs": programs}

        if cmd == "untrust_program":
            exe = normalize_exe(req.get("exe"))
            programs = [p for p in (self.state.get("trusted_programs") or []) if p.get("exe") != exe]
            self.state.update(trusted_programs=programs)
            self._trusted_set = {p["exe"] for p in programs}
            self.monitor.dpkg_cache.pop(exe, None)
            self.write_log(f"✘ untrusted program: {exe}")
            self.broadcast({"event": "trusted", "programs": programs, "acknowledged": self.state.get("acknowledged_persistence") or []})
            return {"ok": True, "programs": programs}

        if cmd == "tray_quit":
            # « Quitter » autorisé par un administrateur : ne pas relancer le bouclier dans cette session
            ids = {s["id"] for s in graphical_sessions() if s["uid"] == uid} if not TEST_MODE else {"test"}
            self.tray_stopped[uid] = ids
            self.write_log(f"tray quit by uid {uid} (sessions {sorted(ids)})")
            return {"ok": True, "sessions": sorted(ids)}

        if cmd == "telemetry_preview":
            # Aperçu de la charge utile telle qu'elle serait envoyée (rien n'est transmis)
            try:
                payload = self.build_telemetry_payload()
            except Exception as e:  # noqa: BLE001
                return {"ok": False, "error": "internal", "detail": str(e)[:200]}
            return {"ok": True, "payload": payload, "url": TELEMETRY_URL}

        if cmd == "forget_network":
            # Le réseau redevient inconnu : Public d'office à la prochaine connexion (tout de suite si c'est le réseau courant)
            key = str(req.get("key") or "")
            known = dict(self.state.get("network_profiles") or {})
            if key not in known:
                return {"ok": False, "error": "not_found"}
            known.pop(key)
            self.state.update(network_profiles=known)
            self.write_log(f"network forgotten: {key}")
            if self.current_network and self.current_network.get("key") == key:
                self.check_network(force=True)
            else:
                self.refresh_security(force=True)
            return {"ok": True}

        if cmd == "acknowledge_integrity":
            # « C'est normal » : un avertissement d'intégrité (chkrootkit, debsums, unhide, Lynis) approuvé ne compte plus
            tool, text = str(req.get("tool") or "")[:32], str(req.get("text") or "")[:4000]
            if tool not in INTEGRITY_TOOLS or not text.strip():
                return {"ok": False, "error": "invalid_key"}
            key = integrity_ack_key(tool, text)
            ack = [k for k in (self.state.get("acknowledged_integrity") or []) if k != key]
            if not req.get("remove"):
                ack.insert(0, key)
            self.state.update(acknowledged_integrity=ack[:500])
            integ = self.apply_integrity_acks(dict(self.state.get("integrity") or {}))
            if integ:
                self.state.update(integrity=integ)
            self.write_log(f"integrity warning {'re-enabled' if req.get('remove') else 'acknowledged'} ({tool}): {text.splitlines()[0][:120]}")
            self.broadcast({"event": "integrity", "integrity": self.integrity_payload()})
            self.refresh_overall()
            return {"ok": True, "key": key}

        if cmd == "acknowledge_vuln":
            # « Ignorer » une ou plusieurs failles sans correctif (par CVE, tous paquets confondus) ; remove les réaffiche
            vulns = self.state.get("vulns") or {}
            acks = dict(self.state.get("acknowledged_vulns") or {})
            wanted = req.get("cves")
            if req.get("all_open"):
                wanted = [it.get("cve") or it.get("id") for it in vulns.get("items") or []
                          if it.get("status") in VULN_ACK_STATUSES and not it.get("dormant")]
            if not isinstance(wanted, list):
                wanted = [req.get("cve")]
            cves = []
            for c in wanted[:VULN_ACK_MAX]:
                c = str(c or "").strip()[:64]
                if re.match(r"^[A-Za-z0-9._:-]{4,64}$", c) and c not in cves:
                    cves.append(c)
            if not cves:
                return {"ok": False, "error": "invalid_key"}
            remove = bool(req.get("remove"))
            if remove:
                for c in cves:
                    acks.pop(c, None)
            else:
                pkgs = {}
                for it in vulns.get("items") or []:
                    if it.get("status") in VULN_ACK_STATUSES:
                        pkgs.setdefault(it.get("cve") or it.get("id"), set()).add(it.get("package") or "")
                now = now_iso()
                for c in cves:
                    acks[c] = {"at": now, "packages": sorted(pkgs.get(c) or [])[:20]}
                if len(acks) > VULN_ACK_MAX:
                    acks = dict(sorted(acks.items(), key=lambda kv: kv[1].get("at") or "")[-VULN_ACK_MAX:])
            self.state.update(acknowledged_vulns=acks)
            vulns = apply_vuln_acks(vulns, acks)
            self.state.update(vulns=vulns)
            self.write_log(f"{len(cves)} vulnerability(ies) {'re-enabled' if remove else 'acknowledged'}: {', '.join(cves[:8])}{'…' if len(cves) > 8 else ''}")
            self.broadcast({"event": "vulns", "vulns": self.public_vulns(vulns)})
            self.refresh_overall()
            return {"ok": True, "count": len(cves), "acknowledged": (vulns.get("counts") or {}).get("acknowledged_cves") or 0}

        if cmd == "acknowledge_port":
            # « Ignorer » un port joignable voulu (serveur web de développement…) : ne compte plus dans la checklist
            acks = dict(self.state.get("acknowledged_ports") or {})
            ports = (self.state.get("checklist") or {}).get("ports") or []
            wanted = req.get("keys")
            if req.get("all_reachable"):
                wanted = [p.get("key") or port_key(p) for p in ports if p.get("verdict") == "reachable"]
            if not isinstance(wanted, list):
                wanted = [req.get("key")]
            keys = []
            for k in wanted[:200]:
                k = str(k or "").strip()[:120]
                if re.match(r"^\d{1,5}/(tcp|udp):[A-Za-z0-9._+@ -]{0,80}$", k) and k not in keys:
                    keys.append(k)
            if not keys:
                return {"ok": False, "error": "invalid_key"}
            remove = bool(req.get("remove"))
            if remove:
                for k in keys:
                    acks.pop(k, None)
            else:
                now = now_iso()
                for k in keys:
                    acks[k] = {"at": now}
                if len(acks) > 500:
                    acks = dict(sorted(acks.items(), key=lambda kv: kv[1].get("at") or "")[-500:])
            self.state.update(acknowledged_ports=acks)
            self.write_log(f"{len(keys)} listening port(s) {'re-enabled' if remove else 'acknowledged'}: {', '.join(keys[:8])}")
            checklist = self.refresh_checklist()
            return {"ok": True, "count": len(keys), "checklist": checklist}

        if cmd == "acknowledge_persistence":
            key = str(req.get("key") or "")[:500]
            if not key:
                return {"ok": False, "error": "invalid_key"}
            ack = [k for k in (self.state.get("acknowledged_persistence") or []) if k != key]
            if not req.get("remove"):
                ack.insert(0, key)
            ack = ack[:500]
            self.state.update(acknowledged_persistence=ack)
            pers = self.apply_acknowledged(self.state.get("persistence") or {})
            self.state.update(persistence=pers)
            if not req.get("remove"):
                alerts = [a for a in (self.state.get("alerts") or [])
                          if not (a.get("kind") == "persistence" and key in ((a.get("item") or {}).get("key"), (a.get("extension") or {}).get("key")))]
                self.state.update(alerts=alerts)
            self.write_log(f"{'✘ un' if req.get('remove') else '✔ '}acknowledged persistence: {key}")
            self.broadcast({"event": "persistence", "persistence": pers})
            self.broadcast({"event": "trusted", "programs": self.state.get("trusted_programs") or [], "acknowledged": ack})
            self.refresh_overall()
            return {"ok": True, "acknowledged": ack}

        if cmd == "clear_alerts":
            self.state.update(alerts=[])
            return {"ok": True}

        if cmd == "quarantine_list":
            return {"ok": True, "files": self.quarantine_list()}

        if cmd == "quarantine_delete":
            p = req.get("path", "")
            if not self._in_quarantine(p):
                return {"ok": False, "error": "forbidden"}
            os.remove(p)
            self.write_log(f"quarantine: deleted {os.path.basename(p)}")
            return {"ok": True, "msg_key": "msg.quarantine.deleted",
                    "msg_params": {"name": os.path.basename(p)}}

        if cmd == "quarantine_restore":
            p, dest = req.get("path", ""), req.get("dest", "")
            if not self._in_quarantine(p):
                return {"ok": False, "error": "forbidden"}
            if not (os.path.isabs(dest) and os.path.isdir(dest) and self._dest_allowed(dest, uid)):
                return {"ok": False, "error": "restore_dest"}
            target = os.path.join(dest, os.path.basename(p))
            shutil.move(p, target)
            if uid:
                try:
                    pw = pwd.getpwuid(uid)
                    os.chown(target, pw.pw_uid, pw.pw_gid)
                except (KeyError, OSError):
                    pass
            self.write_log(f"quarantine: restored {os.path.basename(p)} -> {dest}")
            return {"ok": True, "msg_key": "msg.quarantine.restored",
                    "msg_params": {"name": os.path.basename(p)}}

        if cmd == "quarantine_empty":
            count = 0
            for f in Path(SYSTEM_QUARANTINE_DIR).iterdir():
                if f.is_file() and not f.name.startswith(".clamav-quarantine-lock"):
                    f.unlink()
                    count += 1
            self.write_log(f"quarantine: emptied ({count})")
            return {"ok": True, "msg_key": "msg.quarantine.emptied_system", "msg_params": {"count": count}}

        if cmd == "get_log":
            n = int(req.get("lines", 200))
            try:
                with open(SYSTEM_LOG_FILE) as f:
                    lines = f.readlines()[-n:]
            except OSError:
                lines = []
            return {"ok": True, "lines": lines}

        if cmd == "clear_log":
            open(SYSTEM_LOG_FILE, "w").close()
            return {"ok": True}

        if cmd == "test_event" and TEST_MODE:
            # Mode test uniquement (daemon non root) : injecter un événement pour le GUI
            event = req.get("payload") or {}
            if event.get("event") == "alert":
                self.publish_alert(event["alert"])
            elif event.get("event") == "usb_priority":
                # Simule une clé insérée pendant un scan : dossier déjà monté, analysé en priorité
                path = os.path.normpath(str(event.get("path") or ""))
                usb = {"devnode": "test", "label": event.get("label") or "TEST", "model": "", "size": 0, "fstype": "vfat",
                       "private_mount": False, "mountpoint": path}
                self._start_usb_job(Job("scan", path=path, usb=usb, requested_by="system"))
            else:
                self.broadcast(event)
            return {"ok": True}

        return {"ok": False, "error": "unknown_command", "cmd": cmd}

    def security_command(self, cmd, req):
        """Actions pare-feu / SSH demandées depuis la page Pare-feu."""
        if cmd == "firewall_set":
            if req.get("enabled"):
                if req.get("allow_ssh"):
                    self.ufw("allow", f"{ssh_port()}/tcp", "comment", "SSH")
                return firewall_enable_checked(self.ufw, self.write_log)
            return self.ufw("disable")
        if cmd == "firewall_defaults":
            results = []
            for direction in ("incoming", "outgoing"):
                policy = str(req.get(direction, "")).lower()
                if policy in VALID_POLICY:
                    results.append(self.ufw("default", policy, direction))
            if not results:
                return False, "invalid_policy"
            return all(ok for ok, _ in results), " | ".join(text for _, text in results)
        if cmd == "firewall_rule_add":
            action = str(req.get("rule_action") or req.get("action") or "allow").lower()
            proto = str(req.get("proto", "tcp")).lower()
            port = str(req.get("port", "")).strip()
            if action not in VALID_ACTION or proto not in VALID_PROTO or not re.fullmatch(r"\d{1,5}(:\d{1,5})?(,\d{1,5})*", port):
                return False, "invalid_rule"
            target = port if proto == "any" else f"{port}/{proto}"
            args = [action, target]
            comment = re.sub(r"[^\w .-]", "", str(req.get("comment", "")))[:40]
            if comment:
                args += ["comment", comment]
            return self.ufw(*args)
        if cmd == "firewall_rule_delete":
            try:
                number = int(req.get("number"))
            except (TypeError, ValueError):
                return False, "invalid_rule"
            return self.ufw("delete", str(number))
        if cmd == "ssh_set":
            if not (shutil.which("sshd") or os.path.exists("/usr/sbin/sshd")):
                return False, "ssh_not_installed"
            action = "enable" if req.get("enabled") else "disable"
            r = run_quiet(["systemctl", action, "--now", "ssh"], timeout=60)
            self.write_log(f"ssh: {action} → {r.returncode}")
            return r.returncode == 0, ((r.stdout or "") + (r.stderr or "")).strip()[:300]
        return False, "unknown"

    def handle_connection(self, sock):
        try:
            _pid, uid, _gid = peer_credentials(sock)
        except OSError:
            uid = -1
        sock.settimeout(30)
        conn = LineSocket(sock)
        try:
            req = conn.recv()
            if req is None:
                return
            if req.get("cmd") == "subscribe":
                conn.send(self.status(uid))
                sock.settimeout(5)   # ne jamais bloquer la diffusion sur un client lent
                with self.sub_lock:
                    self.subscribers.append(conn)
                return               # la connexion reste ouverte, gérée par broadcast()
            try:
                resp = self.handle(req, uid)
            except Exception as e:  # noqa: BLE001
                resp = {"ok": False, "error": "internal", "detail": str(e)}
            conn.send(resp)
        except (OSError, ValueError, socket.timeout) as e:
            log(f"Connexion : {e}")
        finally:
            with self.sub_lock:
                if conn not in self.subscribers:
                    conn.close()

    # ── Serveur ──────────────────────────────────────────────────────────
    def serve(self):
        for d in (SYSTEM_STATE_DIR, SYSTEM_LOG_DIR, SYSTEM_QUARANTINE_DIR,
                  os.path.dirname(DAEMON_SOCKET), USB_MOUNT_ROOT):
            os.makedirs(d, exist_ok=True)
        os.chmod(SYSTEM_QUARANTINE_DIR, 0o700)

        # Refuser de démarrer si un daemon répond déjà sur le socket
        if daemon_request("ping", timeout=1).get("ok"):
            log("Un daemon est déjà actif sur ce socket — arrêt.")
            sys.exit(1)
        try:
            os.unlink(DAEMON_SOCKET)
        except FileNotFoundError:
            pass

        self.server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.server.bind(DAEMON_SOCKET)
        os.chmod(DAEMON_SOCKET, 0o666)
        self.server.listen(16)
        self.server.settimeout(1)

        threading.Thread(target=self.worker, daemon=True, name="worker").start()
        threading.Thread(target=self.maintenance_loop, daemon=True, name="maintenance").start()
        threading.Thread(target=self.network_loop, daemon=True, name="network").start()
        self.monitor.start()
        self.network.start()
        self.connections.start()
        self.usb.start()
        os.makedirs(UPDATES_DIR, exist_ok=True)

        def warmup():
            self.refresh_security(force=True, broadcast=False)
            self.refresh_overall()
            time.sleep(90)
            if not self.shutdown.is_set():
                self.daily_tasks()
        threading.Thread(target=warmup, daemon=True).start()

        log(f"ClamAV Antivirus GUI daemon v{VERSION} à l'écoute sur {DAEMON_SOCKET}"
            + (" (mode test)" if TEST_MODE else ""))
        while not self.shutdown.is_set():
            try:
                sock, _ = self.server.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self.handle_connection, args=(sock,), daemon=True).start()

        self.stop()

    def stop(self):
        self.shutdown.set()
        with self.queue_lock:
            job = self.current
            self.queue_lock.notify_all()
        if job:
            log("Arrêt : interruption de l'opération en cours (reprise possible)")
            job.cancel()
            deadline = time.time() + 10
            while self.current is not None and time.time() < deadline:
                time.sleep(0.2)
        self.monitor.stop()
        for devnode in list(self.usb.mounted):
            self.usb.unmount(devnode)
        with self.sub_lock:
            for sub in self.subscribers:
                sub.close()
            self.subscribers.clear()
        try:
            self.server.close()
        except OSError:
            pass
        try:
            os.unlink(DAEMON_SOCKET)
        except OSError:
            pass
        log("Daemon arrêté")


# ═══════════════════════════════════════════════════════════════════════════
# Mode client (utilisé par le timer systemd et pour le diagnostic)
# ═══════════════════════════════════════════════════════════════════════════

def client_request(kind, path="/"):
    """Envoie une demande au daemon et suit son exécution jusqu'à la fin. Code retour 0 = OK."""
    if kind == "status":
        resp = daemon_request("status", timeout=3)
        print(json.dumps(resp, indent=2, ensure_ascii=False))
        return 0 if resp.get("ok") else 1
    if kind == "system-status":
        resp = daemon_request("system_status", timeout=3, refresh=True, force=True)
        print(json.dumps(resp, indent=2, ensure_ascii=False))
        return 0 if resp.get("ok") else 1
    if kind in ("check-update", "checklist", "vulns", "integrity", "connections", "persistence"):
        cmd = {"check-update": "check_update"}.get(kind, kind)
        resp = daemon_request(cmd, timeout=600, refresh=True, run=(kind == "integrity"))
        print(json.dumps(resp, indent=2, ensure_ascii=False)[:20000])
        return 0 if resp.get("ok") else 1

    # S'abonner avant de lancer pour ne rater aucun événement
    try:
        sub = daemon_connect(timeout=None)
        sub.send({"cmd": "subscribe"})
        sub.recv()
    except OSError as e:
        print(f"Service unavailable ({e})", flush=True)
        if kind == "update" and os.geteuid() == 0:
            print("Running freshclam directly.", flush=True)
            subprocess.run(["systemctl", "stop", "clamav-freshclam"], capture_output=True)
            rc = subprocess.run(["freshclam", "--stdout"]).returncode
            subprocess.run(["systemctl", "start", "clamav-freshclam"], capture_output=True)
            return rc
        return 1

    if kind == "update":
        resp = daemon_request("update", timeout=5)
    else:
        resp = daemon_request("scan", timeout=5, path=path)
    if not resp.get("ok"):
        print(f"Refused: {resp.get('error')}", flush=True)
        return 1
    job_id = resp.get("job_id")
    if resp.get("queued"):
        print(f"{kind} queued (job {job_id}) behind the running operation.", flush=True)
        return 0

    last_pct = -1
    while True:
        ev = sub.recv()
        if ev is None:
            print("Connection to daemon lost", flush=True)
            return 1
        et = ev.get("event")
        if et == "line":
            print(ev.get("text", ""), flush=True)
        elif et == "progress" and ev.get("total"):
            pct = int(ev["scanned"] * 100 / ev["total"])
            if pct != last_pct and pct % 5 == 0:
                print(f"… {pct}% ({ev['scanned']}/{ev['total']})", flush=True)
                last_pct = pct
        elif et == "job_done" and ev.get("id") == job_id:
            print(f"{ev.get('status')}: {ev.get('message')}", flush=True)
            return 0 if ev.get("status") in ("success", "clean", "infected") else 1


def main():
    args = sys.argv[1:]
    if args and args[0] == "--request":
        kind = args[1] if len(args) > 1 else "status"
        path = args[2] if len(args) > 2 else "/"
        sys.exit(client_request(kind, path))
    if args and args[0] in ("-h", "--help"):
        print(__doc__)
        return

    if os.geteuid() != 0 and "CLAMAV_ANTIVIRUS_SOCKET" not in os.environ:
        print("Ce service doit être lancé en root (ou avec CLAMAV_ANTIVIRUS_SOCKET pour les tests).",
              file=sys.stderr)
        sys.exit(1)

    daemon = Daemon()

    def on_signal(signum, _frame):
        log(f"Signal {signum} reçu")
        daemon.shutdown.set()

    signal.signal(signal.SIGTERM, on_signal)
    signal.signal(signal.SIGINT, on_signal)
    daemon.serve()


if __name__ == "__main__":
    main()
