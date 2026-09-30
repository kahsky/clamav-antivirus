#!/usr/bin/env python3
"""
ClamAV Antivirus GUI — module partagé entre le GUI et le daemon système.
Chemins, exclusions de scan, protocole socket (JSON par ligne) et utilitaires.
(c) 2026 Dukiwi SA - Estavayer-le-Lac
"""

import json
import os
import re
import socket
import struct
import subprocess
from datetime import datetime

VERSION = "1.20.2"

# ─── Chemins système (daemon root) ───────────────────────────────────────────
# Surchargeables par variables d'environnement pour les tests sans root.
SYSTEM_STATE_DIR = os.environ.get("CLAMAV_ANTIVIRUS_STATE_DIR", "/var/lib/clamav-antivirus")
SYSTEM_LOG_DIR   = os.environ.get("CLAMAV_ANTIVIRUS_LOG_DIR",   "/var/log/clamav-antivirus")
DAEMON_SOCKET    = os.environ.get("CLAMAV_ANTIVIRUS_SOCKET",    "/run/clamav-antivirus/daemon.sock")

SYSTEM_STATE_FILE      = os.path.join(SYSTEM_STATE_DIR, "state.json")
SYSTEM_QUARANTINE_DIR  = os.path.join(SYSTEM_STATE_DIR, "quarantine")
SYSTEM_PROGRESS_FILE   = os.path.join(SYSTEM_STATE_DIR, "scan_progress.json")
SYSTEM_FILELIST_CACHE  = os.path.join(SYSTEM_STATE_DIR, "scan_filelist.txt")
SYSTEM_SCAN_CACHE_DB   = os.path.join(SYSTEM_STATE_DIR, "scan-cache.db")     # fichiers sains déjà vérifiés (empreintes)
SYSTEM_SECRET_FILE     = os.path.join(SYSTEM_STATE_DIR, "secret")            # HMAC des manifestes .clamav (jamais sur la clé)
FIRST_SCAN_FLAG        = os.path.join(SYSTEM_STATE_DIR, "first-scan-pending")
SYSTEM_LOG_FILE        = os.path.join(SYSTEM_LOG_DIR, "scan.log")
SYSTEM_SETTINGS_FILE   = os.path.join(SYSTEM_STATE_DIR, "settings.json")

CLAMAV_DB_DIR = "/var/lib/clamav"

USB_MOUNT_ROOT         = os.path.join(os.path.dirname(DAEMON_SOCKET), "mnt")

# Unités systemd
UPDATE_TIMER_UNIT  = "clamav-antivirus-update.timer"
DAEMON_UNIT        = "clamav-antivirus-daemon.service"

# ─── Détection avancée ───────────────────────────────────────────────────────
# Supports USB : en dessous de cette taille, scan automatique avant montage ;
# au-dessus (disque dur USB), on demande à l'utilisateur.
USB_AUTO_SCAN_MAX_BYTES = 128 * 1024 ** 3
# Rafales d'écritures : un processus qui modifie autant de fichiers distincts
# dans la fenêtre donnée déclenche une alerte (info, ou danger si suspect).
BURST_WINDOW_SEC        = 15
BURST_INFO_THRESHOLD    = 50
BURST_DANGER_THRESHOLD  = 25      # fichiers du répertoire personnel, processus non fiable
BURST_PID_COOLDOWN_SEC  = 600
BURST_GLOBAL_COOLDOWN   = 30
# Écritures ignorées par le moniteur (caches, journaux, fichiers temporaires)
BURST_IGNORE_PREFIXES = (
    "/proc/", "/sys/", "/dev/", "/run/", "/tmp/", "/var/tmp/", "/var/log/",
    "/var/cache/", "/var/lib/apt/lists/", "/var/lib/clamav/", "/var/lib/clamav-antivirus/",
    "/var/log/journal/", "/var/lib/systemd/", "/home/.ecryptfs/",
)
BURST_IGNORE_PARTS = (
    "/.cache/", "/Cache/", "/cache2/", "/CachedData/", "/.local/share/Trash/",
    "/.thumbnails/", "/node_modules/", "/.git/", "/__pycache__/", "/.npm/", "/.cargo/registry/",
    "/.local/share/clamav-antivirus/", "/.config/Code/", "/.vscode/", "/.mozilla/firefox/",
    "/.config/google-chrome/", "/.config/chromium/", "/.config/BraveSoftware/",
)

LANGUAGES = ("fr", "en", "de", "it")

# ─── Réglages système (modifiables depuis la page Paramètres, appliqués par le daemon) ──
DEFAULT_SETTINGS = {
    # Envoi Internet : popup quand le volume envoyé dépasse le seuil dans la fenêtre donnée
    "upload_monitor": True,
    "upload_alert_gb": 5.0,
    "upload_window_hours": 1,
    # Rafales d'écritures (fanotify)
    "burst_monitor": True,
    "burst_info_threshold": BURST_INFO_THRESHOLD,
    "burst_danger_threshold": BURST_DANGER_THRESHOLD,
    "burst_window_sec": BURST_WINDOW_SEC,
    # Supports USB
    "usb_auto_scan": True,
    "usb_auto_scan_max_gib": 128,
    # Recherche de mises à jour des signatures (timer systemd)
    "update_hour": 7,
    "update_minute": 0,
    # Scan complet automatique hebdomadaire (0 = lundi … 6 = dimanche)
    "weekly_scan": False,
    "weekly_scan_day": 6,
    "weekly_scan_hour": 12,
    # Cache de scan : un fichier sain et inchangé (taille, dates, inode) n'est pas relu pendant N jours (0 = désactivé)
    "scan_cache_days": 30,
    # Mode famille : réglages et actions sensibles réservés à un administrateur authentifié
    "family_mode": False,
    # Réponse automatique : suspendre (SIGSTOP) un programme jugé dangereux, puis demander
    "auto_response": True,
    # Connexions sortantes : programmes inconnus, listes d'IP malveillantes, géolocalisation
    "connection_monitor": True,
    "geoip_lookup": True,
    # Clé ip-api.com Pro (optionnelle) : HTTPS et sans limite ; vide = service gratuit (15 requêtes groupées/min, HTTP)
    "geoip_api_key": "",
    # Disponibilité : sauvegarde des fichiers de l'utilisateur comptée dans l'état global (False = « Ignorer »)
    "backup_check": True,
    # État de Timeshift compté dans l'état global (False = « Ignorer » : PC sans place pour les instantanés)
    "timeshift_check": True,
    # Profil réseau du pare-feu : "" (non choisi), "home", "public", "enterprise"
    "firewall_profile": "",
    # Télémétrie anonyme (opt-in) : version, système, score, faux positifs approuvés, sans identifiant personnel
    "telemetry": False,
    # Durcissement automatique : recommandations Lynis sans risque appliquées après chaque audit
    "auto_harden": False,
    # Vérification d'intégrité hebdomadaire (Lynis, unhide, chkrootkit, debsums, fichiers de l'app)
    "integrity_weekly": True,
    "integrity_day": 6,
    "integrity_hour": 13,
    # Mises à jour de l'application (manifeste signé sur le dépôt Dukiwi)
    "app_update_check": True,
    "app_update_auto": False,
}

SETTINGS_LIMITS = {
    "upload_alert_gb": (0.1, 10000.0), "upload_window_hours": (1, 168),
    "burst_info_threshold": (5, 100000), "burst_danger_threshold": (5, 100000), "burst_window_sec": (5, 600),
    "usb_auto_scan_max_gib": (1, 100000),
    "update_hour": (0, 23), "update_minute": (0, 59),
    "weekly_scan_day": (0, 6), "weekly_scan_hour": (0, 23),
    "scan_cache_days": (0, 365),
    "integrity_day": (0, 6), "integrity_hour": (0, 23),
}


def sanitize_settings(current, incoming):
    """Fusionne des réglages entrants (dict) dans `current` en respectant types et limites.
    Retourne (settings, erreurs)."""
    result = dict(DEFAULT_SETTINGS)
    result.update(current or {})
    errors = []
    for key, value in (incoming or {}).items():
        if key not in DEFAULT_SETTINGS:
            errors.append(f"unknown:{key}")
            continue
        default = DEFAULT_SETTINGS[key]
        try:
            if isinstance(default, bool):
                value = value if isinstance(value, bool) else str(value).lower() in ("1", "true", "yes", "on")
            elif isinstance(default, int):
                value = int(float(value))
            elif isinstance(default, float):
                value = float(value)
            elif isinstance(default, str):
                value = "".join(ch for ch in str(value).strip() if ch.isalnum() or ch in "-_")[:128]
        except (TypeError, ValueError):
            errors.append(f"invalid:{key}")
            continue
        if key in SETTINGS_LIMITS:
            lo, hi = SETTINGS_LIMITS[key]
            value = max(lo, min(hi, value))
        result[key] = value
    return result, errors

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


# ── Index de quarantaine : fichier isolé → chemin d'origine et signature (alimenté par les lignes « moved to ») ──
def quarantine_index_path(quarantine_dir):
    return os.path.join(os.path.dirname(quarantine_dir.rstrip("/")), "quarantine-index.json")


def quarantine_index_load(quarantine_dir):
    try:
        with open(quarantine_index_path(quarantine_dir), encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def quarantine_index_add(quarantine_dir, dest, origin, signature):
    """Mémorise, pour le fichier isolé `dest`, son chemin d'origine et la signature détectée."""
    index = quarantine_index_load(quarantine_dir)
    index[os.path.basename(dest)] = {"origin": origin, "signature": signature or "",
                                     "time": datetime.now().isoformat(timespec="seconds")}
    if len(index) > 5000:
        for k in sorted(index, key=lambda k: index[k].get("time", ""))[:-5000]:
            index.pop(k, None)
    path = quarantine_index_path(quarantine_dir)
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(index, f, ensure_ascii=False)
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except OSError:
        pass


def parse_moved_line(line):
    """« /chemin/origine: moved to '/quarantaine/nom' » → (origine, destination) ou None."""
    m = re.match(r"^(.*): moved to '(.*)'$", line)
    return (m.group(1), m.group(2)) if m else None


def quarantine_enrich(files, quarantine_dir):
    """Ajoute origine, signature et date de détection aux entrées de la liste de quarantaine."""
    index = quarantine_index_load(quarantine_dir)
    for f in files:
        info = index.get(f.get("name") or "")
        if info:
            f["origin"] = info.get("origin") or ""
            f["signature"] = info.get("signature") or ""
            f["found_at"] = info.get("time") or ""
    return files


def find_command(path, exclude=SCAN_EXCLUDE, stat=False):
    """Commande find listant les fichiers réguliers à scanner sous `path`. Avec `stat`, chaque ligne porte aussi
    l'empreinte (taille, mtime, ctime, inode) séparée par des tabulations, pour le cache des fichiers sains."""
    cmd = ['find', path, '-type', 'f']
    for excl in exclude:
        cmd += ['!', '-path', excl]
    if stat:
        cmd += ['-printf', '%p\t%s\t%T@\t%C@\t%i\n']
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


# ─── Pare-feu UFW : analyse des sorties de commande ──────────────────────────

def parse_ufw_verbose(text):
    """Analyse `ufw status verbose` : statut et politiques par défaut."""
    info = {"active": False, "default_incoming": "", "default_outgoing": "", "default_routed": "", "logging": ""}
    for line in (text or "").splitlines():
        line = line.strip()
        if line.lower().startswith("status:"):
            info["active"] = "active" in line.lower() and "inactive" not in line.lower()
        elif line.lower().startswith("default:"):
            for part in line.split(":", 1)[1].split(","):
                part = part.strip()
                if "(incoming)" in part:
                    info["default_incoming"] = part.split()[0]
                elif "(outgoing)" in part:
                    info["default_outgoing"] = part.split()[0]
                elif "(routed)" in part:
                    info["default_routed"] = part.split()[0]
        elif line.lower().startswith("logging:"):
            info["logging"] = line.split(":", 1)[1].strip()
    return info


def parse_ufw_numbered(text):
    """Analyse `ufw status numbered` : liste de règles [{number, to, action, from, v6, raw}]."""
    rules = []
    for line in (text or "").splitlines():
        line = line.rstrip()
        if not line.startswith("["):
            continue
        try:
            number = int(line[1:line.index("]")].strip())
        except ValueError:
            continue
        rest = line[line.index("]") + 1:].strip()
        v6 = "(v6)" in rest
        rest = rest.replace("(v6)", "").strip()
        # Colonnes séparées par 2 espaces ou plus : To | Action | From
        cols = [c.strip() for c in re.split(r"\s{2,}", rest) if c.strip()]
        to = cols[0] if cols else rest
        action = cols[1] if len(cols) > 1 else ""
        src = " ".join(cols[2:]) if len(cols) > 2 else ""
        comment = ""
        if "#" in src:
            src, comment = src.split("#", 1)
            src, comment = src.strip(), comment.strip()
        rules.append({"number": number, "to": to, "action": action, "from": src, "v6": v6,
                      "comment": comment, "raw": line.strip()})
    return rules


# ─── Internationalisation ────────────────────────────────────────────────────

_I18N_CACHE = None


def load_i18n():
    """Charge ui/i18n.js (window.I18N = {...};) et retourne le dictionnaire par langue."""
    global _I18N_CACHE
    if _I18N_CACHE is not None:
        return _I18N_CACHE
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ui", "i18n.js")
    try:
        with open(path, encoding="utf-8") as f:
            raw = f.read()
        start, end = raw.index("{"), raw.rindex("}")
        _I18N_CACHE = json.loads(raw[start:end + 1])
    except Exception:
        _I18N_CACHE = {}
    return _I18N_CACHE


def pick_language(preferred=None):
    """Langue de l'interface : préférence explicite, sinon locale du système, sinon anglais."""
    if preferred in LANGUAGES:
        return preferred
    for var in ("LANGUAGE", "LC_ALL", "LC_MESSAGES", "LANG"):
        value = os.environ.get(var)
        if value:
            code = value.split(":")[0].split("_")[0].split(".")[0].lower()
            if code in LANGUAGES:
                return code
            if code and code != "c":
                break
    return "en"


def t(lang, key, **params):
    """Traduit une clé (repli : anglais, puis français, puis la clé elle-même)."""
    i18n = load_i18n()
    text = None
    for candidate in (lang, "en", "fr"):
        text = (i18n.get(candidate) or {}).get(key)
        if text is not None:
            break
    if text is None:
        text = key
    if params:
        try:
            text = text.format(**params)
        except (KeyError, IndexError, ValueError):
            pass
    return text


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
