#!/usr/bin/env python3
"""
ClamAV Antivirus — service système (root).

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
import json
import os
import pwd
import re
import shutil
import signal
import socket
import struct
import subprocess
import sys
import threading
import time
from collections import deque
from datetime import datetime
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from clamav_common import (  # noqa: E402
    VERSION, SYSTEM_STATE_DIR, SYSTEM_LOG_DIR, DAEMON_SOCKET,
    SYSTEM_STATE_FILE, SYSTEM_QUARANTINE_DIR, SYSTEM_PROGRESS_FILE,
    SYSTEM_FILELIST_CACHE, FIRST_SCAN_FLAG, SYSTEM_LOG_FILE, USB_MOUNT_ROOT,
    SYSTEM_SETTINGS_FILE, DEFAULT_SETTINGS, DAEMON_ALLOWED_ROOTS,
    BURST_PID_COOLDOWN_SEC, BURST_GLOBAL_COOLDOWN, BURST_IGNORE_PREFIXES, BURST_IGNORE_PARTS,
    LineSocket, peer_credentials, daemon_connect, daemon_request, find_command,
    is_noise_line, classify_line, db_last_update, db_files_info, t,
    sanitize_settings, parse_ufw_verbose, parse_ufw_numbered, systemd_is_active,
)

LOG_MAX_BYTES = 5 * 1024 * 1024
PROGRESS_INTERVAL = 0.25      # secondes entre deux événements de progression
PROGRESS_SAVE_INTERVAL = 2.0  # secondes entre deux sauvegardes du fichier de reprise
HISTORY_MAX = 20
ALERTS_MAX = 30
SYSTEM_STATUS_MIN_INTERVAL = 300   # secondes entre deux relevés apt à la demande
TEST_MODE = os.geteuid() != 0 and "CLAMAV_ANTIVIRUS_SOCKET" in os.environ


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

class Job:
    _counter = 0
    _counter_lock = threading.Lock()

    def __init__(self, kind, path=None, resume=False, auto=False, requested_by=None, usb=None):
        with Job._counter_lock:
            Job._counter += 1
            self.id = Job._counter
        self.kind = kind            # 'scan' | 'update'
        self.path = path
        self.resume = resume
        self.auto = auto            # lancé par le système (première installation, reprise)
        self.usb = usb              # dict décrivant le support USB analysé, ou None
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

    def cancel(self, by_user=False):
        self.cancelled_by_user = self.cancelled_by_user or by_user
        self.cancel_event.set()
        with self.proc_lock:
            if self.proc and self.proc.poll() is None:
                try:
                    self.proc.terminate()
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
        """Exécutable connu du système (paquet dpkg / emplacement système) ?"""
        if not exe or exe.endswith(" (deleted)"):
            return False
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
        trusted = self.exe_trusted(info["exe"])
        exe_path = info["exe"].replace(" (deleted)", "")
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
            "user": info["user"], "trusted": trusted,
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
VALID_ACTION = ("allow", "deny", "reject", "limit")
VALID_POLICY = ("allow", "deny", "reject")


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

    packages = []
    for pkg in cache:
        try:
            if not pkg.is_upgradable:
                continue
            cand = pkg.candidate
            origins = cand.origins if cand else []
            security = any((o.archive or "").endswith("-security") or (o.label or "") == "Debian-Security"
                           for o in origins)
            packages.append({
                "name": pkg.name, "installed": pkg.installed.version if pkg.installed else "",
                "candidate": cand.version if cand else "", "security": security,
                "archive": origins[0].archive if origins else "", "cves": {},
            })
        except Exception:  # noqa: BLE001
            continue
    status["upgradable"] = len(packages)
    status["security"] = sum(1 for p in packages if p["security"])

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
    status["packages"] = sorted(packages, key=lambda p: (not p["security"], p["name"]))
    status["cves"] = cves
    status["cve_count"] = len(cves)
    return status


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
        self.usb = UsbWatcher(self)
        self.security = None
        self.security_lock = threading.Lock()
        self.last_security = 0
        self.last_weekly_check = 0
        self.system_status_lock = threading.Lock()
        self.system_status_running = False
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
        self.broadcast({"event": "progress", **job.public()})

    def publish_alert(self, alert):
        self.state.prepend("alerts", alert, ALERTS_MAX)
        if alert.get("kind") == "upload":
            self.write_log(f"⚠ upload: {alert.get('gb')} GB sent in {alert.get('window_hours')} h "
                           f"(threshold {alert.get('threshold_gb')} GB)")
            log(f"Alerte envoi Internet : {alert.get('gb')} Go en {alert.get('window_hours')} h")
        else:
            self.write_log(f"⚠ {alert['severity']}: {alert['comm']} (pid {alert['pid']}, {alert.get('exe')}) "
                           f"modified {alert['count']} files in {alert['window']} s — {alert['top_dir']}")
            log(f"Alerte {alert['severity']} : {alert['comm']} pid {alert['pid']} {alert['count']} fichiers")
        self.broadcast({"event": "alert", "alert": alert})

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
                if job.usb:
                    if job.usb.get("private_mount"):
                        self.usb.unmount(job.usb["devnode"])
                    status, key, params = job.result or ("error", "msg.scan.internal", {})
                    self.broadcast({
                        "event": "usb_done", "usb": job.usb, "status": status,
                        "msg_key": key, "msg_params": params, "infected": job.infected,
                        "files": job.total, "threats": job.threats[-50:],
                        "removed": bool(job.usb.get("removed")),
                    })

    def finish(self, job, status, key, params=None, summary=None):
        job.phase = "done"
        params = params or {}
        job.result = (status, key, params)
        self.broadcast({
            "event": "job_done", "id": job.id, "kind": job.kind, "path": job.path,
            "status": status, "msg_key": key, "msg_params": params,
            "message": t("en", key, **params), "summary": summary or {},
            "auto": job.auto, "usb": job.usb,
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

    def _count_files(self, job, cache):
        """Phase inventaire : find → fichier cache, en streaming (peu de mémoire)."""
        job.phase = "counting"
        job.found = 0
        self.emit_progress(job)
        cmd = find_command(job.path, exclude=[]) if job.usb else find_command(job.path)
        with job.proc_lock:
            job.proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                        stderr=subprocess.DEVNULL, text=True, bufsize=1)
        last_emit = time.time()
        with open(cache, "w") as out:
            for line in job.proc.stdout:
                if job.cancel_event.is_set():
                    break
                if line.strip():
                    out.write(line)
                    job.found += 1
                    if time.time() - last_emit >= PROGRESS_INTERVAL:
                        self.emit_progress(job)
                        last_emit = time.time()
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
                if idx is None and last_file and line.rstrip("\n") == last_file:
                    idx = i + 1
        job.total = total
        job.infected = int(prog.get("infected", 0) or 0)
        return idx if idx is not None else 0

    def run_scan(self, job):
        self.rotate_log()
        start_idx = 0
        resumed = False
        cache = SYSTEM_FILELIST_CACHE + (".usb" if job.usb else "")

        if job.resume and not job.usb:
            idx = self._resume_offset(job)
            if idx is not None:
                start_idx, resumed = idx, True
            else:
                job.resume = False

        if not resumed:
            label = "usb " if job.usb else ("auto " if job.auto else "")
            self.write_log(f"▶ scan {label}{job.path}")
            self.emit_line("info", f"▶ {job.path}")
            total = self._count_files(job, cache)
            if job.cancel_event.is_set():
                if job.cancelled_by_user:
                    self._forget_auto(job)
                self._save_progress(job, in_progress=False)
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
            self.finish(job, "clean", "msg.scan.nofiles", {}, self._summary(job))
            return

        # Liste des fichiers restants (copie en streaming)
        tmp_list = cache + ".tmp"
        with open(cache) as src, open(tmp_list, "w") as dst:
            for i, line in enumerate(src):
                if i >= start_idx:
                    dst.write(line)

        job.phase = "scanning"
        self.emit_progress(job)
        self.emit_line("info", f"▶ clamscan × {job.total}")

        # Priorité basse : scan automatique en tâche de fond, scan manuel un peu moins
        if job.auto:
            prefix = ["nice", "-n", "19", "ionice", "-c", "3"]
        else:
            prefix = ["nice", "-n", "5", "ionice", "-c", "2", "-n", "7"]
        cmd = prefix + ["clamscan", "--verbose", "--suppress-ok-results",
                        f"--move={SYSTEM_QUARANTINE_DIR}", f"--file-list={tmp_list}"]
        with job.proc_lock:
            job.proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                        stderr=subprocess.STDOUT, text=True, bufsize=1)

        last_emit = last_save = time.time()
        for raw in job.proc.stdout:
            line = raw.rstrip("\n")
            if not line:
                continue
            counted = False
            if line.startswith("Scanning "):
                job.current_file = line[9:]
                counted = True
            elif line.endswith((": Empty file", ": No such file or directory", ": Excluded")):
                job.current_file = line.rsplit(": ", 1)[0]
                counted = True
            elif line.endswith(" FOUND"):
                job.infected += 1
                path, _, sig = line[:-6].rpartition(": ")
                job.threats.append({"path": path, "signature": sig, "time": now_iso()})
                self.write_log(line)
                self.emit_line("found", line)
            elif not is_noise_line(line):
                kind = classify_line(line)
                if kind == "denied":
                    job.denied += 1
                elif kind == "error":
                    job.errors += 1
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

        if job.cancel_event.is_set():
            if job.cancelled_by_user:
                self._forget_auto(job)
            self._save_progress(job, in_progress=True)
            self.write_log(f"■ interrupted {job.scanned}/{job.total}")
            self.finish(job, "cancelled", "msg.scan.cancelled",
                        {"scanned": job.scanned, "total": job.total}, self._summary(job))
            return

        job.scanned = job.total
        job.current_file = ""
        self._save_progress(job, in_progress=False)
        try:
            os.remove(tmp_list)
        except OSError:
            pass

        if rc not in (0, 1, 2):
            self._record_scan(job, "error")
            self.finish(job, "error", "msg.scan.failed", {"code": rc}, self._summary(job))
            return

        status = "infected" if job.infected > 0 else "clean"
        self._record_scan(job, status)
        if job.infected:
            key, params = "msg.scan.infected", {"count": job.infected}
        else:
            key, params = "msg.scan.clean", {"files": job.total}
        self.write_log(f"■ done: {job.infected} infected / {job.total} files")
        self.finish(job, status, key, params, self._summary(job))

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
        }

    def _record_scan(self, job, status):
        duration = time.time() - (job.started_at or time.time())
        entry = {
            "date": now_iso(), "path": job.path, "files": job.total,
            "infected": job.infected, "duration": round(duration),
            "status": status, "source": "daemon", "auto": job.auto,
            "usb": {k: job.usb.get(k) for k in ("label", "model", "size", "devnode")} if job.usb else None,
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
        self.enqueue(Job("scan", path=mountpoint, usb=usb, requested_by="system"))

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
    def refresh_security(self, force=False, broadcast=True):
        with self.security_lock:
            if not force and self.security and time.time() - self.last_security < 60:
                return self.security
            self.security = collect_security_status()
            self.last_security = time.time()
            result = self.security
        if broadcast:
            self.broadcast({"event": "security_status", "security": result})
        return result

    def ufw(self, *args):
        r = run_quiet(["ufw", "--force"] + list(args), timeout=60)
        text = ((r.stdout or "") + (r.stderr or "")).strip()
        self.write_log(f"ufw {' '.join(args)} → {r.returncode}")
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
            except Exception as e:  # noqa: BLE001
                log(f"Maintenance : {e}")
            self.shutdown.wait(60)

    # ── Statut ───────────────────────────────────────────────────────────
    def status(self):
        with self.queue_lock:
            job = self.current.public() if self.current else None
            queue = [j.public() for j in self.queue]
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
            "state": {k: v for k, v in state.items() if k not in ("system_status", "alerts")},
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
            "alerts": (state.get("alerts") or [])[:10],
            "system_status": {k: sys_status.get(k) for k in
                              ("checked_at", "ok", "upgradable", "security", "cve_count",
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
        return files

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
            return self.status()

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
                                   resume=bool(req.get("resume")), requested_by=uid, usb=usb))
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
            return {"ok": True, "settings": self.settings.snapshot()}

        if cmd == "set_settings":
            changed, errors = self.settings.update(req.get("settings") or {})
            applied = self.apply_settings(changed)
            if changed:
                self.write_log(f"settings: {', '.join(f'{k}={v}' for k, v in changed.items())}")
                self.broadcast({"event": "settings", "settings": self.settings.snapshot()})
            return {"ok": True, "settings": self.settings.snapshot(), "changed": changed,
                    "applied": applied, "errors": errors}

        if cmd == "security_status":
            return {"ok": True, "security": self.refresh_security(force=bool(req.get("refresh")), broadcast=False)}

        if cmd in ("firewall_set", "firewall_defaults", "firewall_rule_add", "firewall_rule_delete", "ssh_set"):
            if os.geteuid() != 0:
                return {"ok": False, "error": "root_required"}
            if uid not in (0,) and uid < 1000:
                return {"ok": False, "error": "forbidden"}
            ok, text = self.security_command(cmd, req)
            self.refresh_security(force=True)
            return {"ok": ok, "error": "" if ok else "command_failed", "detail": text}

        if cmd == "alerts":
            return {"ok": True, "alerts": self.state.get("alerts", [])}

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
                return self.ufw("enable")
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
            action = str(req.get("action", "allow")).lower()
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
                conn.send(self.status())
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
        self.monitor.start()
        self.network.start()
        self.usb.start()
        threading.Thread(target=self.refresh_security, kwargs={"force": True, "broadcast": False}, daemon=True).start()

        log(f"ClamAV Antivirus daemon v{VERSION} à l'écoute sur {DAEMON_SOCKET}"
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
