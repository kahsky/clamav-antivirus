#!/usr/bin/env python3
"""
ClamAV Antivirus GUI — sauvegarde des fichiers de l'utilisateur (disponibilité, le « A » du triptyque CIA).

Tourne avec les droits de l'utilisateur (aucun root nécessaire) :
- clé USB / disque externe / dossier : instantanés rsync incrémentaux (--link-dest, historique conservé
  avec la rétention choisie) ; sur FAT32/exFAT/NTFS, miroir simple (pas de liens durs) ;
- cloud : rclone (S3 compatible, Infomaniak Swiss Backup S3 ou Swift, kDrive WebDAV, ou un remote
  rclone déjà configuré), synchronisation avec archivage des fichiers remplacés (--backup-dir).
L'état (destinations, contenu, planification, historique) vit dans ~/.local/share/clamav-antivirus/backup.json.
Les instantanés système restent l'affaire de Timeshift (lu par le service, voir clamav-antivirus-daemon.py).
"""

import json
import os
import pwd
import re
import shutil
import socket
import subprocess
import threading
import time
import uuid
from datetime import datetime

DATA_DIR = os.path.expanduser("~/.local/share/clamav-antivirus")
BACKUP_FILE = os.path.join(DATA_DIR, "backup.json")
BACKUP_DIRNAME = "ClamAV-Backup"
SNAPSHOT_RE = re.compile(r"^\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2}$")
PORTABLE_FS = ("vfat", "exfat", "ntfs", "ntfs3", "fuseblk", "msdos", "fat32")
DEFAULT_EXCLUDES = [".cache", ".local/share/Trash", ".Trash-*", "node_modules", "__pycache__", "*.tmp", "*.part",
                    "*.crdownload", ".thumbnails", "lost+found", ".npm", ".cargo/registry", "Cache", "CachedData"]
SCHEDULE_DAYS = {"daily": 1, "weekly": 7, "monthly": 30, "manual": None}
MAX_AGE_OK_DAYS = 7          # au-delà : « ancienne » (orange)
HISTORY_MAX = 40

PROVIDERS = {
    # kind : (type rclone, champs demandés dans l'interface, paramètres fixes)
    "s3": ("s3", ["endpoint", "access_key", "secret_key", "bucket"], {"provider": "Other", "env_auth": "false", "acl": "private"}),
    "infomaniak_s3": ("s3", ["endpoint", "access_key", "secret_key", "bucket"], {"provider": "Other", "env_auth": "false", "acl": "private", "region": "other-v2-signature"}),
    "infomaniak_swift": ("swift", ["auth", "user", "key", "container"], {"auth_version": "3", "domain": "default", "tenant_domain": "default"}),
    "kdrive": ("webdav", ["url", "user", "pass"], {"vendor": "other"}),
}


# ─── État ────────────────────────────────────────────────────────────────────
def _defaults():
    return {"destinations": [], "sources": default_sources(), "excludes": list(DEFAULT_EXCLUDES),
            "retention": 8, "schedule": "weekly", "history": [], "last_ok": None, "last_dest": ""}


def load_state():
    st = _defaults()
    try:
        with open(BACKUP_FILE, encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            st.update({k: v for k, v in data.items() if k in st})
    except (OSError, ValueError):
        pass
    return st


def save_state(st):
    os.makedirs(DATA_DIR, exist_ok=True)
    tmp = BACKUP_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(st, f, indent=2, ensure_ascii=False)
    os.replace(tmp, BACKUP_FILE)


def default_sources():
    """Dossiers XDG de l'utilisateur (Documents, Images, Vidéos, Musique, Bureau) qui existent."""
    home = os.path.expanduser("~")
    dirs = {}
    try:
        with open(os.path.join(home, ".config", "user-dirs.dirs"), encoding="utf-8") as f:
            for line in f:
                m = re.match(r'^XDG_(\w+)_DIR="(.*)"$', line.strip())
                if m:
                    dirs[m.group(1)] = m.group(2).replace("$HOME", home)
    except OSError:
        pass
    wanted = ["DOCUMENTS", "PICTURES", "VIDEOS", "MUSIC", "DESKTOP"]
    fallback = {"DOCUMENTS": "Documents", "PICTURES": "Images", "VIDEOS": "Vidéos", "MUSIC": "Musique", "DESKTOP": "Bureau"}
    out = []
    for key in wanted:
        p = dirs.get(key) or os.path.join(home, fallback[key])
        if os.path.isdir(p) and p != home and p not in out:
            out.append(p)
    return out or [home]


def _hostuser():
    try:
        user = pwd.getpwuid(os.getuid()).pw_name
    except KeyError:
        user = str(os.getuid())
    return f"{socket.gethostname()}-{user}"


def _run(cmd, timeout=60, **kw):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, **kw)
    except (OSError, subprocess.SubprocessError) as e:
        return subprocess.CompletedProcess(cmd, 1, "", str(e))


# ─── Supports amovibles ─────────────────────────────────────────────────────
def detect_drives():
    """Clés USB, disques externes et autres volumes montés utilisables comme destination."""
    r = _run(["lsblk", "-J", "-o", "NAME,PATH,MOUNTPOINTS,LABEL,SIZE,RM,TRAN,FSTYPE,TYPE,HOTPLUG,MODEL,VENDOR,UUID"], timeout=20)
    try:
        tree = json.loads(r.stdout or "{}").get("blockdevices") or []
    except ValueError:
        tree = []
    flat = []

    def walk(node, parent):
        node = dict(node)
        node["_parent"] = parent
        flat.append(node)
        for ch in node.get("children") or []:
            walk(ch, node)
    for n in tree:
        walk(n, None)
    me = pwd.getpwuid(os.getuid()).pw_name
    user_roots = (f"/media/{me}/", f"/run/media/{me}/", "/mnt/")
    drives = []
    for n in flat:
        mps = [m for m in (n.get("mountpoints") or [n.get("mountpoint")]) if m]
        if not mps or n.get("type") not in ("part", "disk", "crypt", "lvm"):
            continue
        mp = mps[0]
        if mp in ("/", "/boot", "/boot/efi", "/home", "[SWAP]") or mp.startswith(("/snap/", "/var/lib/", "/timeshift")):
            continue
        top = n
        while top.get("_parent"):
            top = top["_parent"]
        removable = bool(n.get("rm") or n.get("hotplug") or top.get("rm") or top.get("hotplug")) or \
            (top.get("tran") or "") in ("usb", "mmc") or mp.startswith(user_roots)
        if not removable:
            continue
        try:
            du = shutil.disk_usage(mp)
        except OSError:
            continue
        model = " ".join(x for x in [(top.get("vendor") or "").strip(), (top.get("model") or "").strip()] if x)
        drives.append({"devnode": n.get("path") or n.get("name"), "label": n.get("label") or model or os.path.basename(mp),
                       "model": model, "mountpoint": mp, "uuid": n.get("uuid") or "", "fstype": (n.get("fstype") or "").lower(),
                       "size": du.total, "free": du.free, "writable": os.access(mp, os.W_OK),
                       "transport": top.get("tran") or ""})
    return drives


# ─── Cloud (rclone) ─────────────────────────────────────────────────────────
def rclone_path():
    return shutil.which("rclone")


def rclone_remotes():
    if not rclone_path():
        return []
    r = _run(["rclone", "listremotes"], timeout=20)
    return [x.strip().rstrip(":") for x in (r.stdout or "").splitlines() if x.strip()]


def cloud_configure(kind, name, params):
    """Crée (ou remplace) un remote rclone. Retourne (ok, détail)."""
    if not rclone_path():
        return False, "rclone_missing"
    if kind not in PROVIDERS:
        return False, "unknown_provider"
    rtype, fields, fixed = PROVIDERS[kind]
    name = re.sub(r"[^A-Za-z0-9_-]", "", name or kind)[:32] or kind
    args = ["rclone", "config", "create", name, rtype, "--non-interactive", "--obscure"]
    mapping = {"endpoint": "endpoint", "access_key": "access_key_id", "secret_key": "secret_access_key",
               "auth": "auth", "user": "user", "key": "key", "url": "url", "pass": "pass"}
    for k, v in fixed.items():
        args.append(f"{k}={v}")
    for f in fields:
        if f in mapping and params.get(f):
            args.append(f"{mapping[f]}={params[f]}")
    r = _run(args, timeout=60)
    if r.returncode != 0:
        return False, ((r.stderr or "") + (r.stdout or "")).strip()[-300:]
    sub = params.get("bucket") or params.get("container") or ""
    return True, f"{name}:{sub}".rstrip(":")


def cloud_test(remote):
    """Vérifie l'accès (liste le dossier racine). remote = 'nom:bucket/chemin'."""
    if not rclone_path():
        return False, "rclone_missing"
    r = _run(["rclone", "lsd", "--max-depth", "1", "--contimeout", "20s", "--timeout", "60s", remote + ("" if ":" in remote else ":")], timeout=90)
    if r.returncode == 0:
        return True, "ok"
    # un bucket/dossier encore vide ou inexistant : tenter de le créer
    r2 = _run(["rclone", "mkdir", "--contimeout", "20s", remote], timeout=90)
    if r2.returncode == 0:
        return True, "created"
    return False, ((r.stderr or "") + (r2.stderr or "")).strip()[-300:]


# ─── Destinations ───────────────────────────────────────────────────────────
def add_destination(st, dest):
    dest = dict(dest)
    dest.setdefault("id", uuid.uuid4().hex[:10])
    dest.setdefault("added", datetime.now().isoformat(timespec="seconds"))
    dest.setdefault("last", None)
    dest.setdefault("last_ok", None)
    st["destinations"] = [d for d in st["destinations"] if d.get("id") != dest["id"]] + [dest]
    return dest


def remove_destination(st, dest_id):
    st["destinations"] = [d for d in st["destinations"] if d.get("id") != dest_id]


def destination_available(dest, drives=None):
    """(disponible, chemin ou remote effectif)."""
    t = dest.get("type")
    if t == "cloud":
        return (rclone_path() is not None and bool(dest.get("remote"))), dest.get("remote", "")
    if t == "path":
        p = dest.get("mountpoint") or dest.get("path") or ""
        return (os.path.isdir(p) and os.access(p, os.W_OK)), p
    drives = detect_drives() if drives is None else drives
    for d in drives:
        if (dest.get("uuid") and d["uuid"] == dest["uuid"]) or (not dest.get("uuid") and d["mountpoint"] == dest.get("mountpoint")):
            return d["writable"], d["mountpoint"]
    return False, dest.get("mountpoint", "")


def format_size(n):
    n = float(n or 0)
    for unit in ("o", "Kio", "Mio", "Gio", "Tio"):
        if n < 1024 or unit == "Tio":
            return f"{n:.0f} {unit}" if unit == "o" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} Tio"


# ─── Résumé pour l'interface ────────────────────────────────────────────────
def summary(st, now=None):
    now = now or time.time()
    last = st.get("last_ok")
    age = None
    if last:
        try:
            age = (now - datetime.fromisoformat(last).timestamp()) / 86400
        except ValueError:
            age = None
    if not st.get("destinations"):
        state = "none"                   # rien de configuré
    elif age is None:
        state = "missing"                # destination configurée mais jamais sauvegardé
    elif age > max(MAX_AGE_OK_DAYS, SCHEDULE_DAYS.get(st.get("schedule")) or 0) * 2:
        state = "old"
    else:
        state = "ok"
    period = SCHEDULE_DAYS.get(st.get("schedule"))
    due = bool(period) and (age is None or age >= period) and bool(st.get("destinations"))
    return {"state": state, "last": last, "age_days": round(age, 1) if age is not None else None,
            "dest_label": st.get("last_dest") or "", "destinations": len(st.get("destinations") or []),
            "schedule": st.get("schedule"), "due": due, "sources": len(st.get("sources") or [])}


def record_result(st, result):
    st["history"] = ([result] + (st.get("history") or []))[:HISTORY_MAX]
    for d in st["destinations"]:
        if d.get("id") == result.get("dest_id"):
            d["last"] = result.get("date")
            d["last_ok"] = bool(result.get("ok"))
    if result.get("ok"):
        st["last_ok"] = result.get("date")
        st["last_dest"] = result.get("dest_label", "")


# ─── Exécution ──────────────────────────────────────────────────────────────
class BackupRunner(threading.Thread):
    """Sauvegarde vers une destination ; progression 0-100 via on_progress(pct, text), fin via on_done(result)."""

    def __init__(self, dest, st, on_progress=None, on_done=None, auto=False):
        super().__init__(daemon=True)
        self.dest = dict(dest)
        self.sources = [s for s in (st.get("sources") or []) if os.path.isdir(os.path.expanduser(s))]
        self.excludes = list(st.get("excludes") or [])
        self.retention = max(1, int(st.get("retention") or 8))
        self.on_progress = on_progress or (lambda pct, text: None)
        self.on_done = on_done or (lambda result: None)
        self.auto = auto
        self.cancelled = threading.Event()
        self.proc = None
        self.started = time.time()
        self.log_tail = []

    def cancel(self):
        self.cancelled.set()
        p = self.proc
        if p and p.poll() is None:
            try:
                p.terminate()
            except OSError:
                pass

    def _result(self, ok, error="", **extra):
        res = {"ok": ok, "error": error, "date": datetime.now().isoformat(timespec="seconds"),
               "dest_id": self.dest.get("id"), "dest_label": self.dest.get("label", ""), "type": self.dest.get("type"),
               "duration": round(time.time() - self.started), "sources": len(self.sources), "auto": self.auto,
               "cancelled": self.cancelled.is_set()}
        res.update(extra)
        return res

    def run(self):
        try:
            if not self.sources:
                return self.on_done(self._result(False, "no_sources"))
            ok, target = destination_available(self.dest)
            if not ok:
                return self.on_done(self._result(False, "destination_unavailable"))
            if self.dest.get("type") == "cloud":
                self.on_done(self._run_cloud(target))
            else:
                self.on_done(self._run_local(target))
        except Exception as e:  # noqa: BLE001
            self.on_done(self._result(False, f"internal: {e}"[:200]))

    # ── rsync (support local) ──
    def _run_local(self, mountpoint):
        base = os.path.join(mountpoint, BACKUP_DIRNAME, _hostuser())
        os.makedirs(base, exist_ok=True)
        fstype = (self.dest.get("fstype") or "").lower()
        portable = fstype in PORTABLE_FS
        stamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        latest = os.path.join(base, "latest")
        if portable:
            target = latest                     # miroir simple : pas de liens durs ni symboliques sur FAT/NTFS
            prev = None
        else:
            target = os.path.join(base, stamp)
            prev = os.path.realpath(latest) if os.path.islink(latest) and os.path.isdir(os.path.realpath(latest)) else None
        os.makedirs(target, exist_ok=True)
        args = ["rsync", "--delete", "--delete-excluded", "--info=progress2,stats2", "--no-inc-recursive"]   # tailles brutes : stats lisibles par le programme
        args += ["-rt", "--modify-window=2", "--no-perms", "--no-owner", "--no-group", "--no-links"] if portable else ["-a"]
        for ex in self.excludes:
            args.append(f"--exclude={ex}")
        if prev:
            args.append(f"--link-dest={prev}")
        args += [os.path.expanduser(s).rstrip("/") for s in self.sources] + [target + "/"]
        rc, files, size = self._stream(args)
        if self.cancelled.is_set():
            if not portable:
                shutil.rmtree(target, ignore_errors=True)
            return self._result(False, "cancelled", path=target)
        if rc not in (0, 23, 24):               # 23/24 : quelques fichiers ignorés (permissions, fichiers disparus)
            return self._result(False, f"rsync_{rc}", detail="\n".join(self.log_tail[-5:])[-300:], path=target)
        if not portable:
            tmp_link = latest + ".new"
            try:
                if os.path.lexists(tmp_link):
                    os.remove(tmp_link)
                os.symlink(stamp, tmp_link)
                os.replace(tmp_link, latest)
            except OSError:
                pass
            self._apply_retention(base)
        self._write_readme(base)
        return self._result(True, files=files, bytes=size, path=target, partial=rc != 0)

    def _apply_retention(self, base):
        snaps = sorted(d for d in os.listdir(base) if SNAPSHOT_RE.match(d) and os.path.isdir(os.path.join(base, d)))
        for old in snaps[:-self.retention]:
            shutil.rmtree(os.path.join(base, old), ignore_errors=True)

    @staticmethod
    def _write_readme(base):
        try:
            with open(os.path.join(base, "LISEZ-MOI.txt"), "w", encoding="utf-8") as f:
                f.write("Sauvegarde ClamAV Antivirus GUI (Dukiwi SA)\n\n"
                        "latest/ : dernière sauvegarde complète de vos dossiers.\n"
                        "AAAA-MM-JJ_HH-MM-SS/ : sauvegardes précédentes (fichiers identiques partagés, sans doublon).\n"
                        "Pour restaurer : copiez simplement les dossiers voulus depuis latest/ vers votre dossier personnel.\n")
        except OSError:
            pass

    # ── rclone (cloud) ──
    def _run_cloud(self, remote):
        remote = remote.rstrip("/")
        base = f"{remote}/{BACKUP_DIRNAME}/{_hostuser()}"
        stamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        total_files, total_bytes, n = 0, 0, len(self.sources)
        for i, src in enumerate(self.sources):
            src = os.path.expanduser(src).rstrip("/")
            name = os.path.basename(src) or "home"
            args = ["rclone", "sync", src, f"{base}/latest/{name}", "--backup-dir", f"{base}/archive/{stamp}/{name}",
                    "--stats", "1s", "--stats-one-line", "--stats-log-level", "NOTICE", "--transfers", "4",
                    "--contimeout", "30s", "--retries", "2", "--low-level-retries", "3"]
            for ex in self.excludes:
                args += ["--exclude", ex.rstrip("/") + ("/**" if not any(c in ex for c in "*?") else "")]
            rc, files, size = self._stream(args, base_pct=i * 100 / n, span=100 / n, label=name)
            total_files += files
            total_bytes += size
            if self.cancelled.is_set():
                return self._result(False, "cancelled", path=base)
            if rc != 0:
                return self._result(False, f"rclone_{rc}", detail="\n".join(self.log_tail[-5:])[-300:], path=base)
        self._prune_cloud_archives(base)
        return self._result(True, files=total_files, bytes=total_bytes, path=base)

    def _prune_cloud_archives(self, base):
        r = _run(["rclone", "lsf", "--dirs-only", f"{base}/archive"], timeout=120)
        stamps = sorted(x.strip("/") for x in (r.stdout or "").splitlines() if SNAPSHOT_RE.match(x.strip("/")))
        for old in stamps[:-self.retention]:
            _run(["rclone", "purge", f"{base}/archive/{old}"], timeout=600)

    # ── suivi de progression ──
    def _stream(self, args, base_pct=0.0, span=100.0, label=""):
        files, size, last_emit = 0, 0, 0.0
        try:
            self.proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1,
                                         errors="replace")
        except OSError as e:
            self.log_tail.append(str(e))
            return 127, 0, 0
        buf = ""
        while True:
            ch = self.proc.stdout.read(1)
            if not ch:
                break
            if ch in "\r\n":
                line, buf = buf.strip(), ""
                if not line:
                    continue
                self.log_tail = (self.log_tail + [line])[-40:]
                pct = None
                m = re.search(r"(\d{1,3})%", line)
                if m:
                    pct = min(100, int(m.group(1)))
                m2 = re.search(r"Number of regular files transferred: ([\d,]+)", line)
                if m2:
                    files = int(m2.group(1).replace(",", ""))
                m3 = re.search(r"Total transferred file size: ([\d,]+)", line)
                if m3:
                    size = int(m3.group(1).replace(",", ""))
                m4 = re.search(r"Transferred:\s+([\d.]+\s*\w+)\s*/\s*([\d.]+\s*\w+)", line)
                if m4 and not m2:
                    size = _parse_size(m4.group(1))
                if pct is not None and time.time() - last_emit > 0.4:
                    last_emit = time.time()
                    self.on_progress(base_pct + pct * span / 100, (label + " · " if label else "") + line[:120])
            else:
                buf += ch
        rc = self.proc.wait()
        return rc, files, size


def _parse_size(text):
    m = re.match(r"([\d.]+)\s*([KMGT]?i?B?)", text.strip())
    if not m:
        return 0
    n = float(m.group(1))
    unit = m.group(2).upper()
    for prefix, mult in (("K", 1024), ("M", 1024 ** 2), ("G", 1024 ** 3), ("T", 1024 ** 4)):
        if unit.startswith(prefix):
            return int(n * mult)
    return int(n)
