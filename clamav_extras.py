#!/usr/bin/env python3
"""
ClamAV Antivirus GUI — fonctions côté utilisateur (sans root) :
- fuites de données : mots de passe (Have I Been Pwned, k-anonymity : seuls 5 caractères du SHA-1 sont envoyés)
  et adresses e-mail (API HIBP avec clé, ou relais Dukiwi) ;
- inventaire des applications hors dépôts : Flatpak (permissions larges), Snap (confinement classic, plugs
  sensibles), AppImage (non mises à jour automatiquement) ;
- coffre chiffré gocryptfs (~/.coffre chiffré, monté sur ~/Coffre) ;
- bilan hebdomadaire.
"""

import glob
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
import urllib.parse
import urllib.request
from datetime import datetime, timedelta

USER_AGENT = "ClamAV-Antivirus-GUI (Dukiwi SA; +https://www.dukiwi.com)"
HIBP_RANGE_URL = "https://api.pwnedpasswords.com/range/"
HIBP_ACCOUNT_URL = "https://haveibeenpwned.com/api/v3/breachedaccount/"
DUKIWI_HIBP_PROXY = "https://www.dukiwi.com/repo/api/hibp.php"
XON_ANALYTICS_URL = "https://api.xposedornot.com/v1/breach-analytics?email="   # source gratuite, sans clé (repli)
VAULT_CIPHER = os.path.expanduser("~/.coffre")
VAULT_MOUNT = os.path.expanduser("~/Coffre")
APPIMAGE_DIRS = ["~", "~/Downloads", "~/Téléchargements", "~/Applications", "~/Apps", "~/.local/bin", "~/bin", "~/Desktop", "~/Bureau"]
RISKY_FLATPAK_FS = ("host", "host-os", "host-etc", "home")
RISKY_FLATPAK_SOCKETS = ("session-bus", "system-bus", "ssh-auth", "pcsc", "cups")
RISKY_SNAP_PLUGS = ("home", "removable-media", "system-files", "personal-files", "network-control", "docker", "kernel-module-control",
                    "mount-observe", "process-control", "raw-usb", "ssh-keys", "gpg-keys", "password-manager-service", "system-backup")


def _http(url, headers=None, timeout=25):
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, **(headers or {})})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.status, resp.read()


# ─── Fuites de données (HIBP) ───────────────────────────────────────────────
def check_password(password):
    """Nombre d'apparitions du mot de passe dans les fuites connues (k-anonymity : 5 caractères du SHA-1 envoyés).
    Retourne (count, error). Le mot de passe ne quitte jamais l'ordinateur."""
    if not password:
        return None, "empty"
    digest = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = digest[:5], digest[5:]
    try:
        status, body = _http(HIBP_RANGE_URL + prefix, headers={"Add-Padding": "true"})
    except Exception as e:  # noqa: BLE001
        return None, f"network: {e}"[:120]
    for line in body.decode("utf-8", "replace").splitlines():
        parts = line.strip().split(":")
        if len(parts) == 2 and parts[0] == suffix:
            try:
                return int(parts[1]), ""
            except ValueError:
                return 0, ""
    return 0, ""


def check_email_xon(email):
    """Repli gratuit sans clé : XposedOrNot (breach-analytics). Retourne (breaches, error)."""
    try:
        status, body = _http(XON_ANALYTICS_URL + urllib.parse.quote(email), timeout=30)
        data = json.loads(body.decode("utf-8", "replace") or "{}")
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return [], ""
        if e.code == 429:
            return [], "rate_limited"
        return [], f"http_{e.code}"
    except Exception as e:  # noqa: BLE001
        return [], f"network: {e}"[:120]
    if not isinstance(data, dict) or data.get("Error"):
        return [], ""
    out = []
    for b in ((data.get("ExposedBreaches") or {}).get("breaches_details") or []):
        year = str(b.get("xposed_date") or "")
        out.append({"name": b.get("breach", ""), "title": b.get("breach", ""), "domain": b.get("domain", ""),
                    "date": year, "added": "", "count": b.get("xposed_records", 0),
                    "data": [x.strip() for x in str(b.get("xposed_data") or "").split(";") if x.strip()][:8],
                    "verified": True, "source": "xposedornot"})
    out.sort(key=lambda b: b.get("date", ""), reverse=True)
    return out, ""


def check_email(email, api_key="", proxy_url=""):
    """Fuites connues pour une adresse : API HIBP (clé personnelle), sinon relais Dukiwi, sinon XposedOrNot (gratuit).
    Retourne (breaches, error)."""
    email = (email or "").strip().lower()
    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[a-z]{2,}", email):
        return [], "invalid_email"
    try:
        if api_key:
            status, body = _http(HIBP_ACCOUNT_URL + urllib.parse.quote(email) + "?truncateResponse=false",
                                 headers={"hibp-api-key": api_key})
        elif proxy_url:
            status, body = _http(proxy_url + "?email=" + urllib.parse.quote(email))
        else:
            return check_email_xon(email)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return [], ""                       # aucune fuite connue
        if e.code == 401:
            return [], "bad_key"
        if e.code == 429:
            return [], "rate_limited"
        if not api_key:                         # relais sans clé (503) ou indisponible : repli gratuit
            return check_email_xon(email)
        return [], f"http_{e.code}"
    except Exception as e:  # noqa: BLE001
        if not api_key:
            return check_email_xon(email)
        return [], f"network: {e}"[:120]
    try:
        data = json.loads(body.decode("utf-8", "replace") or "[]")
    except ValueError:
        return [], "bad_response"
    if isinstance(data, dict) and "breaches" in data:
        data = data["breaches"]
    out = []
    for b in data if isinstance(data, list) else []:
        out.append({"name": b.get("Name") or b.get("name", ""), "title": b.get("Title") or b.get("title", ""),
                    "domain": b.get("Domain") or b.get("domain", ""), "date": b.get("BreachDate") or b.get("date", ""),
                    "added": b.get("AddedDate") or b.get("added", ""), "count": b.get("PwnCount") or b.get("count", 0),
                    "data": (b.get("DataClasses") or b.get("data") or [])[:8], "verified": b.get("IsVerified", True)})
    out.sort(key=lambda b: b.get("date", ""), reverse=True)
    return out, ""


# ─── Applications hors dépôts ───────────────────────────────────────────────
def _run(cmd, timeout=60):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError) as e:
        return subprocess.CompletedProcess(cmd, 1, "", str(e))


def flatpak_apps():
    if not shutil.which("flatpak"):
        return []
    r = _run(["flatpak", "list", "--app", "--columns=application,name,version,origin,installation"], timeout=60)
    apps = []
    for line in (r.stdout or "").splitlines():
        parts = line.split("\t")
        if len(parts) < 4:
            continue
        app_id, name, version, origin = parts[0], parts[1], parts[2], parts[3]
        inst = parts[4] if len(parts) > 4 else ""
        perms = {"filesystems": [], "devices": [], "sockets": [], "shared": [], "talk": []}
        info = _run(["flatpak", "info", "--show-permissions", app_id] + (["--user"] if inst == "user" else []), timeout=30)
        section = ""
        for ln in (info.stdout or "").splitlines():
            ln = ln.strip()
            if ln.startswith("[") and ln.endswith("]"):
                section = ln[1:-1]
            elif "=" in ln:
                k, v = ln.split("=", 1)
                vals = [x for x in v.split(";") if x]
                if section == "Context" and k in perms:
                    perms[k] = vals
                elif section == "Session Bus Policy":
                    if v.strip() == "talk" or v.strip() == "own":
                        perms["talk"].append(k)
        risky = []
        if any(fs.split(":")[0] in RISKY_FLATPAK_FS for fs in perms["filesystems"]):
            risky.append("filesystem")
        if "all" in perms["devices"]:
            risky.append("devices")
        if any(s in RISKY_FLATPAK_SOCKETS for s in perms["sockets"]):
            risky.append("sockets")
        if any(t.startswith("org.freedesktop.Flatpak") or t.startswith("org.freedesktop.systemd1") for t in perms["talk"]):
            risky.append("sandbox_escape")
        if origin and origin not in ("flathub", "flathub-beta", "fedora", "gnome-nightly"):
            risky.append("origin")
        apps.append({"kind": "flatpak", "id": app_id, "name": name or app_id, "version": version, "origin": origin,
                     "installation": inst, "permissions": perms, "risky": risky, "key": f"flatpak:{app_id}"})
    return apps


def snap_apps():
    if not shutil.which("snap"):
        return []
    r = _run(["snap", "list"], timeout=60)
    apps = []
    for line in (r.stdout or "").splitlines()[1:]:
        parts = line.split()
        if len(parts) < 5:
            continue
        name, version, publisher, notes = parts[0], parts[1], parts[4], (parts[5] if len(parts) > 5 else "")
        if name in ("core", "core18", "core20", "core22", "core24", "snapd", "bare") or name.startswith(("gnome-", "gtk-common", "kde-frameworks", "mesa-")):
            continue
        plugs = []
        c = _run(["snap", "connections", name], timeout=30)
        for ln in (c.stdout or "").splitlines()[1:]:
            cols = ln.split()
            if len(cols) >= 3 and cols[2] != "-":
                plugs.append(cols[0])
        risky = []
        if "classic" in notes:
            risky.append("classic")
        if any(p in RISKY_SNAP_PLUGS for p in plugs):
            risky.append("plugs")
        if publisher.endswith("✓") or publisher.endswith("*"):
            publisher = publisher.rstrip("✓*")
        apps.append({"kind": "snap", "id": name, "name": name, "version": version, "origin": publisher, "notes": notes,
                     "plugs": [p for p in plugs if p in RISKY_SNAP_PLUGS], "risky": risky, "key": f"snap:{name}"})
    return apps


def appimages():
    seen, out = set(), []
    for d in APPIMAGE_DIRS:
        base = os.path.expanduser(d)
        if not os.path.isdir(base):
            continue
        for p in glob.glob(os.path.join(base, "*.[Aa]pp[Ii]mage")) + glob.glob(os.path.join(base, "*", "*.[Aa]pp[Ii]mage")):
            rp = os.path.realpath(p)
            if rp in seen:
                continue
            seen.add(rp)
            try:
                st = os.stat(rp)
            except OSError:
                continue
            out.append({"kind": "appimage", "id": rp, "name": os.path.basename(rp), "path": rp, "size": st.st_size,
                        "mtime": datetime.fromtimestamp(st.st_mtime).isoformat(timespec="seconds"),
                        "executable": os.access(rp, os.X_OK), "risky": ["unsandboxed"], "key": f"appimage:{rp}"})
    return out


def inventory_apps():
    fl, sn, ai = flatpak_apps(), snap_apps(), appimages()
    return {"checked_at": datetime.now().isoformat(timespec="seconds"), "flatpak": fl, "snap": sn, "appimage": ai,
            "counts": {"flatpak": len(fl), "snap": len(sn), "appimage": len(ai),
                       "risky": sum(1 for a in fl + sn if a["risky"]) + len(ai)}}


# ─── Coffre chiffré (gocryptfs) ─────────────────────────────────────────────
def vault_status():
    mounted = False
    try:
        with open("/proc/mounts") as f:
            mounted = any(len(ln.split()) > 1 and ln.split()[1] == VAULT_MOUNT for ln in f)
    except OSError:
        pass
    return {"available": shutil.which("gocryptfs") is not None, "exists": os.path.isfile(os.path.join(VAULT_CIPHER, "gocryptfs.conf")),
            "mounted": mounted, "mountpoint": VAULT_MOUNT, "cipherdir": VAULT_CIPHER}


def _with_passfile(password, fn):
    fd, path = tempfile.mkstemp(prefix="cav-vault-", dir="/dev/shm" if os.path.isdir("/dev/shm") else None)
    try:
        os.write(fd, (password or "").encode("utf-8"))
        os.close(fd)
        os.chmod(path, 0o600)
        return fn(path)
    finally:
        try:
            os.remove(path)
        except OSError:
            pass


def vault_create(password):
    if not shutil.which("gocryptfs"):
        return False, "gocryptfs_missing"
    if len(password or "") < 8:
        return False, "password_short"
    st = vault_status()
    if st["exists"]:
        return False, "exists"
    os.makedirs(VAULT_CIPHER, mode=0o700, exist_ok=True)
    os.makedirs(VAULT_MOUNT, mode=0o700, exist_ok=True)

    def init(pf):
        r = _run(["gocryptfs", "-init", "-q", "-passfile", pf, VAULT_CIPHER], timeout=120)
        return r.returncode == 0, ((r.stderr or "") + (r.stdout or "")).strip()[-200:]
    ok, detail = _with_passfile(password, init)
    if not ok:
        return False, detail
    return vault_open(password)


def vault_open(password):
    if not shutil.which("gocryptfs"):
        return False, "gocryptfs_missing"
    st = vault_status()
    if not st["exists"]:
        return False, "no_vault"
    if st["mounted"]:
        return True, "already_mounted"
    os.makedirs(VAULT_MOUNT, mode=0o700, exist_ok=True)

    def mount(pf):
        r = _run(["gocryptfs", "-q", "-passfile", pf, "-i", "30m", VAULT_CIPHER, VAULT_MOUNT], timeout=60)
        return r.returncode == 0, ((r.stderr or "") + (r.stdout or "")).strip()[-200:]
    ok, detail = _with_passfile(password, mount)
    if not ok and ("password" in detail.lower() or "Password incorrect" in detail):
        return False, "bad_password"
    return ok, detail


def vault_close():
    st = vault_status()
    if not st["mounted"]:
        return True, "not_mounted"
    r = _run(["fusermount", "-u", VAULT_MOUNT], timeout=30)
    if r.returncode != 0:
        r = _run(["fusermount", "-uz", VAULT_MOUNT], timeout=30)
    return r.returncode == 0, ((r.stderr or "") + (r.stdout or "")).strip()[-200:]


# ─── Bilan hebdomadaire ─────────────────────────────────────────────────────
def weekly_report(history, alerts, checklist, backup, read_lessons, previous_score, days=7):
    """Résumé des `days` derniers jours à partir des données déjà connues du GUI."""
    since = datetime.now() - timedelta(days=days)

    def recent(entries, key):
        out = []
        for e in entries or []:
            try:
                if datetime.fromisoformat(str(e.get(key, ""))[:19]) >= since:
                    out.append(e)
            except ValueError:
                continue
        return out
    scans = recent(history, "date")
    alerts7 = recent(alerts, "time")
    score = (checklist or {}).get("score")
    return {"period_days": days, "scans": len(scans), "files": sum(int(s.get("files") or 0) for s in scans),
            "threats": sum(int(s.get("infected") or 0) for s in scans),
            "alerts": len(alerts7), "danger_alerts": sum(1 for a in alerts7 if a.get("severity") == "danger"),
            "score": score, "grade": (checklist or {}).get("grade"), "score_delta": (score - previous_score) if (score is not None and previous_score is not None) else None,
            "backup_state": (backup or {}).get("state"), "backup_last": (backup or {}).get("last"),
            "lessons_read": len(read_lessons or []), "generated": datetime.now().isoformat(timespec="seconds")}
