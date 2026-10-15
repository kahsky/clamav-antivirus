#!/usr/bin/env python3
"""
ClamAV Antivirus GUI — couche de distribution.
Debian / Ubuntu / Linux Mint : apt, dpkg, ufw. Fedora / RHEL et dérivés : dnf, rpm, firewalld, SELinux.
Tout ce qui dépend de la distribution passe par ici ; le reste du programme ne parle ni apt ni dnf.
Test : CLAMAV_ANTIVIRUS_OS_RELEASE=<fichier> simule une autre distribution.
"""
import os
import re
import shutil
import subprocess

OS_RELEASE = os.environ.get("CLAMAV_ANTIVIRUS_OS_RELEASE") or "/etc/os-release"
RPM_IDS = ("fedora", "rhel", "centos", "rocky", "almalinux", "nobara", "ultramarine", "bazzite", "ol", "amzn")


def _os_release():
    out = {}
    try:
        with open(OS_RELEASE, encoding="utf-8", errors="replace") as f:
            for ln in f:
                if "=" in ln and not ln.startswith("#"):
                    k, v = ln.rstrip("\n").split("=", 1)
                    out[k.strip()] = v.strip().strip('"')
    except OSError:
        pass
    return out


def detect():
    d = _os_release()
    ident, like = d.get("ID", "").lower(), d.get("ID_LIKE", "").lower()
    family = "rpm" if ident in RPM_IDS or any(x in like.split() for x in ("fedora", "rhel", "centos")) else "deb"
    return {"family": family, "id": ident, "like": like, "pretty": d.get("PRETTY_NAME", ""), "version": d.get("VERSION_ID", "")}


DISTRO = detect()
FAMILY = DISTRO["family"]


def is_rpm():
    return FAMILY == "rpm"


def run(cmd, timeout=60, env=None):
    e = dict(os.environ, LC_ALL="C.UTF-8")
    if env:
        e.update(env)
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=e)
    except Exception as ex:  # noqa: BLE001
        return subprocess.CompletedProcess(cmd, 1, "", str(ex))


# ── Paquets ──────────────────────────────────────────────────────────────────
def install_shell(pkgs):
    """Commande shell d'installation (unité systemd transitoire) — sans question."""
    names = " ".join(pkgs)
    if is_rpm():
        return f"dnf -y install {names}"
    return f"apt-get install -y {names}"


def remove_shell(pkgs):
    names = " ".join(pkgs)
    return f"dnf -y remove {names}" if is_rpm() else f"apt-get purge -y {names}"


def upgrade_shell():
    if is_rpm():
        return "dnf -y upgrade --refresh"
    return ("apt-get update -q && apt-get upgrade -y -q "
            "-o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold")


def tools_packages():
    """Outils d'intégrité installables : debsums n'existe pas sur Fedora (rpm -Va intégré)."""
    return ["lynis", "unhide", "chkrootkit"] if is_rpm() else ["lynis", "unhide", "chkrootkit", "debsums"]


def update_manager_cmds():
    if is_rpm():
        return (["gnome-software", "--mode=updates"], ["plasma-discover", "--mode", "update"], ["dnfdragora"])
    return (["mintupdate"], ["update-manager"], ["gnome-software", "--mode=updates"])


def clamav_install_shell():
    if is_rpm():
        return "dnf -y install clamav clamd clamav-update"
    return "apt-get update && apt-get install -y clamav clamav-daemon clamav-freshclam"


def owners(paths):
    """{chemin: paquet} pour les chemins livrés par un paquet installé (rpm -qf, un appel par chemin)."""
    out = {}
    for p in [x for x in dict.fromkeys(paths) if x.startswith("/")][:400]:
        r = run(["rpm", "-qf", "--queryformat", "%{NAME}\n", p], timeout=20)
        if r.returncode == 0:
            name = (r.stdout or "").strip().splitlines()
            if name and not name[0].startswith("file "):
                out[p] = name[0].strip()
    return out


def owner_verify(path):
    """(paquet, modifié) pour un fichier : propriétaire rpm et vérification du contenu (rpm -V, drapeau 5)."""
    r = run(["rpm", "-qf", "--queryformat", "%{NAME}\n", path], timeout=20)
    if r.returncode != 0:
        return "", False
    pkg = (r.stdout or "").strip().splitlines()[0].strip()
    modified = False
    v = run(["rpm", "-V", pkg], timeout=120)
    for ln in (v.stdout or "").splitlines():
        parts = ln.split()
        if len(parts) >= 2 and parts[-1] == path and "5" in parts[0]:
            modified = True
    return pkg, modified


def _nevra_name(nevra):
    """kernel-core-6.11.4-301.fc41.x86_64 → kernel-core"""
    s = nevra.rsplit(".", 1)[0] if re.search(r"\.(x86_64|aarch64|noarch|i686|ppc64le|s390x|riscv64)$", nevra) else nevra
    m = re.match(r"^(.*)-[^-]+-[^-]+$", s)
    return m.group(1) if m else s


def pending_updates(status):
    """État des mises à jour avec dnf : paquets installables, avis de sécurité (CVE) et redémarrage requis."""
    r = run(["dnf", "-q", "-y", "check-update"], timeout=900)
    if r.returncode not in (0, 100):
        status["ok"] = False
        status["error"] = f"dnf: {(r.stderr or r.stdout or '').strip()[-200:]}"
        return status
    packages = []
    for ln in (r.stdout or "").splitlines():
        if ln.lower().startswith("obsoleting"):
            break
        parts = ln.split()
        if len(parts) >= 3 and "." in parts[0] and re.match(r"^\d", parts[1]):
            packages.append({"name": parts[0].rsplit(".", 1)[0], "arch": parts[0].rsplit(".", 1)[1], "candidate": parts[1],
                             "archive": parts[2], "installed": "", "security": False, "category": "recommended", "phase": None, "cves": {}})
    # Avis de sécurité : paquets concernés et CVE
    sec_names, adv_by_name = set(), {}
    s = run(["dnf", "-q", "updateinfo", "list", "--security"], timeout=300)
    for ln in (s.stdout or "").splitlines():
        parts = ln.split()
        if len(parts) >= 2 and re.match(r"^[A-Z]+[A-Z0-9]*-\d", parts[0]):
            name = _nevra_name(parts[-1])
            sec_names.add(name)
            adv_by_name.setdefault(name, set()).add(parts[0])
    adv_cves = {}
    info = run(["dnf", "-q", "updateinfo", "info", "--security"], timeout=300)
    current = None
    for ln in (info.stdout or "").splitlines():
        m = re.search(r"\b([A-Z]+[A-Z0-9]*-\d[\w:.-]*)\b", ln)
        if m and re.match(r"^\s*(Update ID|Name|Id)\s*:", ln):
            current = m.group(1)
            adv_cves.setdefault(current, set())
        for cve in re.findall(r"CVE-\d{4}-\d{4,}", ln):
            if current:
                adv_cves[current].add(cve)
    names = [p["name"] for p in packages]
    if names:
        q = run(["rpm", "-q", "--queryformat", "%{NAME}\t%{VERSION}-%{RELEASE}\n"] + names, timeout=120)
        installed = {}
        for ln in (q.stdout or "").splitlines():
            if "\t" in ln:
                n, v = ln.split("\t", 1)
                installed.setdefault(n, v)
        for p in packages:
            p["installed"] = installed.get(p["name"], "")
    all_cves = set()
    for p in packages:
        if p["name"] in sec_names:
            p["security"], p["category"] = True, "security"
            for adv in adv_by_name.get(p["name"], ()):
                for cve in adv_cves.get(adv, ()):
                    p["cves"][cve] = adv
                    all_cves.add(cve)
    status["packages"] = packages
    status["upgradable"] = len(packages)
    status["security"] = sum(1 for p in packages if p["security"])
    status["recommended"] = sum(1 for p in packages if not p["security"])
    status["phased"] = 0
    status["held"] = 0
    status["cves"] = sorted(all_cves)
    status["cve_count"] = len(all_cves)
    # Redémarrage : dnf needs-restarting -r (code 1 = redémarrage nécessaire), sinon noyau installé ≠ noyau en cours
    nr = run(["dnf", "needs-restarting", "-r"], timeout=120)
    if nr.returncode == 1:
        status["reboot_required"] = True
        status["reboot_pkgs"] = [ln.strip("* ").strip() for ln in (nr.stdout or "").splitlines() if ln.strip().startswith("*")][:10]
    elif nr.returncode not in (0,):
        k = run(["rpm", "-q", "--queryformat", "%{VERSION}-%{RELEASE}.%{ARCH}\n", "kernel-core"], timeout=30)
        kernels = [x for x in (k.stdout or "").split() if x]
        if kernels and os.uname().release not in kernels:
            status["reboot_required"] = True
            status["reboot_pkgs"] = ["kernel-core"]
    for cache in ("/var/cache/libdnf5", "/var/cache/dnf"):
        try:
            newest = max(os.stat(os.path.join(dp, fn)).st_mtime for dp, _, fns in os.walk(cache) for fn in fns if fn.endswith("repomd.xml"))
            import datetime
            status["lists_updated"] = datetime.datetime.fromtimestamp(newest).isoformat(timespec="seconds")
            break
        except (OSError, ValueError):
            continue
    return status


AUTO_TIMERS = ("dnf-automatic.timer", "dnf-automatic-install.timer", "dnf5-automatic.timer")


def _unit_enabled(unit):
    r = run(["systemctl", "is-enabled", unit], timeout=10)
    return (r.stdout or "").strip() == "enabled"


def auto_updates_enabled():
    """Mises à jour automatiques actives (dnf-automatic) ; False sur Debian (logique apt dans le service)."""
    return is_rpm() and any(_unit_enabled(u) for u in AUTO_TIMERS)


def auto_updates_enable():
    """Active dnf-automatic (installation si besoin, apply_updates = yes, minuterie). Retourne (ok, méthode, détail)."""
    if not shutil.which("dnf-automatic") and not os.path.exists("/usr/lib/systemd/system/dnf-automatic.timer") \
            and not os.path.exists("/usr/lib/systemd/system/dnf5-automatic.timer"):
        r = run(["dnf", "-y", "install", "dnf-automatic"], timeout=900)
        if r.returncode != 0:
            r = run(["dnf", "-y", "install", "dnf5-plugin-automatic"], timeout=900)
            if r.returncode != 0:
                return False, "dnf-automatic", (r.stderr or r.stdout or "").strip()[-200:]
    conf = "/etc/dnf/automatic.conf"
    try:
        text = open(conf, encoding="utf-8").read() if os.path.exists(conf) else ""
        if re.search(r"^apply_updates\s*=", text, flags=re.M):
            text = re.sub(r"^apply_updates\s*=.*$", "apply_updates = yes", text, flags=re.M)
        else:
            text += "\n[commands]\napply_updates = yes\n"
        with open(conf, "w", encoding="utf-8") as f:
            f.write(text)
    except OSError as e:
        return False, "dnf-automatic", str(e)
    for unit in ("dnf-automatic.timer", "dnf5-automatic.timer", "dnf-automatic-install.timer"):
        r = run(["systemctl", "enable", "--now", unit], timeout=60)
        if r.returncode == 0:
            return True, unit, ""
    return False, "dnf-automatic", "aucune minuterie dnf-automatic"


# ── Contrôle d'accès obligatoire ─────────────────────────────────────────────
def mac():
    """(« apparmor » | « selinux », actif)."""
    if is_rpm():
        r = run(["getenforce"], timeout=10)
        return "selinux", (r.stdout or "").strip() == "Enforcing"
    try:
        with open("/sys/module/apparmor/parameters/enabled") as f:
            return "apparmor", f.read().strip() == "Y"
    except OSError:
        return "apparmor", False


# ── ClamAV ───────────────────────────────────────────────────────────────────
def clamd_conf():
    if is_rpm():
        return "/etc/clamd.d/scan.conf"
    return "/etc/clamav/clamd.conf"


def clamd_unit():
    return "clamd@scan" if is_rpm() else "clamav-daemon"


def clamdscan_args():
    """Fedora : clamdscan ne lit pas /etc/clamd.d/scan.conf sans -c."""
    return ["-c", clamd_conf()] if is_rpm() else []


def ssh_unit():
    return "sshd" if is_rpm() else "ssh"


# ── Pare-feu ─────────────────────────────────────────────────────────────────
def firewall_backend():
    """« firewalld » (Fedora, ou firewalld seul présent) sinon « ufw »."""
    has_fwd, has_ufw = shutil.which("firewall-cmd") is not None, shutil.which("ufw") is not None
    if has_fwd and (is_rpm() or not has_ufw):
        return "firewalld"
    return "ufw"


# ── Courrier ─────────────────────────────────────────────────────────────────
def sendmail_cmd():
    """Commande d'envoi : sendmail du système, sinon msmtp directement (Fedora ne l'enregistre pas comme sendmail)."""
    p = os.environ.get("CLAMAV_ANTIVIRUS_SENDMAIL") or shutil.which("sendmail") or ("/usr/sbin/sendmail" if os.path.exists("/usr/sbin/sendmail") else "")
    if not p and shutil.which("msmtp"):
        return [shutil.which("msmtp"), "-t"]
    return [p or "/usr/sbin/sendmail", "-t", "-i"]
