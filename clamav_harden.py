#!/usr/bin/env python3
"""ClamAV Antivirus GUI — durcissement du système : application (et annulation) des recommandations Lynis.

Exécuté par le service (root). Chaque correctif écrit ses propres fichiers (90-clamav-antivirus-*) ou retient la
valeur précédente, pour pouvoir revenir en arrière. Les recommandations qui pourraient gêner un usage courant sont
marquées « caution » (jamais appliquées automatiquement), celles sans objet sur un poste de travail « skip ».

Tests : CLAMAV_ANTIVIRUS_HARDEN_ROOT=<dossier> préfixe tous les chemins et n'exécute aucune commande."""
import os
import re
import shutil
import socket
import subprocess

ROOT = os.environ.get("CLAMAV_ANTIVIRUS_HARDEN_ROOT", "/")
DRY = ROOT != "/"
TAG = "# ClamAV Antivirus GUI"

SYSCTL_FILE = "/etc/sysctl.d/90-clamav-antivirus-hardening.conf"
LIMITS_FILE = "/etc/security/limits.d/90-clamav-antivirus.conf"
COREDUMP_FILE = "/etc/systemd/coredump.conf.d/90-clamav-antivirus.conf"
MODPROBE_FILE = "/etc/modprobe.d/90-clamav-antivirus-protocols.conf"
FIREWIRE_FILE = "/etc/modprobe.d/90-clamav-antivirus-firewire.conf"
SSHD_FILE = "/etc/ssh/sshd_config.d/90-clamav-antivirus.conf"
NEEDRESTART_FILE = "/etc/needrestart/conf.d/90-clamav-antivirus.conf"
LOGIN_DEFS = "/etc/login.defs"

# Profil Lynis (KRNL-6000). Volontairement absents : kernel.modules_disabled (bloquerait tout pilote jusqu'au
# redémarrage), net.ipv4.conf.all.rp_filter=1 (Ubuntu choisit 2 : VPN, conteneurs, routages asymétriques),
# kernel.perf_event_paranoid (Ubuntu est déjà plus strict que le profil).
SYSCTL = [
    ("kernel.core_uses_pid", "1"), ("kernel.dmesg_restrict", "1"), ("kernel.kptr_restrict", "2"), ("kernel.sysrq", "0"),
    ("kernel.unprivileged_bpf_disabled", "1"), ("kernel.yama.ptrace_scope", "1"), ("net.core.bpf_jit_harden", "2"),
    ("fs.protected_fifos", "2"), ("fs.protected_regular", "2"), ("fs.protected_hardlinks", "1"), ("fs.protected_symlinks", "1"),
    ("fs.suid_dumpable", "0"), ("dev.tty.ldisc_autoload", "0"),
    ("net.ipv4.conf.all.accept_redirects", "0"), ("net.ipv4.conf.default.accept_redirects", "0"),
    ("net.ipv4.conf.all.secure_redirects", "0"), ("net.ipv4.conf.default.secure_redirects", "0"),
    ("net.ipv4.conf.all.send_redirects", "0"), ("net.ipv4.conf.default.send_redirects", "0"),
    ("net.ipv4.conf.all.accept_source_route", "0"), ("net.ipv4.conf.default.accept_source_route", "0"),
    ("net.ipv4.conf.all.log_martians", "1"), ("net.ipv4.conf.default.log_martians", "1"),
    ("net.ipv4.icmp_echo_ignore_broadcasts", "1"), ("net.ipv4.icmp_ignore_bogus_error_responses", "1"),
    ("net.ipv4.tcp_syncookies", "1"),
    ("net.ipv6.conf.all.accept_redirects", "0"), ("net.ipv6.conf.default.accept_redirects", "0"),
    ("net.ipv6.conf.all.accept_source_route", "0"), ("net.ipv6.conf.default.accept_source_route", "0"),
]
PROTOCOLS = ("dccp", "sctp", "rds", "tipc")
BANNER = ("Access to this system is restricted to authorized users. All activity may be monitored and recorded.\n"
          "Unauthorized access is prohibited and may be prosecuted.\n"
          "Accès réservé aux utilisateurs autorisés. Toute activité peut être surveillée et enregistrée.\n"
          "Tout accès non autorisé est interdit et passible de poursuites.\n")
SSHD_CONF = (f"{TAG} (SSH-7408) — supprimer ce fichier pour revenir aux réglages précédents\n"
             "AllowAgentForwarding no\nAllowTcpForwarding no\nClientAliveCountMax 2\nClientAliveInterval 300\n"
             "Compression no\nLogLevel VERBOSE\nMaxAuthTries 3\nMaxSessions 2\nPermitRootLogin no\n"
             "TCPKeepAlive no\nX11Forwarding no\n")
PACKAGES = {"pwquality": ["libpam-pwquality"], "acct": ["acct"], "auditd": ["auditd"], "fail2ban": ["fail2ban"],
            "pam_tmpdir": ["libpam-tmpdir"], "apt_show_versions": ["apt-show-versions"]}

# Catalogue : test Lynis → traitement. kind : apply (bouton), gui (réglage ailleurs dans l'application),
# manual (explication), skip (sans objet ou déconseillé ici). caution : jamais automatique, à lire avant.
CATALOG = {
    "KRNL-6000": {"kind": "apply", "fn": "sysctl"},
    "KRNL-5820": {"kind": "apply", "fn": "coredumps"},
    "AUTH-9286": {"kind": "apply", "fn": "password_age"},
    "AUTH-9230": {"kind": "apply", "fn": "hash_rounds"},
    "AUTH-9328": {"kind": "apply", "fn": "umask", "caution": True},
    "AUTH-9262": {"kind": "apply", "fn": "pwquality"},
    "BANN-7126": {"kind": "apply", "fn": "banner"},
    "BANN-7130": {"kind": "apply", "fn": "banner"},
    "NETW-3200": {"kind": "apply", "fn": "protocols"},
    "STRG-1846": {"kind": "apply", "fn": "firewire"},
    "ACCT-9622": {"kind": "apply", "fn": "acct"},
    "ACCT-9626": {"kind": "apply", "fn": "sysstat"},
    "ACCT-9628": {"kind": "apply", "fn": "auditd"},
    "DEB-0880": {"kind": "apply", "fn": "fail2ban"},
    "DEB-0280": {"kind": "apply", "fn": "pam_tmpdir", "caution": True},
    "DEB-0831": {"kind": "apply", "fn": "needrestart"},
    "PKGS-7394": {"kind": "apply", "fn": "apt_show_versions"},
    "PKGS-7346": {"kind": "apply", "fn": "purge_rc", "no_revert": True},
    "PKGS-7410": {"kind": "apply", "fn": "old_kernels", "no_revert": True},
    "PRNT-2307": {"kind": "apply", "fn": "cups_perms"},
    "NAME-4404": {"kind": "apply", "fn": "hosts"},
    "SSH-7408": {"kind": "apply", "fn": "sshd", "caution": True},
    "TIME-3104": {"kind": "apply", "fn": "ntp", "no_revert": True},
    "FILE-7524": {"kind": "apply", "fn": "file_perms"},
    "PKGS-7420": {"kind": "gui", "action": "auto_updates_enable"},
    "FIRE-4512": {"kind": "gui", "action": "firewall"},
    "USB-1000": {"kind": "skip"}, "STRG-1840": {"kind": "skip"}, "FINT-4350": {"kind": "skip"},
    "DEB-0810": {"kind": "skip"}, "DEB-0811": {"kind": "skip"}, "DEB-0520": {"kind": "skip"},
    "HRDN-7222": {"kind": "skip"}, "BOOT-5122": {"kind": "skip"}, "HTTP-6640": {"kind": "skip"},
    "HTTP-6643": {"kind": "skip"}, "FILE-6310": {"kind": "skip"}, "LOGG-2154": {"kind": "skip"},
    "TOOL-5002": {"kind": "skip"}, "LYNIS": {"kind": "skip"},
    "AUTH-9282": {"kind": "manual"}, "BOOT-5264": {"kind": "manual"}, "LOGG-2190": {"kind": "manual"},
    "NAME-4028": {"kind": "manual"}, "FIRE-4513": {"kind": "manual"}, "PROC-3614": {"kind": "manual"},
    "KRNL-5788": {"kind": "manual"},
}


def catalog_public():
    """Catalogue pour l'interface (kind, caution, no_revert, action)."""
    return {t: {k: v for k, v in e.items() if k != "fn"} for t, e in CATALOG.items()}


def is_safe(test):
    e = CATALOG.get(test) or {}
    return e.get("kind") == "apply" and not e.get("caution")


def tests_sharing(test):
    fn = (CATALOG.get(test) or {}).get("fn")
    return [t for t, e in CATALOG.items() if fn and e.get("fn") == fn]


# ── Outils ───────────────────────────────────────────────────────────────
def _p(path):
    return path if ROOT == "/" else os.path.join(ROOT, path.lstrip("/"))


def _run(cmd, timeout=900, env=None):
    if DRY:
        return subprocess.CompletedProcess(cmd, 0, "", "")
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env)
    except Exception as e:  # noqa: BLE001
        return subprocess.CompletedProcess(cmd, 1, "", str(e))


def _check(r, what):
    if r.returncode != 0:
        raise RuntimeError(f"{what}: " + ((r.stderr or r.stdout or "").strip()[-300:] or f"code {r.returncode}"))
    return r


def _write(path, content, mode=0o644):
    full = _p(path)
    os.makedirs(os.path.dirname(full), exist_ok=True)
    tmp = full + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(content)
    os.chmod(tmp, mode)
    os.replace(tmp, full)


def _read(path):
    try:
        with open(_p(path), encoding="utf-8", errors="replace") as f:
            return f.read()
    except OSError:
        return ""


def _remove(path):
    try:
        os.remove(_p(path))
        return True
    except FileNotFoundError:
        return False


def _apt(args, timeout=1200):
    env = dict(os.environ, DEBIAN_FRONTEND="noninteractive", LC_ALL="C")
    cmd = ["apt-get", "-y", "-q", "-o", "DPkg::Lock::Timeout=180", "-o", "Dpkg::Options::=--force-confdef",
           "-o", "Dpkg::Options::=--force-confold"] + args
    return _check(_run(cmd, timeout=timeout, env=env), "apt-get " + args[0])


def _login_defs_set(changes):
    """Modifie /etc/login.defs (clé → valeur, lignes marquées) ; retourne {clé: ancienne valeur ou None}."""
    lines = _read(LOGIN_DEFS).splitlines()
    prev = {}
    for key, value in changes.items():
        pat = re.compile(rf"^\s*{re.escape(key)}\s+(\S+)")
        found = False
        for i, ln in enumerate(lines):
            m = pat.match(ln)
            if m:
                if not found:
                    prev[key] = m.group(1)
                lines[i] = f"{key}\t\t{value}\t{TAG}"
                found = True
        if not found:
            prev[key] = None
            lines.append(f"{key}\t\t{value}\t{TAG}")
    _write(LOGIN_DEFS, "\n".join(lines) + "\n")
    return prev


def _login_defs_restore(prev):
    out = []
    for ln in _read(LOGIN_DEFS).splitlines():
        m = re.match(r"^\s*(\S+)\s+(\S+)\s*" + re.escape(TAG), ln)
        if m and m.group(1) in prev:
            if prev[m.group(1)] is not None:
                out.append(f"{m.group(1)}\t\t{prev[m.group(1)]}")
            continue                                    # ligne ajoutée par nous : retirée
        out.append(ln)
    _write(LOGIN_DEFS, "\n".join(out) + "\n")


# ── Correctifs : apply_<fn>(ctx) → (détail, prev) ; revert_<fn>(prev) → détail ──
def apply_sysctl(_ctx):
    body = f"{TAG} : profil Lynis (KRNL-6000). Supprimer ce fichier pour revenir aux valeurs par défaut.\n"
    body += "".join(f"{k} = {v}\n" for k, v in SYSCTL)
    _write(SYSCTL_FILE, body)
    r = _run(["sysctl", "-q", "-p", SYSCTL_FILE])       # une clé absente de ce noyau n'est pas bloquante
    return f"{len(SYSCTL)} clés dans {SYSCTL_FILE}" + ("" if r.returncode == 0 else " (clés inconnues ignorées)"), {}


def revert_sysctl(_prev):
    _remove(SYSCTL_FILE)
    _run(["sysctl", "-q", "--system"])
    return "fichier supprimé ; valeurs d'origine au prochain démarrage"


def apply_coredumps(_ctx):
    _write(LIMITS_FILE, f"{TAG} (KRNL-5820)\n*\thard\tcore\t0\nroot\thard\tcore\t0\n")
    _write(COREDUMP_FILE, f"{TAG} (KRNL-5820)\n[Coredump]\nStorage=none\nProcessSizeMax=0\n")
    _run(["sysctl", "-q", "-w", "fs.suid_dumpable=0"])
    return "core dumps désactivés (limits.d, systemd-coredump, fs.suid_dumpable=0)", {}


def revert_coredumps(_prev):
    _remove(LIMITS_FILE)
    _remove(COREDUMP_FILE)
    return "fichiers supprimés ; effectif à la prochaine session"


def apply_password_age(_ctx):
    prev = _login_defs_set({"PASS_MAX_DAYS": "365", "PASS_MIN_DAYS": "1", "PASS_WARN_AGE": "14"})
    return "PASS_MAX_DAYS 365, PASS_MIN_DAYS 1, PASS_WARN_AGE 14 (nouveaux comptes)", prev


def revert_password_age(prev):
    _login_defs_restore(prev or {})
    return "valeurs précédentes de /etc/login.defs rétablies"


def apply_hash_rounds(_ctx):
    prev = _login_defs_set({"SHA_CRYPT_MIN_ROUNDS": "640000", "SHA_CRYPT_MAX_ROUNDS": "640000"})
    return "SHA_CRYPT_MIN/MAX_ROUNDS 640000", prev


revert_hash_rounds = revert_password_age


def apply_umask(_ctx):
    prev = _login_defs_set({"UMASK": "027"})
    return "UMASK 027 (nouvelles sessions)", prev


revert_umask = revert_password_age


def _apply_packages(fn):
    pkgs = PACKAGES[fn]
    _apt(["install"] + pkgs)
    return "installé : " + ", ".join(pkgs), {}


def _revert_packages(fn):
    pkgs = PACKAGES[fn]
    _apt(["purge"] + pkgs)
    return "désinstallé : " + ", ".join(pkgs)


def apply_pwquality(_ctx):
    return _apply_packages("pwquality")


def revert_pwquality(_prev):
    return _revert_packages("pwquality")


def apply_acct(_ctx):
    return _apply_packages("acct")


def revert_acct(_prev):
    return _revert_packages("acct")


def apply_auditd(_ctx):
    return _apply_packages("auditd")


def revert_auditd(_prev):
    return _revert_packages("auditd")


def apply_pam_tmpdir(_ctx):
    return _apply_packages("pam_tmpdir")


def revert_pam_tmpdir(_prev):
    return _revert_packages("pam_tmpdir")


def apply_apt_show_versions(_ctx):
    return _apply_packages("apt_show_versions")


def revert_apt_show_versions(_prev):
    return _revert_packages("apt_show_versions")


def apply_fail2ban(_ctx):
    detail, prev = _apply_packages("fail2ban")
    _run(["systemctl", "enable", "--now", "fail2ban"])
    return detail + " (service actif)", prev


def revert_fail2ban(_prev):
    return _revert_packages("fail2ban")


def apply_sysstat(_ctx):
    _apt(["install", "sysstat"])
    text = _read("/etc/default/sysstat")
    if re.search(r'^\s*ENABLED=', text, re.M):
        text = re.sub(r'^\s*ENABLED=.*$', 'ENABLED="true"', text, flags=re.M)
    else:
        text += '\nENABLED="true"\n'
    _write("/etc/default/sysstat", text)
    _run(["systemctl", "enable", "--now", "sysstat"])
    return "sysstat installé et activé (sar)", {}


def revert_sysstat(_prev):
    _apt(["purge", "sysstat"])
    return "sysstat désinstallé"


def apply_needrestart(_ctx):
    _apt(["install", "needrestart"])
    _write(NEEDRESTART_FILE, f"{TAG} (DEB-0831) : redémarrage automatique des services après mise à jour\n"
                             "$nrconf{restart} = 'a';\n$nrconf{kernelhints} = 0;\n")
    return "needrestart installé en mode automatique", {}


def revert_needrestart(_prev):
    _remove(NEEDRESTART_FILE)
    _apt(["purge", "needrestart"])
    return "needrestart désinstallé"


def apply_banner(_ctx):
    prev = {}
    for path in ("/etc/issue", "/etc/issue.net"):
        old = _read(path)
        prev[path] = old if os.path.exists(_p(path)) else None     # None : le fichier n'existait pas
        first = (old.splitlines() or [""])[0] if path == "/etc/issue" else ""
        _write(path, (first + "\n\n" if first.strip() else "") + BANNER)
    return "bannières légales dans /etc/issue et /etc/issue.net", prev


def revert_banner(prev):
    for path, old in (prev or {}).items():
        if old is None:
            _remove(path)
        else:
            _write(path, old)
    return "bannières précédentes rétablies"


def apply_protocols(_ctx):
    body = f"{TAG} (NETW-3200) : protocoles réseau rarement utilisés, désactivés\n"
    body += "".join(f"install {p} /bin/false\nblacklist {p}\n" for p in PROTOCOLS)
    _write(MODPROBE_FILE, body)
    return "modules " + ", ".join(PROTOCOLS) + " désactivés", {}


def revert_protocols(_prev):
    _remove(MODPROBE_FILE)
    return "fichier modprobe supprimé"


def apply_firewire(_ctx):
    _write(FIREWIRE_FILE, f"{TAG} (STRG-1846)\nblacklist firewire-core\nblacklist firewire-ohci\nblacklist firewire-sbp2\n"
                          "install firewire-core /bin/false\n")
    return "pilotes FireWire désactivés", {}


def revert_firewire(_prev):
    _remove(FIREWIRE_FILE)
    return "fichier modprobe supprimé"


def apply_purge_rc(_ctx):
    r = _run(["dpkg-query", "-W", "-f", "${Package}\t${db:Status-Abbrev}\n"])
    rc = [ln.split("\t")[0] for ln in (r.stdout or "").splitlines()
          if len(ln.split("\t")) > 1 and ln.split("\t")[1].strip().startswith("rc")]
    if not rc:
        return "aucun reste de configuration à purger", {}
    _check(_run(["dpkg", "--purge"] + rc, timeout=900), "dpkg --purge")
    return f"{len(rc)} paquet(s) purgé(s) : " + ", ".join(rc[:8]) + ("…" if len(rc) > 8 else ""), {}


def _kernel_key(rel):
    m = re.match(r"(\d+)\.(\d+)\.(\d+)-(\d+)", rel)
    return tuple(int(x) for x in m.groups()) if m else (0, 0, 0, 0)


def _kernel_family(rel):
    m = re.match(r"(\d+\.\d+)\.\d+-\d+-(.+)$", rel)
    return (m.group(1), m.group(2)) if m else (rel, "")


def old_kernels(installed_packages, running):
    """Noyaux installés mais à supprimer : tous sauf celui qui tourne et le plus récent de chaque famille
    (6.8 generic, 7.0 generic…). Retourne (releases, paquets)."""
    releases = set()
    for pkg in installed_packages:
        m = re.match(r"linux-image-(?:unsigned-)?(\d+\.\d+\.\d+-\d+-\S+)$", pkg)
        if m:
            releases.add(m.group(1))
    newest = {}
    for rel in releases:
        fam = _kernel_family(rel)
        if fam not in newest or _kernel_key(rel) > _kernel_key(newest[fam]):
            newest[fam] = rel
    remove = sorted(rel for rel in releases if rel != running and rel != newest[_kernel_family(rel)])
    pkgs = []
    for rel in remove:
        base = re.match(r"(\d+\.\d+\.\d+-\d+)", rel).group(1)
        pkgs += [p for p in installed_packages if p.startswith("linux-") and re.search(rf"-{re.escape(base)}(-|$)", p)]
    return remove, sorted(set(pkgs))


def apply_old_kernels(_ctx):
    r = _run(["dpkg-query", "-W", "-f", "${Package}\t${db:Status-Status}\n"])
    installed = [ln.split("\t")[0] for ln in (r.stdout or "").splitlines() if ln.rstrip().endswith("installed")]
    remove, pkgs = old_kernels(installed, os.uname().release)
    if not remove:
        return "aucun ancien noyau à supprimer", {}
    _apt(["purge"] + pkgs, timeout=1800)
    return f"{len(remove)} noyau(x) supprimé(s) : " + ", ".join(remove), {}


def apply_cups_perms(_ctx):
    path = "/etc/cups/cupsd.conf"
    full = _p(path)
    if not os.path.exists(full):
        raise RuntimeError("cupsd.conf absent")
    prev = {"mode": oct(os.stat(full).st_mode & 0o777)}
    os.chmod(full, 0o640)
    if not DRY:
        shutil.chown(full, "root", "lp")
    return "cupsd.conf en 640 root:lp", prev


def revert_cups_perms(prev):
    full = _p("/etc/cups/cupsd.conf")
    if os.path.exists(full):
        os.chmod(full, int((prev or {}).get("mode", "0o644"), 8))
    return "permissions précédentes rétablies"


def apply_hosts(_ctx):
    host = socket.gethostname()
    text = _read("/etc/hosts")
    for ln in text.splitlines():
        if not ln.strip().startswith("#") and host in ln.split()[1:]:
            return f"{host} déjà présent dans /etc/hosts", {}
    _write("/etc/hosts", text.rstrip("\n") + f"\n127.0.1.1\t{host}\t{TAG}\n")
    return f"{host} ajouté à /etc/hosts", {}


def revert_hosts(_prev):
    lines = [ln for ln in _read("/etc/hosts").splitlines() if TAG not in ln]
    _write("/etc/hosts", "\n".join(lines) + "\n")
    return "ligne retirée de /etc/hosts"


def apply_sshd(_ctx):
    if not DRY and not os.path.exists("/usr/sbin/sshd"):
        raise RuntimeError("serveur SSH absent")
    _write(SSHD_FILE, SSHD_CONF)
    r = _run(["sshd", "-t"])
    if r.returncode != 0:
        _remove(SSHD_FILE)
        raise RuntimeError("sshd -t : " + (r.stderr or r.stdout or "")[-200:])
    _run(["systemctl", "reload", "ssh"])
    _run(["systemctl", "reload", "sshd"])
    return "sshd_config.d/90-clamav-antivirus.conf écrit et service rechargé", {}


def revert_sshd(_prev):
    _remove(SSHD_FILE)
    _run(["systemctl", "reload", "ssh"])
    _run(["systemctl", "reload", "sshd"])
    return "fichier supprimé et service rechargé"


def apply_ntp(_ctx):
    _check(_run(["timedatectl", "set-ntp", "true"]), "timedatectl")
    return "synchronisation de l'heure activée", {}


def apply_file_perms(ctx):
    items = (ctx or {}).get("file_perms") or []
    if not items:
        raise RuntimeError("aucun fichier relevé par Lynis : relancez l'audit")
    prev, done = {}, []
    for it in items:
        full = _p(it["path"])
        if not os.path.exists(full):
            continue
        prev[it["path"]] = oct(os.stat(full).st_mode & 0o777)
        os.chmod(full, int(it["expected"], 8))
        done.append(f"{it['path']} → {it['expected']}")
    if not done:
        raise RuntimeError("fichiers introuvables")
    return f"{len(done)} fichier(s) : " + ", ".join(done[:10]) + ("…" if len(done) > 10 else ""), prev


def revert_file_perms(prev):
    for path, mode in (prev or {}).items():
        full = _p(path)
        if os.path.exists(full):
            os.chmod(full, int(mode, 8))
    return "permissions précédentes rétablies"


def apply(fn, ctx=None):
    """Applique le correctif `fn` ; retourne (détail, valeurs précédentes pour l'annulation). Lève RuntimeError."""
    func = globals().get(f"apply_{fn}")
    if not func:
        raise RuntimeError(f"correctif inconnu : {fn}")
    return func(ctx or {})


def revert(fn, prev=None):
    func = globals().get(f"revert_{fn}")
    if not func:
        raise RuntimeError(f"annulation impossible : {fn}")
    return func(prev or {})
