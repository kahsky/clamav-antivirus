#!/usr/bin/env python3
"""
ClamAV Antivirus GUI — pot de miel réseau (service système, opt-in).

Quelques ports TCP « leurres » sont mis à l'écoute : deux ports hauts tirés au sort (mémorisés d'un démarrage à
l'autre) et les ports telnet 23 et 2323, que plus aucun programme légitime n'utilise sur un poste de travail et que
tous les outils de balayage essaient. Aucun service ne se trouve derrière : toute connexion est suspecte.

Pour chaque connexion, le service note la source (adresse, nom, adresse matérielle, passerelle ou non), lit les
premiers octets reçus pour deviner l'intention (simple sondage, SSH, HTTP, requête d'exploitation, TLS, SMB, RDP,
SOCKS, tentative de connexion telnet avec identifiant…), et signale un balayage de ports quand une même source touche
plusieurs leurres ou quand le journal du pare-feu (ufw / firewalld) la montre frapper d'autres ports fermés.

Le pot de miel ne répond rien d'utile, ne fait tourner aucun service et ne ralentit pas la machine : les leurres sont
de simples sockets en attente.
(c) 2026 Dukiwi SA - Estavayer-le-Lac
"""

import ipaddress
import json
import os
import random
import re
import select
import shutil
import socket
import subprocess
import threading
import time
from datetime import datetime

import clamav_distro as distro

TAG = "cav-honeypot"                      # commentaire des règles de pare-feu gérées ici
DECOY_PORTS = (23, 2323)                  # telnet : jamais utilisé sur un poste de travail, toujours balayé
RANDOM_RANGE = (20000, 32000)             # hors plage éphémère (32768+) : pas de collision avec les connexions sortantes
RANDOM_COUNT = 2
# Ports que chkrootkit (test bindshell) considère comme des portes dérobées : jamais tirés au sort
BINDSHELL_PORTS = {114, 145, 465, 511, 1008, 1524, 1999, 3879, 4369, 5665, 10008, 12321, 23132, 27374, 29364,
                   31336, 31337, 45454, 47017, 47889, 60001, 65535}
READ_TIMEOUT = 4.0                        # s d'attente des premiers octets
MAX_PAYLOAD = 512
SOURCES_MAX = 60
EVENTS_MAX = 150
ALERT_COOLDOWN = 600                      # s entre deux alertes pour la même source (sauf aggravation)
SCAN_WINDOW = 180                         # s : fenêtre dans laquelle plusieurs ports touchés = balayage
FW_SCAN_WARN = 5                          # ports distincts (leurres + refus du pare-feu) → balayage
FW_SCAN_DANGER = 15
# Bruit UDP normal d'un réseau local, jamais compté : DHCP, NetBIOS, SSDP, mDNS, LLMNR, WS-Discovery, Dropbox, Spotify, Plex…
FW_NOISE_UDP = {7, 9, 67, 68, 137, 138, 546, 547, 1900, 3702, 5353, 5355, 6771, 8612, 17500, 32412, 32414, 57621}
PERSIST_INTERVAL = 5
FW_RULES_INTERVAL = 300

FW_LINE_RE = re.compile(r"IN=(?P<in>\S*)\s+OUT=(?P<out>\S*)\s.*?SRC=(?P<src>[0-9a-fA-F.:]+)\s+DST=(?P<dst>[0-9a-fA-F.:]+)\s"
                        r".*?PROTO=(?P<proto>\w+)(?:\s.*?DPT=(?P<dpt>\d+))?")
HTTP_RE = re.compile(rb"^(GET|POST|HEAD|PUT|OPTIONS|DELETE|CONNECT|PROPFIND|TRACE|PATCH)\s+(\S+)")
# Chemins typiques des robots d'exploitation (routeurs, caméras, WordPress, phpMyAdmin, Spring, Tomcat, traversée…)
EXPLOIT_PATH_RE = re.compile(r"(\.env\b|cgi-bin|wp-login|wp-admin|xmlrpc\.php|phpmyadmin|boaform|GponForm|HNAP1|manager/html|"
                             r"\.git/|actuator|/solr|/console|setup\.cgi|/shell|/cmd|eval-stdin|\.\./|%2e%2e|login\.cgi|"
                             r"formLogin|/admin|/owa/|/autodiscover|/vendor/|/\.aws|/config\.|/backup|/id_rsa)", re.I)
INTENTS = ("probe", "ssh", "http", "exploit", "tls", "smb", "rdp", "socks", "telnet", "rtsp", "sip", "login", "text", "binary")


def _iso(ts=None):
    return datetime.fromtimestamp(ts or time.time()).isoformat(timespec="seconds")


def _parse_iso(s):
    try:
        return datetime.fromisoformat(s).timestamp()
    except (TypeError, ValueError):
        return 0.0


def _run(cmd, timeout=20):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
    except (OSError, subprocess.SubprocessError):
        return subprocess.CompletedProcess(cmd, 1, "", "")


def valid_ip(text):
    """Adresse IP normalisée (v4 ou v6, « ::ffff:1.2.3.4 » → « 1.2.3.4 »), ou None."""
    try:
        addr = ipaddress.ip_address(str(text or "").strip().split("%")[0])
    except ValueError:
        return None
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    return str(addr)


def is_local_ip(ip):
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr.is_private or addr.is_link_local or addr.is_loopback


def classify_payload(data):
    """Premiers octets reçus → (intention, détail lisible). Rien reçu = simple sondage de port."""
    if not data:
        return "probe", ""
    if re.match(rb"^(INVITE|REGISTER|OPTIONS)\s+sip:", data):
        return "sip", ""
    m = HTTP_RE.match(data)
    if m:
        path = m.group(2).decode("utf-8", errors="replace")[:80]
        line = f"{m.group(1).decode()} {path}"
        return ("exploit" if EXPLOIT_PATH_RE.search(path) else "http"), line
    if data.startswith(b"SSH-"):
        return "ssh", data.split(b"\n", 1)[0].decode("utf-8", errors="replace").strip()[:60]
    if len(data) >= 3 and data[0] == 0x16 and data[1] == 0x03:
        return "tls", ""
    if b"SMB" in data[:12]:
        return "smb", ""
    if data[:2] == b"\x03\x00" and len(data) >= 4:
        return "rdp", ""
    if data[:1] in (b"\x05", b"\x04") and len(data) >= 3 and data[1] < 0x10:
        return "socks", ""
    if data[:1] == b"\xff":
        return "telnet", ""
    if data.startswith((b"RTSP", b"DESCRIBE ", b"SETUP ")):
        return "rtsp", ""
    printable = sum(1 for b in data if 32 <= b < 127 or b in (9, 10, 13)) / max(1, len(data))
    text = data.decode("utf-8", errors="replace")
    first = text.strip().splitlines()[0].strip() if text.strip() else ""
    if printable >= 0.9 and first:
        if re.match(r"^(USER|PASS|AUTH|LOGIN|HELO|EHLO)\b", first, re.I):
            return "login", first[:60]
        return "text", first[:60]
    return "binary", data[:16].hex()


def _clean_line(raw):
    """Ligne telnet → texte : négociations IAC (≥ 0x80) et caractères de contrôle retirés."""
    return "".join(chr(b) for b in raw if 32 <= b < 127).strip()[:32]


class Honeypot(threading.Thread):
    """Leurres TCP + lecture du journal du pare-feu. `helpers` : log, write_log, ufw(*args), parse_ufw_numbered."""

    def __init__(self, daemon, helpers):
        super().__init__(daemon=True, name="honeypot")
        self.daemon = daemon
        self.h = helpers
        self.lock = threading.Lock()
        self.socks = {}                      # port → socket
        self.started_at = None
        self.active = False
        self.fw_log = False
        self.fw_proc = None
        self.fw_thread = None
        self.last_fw_check = 0.0
        self.last_persist = 0.0
        self.dirty = False
        self._own = (0.0, set())
        self._gw = (0.0, "")
        self._log_denied_set = False
        saved = daemon.state.get("honeypot") or {}
        self.sources = {}
        for s in saved.get("sources") or []:
            if s.get("ip"):
                s.setdefault("port_times", {})
                s.setdefault("alerted_at", 0)
                s.setdefault("alerted_severity", "")
                self.sources[s["ip"]] = s
        self.events = list(saved.get("events") or [])[:EVENTS_MAX]
        self.blocked = dict(saved.get("blocked") or {})

    # ── Journal ─────────────────────────────────────────────────────────
    def _log(self, msg):
        try:
            self.h["log"](msg)
        except Exception:  # noqa: BLE001
            pass

    def _wlog(self, msg):
        try:
            self.h["write_log"](msg)
        except Exception:  # noqa: BLE001
            pass

    # ── Identité locale ──────────────────────────────────────────────────
    def own_ips(self):
        ts, ips = self._own
        if time.time() - ts < 300:
            return ips
        ips = set()
        r = _run(["ip", "-j", "addr"], timeout=10)
        try:
            for link in json.loads(r.stdout or "[]"):
                for a in link.get("addr_info") or []:
                    ip = valid_ip(a.get("local", ""))
                    if ip:
                        ips.add(ip)
        except ValueError:
            pass
        self._own = (time.time(), ips)
        return ips

    def gateway(self):
        ts, gw = self._gw
        if time.time() - ts < 300:
            return gw
        gw = ""
        r = _run(["ip", "-j", "route", "show", "default"], timeout=10)
        try:
            routes = sorted((x for x in json.loads(r.stdout or "[]") if x.get("gateway")), key=lambda x: x.get("metric", 0))
            gw = valid_ip(routes[0]["gateway"]) or "" if routes else ""
        except (ValueError, IndexError):
            pass
        self._gw = (time.time(), gw)
        return gw

    # ── Ports ────────────────────────────────────────────────────────────
    def _bind(self, port):
        last = None
        for family, addr in ((socket.AF_INET6, "::"), (socket.AF_INET, "0.0.0.0")):
            s = None
            try:
                s = socket.socket(family, socket.SOCK_STREAM)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                if family == socket.AF_INET6:
                    s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
                s.bind((addr, port))
                s.listen(16)
                s.setblocking(False)
                return s
            except OSError as e:
                last = e
                if s is not None:
                    try:
                        s.close()
                    except OSError:
                        pass
        self._log(f"Pot de miel : port {port} indisponible ({last})")
        return None

    def _random_ports(self):
        stored = [p for p in (self.daemon.state.get("honeypot_random_ports") or []) if isinstance(p, int)
                  and RANDOM_RANGE[0] <= p <= RANDOM_RANGE[1] and p not in BINDSHELL_PORTS]
        return stored[:RANDOM_COUNT]

    def _pick_port(self, taken):
        for _ in range(200):
            p = random.randint(*RANDOM_RANGE)
            if p not in BINDSHELL_PORTS and p not in taken and p not in DECOY_PORTS:
                return p
        return None

    def _start(self):
        randoms = self._random_ports()
        socks = {}
        changed = False
        for p in list(randoms):
            s = self._bind(p)
            if s:
                socks[p] = s
            else:
                randoms.remove(p)
                changed = True
        while len(randoms) < RANDOM_COUNT:
            p = self._pick_port(set(randoms) | set(socks))
            if p is None:
                break
            s = self._bind(p)
            if s:
                socks[p] = s
                randoms.append(p)
                changed = True
        if changed:
            self.daemon.state.update(honeypot_random_ports=sorted(randoms))
        for p in DECOY_PORTS:
            s = self._bind(p)
            if s:
                socks[p] = s
        if not socks:
            self._log("Pot de miel : aucun port disponible")
            return
        self.socks = socks
        self.started_at = _iso()
        self.last_fw_check = 0.0
        self._wlog(f"honeypot: listening on {', '.join(str(p) for p in sorted(socks))}")
        self._start_fw_log()
        self.dirty = True

    def _stop(self, remove_rules=True):
        socks, self.socks = self.socks, {}
        for s in socks.values():
            try:
                s.close()
            except OSError:
                pass
        self._stop_fw_log()
        if socks:
            self._wlog("honeypot: stopped")
            if remove_rules:
                try:
                    self._remove_allow_rules()
                except Exception as e:  # noqa: BLE001
                    self._log(f"Pot de miel : règles pare-feu : {e}")
        self.dirty = True
        self._persist()

    @property
    def ports(self):
        return sorted(self.socks)

    def close(self):
        """Arrêt du service : leurres fermés et lecteur du journal du pare-feu tué, état enregistré (règles conservées)."""
        if self.socks or self.fw_proc:
            self._stop(remove_rules=False)

    # ── Boucle principale ────────────────────────────────────────────────
    def run(self):
        self.active = True
        while not self.daemon.shutdown.is_set():
            try:
                want = bool(self.daemon.settings.get("honeypot"))
                if want and not self.socks:
                    self._start()
                    if not self.socks:
                        self.daemon.shutdown.wait(60)
                        continue
                elif not want and self.socks:
                    self._stop()
                if self.socks:
                    ready, _, _ = select.select(list(self.socks.values()), [], [], 1.0)
                    for s in ready:
                        try:
                            conn, addr = s.accept()
                        except OSError:
                            continue
                        port = next((p for p, sk in self.socks.items() if sk is s), 0)
                        threading.Thread(target=self._handle, args=(conn, addr, port), daemon=True).start()
                    if time.time() - self.last_fw_check > FW_RULES_INTERVAL:
                        self.last_fw_check = time.time()
                        try:
                            self._ensure_allow_rules()
                        except Exception as e:  # noqa: BLE001
                            self._log(f"Pot de miel : règles pare-feu : {e}")
                else:
                    self.daemon.shutdown.wait(2)
                if self.dirty and time.time() - self.last_persist > PERSIST_INTERVAL:
                    self._persist()
            except Exception as e:  # noqa: BLE001
                self._log(f"Pot de miel : {e}")
                time.sleep(1)
        self._stop(remove_rules=False)
        self.active = False

    # ── Connexions ───────────────────────────────────────────────────────
    def _read_line(self, conn, limit=128):
        buf = b""
        deadline = time.time() + READ_TIMEOUT
        while len(buf) < limit and time.time() < deadline:
            try:
                chunk = conn.recv(limit - len(buf))
            except socket.timeout:
                break
            except OSError:
                return buf or None
            if not chunk:
                return buf or None
            buf += chunk
            if b"\n" in buf or b"\r" in buf:
                break
        return buf

    def _telnet_dialog(self, conn):
        """Leurre telnet : invite « login: » puis « Password: » ; on garde l'identifiant essayé, jamais le mot de passe."""
        try:
            conn.sendall(b"\r\nlogin: ")
        except OSError:
            return "probe", "", b""
        first = self._read_line(conn)
        if first is None:
            return "probe", "", b""
        intent, detail = classify_payload(first)
        if intent not in ("text", "login", "telnet", "probe"):
            return intent, detail, first                 # un scanner de versions (nmap -sV) parle un autre protocole
        user = _clean_line(first)
        if not user:
            return ("telnet" if first else "probe"), "", first
        try:
            conn.sendall(b"Password: ")
            pw = self._read_line(conn)
        except OSError:
            pw = None
        return "login", f"login={user}" + (" +password" if pw else ""), first

    def _handle(self, conn, addr, port):
        ip = valid_ip(addr[0]) or str(addr[0])
        data = b""
        intent, detail = "probe", ""
        try:
            conn.settimeout(READ_TIMEOUT)
            if port in DECOY_PORTS:
                intent, detail, data = self._telnet_dialog(conn)
            else:
                try:
                    data = conn.recv(MAX_PAYLOAD)
                except (socket.timeout, OSError):
                    data = b""
                intent, detail = classify_payload(data)
        except Exception as e:  # noqa: BLE001
            self._log(f"Pot de miel : connexion {ip} : {e}")
        finally:
            try:
                conn.close()
            except OSError:
                pass
        if (ip in self.own_ips() or ip.startswith("127.") or ip == "::1") and not os.environ.get("CLAMAV_ANTIVIRUS_HONEYPOT_SELF"):
            return                                        # test depuis cet ordinateur : pas une menace (sauf en test)
        self._record(ip, port, intent, detail)

    def _new_source(self, ip, now):
        src = {"ip": ip, "host": "", "mac": "", "local": is_local_ip(ip), "gateway": ip == self.gateway(),
               "first": _iso(now), "last": _iso(now), "count": 0, "ports": [], "fw_ports": [], "intents": {},
               "samples": [], "severity": "", "alerted_at": 0, "alerted_severity": "", "blocked": ip in self.blocked,
               "ignored": False, "port_times": {}}
        self.sources[ip] = src
        threading.Thread(target=self._enrich, args=(ip,), daemon=True).start()
        return src

    def _record(self, ip, port, intent, detail):
        now = time.time()
        with self.lock:
            src = self.sources.get(ip) or self._new_source(ip, now)
            src["last"] = _iso(now)
            src["count"] += 1
            if port not in src["ports"]:
                src["ports"].append(port)
            src["port_times"][str(port)] = now
            src["intents"][intent] = src["intents"].get(intent, 0) + 1
            if detail:
                src["samples"] = ([detail] + [s for s in src["samples"] if s != detail])[:5]
            self.events.insert(0, {"t": _iso(now), "ip": ip, "port": port, "intent": intent, "detail": detail, "fw": False})
            del self.events[EVENTS_MAX:]
            self.dirty = True
        self._wlog(f"honeypot: {ip} → port {port} ({intent}{' ' + detail if detail else ''})")
        self._evaluate(ip)

    def _fw_hit(self, ip, port, proto):
        now = time.time()
        key = f"{port}/{proto}"
        with self.lock:
            src = self.sources.get(ip) or self._new_source(ip, now)
            src["last"] = _iso(now)
            src["port_times"][f"fw:{key}"] = now
            new = key not in src["fw_ports"]
            if new:
                src["fw_ports"] = (src["fw_ports"] + [key])[-40:]
                self.events.insert(0, {"t": _iso(now), "ip": ip, "port": port, "intent": "fw", "detail": proto, "fw": True})
                del self.events[EVENTS_MAX:]
            self.dirty = True
        if new:
            self._evaluate(ip)

    def _enrich(self, ip):
        host, mac = "", ""
        result = {}

        def rdns():
            try:
                result["host"] = socket.gethostbyaddr(ip)[0]
            except (OSError, socket.herror, socket.gaierror):
                pass
        t = threading.Thread(target=rdns, daemon=True)
        t.start()
        t.join(2.0)
        host = result.get("host", "")
        if not host and is_local_ip(ip) and shutil.which("avahi-resolve-address"):
            r = _run(["avahi-resolve-address", ip], timeout=3)
            parts = (r.stdout or "").split()
            if len(parts) >= 2:
                host = parts[1]
        r = _run(["ip", "-j", "neigh", "show", ip], timeout=5)
        try:
            mac = next((x.get("lladdr", "") for x in json.loads(r.stdout or "[]") if x.get("lladdr")), "")
        except ValueError:
            pass
        with self.lock:
            src = self.sources.get(ip)
            if src:
                src["host"] = host or src.get("host", "")
                src["mac"] = mac or src.get("mac", "")
                self.dirty = True

    # ── Évaluation et alertes ────────────────────────────────────────────
    def _evaluate(self, ip):
        now = time.time()
        with self.lock:
            src = self.sources.get(ip)
            if not src or src.get("ignored"):
                return
            recent = [k for k, ts in src["port_times"].items() if now - ts <= SCAN_WINDOW]
            hp_hits = [k for k in recent if not k.startswith("fw:")]
            fw_hits = [k for k in recent if k.startswith("fw:")]
            reasons = []
            if src["count"]:
                reasons.append("honeypot_hit")
            if len(hp_hits) >= 2 or len(set(hp_hits) | set(fw_hits)) >= FW_SCAN_WARN:
                reasons.append("port_scan")
            if src["intents"].get("login"):
                reasons.append("login_attempt")
            if src["intents"].get("exploit"):
                reasons.append("exploit_attempt")
            if not reasons:
                return                                    # refus isolés du pare-feu : bruit, pas (encore) un balayage
            danger = any(r in reasons for r in ("port_scan", "login_attempt", "exploit_attempt")) or len(fw_hits) >= FW_SCAN_DANGER
            severity = "danger" if danger else "warn"
            src["severity"] = severity
            escalated = severity == "danger" and src.get("alerted_severity") != "danger"
            if src.get("blocked"):
                return
            if now - float(src.get("alerted_at") or 0) < ALERT_COOLDOWN and not escalated:
                return
            src["alerted_at"] = now
            src["alerted_severity"] = severity
            ports = sorted(src["ports"])
            fw_ports = src["fw_ports"][-12:]
            intents = dict(src["intents"])
            detail = ", ".join(str(p) for p in ports[:12])
            if fw_ports:
                detail += (" · " if detail else "") + "fw " + ", ".join(fw_ports)
            top = ", ".join(f"{k}×{v}" for k, v in sorted(intents.items(), key=lambda kv: -kv[1])[:4])
            alert = {"kind": "honeypot", "severity": severity, "time": _iso(now), "ip": ip, "host": src.get("host", ""),
                     "mac": src.get("mac", ""), "local": src.get("local"), "gateway": src.get("gateway"),
                     "ports": ports[:12], "fw_ports": fw_ports, "count": src["count"], "intents": intents,
                     "samples": list(src["samples"]), "reasons": reasons, "title": src.get("host") or ip,
                     "detail": (detail + (" · " + top if top else ""))[:200], "comm": "", "exe": "", "pid": 0, "user": "",
                     "top_dir": "", "sample": [], "cmdline": ""}
            self.dirty = True
        self.daemon.publish_alert(alert)
        try:
            self.daemon.broadcast({"event": "honeypot", "summary": self.summary()})
        except Exception:  # noqa: BLE001
            pass

    # ── Journal du pare-feu ──────────────────────────────────────────────
    def _fw_log_cmd(self):
        path = os.environ.get("CLAMAV_ANTIVIRUS_FW_LOG")
        if path:
            return ["tail", "-F", "-n", "0", path]
        if os.geteuid() != 0:
            return None
        if distro.firewall_backend() != "firewalld" and os.path.exists("/var/log/ufw.log"):
            return ["tail", "-F", "-n", "0", "/var/log/ufw.log"]
        if shutil.which("journalctl"):
            return ["journalctl", "-k", "-f", "-n", "0", "-o", "cat"]
        return None

    def _start_fw_log(self):
        if self.fw_thread and self.fw_thread.is_alive():
            return
        self.fw_thread = threading.Thread(target=self._fw_log_loop, daemon=True, name="honeypot-fwlog")
        self.fw_thread.start()

    def _stop_fw_log(self):
        proc, self.fw_proc = self.fw_proc, None
        self.fw_log = False
        if proc:
            try:
                proc.kill()
            except OSError:
                pass

    def _fw_log_loop(self):
        while self.socks and not self.daemon.shutdown.is_set():
            cmd = self._fw_log_cmd()
            if not cmd:
                self.fw_log = False
                return
            try:
                proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, errors="replace")
            except OSError as e:
                self._log(f"Pot de miel : journal du pare-feu : {e}")
                self.fw_log = False
                return
            self.fw_proc = proc
            self.fw_log = True
            try:
                for line in proc.stdout:
                    if not self.socks or self.daemon.shutdown.is_set():
                        break
                    try:
                        self._fw_line(line)
                    except Exception as e:  # noqa: BLE001
                        self._log(f"Pot de miel : ligne pare-feu : {e}")
            finally:
                try:
                    proc.kill()
                except OSError:
                    pass
            if self.socks and not self.daemon.shutdown.is_set():
                self.daemon.shutdown.wait(5)
        self.fw_log = False

    def _fw_line(self, line):
        if not any(k in line for k in ("BLOCK", "REJECT", "DROP")):
            return
        m = FW_LINE_RE.search(line)
        if not m or m.group("out") or not m.group("in"):
            return
        src, dst = valid_ip(m.group("src")), valid_ip(m.group("dst"))
        proto = m.group("proto").upper()
        try:
            dpt = int(m.group("dpt") or 0)
        except ValueError:
            dpt = 0
        if not src or not dst or not dpt or proto not in ("TCP", "UDP"):
            return
        if src in self.own_ips() or ipaddress.ip_address(src).is_loopback:
            return
        daddr = ipaddress.ip_address(dst)
        if daddr.is_multicast or dst.endswith(".255") or dst == "255.255.255.255":
            return
        if proto == "TCP" and ("SYN" not in line or " ACK" in line):
            return                                        # seuls les SYN comptent (pas les restes d'une connexion)
        if proto == "UDP" and dpt in FW_NOISE_UDP:
            return
        self._fw_hit(src, dpt, proto.lower())

    # ── Pare-feu : ouverture des leurres, blocage d'une source ──────────
    def _fw_managed(self):
        if os.environ.get("CLAMAV_ANTIVIRUS_HONEYPOT_FW") == "1":
            return True
        if os.geteuid() != 0:
            return False
        return shutil.which("firewall-cmd" if distro.firewall_backend() == "firewalld" else "ufw") is not None

    def _fwcmd(self, *args, timeout=60):
        r = _run(["firewall-cmd", *args], timeout=timeout)
        text = ((r.stdout or "") + (r.stderr or "")).strip()
        return r.returncode == 0, text[:300]

    def _zone(self):
        ok, zone = self._fwcmd("--get-default-zone", timeout=20)
        return zone.strip() if ok and zone.strip() else "public"

    def _ufw_rules(self):
        r = _run(["ufw", "status", "numbered"], timeout=30)
        return self.h["parse_ufw_numbered"](r.stdout or "") if r.returncode == 0 else []

    def _ensure_allow_rules(self):
        if not self.socks or not self._fw_managed():
            return
        ports = sorted(self.socks)
        if distro.firewall_backend() == "firewalld":
            zone = self._zone()
            ok, cur = self._fwcmd("--permanent", "--zone", zone, "--list-ports")
            have = set(cur.split()) if ok else set()
            changed = False
            for p in ports:
                if f"{p}/tcp" not in have:
                    self._fwcmd("--permanent", "--zone", zone, "--add-port", f"{p}/tcp")
                    changed = True
            if not self._log_denied_set:
                self._log_denied_set = True
                ok, cur = self._fwcmd("--get-log-denied", timeout=20)
                if ok and cur.strip() == "off":
                    self._fwcmd("--set-log-denied", "unicast")     # journal des refus → détection des balayages
                    changed = True
            if changed:
                self._fwcmd("--reload")
                self._wlog(f"honeypot: firewalld zone {zone} ports {ports}")
            return
        have = set()
        for r in self._ufw_rules():
            if TAG in (r.get("comment") or "") and (r.get("action") or "").startswith("ALLOW"):
                have.add((r.get("to") or "").split()[0] if r.get("to") else "")
        for p in ports:
            if f"{p}/tcp" not in have:
                ok, text = self.h["ufw"]("allow", f"{p}/tcp", "comment", f"{TAG} decoy")
                if not ok:
                    self._log(f"Pot de miel : ufw allow {p}/tcp : {text}")

    def _remove_allow_rules(self):
        if not self._fw_managed():
            return
        if distro.firewall_backend() == "firewalld":
            zone = self._zone()
            ok, cur = self._fwcmd("--permanent", "--zone", zone, "--list-ports")
            removed = False
            for spec in (cur.split() if ok else []):
                port = spec.split("/")[0]
                if port.isdigit() and (int(port) in DECOY_PORTS or int(port) in self._random_ports()):
                    self._fwcmd("--permanent", "--zone", zone, "--remove-port", spec)
                    removed = True
            if removed:
                self._fwcmd("--reload")
            return
        for r in sorted(self._ufw_rules(), key=lambda x: -x["number"]):
            if f"{TAG} decoy" in (r.get("comment") or "") or f"{TAG} decoy" in (r.get("raw") or ""):
                self.h["ufw"]("delete", str(r["number"]))

    def block(self, ip, remove=False):
        """Bloque (ou débloque) toute connexion venant de cette adresse : règle DENY en tête (ufw) ou rich rule drop (firewalld)."""
        ip = valid_ip(ip)
        if not ip:
            return False, "invalid_ip"
        if ip in self.own_ips() or ip == self.gateway() and not remove:
            return False, "invalid_ip"                    # jamais soi-même ni la passerelle (plus de réseau du tout)
        ok, text = True, ""
        if self._fw_managed():
            if distro.firewall_backend() == "firewalld":
                fam = "ipv6" if ":" in ip else "ipv4"
                rule = f'rule family="{fam}" source address="{ip}" drop'
                ok, text = self._fwcmd("--permanent", "--remove-rich-rule" if remove else "--add-rich-rule", rule)
                if remove and "NOT_ENABLED" in text:
                    ok = True
                self._fwcmd("--reload")
            else:
                rules = self._ufw_rules()
                if remove:
                    for r in sorted(rules, key=lambda x: -x["number"]):
                        if f"{TAG} block" in (r.get("comment") or "") and (r.get("from") or "").split()[:1] == [ip]:
                            ok2, text = self.h["ufw"]("delete", str(r["number"]))
                            ok = ok and ok2
                else:
                    already = any(f"{TAG} block" in (r.get("comment") or "") and (r.get("from") or "").split()[:1] == [ip] for r in rules)
                    if not already:
                        args = ["insert", "1"] if rules else []
                        ok, text = self.h["ufw"](*args, "deny", "from", ip, "to", "any", "comment", f"{TAG} block")
        with self.lock:
            src = self.sources.get(ip) or self._new_source(ip, time.time())
            if ok:
                src["blocked"] = not remove
                if remove:
                    self.blocked.pop(ip, None)
                else:
                    self.blocked[ip] = {"t": _iso(), "host": src.get("host", "")}
            self.dirty = True
        self._wlog(f"honeypot: {'unblock' if remove else 'block'} {ip} → {ok}{' ' + text if not ok else ''}")
        self._persist()
        return ok, text

    def ignore(self, ip, remove=False):
        ip = valid_ip(ip)
        if not ip:
            return False
        with self.lock:
            src = self.sources.get(ip) or self._new_source(ip, time.time())
            src["ignored"] = not remove
            if not remove:
                src["severity"] = ""
            self.dirty = True
        self._wlog(f"honeypot: {'unignore' if remove else 'ignore'} {ip}")
        self._persist()
        return True

    def forget(self, ip):
        ip = valid_ip(ip)
        with self.lock:
            self.sources.pop(ip, None)
            self.events = [e for e in self.events if e.get("ip") != ip]
            self.dirty = True
        self._persist()
        return True

    # ── État ─────────────────────────────────────────────────────────────
    @staticmethod
    def _public(src):
        out = {k: v for k, v in src.items() if k not in ("port_times", "alerted_at", "alerted_severity")}
        out["ports"] = sorted(src.get("ports") or [])
        return out

    def _sorted_sources(self):
        return sorted(self.sources.values(), key=lambda s: s.get("last", ""), reverse=True)[:SOURCES_MAX]

    def _persist(self):
        with self.lock:
            srcs = self._sorted_sources()
            self.sources = {s["ip"]: s for s in srcs}
            data = {"ports": sorted(self.socks), "listening": bool(self.socks), "started_at": self.started_at, "fw_log": self.fw_log,
                    "sources": [dict(s) for s in srcs], "events": self.events[:EVENTS_MAX], "blocked": dict(self.blocked)}
            self.dirty = False
            self.last_persist = time.time()
        try:
            self.daemon.state.update(honeypot=data)
        except Exception as e:  # noqa: BLE001
            self._log(f"Pot de miel : enregistrement : {e}")

    def summary(self):
        now = time.time()
        with self.lock:
            recent = [s for s in self.sources.values() if now - _parse_iso(s.get("last")) <= 86400 and not s.get("ignored")]
            return {"enabled": bool(self.daemon.settings.get("honeypot")), "active": bool(self.socks), "ports": sorted(self.socks),
                    "fw_log": self.fw_log, "sources_24h": len(recent),
                    "danger_24h": sum(1 for s in recent if s.get("severity") == "danger" and not s.get("blocked")),
                    "last": self.events[0]["t"] if self.events else None, "blocked": len(self.blocked),
                    "answered": bool(self.daemon.state.get("honeypot_answered"))}

    def snapshot(self):
        with self.lock:
            srcs = [self._public(s) for s in self._sorted_sources()]
            events = list(self.events[:60])
            blocked = dict(self.blocked)
        s = self.summary()
        s.update({"backend": distro.firewall_backend(), "started_at": self.started_at, "decoys": list(DECOY_PORTS),
                  "sources": srcs, "events": events, "blocked_list": blocked, "fw_managed": self._fw_managed()})
        return s
