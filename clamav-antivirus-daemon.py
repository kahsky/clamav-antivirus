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
  - les mises à jour planifiées (déclenchées par clamav-antivirus-update.timer :
    tous les jours à 07:00 et 5 minutes après le démarrage).

Usage :
  clamav-antivirus-daemon.py                 # mode daemon (root)
  clamav-antivirus-daemon.py --request update      # client : demander une MàJ et attendre
  clamav-antivirus-daemon.py --request scan [/chemin]
  clamav-antivirus-daemon.py --request status

(c) 2026 Dukiwi SA - Estavayer-le-Lac
"""

import json
import os
import pwd
import shutil
import signal
import socket
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
    SYSTEM_FILELIST_CACHE, FIRST_SCAN_FLAG, SYSTEM_LOG_FILE,
    DAEMON_ALLOWED_ROOTS, LineSocket, peer_credentials, daemon_connect,
    daemon_request, find_command, is_noise_line, classify_line,
    db_last_update, db_files_info,
)

LOG_MAX_BYTES = 5 * 1024 * 1024
PROGRESS_INTERVAL = 0.25      # secondes entre deux événements de progression
PROGRESS_SAVE_INTERVAL = 2.0  # secondes entre deux sauvegardes du fichier de reprise
HISTORY_MAX = 20


def now_iso():
    return datetime.now().isoformat(timespec="seconds")


def log(msg):
    """Journal du daemon (journald via stdout)."""
    print(f"[{now_iso()}] {msg}", flush=True)


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

    def add_history(self, entry):
        with self.lock:
            hist = self.data.get("history", [])
            hist.insert(0, entry)
            self.data["history"] = hist[:HISTORY_MAX]
            self._save()

    def _save(self):
        tmp = SYSTEM_STATE_FILE + ".tmp"
        with open(tmp, "w") as f:
            json.dump(self.data, f, indent=2, ensure_ascii=False)
        os.chmod(tmp, 0o644)
        os.replace(tmp, SYSTEM_STATE_FILE)


# ═══════════════════════════════════════════════════════════════════════════
# Jobs
# ═══════════════════════════════════════════════════════════════════════════

class Job:
    _counter = 0
    _counter_lock = threading.Lock()

    def __init__(self, kind, path=None, resume=False, auto=False, requested_by=None):
        with Job._counter_lock:
            Job._counter += 1
            self.id = Job._counter
        self.kind = kind            # 'scan' | 'update'
        self.path = path
        self.resume = resume
        self.auto = auto            # lancé par le système (première installation, reprise)
        self.requested_by = requested_by
        self.created_at = time.time()
        self.started_at = None
        self.cancel_event = threading.Event()
        self.cancelled_by_user = False
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
            except Exception as e:
                log(f"Erreur job {job.kind}: {e}")
                self.finish(job, "error", f"Erreur interne : {e}")
            finally:
                with self.queue_lock:
                    self.current = None

    def finish(self, job, status, message, summary=None):
        job.phase = "done"
        self.broadcast({
            "event": "job_done", "id": job.id, "kind": job.kind, "path": job.path,
            "status": status, "message": message, "summary": summary or {},
            "auto": job.auto, "elapsed": time.time() - (job.started_at or time.time()),
        })

    # ── Scan ─────────────────────────────────────────────────────────────
    def _save_progress(self, job, in_progress=True):
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

    def _count_files(self, job):
        """Phase inventaire : find → fichier cache, en streaming (peu de mémoire)."""
        job.phase = "counting"
        job.found = 0
        self.emit_progress(job)
        cmd = find_command(job.path)
        with job.proc_lock:
            job.proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                        stderr=subprocess.DEVNULL, text=True, bufsize=1)
        last_emit = time.time()
        with open(SYSTEM_FILELIST_CACHE, "w") as out:
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

        if job.resume:
            idx = self._resume_offset(job)
            if idx is not None:
                start_idx, resumed = idx, True
            else:
                job.resume = False

        if not resumed:
            self.write_log(f"▶ Scan {'automatique ' if job.auto else ''}de {job.path}")
            self.emit_line("info", f"▶ Inventaire des fichiers de {job.path}…")
            total = self._count_files(job)
            if job.cancel_event.is_set():
                if job.cancelled_by_user:
                    self._forget_auto(job)
                self._save_progress(job, in_progress=False)
                self.finish(job, "cancelled", "Scan annulé pendant l'inventaire")
                return
            job.total = total
            job.infected = 0
            job.scanned = 0
            self._save_progress(job, in_progress=True)
        else:
            job.scanned = start_idx
            self.write_log(f"▶ Reprise du scan de {job.path} ({start_idx}/{job.total})")
            self.emit_line("info", f"▶ Reprise du scan à {start_idx:,} / {job.total:,} fichiers".replace(",", " "))

        if job.total == 0:
            self._save_progress(job, in_progress=False)
            self._record_scan(job, "clean")
            self.finish(job, "clean", "Aucun fichier à analyser", self._summary(job))
            return

        # Liste des fichiers restants (copie en streaming)
        tmp_list = SYSTEM_FILELIST_CACHE + ".tmp"
        with open(SYSTEM_FILELIST_CACHE) as src, open(tmp_list, "w") as dst:
            for i, line in enumerate(src):
                if i >= start_idx:
                    dst.write(line)

        job.phase = "scanning"
        self.emit_progress(job)
        self.emit_line("info", f"▶ {job.total:,} fichier(s) à analyser — démarrage de clamscan…".replace(",", " "))

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
            self.write_log(f"■ Scan interrompu à {job.scanned}/{job.total}")
            self.finish(job, "cancelled",
                        f"Scan interrompu à {job.scanned:,} / {job.total:,} fichiers — reprise possible".replace(",", " "),
                        self._summary(job))
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
            self.finish(job, "error", f"clamscan a échoué (code {rc})", self._summary(job))
            return

        status = "infected" if job.infected > 0 else "clean"
        self._record_scan(job, status)
        if job.infected:
            msg = f"{job.infected} menace(s) détectée(s) — fichiers déplacés en quarantaine"
        else:
            msg = f"Aucune menace détectée sur {job.total:,} fichiers".replace(",", " ")
        self.write_log(f"■ Scan terminé : {msg}")
        self.finish(job, status, msg, self._summary(job))

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
            "threats": job.threats[-50:], "auto": job.auto,
        }

    def _record_scan(self, job, status):
        duration = time.time() - (job.started_at or time.time())
        entry = {
            "date": now_iso(), "path": job.path, "files": job.total,
            "infected": job.infected, "duration": round(duration),
            "status": status, "source": "daemon", "auto": job.auto,
        }
        self.state.update(last_scan=entry["date"], last_scan_path=job.path,
                          last_scan_infected=job.infected, last_scan_files=job.total,
                          last_scan_duration=round(duration), last_scan_status=status)
        self.state.add_history(entry)
        if job.auto and os.path.exists(FIRST_SCAN_FLAG):
            try:
                os.remove(FIRST_SCAN_FLAG)
            except OSError:
                pass
            self.state.update(first_scan_done=entry["date"])

    # ── Mise à jour des signatures ───────────────────────────────────────
    def run_update(self, job):
        job.phase = "updating"
        self.emit_progress(job)
        self.write_log("▶ Mise à jour des signatures")
        self.emit_line("info", "→ Arrêt temporaire du service clamav-freshclam…")
        subprocess.run(["systemctl", "stop", "clamav-freshclam"],
                       capture_output=True, timeout=60)
        try:
            self.emit_line("info", "→ Téléchargement des signatures…")
            with job.proc_lock:
                job.proc = subprocess.Popen(["freshclam", "--stdout"],
                                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                            text=True, bufsize=1)
            for raw in job.proc.stdout:
                line = raw.strip()
                if line:
                    self.emit_line("info", line)
            rc = job.proc.wait()
        finally:
            self.emit_line("info", "→ Redémarrage du service clamav-freshclam…")
            subprocess.run(["systemctl", "start", "clamav-freshclam"],
                           capture_output=True, timeout=60)

        if job.cancel_event.is_set():
            self.finish(job, "cancelled", "Mise à jour annulée")
            return
        db = db_last_update()
        if rc == 0:
            self.state.update(last_update=now_iso(), last_update_status="success",
                              last_update_db=db.isoformat(timespec="seconds") if db else None)
            self.write_log("■ Signatures à jour")
            self.finish(job, "success", "Base de données virale à jour",
                        {"db_files": db_files_info()})
        else:
            self.state.update(last_update_attempt=now_iso(), last_update_status="error")
            self.write_log(f"■ Échec de la mise à jour (code {rc})")
            self.finish(job, "error", f"Erreur de mise à jour freshclam (code {rc})")

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
        while not self.shutdown.is_set():
            try:
                self.check_first_scan()
            except Exception as e:
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
        return {
            "ok": True, "version": VERSION, "job": job, "queue": queue,
            "state": self.state.snapshot(), "resumable": resumable,
            "first_scan_pending": os.path.exists(FIRST_SCAN_FLAG),
            "db_last_update": db.isoformat(timespec="seconds") if db else None,
            "db_files": db_files_info(),
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
                return {"ok": False, "error": f"Répertoire introuvable : {path}"}
            if not self._scan_path_allowed(path, uid):
                return {"ok": False, "error": "Chemin non autorisé pour le service", "forbidden": True}
            with self.queue_lock:
                if self.current or self.queue:
                    busy = (self.current or self.queue[0]).public()
                    return {"ok": False, "error": "Une opération est déjà en cours", "busy": busy}
            job = self.enqueue(Job("scan", path=os.path.normpath(path),
                                   resume=bool(req.get("resume")), requested_by=uid))
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
            return {"ok": False, "error": "Aucune opération en cours"}

        if cmd == "quarantine_list":
            return {"ok": True, "files": self.quarantine_list()}

        if cmd == "quarantine_delete":
            p = req.get("path", "")
            if not self._in_quarantine(p):
                return {"ok": False, "error": "Chemin non autorisé"}
            os.remove(p)
            self.write_log(f"Quarantaine : suppression de {os.path.basename(p)}")
            return {"ok": True, "message": f"Fichier supprimé : {os.path.basename(p)}"}

        if cmd == "quarantine_restore":
            p, dest = req.get("path", ""), req.get("dest", "")
            if not self._in_quarantine(p):
                return {"ok": False, "error": "Chemin non autorisé"}
            if not (os.path.isabs(dest) and os.path.isdir(dest) and self._dest_allowed(dest, uid)):
                return {"ok": False, "error": "Destination non autorisée (choisissez un dossier de votre répertoire personnel)"}
            target = os.path.join(dest, os.path.basename(p))
            shutil.move(p, target)
            if uid:
                try:
                    pw = pwd.getpwuid(uid)
                    os.chown(target, pw.pw_uid, pw.pw_gid)
                except (KeyError, OSError):
                    pass
            self.write_log(f"Quarantaine : restauration de {os.path.basename(p)} vers {dest}")
            return {"ok": True, "message": f"Fichier restauré : {os.path.basename(p)}"}

        if cmd == "quarantine_empty":
            count = 0
            for f in Path(SYSTEM_QUARANTINE_DIR).iterdir():
                if f.is_file() and not f.name.startswith(".clamav-quarantine-lock"):
                    f.unlink()
                    count += 1
            self.write_log(f"Quarantaine : vidée ({count} fichier(s))")
            return {"ok": True, "message": f"Quarantaine système vidée — {count} fichier(s) supprimé(s)"}

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

        return {"ok": False, "error": f"Commande inconnue : {cmd}"}

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
            except Exception as e:
                resp = {"ok": False, "error": str(e)}
            conn.send(resp)
        except (OSError, ValueError, socket.timeout) as e:
            log(f"Connexion : {e}")
        finally:
            with self.sub_lock:
                if conn not in self.subscribers:
                    conn.close()

    # ── Serveur ──────────────────────────────────────────────────────────
    def serve(self):
        for d in (SYSTEM_STATE_DIR, SYSTEM_LOG_DIR, SYSTEM_QUARANTINE_DIR, os.path.dirname(DAEMON_SOCKET)):
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

        log(f"ClamAV Antivirus daemon v{VERSION} à l'écoute sur {DAEMON_SOCKET}")
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

    # S'abonner avant de lancer pour ne rater aucun événement
    try:
        sub = daemon_connect(timeout=None)
        sub.send({"cmd": "subscribe"})
        sub.recv()
    except OSError as e:
        print(f"Service indisponible ({e})", flush=True)
        if kind == "update" and os.geteuid() == 0:
            print("Exécution directe de freshclam.", flush=True)
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
        print(f"Refusé : {resp.get('error')}", flush=True)
        return 1
    job_id = resp.get("job_id")
    if resp.get("queued"):
        print(f"Demande {kind} mise en file d'attente (job {job_id}) derrière l'opération en cours.", flush=True)
        return 0

    last_pct = -1
    while True:
        ev = sub.recv()
        if ev is None:
            print("Connexion au daemon perdue", flush=True)
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
