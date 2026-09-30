#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════
# CLAMAV ANTIVIRUS — Build .deb package
# Usage: ./build-deb.sh
# Output: clamav-antivirus_<VERSION>_all.deb
# ═══════════════════════════════════════════════════════════════════════════

set -e

APP_NAME="clamav-antivirus"
VERSION="1.20.2"
ARCH="all"
PKG_DIR="${APP_NAME}_${VERSION}_${ARCH}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "══════════════════════════════════════════"
echo "  Building ${APP_NAME} v${VERSION} .deb"
echo "══════════════════════════════════════════"

# ── Clean previous builds ──
rm -rf "$PKG_DIR" "${PKG_DIR}.deb"

# ── Create directory structure ──
echo "[1/5] Creating package structure..."
mkdir -p "${PKG_DIR}/DEBIAN"
mkdir -p "${PKG_DIR}/opt/${APP_NAME}/ui"
mkdir -p "${PKG_DIR}/opt/${APP_NAME}/icons"
mkdir -p "${PKG_DIR}/usr/share/applications"
mkdir -p "${PKG_DIR}/usr/share/nemo/actions"
mkdir -p "${PKG_DIR}/etc/xdg/autostart"
mkdir -p "${PKG_DIR}/lib/systemd/system"
mkdir -p "${PKG_DIR}/lib/udev/rules.d"
mkdir -p "${PKG_DIR}/opt/${APP_NAME}/keys"
mkdir -p "${PKG_DIR}/usr/share/polkit-1/actions"

# ── Copy application files ──
echo "[2/5] Copying application files..."
cp "${SCRIPT_DIR}/clamav-antivirus.py"             "${PKG_DIR}/opt/${APP_NAME}/"
cp "${SCRIPT_DIR}/clamav-antivirus-daemon.py"      "${PKG_DIR}/opt/${APP_NAME}/"
cp "${SCRIPT_DIR}/clamav_common.py"                "${PKG_DIR}/opt/${APP_NAME}/"
cp "${SCRIPT_DIR}/clamav_backup.py"                "${PKG_DIR}/opt/${APP_NAME}/"
cp "${SCRIPT_DIR}/clamav_extras.py"                "${PKG_DIR}/opt/${APP_NAME}/"
cp "${SCRIPT_DIR}/clamav_harden.py"                "${PKG_DIR}/opt/${APP_NAME}/"
cp "${SCRIPT_DIR}/clamav-antivirus-tray"           "${PKG_DIR}/opt/${APP_NAME}/"
cp "${SCRIPT_DIR}/clamav-scan-nemo.sh"             "${PKG_DIR}/opt/${APP_NAME}/"
cp "${SCRIPT_DIR}/systemd/"*.service               "${PKG_DIR}/lib/systemd/system/"
cp "${SCRIPT_DIR}/systemd/"*.timer                 "${PKG_DIR}/lib/systemd/system/"
cp "${SCRIPT_DIR}/ui/index.html"                    "${PKG_DIR}/opt/${APP_NAME}/ui/"
cp "${SCRIPT_DIR}/ui/style.css"                     "${PKG_DIR}/opt/${APP_NAME}/ui/"
cp "${SCRIPT_DIR}/ui/app.js"                        "${PKG_DIR}/opt/${APP_NAME}/ui/"
cp "${SCRIPT_DIR}/ui/i18n.js"                       "${PKG_DIR}/opt/${APP_NAME}/ui/"
cp "${SCRIPT_DIR}/ui/awareness.js"                  "${PKG_DIR}/opt/${APP_NAME}/ui/"
cp "${SCRIPT_DIR}/udev/"*.rules                     "${PKG_DIR}/lib/udev/rules.d/"
cp "${SCRIPT_DIR}/clamav-antivirus-unlock"          "${PKG_DIR}/opt/${APP_NAME}/"
cp "${SCRIPT_DIR}/keys/dukiwi-clamav.gpg"           "${PKG_DIR}/opt/${APP_NAME}/keys/"
cp "${SCRIPT_DIR}/keys/dukiwi-clamav.asc"           "${PKG_DIR}/opt/${APP_NAME}/keys/"
cp "${SCRIPT_DIR}/polkit/"*.policy                  "${PKG_DIR}/usr/share/polkit-1/actions/"
cp "${SCRIPT_DIR}/icons/"*.svg                      "${PKG_DIR}/opt/${APP_NAME}/icons/"
cp "${SCRIPT_DIR}/clamav-antivirus.desktop"         "${PKG_DIR}/usr/share/applications/"
cp "${SCRIPT_DIR}/clamav-antivirus-nemo.nemo_action" "${PKG_DIR}/usr/share/nemo/actions/"
cp "${SCRIPT_DIR}/clamav-antivirus-autostart.desktop" "${PKG_DIR}/etc/xdg/autostart/"

# Normalize permissions (independent of the builder's umask), then mark scripts executable
find "${PKG_DIR}" -type d -exec chmod 755 {} +
find "${PKG_DIR}" -type f -exec chmod 644 {} +
chmod +x "${PKG_DIR}/opt/${APP_NAME}/clamav-antivirus.py"
chmod +x "${PKG_DIR}/opt/${APP_NAME}/clamav-antivirus-daemon.py"
chmod +x "${PKG_DIR}/opt/${APP_NAME}/clamav-antivirus-unlock"
chmod +x "${PKG_DIR}/opt/${APP_NAME}/clamav-antivirus-tray"
chmod +x "${PKG_DIR}/opt/${APP_NAME}/clamav-scan-nemo.sh"

# ── Integrity manifest (sha256 of every packaged file), signed with the Dukiwi key if present ──
echo "[2b/5] Writing integrity manifest..."
REPO_KEYS="${REPO_KEYS:-$HOME/GITHUB/repo/keys/gnupg}"
python3 - "${PKG_DIR}" "${VERSION}" << 'PY'
import hashlib, json, os, sys, datetime
root, version = sys.argv[1], sys.argv[2]
files = {}
for dp, _, fns in os.walk(root):
    if os.path.relpath(dp, root).startswith("DEBIAN"):
        continue
    for fn in fns:
        full = os.path.join(dp, fn)
        rel = os.path.relpath(full, root)
        if os.path.islink(full) or rel in ("opt/clamav-antivirus/integrity.json", "opt/clamav-antivirus/integrity.json.sig"):
            continue
        h = hashlib.sha256()
        with open(full, "rb") as f:
            h.update(f.read())
        files[rel] = h.hexdigest()
with open(os.path.join(root, "opt/clamav-antivirus/integrity.json"), "w") as f:
    json.dump({"version": version, "date": datetime.datetime.now().isoformat(timespec="seconds"),
               "files": dict(sorted(files.items()))}, f, indent=2)
print(f"  {len(files)} fichiers")
PY
if [ -d "${REPO_KEYS}" ]; then
    GNUPGHOME="${REPO_KEYS}" gpg --batch --yes --detach-sign \
        -o "${PKG_DIR}/opt/${APP_NAME}/integrity.json.sig" "${PKG_DIR}/opt/${APP_NAME}/integrity.json" \
        && echo "  integrity.json signé (clé Dukiwi)"
else
    echo "  (clé privée absente : integrity.json non signé)"
fi

# ── Create DEBIAN/control ──
echo "[3/5] Writing package metadata..."
cat > "${PKG_DIR}/DEBIAN/control" << EOF
Package: ${APP_NAME}
Version: ${VERSION}
Section: utils
Priority: optional
Architecture: ${ARCH}
Depends: python3 (>= 3.8), python3-gi, python3-pyudev, python3-apt, gir1.2-webkit2-4.1, gir1.2-appindicator3-0.1, gir1.2-gtk-3.0, policykit-1, clamav, clamav-daemon, clamav-freshclam, lynis, unhide, chkrootkit, debsums, msmtp-mta | mail-transport-agent, zenity, systemd, udev, udisks2
Recommends: libnotify-bin, mintupdate | update-manager, timeshift, rclone, rsync, gocryptfs, flatpak
Maintainer: Dukiwi SA <info@dukiwi.ch>
Homepage: https://dukiwi.ch
Description: ClamAV Antivirus GUI - Interface graphique ClamAV
 Interface graphique moderne pour ClamAV avec :
 - Service système : scan complet et mises à jour sans mot de passe
 - Mises à jour planifiées tous les jours à 07:00 et 5 min après le démarrage
 - Scan complet automatique après la première installation
 - Surveillance des rafales d'écritures (fanotify) et alerte "danger potentiel"
 - Analyse des clés USB avant leur mise à disposition (question pour les disques)
 - État du système : mises à jour de sécurité en attente et CVE associées
 - Popups glissants en bas à droite, interface en français, anglais, allemand, italien
 - Vue simple rassurante et vue avancée, page Paramètres (seuils, USB, planification)
 - Pare-feu UFW et SSH pilotés depuis l'application, surveillance du volume envoyé
 - Scan rapide de répertoires avec progression détaillée
 - Quarantaine automatique des fichiers infectés
 - Icône bouclier dans la barre des tâches
 - Intégration Nemo (clic droit : Scan with ClamAV Antivirus GUI)
 - Interface HTML/CSS facilement personnalisable
 .
 Développé par Dukiwi SA, Estavayer-le-Lac, Suisse.
EOF

# ── Create DEBIAN/postinst (post-installation script) ──
cat > "${PKG_DIR}/DEBIAN/postinst" << 'EOF'
#!/bin/bash
set -e

STATE_DIR=/var/lib/clamav-antivirus

# Enable and start freshclam service
systemctl enable clamav-freshclam 2>/dev/null || true
systemctl start clamav-freshclam 2>/dev/null || true

# Service système + planification des mises à jour (07:00 et 5 min après le démarrage)
mkdir -p "$STATE_DIR"
FIRST_INSTALL=0
if [ "$1" = "configure" ] && [ ! -f "$STATE_DIR/state.json" ]; then
    # Première installation du service : scan complet automatique au démarrage du daemon
    touch "$STATE_DIR/first-scan-pending"
    FIRST_INSTALL=1
fi

systemctl daemon-reload 2>/dev/null || true
udevadm control --reload-rules 2>/dev/null || true
systemctl enable clamav-antivirus-daemon.service 2>/dev/null || true
systemctl enable clamav-antivirus-update.timer 2>/dev/null || true
systemctl restart clamav-antivirus-daemon.service 2>/dev/null || true
systemctl start clamav-antivirus-update.timer 2>/dev/null || true

# Relancer les GUI ouvertes pour charger la nouvelle version : le service utilisateur (Restart=always) ou la
# surveillance du service root relancent le bouclier dans chaque session graphique active
pkill -f "/opt/clamav-antivirus/clamav-antivirus.py" 2>/dev/null || true

# Update desktop database
if command -v update-desktop-database &> /dev/null; then
    update-desktop-database /usr/share/applications/ 2>/dev/null || true
fi

echo ""
echo "═══════════════════════════════════════════════════"
echo "  ✅ ClamAV Antivirus GUI installé avec succès !"
echo ""
echo "  Lancez-le depuis le menu Applications > Système"
echo "  ou via: /opt/clamav-antivirus/clamav-antivirus.py"
echo ""
echo "  Service système : clamav-antivirus-daemon (actif)"
echo "  Mises à jour    : tous les jours à 07:00 et"
echo "                    5 minutes après le démarrage"
echo "  Surveillance    : écritures (fanotify), clés USB (udev)"
if [ "$FIRST_INSTALL" = "1" ]; then
echo "  Scan initial    : un scan complet du système va"
echo "                    démarrer automatiquement."
fi
echo "═══════════════════════════════════════════════════"
echo ""

exit 0
EOF
chmod 755 "${PKG_DIR}/DEBIAN/postinst"

# ── Create DEBIAN/prerm (pre-removal script) ──
cat > "${PKG_DIR}/DEBIAN/prerm" << 'EOF'
#!/bin/bash
set -e
# Kill running instances
pkill -f "/opt/clamav-antivirus/clamav-antivirus.py" 2>/dev/null || true
if [ "$1" = "remove" ]; then
    systemctl stop clamav-antivirus-update.timer 2>/dev/null || true
    systemctl disable clamav-antivirus-update.timer 2>/dev/null || true
    systemctl stop clamav-antivirus-daemon.service 2>/dev/null || true
    systemctl disable clamav-antivirus-daemon.service 2>/dev/null || true
fi
exit 0
EOF
chmod 755 "${PKG_DIR}/DEBIAN/prerm"

# ── Create DEBIAN/postrm (post-removal script) ──
cat > "${PKG_DIR}/DEBIAN/postrm" << 'EOF'
#!/bin/bash
set -e
systemctl daemon-reload 2>/dev/null || true
udevadm control --reload-rules 2>/dev/null || true
if [ "$1" = "purge" ]; then
    rm -rf /var/lib/clamav-antivirus /var/log/clamav-antivirus /run/clamav-antivirus
fi
exit 0
EOF
chmod 755 "${PKG_DIR}/DEBIAN/postrm"

# ── Build the .deb ──
echo "[4/5] Building .deb package..."
dpkg-deb --build --root-owner-group "${PKG_DIR}"

# ── Verify ──
echo "[5/5] Verifying package..."
dpkg-deb --info "${PKG_DIR}.deb"
echo ""

# ── Clean build dir ──
rm -rf "${PKG_DIR}"

SIZE=$(du -h "${PKG_DIR}.deb" | cut -f1)
echo "══════════════════════════════════════════"
echo "  ✅ Package built: ${PKG_DIR}.deb (${SIZE})"
echo ""
echo "  Install:   sudo dpkg -i ${PKG_DIR}.deb"
echo "  Fix deps:  sudo apt-get install -f"
echo "  Remove:    sudo dpkg -r ${APP_NAME}"
echo "══════════════════════════════════════════"
