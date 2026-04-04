#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════
# CLAMAV ANTIVIRUS — Build .deb package
# Usage: ./build-deb.sh
# Output: clamav-antivirus_1.0.0_all.deb
# ═══════════════════════════════════════════════════════════════════════════

set -e

APP_NAME="clamav-antivirus"
VERSION="1.3.1"
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

# ── Copy application files ──
echo "[2/5] Copying application files..."
cp "${SCRIPT_DIR}/clamav-antivirus.py"             "${PKG_DIR}/opt/${APP_NAME}/"
cp "${SCRIPT_DIR}/clamav-scan-nemo.sh"             "${PKG_DIR}/opt/${APP_NAME}/"
cp "${SCRIPT_DIR}/ui/index.html"                    "${PKG_DIR}/opt/${APP_NAME}/ui/"
cp "${SCRIPT_DIR}/ui/style.css"                     "${PKG_DIR}/opt/${APP_NAME}/ui/"
cp "${SCRIPT_DIR}/ui/app.js"                        "${PKG_DIR}/opt/${APP_NAME}/ui/"
cp "${SCRIPT_DIR}/icons/"*.svg                      "${PKG_DIR}/opt/${APP_NAME}/icons/"
cp "${SCRIPT_DIR}/clamav-antivirus.desktop"         "${PKG_DIR}/usr/share/applications/"
cp "${SCRIPT_DIR}/clamav-antivirus-nemo.nemo_action" "${PKG_DIR}/usr/share/nemo/actions/"
cp "${SCRIPT_DIR}/clamav-antivirus-autostart.desktop" "${PKG_DIR}/etc/xdg/autostart/"

# Make scripts executable
chmod +x "${PKG_DIR}/opt/${APP_NAME}/clamav-antivirus.py"
chmod +x "${PKG_DIR}/opt/${APP_NAME}/clamav-scan-nemo.sh"

# ── Create DEBIAN/control ──
echo "[3/5] Writing package metadata..."
cat > "${PKG_DIR}/DEBIAN/control" << EOF
Package: ${APP_NAME}
Version: ${VERSION}
Section: utils
Priority: optional
Architecture: ${ARCH}
Depends: python3 (>= 3.8), python3-gi, gir1.2-webkit2-4.1, gir1.2-appindicator3-0.1, gir1.2-gtk-3.0, policykit-1, clamav, clamav-daemon, clamav-freshclam, zenity
Maintainer: Dukiwi SA <info@dukiwi.ch>
Homepage: https://dukiwi.ch
Description: ClamAV Antivirus - Interface graphique ClamAV
 Interface graphique moderne pour ClamAV avec :
 - Gestion des mises à jour des bases virales (freshclam)
 - Scan rapide de répertoires et scan complet du système
 - Quarantaine automatique des fichiers infectés
 - Icône bouclier dans la barre des tâches
 - Intégration Nemo (clic droit : Scan with ClamAV Antivirus)
 - Interface HTML/CSS facilement personnalisable
 .
 Développé par Dukiwi SA, Estavayer-le-Lac, Suisse.
EOF

# ── Create DEBIAN/postinst (post-installation script) ──
cat > "${PKG_DIR}/DEBIAN/postinst" << 'EOF'
#!/bin/bash
set -e

# Enable and start freshclam service
systemctl enable clamav-freshclam 2>/dev/null || true
systemctl start clamav-freshclam 2>/dev/null || true

# Update desktop database
if command -v update-desktop-database &> /dev/null; then
    update-desktop-database /usr/share/applications/ 2>/dev/null || true
fi

echo ""
echo "═══════════════════════════════════════════════════"
echo "  ✅ ClamAV Antivirus installé avec succès !"
echo ""
echo "  Lancez-le depuis le menu Applications > Système"
echo "  ou via: /opt/clamav-antivirus/clamav-antivirus.py"
echo ""
echo "  freshclam est activé et mettra à jour les bases"
echo "  automatiquement en arrière-plan."
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
pkill -f "clamav-antivirus.py" 2>/dev/null || true
exit 0
EOF
chmod 755 "${PKG_DIR}/DEBIAN/prerm"

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
