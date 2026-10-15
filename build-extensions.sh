#!/bin/bash
# Construit les extensions « Contrôle des liens » (Firefox, Chrome/Chromium/Edge/Brave) et « Protection des courriels »
# (Thunderbird) dans dist/extensions/ :
#   urlguard-chromium/  urlguard-firefox/  mailguard-thunderbird/   (dossiers décompressés, installables à la main)
#   clamav-antivirus-urlguard-firefox.xpi  clamav-antivirus-mailguard.xpi  clamav-antivirus-urlguard-chromium.zip
#   clamav-antivirus-urlguard-<version>.crx + urlguard-update.xml      (si Google Chrome est installé : empaquetage CRX)
#   manifest-info.json (identifiant Chrome dérivé de la clé, identifiants Gecko, URL de mise à jour)
# La clé privée Chrome (chrome-extension.pem) vit dans ../repo/keys/ (jamais dans git) ; générée si absente.
# Usage : ./build-extensions.sh [--quiet]
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VERSION="$(sed -n 's/^VERSION="\(.*\)"/\1/p' "$SCRIPT_DIR/build-deb.sh" | head -1)"
OUT="$SCRIPT_DIR/dist/extensions"
KEY="${CLAMAV_EXT_KEY:-$SCRIPT_DIR/../repo/keys/chrome-extension.pem}"
UPDATE_URL="${CLAMAV_EXT_UPDATE_URL:-https://www.dukiwi.com/repo/extensions/urlguard-update.xml}"
CRX_BASE="${CLAMAV_EXT_CRX_BASE:-https://www.dukiwi.com/repo/extensions}"
QUIET="${1:-}"
say() { [ "$QUIET" = "--quiet" ] || echo "$@"; }

rm -rf "$OUT"
mkdir -p "$OUT"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# ── Clé Chrome : identifiant stable de l'extension (manifest "key") et signature du CRX ──
if [ ! -f "$KEY" ]; then
    mkdir -p "$(dirname "$KEY")"
    openssl genrsa -out "$KEY" 2048 2>/dev/null
    chmod 600 "$KEY"
    say "  clé Chrome générée : $KEY"
fi
PUB_DER="$TMP/pub.der"
openssl rsa -in "$KEY" -pubout -outform DER -out "$PUB_DER" 2>/dev/null
PUB_B64="$(base64 -w0 "$PUB_DER")"
CHROME_ID="$(sha256sum "$PUB_DER" | head -c 32 | tr '0-9a-f' 'a-p')"

# ── Icônes PNG : bouclier vert avec coche (PIL), aux tailles des manifestes ──
mkdir -p "$TMP/icons"
python3 - "$TMP/icons" <<'PY'
import sys
from PIL import Image, ImageDraw
out = sys.argv[1]
for s in (16, 32, 48, 128):
    k = 8                                        # suréchantillonnage pour des bords lisses
    S = s * k
    im = Image.new("RGBA", (S, S), (0, 0, 0, 0)); d = ImageDraw.Draw(im)
    pts = [(S*0.5, S*0.03), (S*0.93, S*0.18), (S*0.90, S*0.58), (S*0.5, S*0.97), (S*0.10, S*0.58), (S*0.07, S*0.18)]
    d.polygon(pts, fill=(22, 163, 74, 255))
    d.polygon([(x*0.86 + S*0.07, y*0.86 + S*0.07) for x, y in pts], fill=(34, 197, 94, 255))
    w = max(2, int(S * 0.11))
    d.line([(S*0.30, S*0.50), (S*0.45, S*0.65), (S*0.72, S*0.34)], fill=(255, 255, 255, 255), width=w, joint="curve")
    im.resize((s, s), Image.LANCZOS).save(f"{out}/{s}.png")
PY

build_dir() {   # nom, manifeste, dossiers source…
    local name="$1" manifest="$2"; shift 2
    local dir="$OUT/$name"
    mkdir -p "$dir/icons"
    cp "$SCRIPT_DIR/extensions/common/client.js" "$dir/"
    cp -r "$SCRIPT_DIR/extensions/common/_locales" "$dir/"
    for src in "$@"; do cp -r "$SCRIPT_DIR/extensions/$src"/. "$dir/"; done
    cp "$TMP/icons/"*.png "$dir/icons/"
    python3 - "$SCRIPT_DIR/extensions/manifests/$manifest" "$dir/manifest.json" "$VERSION" "$PUB_B64" <<'PY'
import json, sys
src, dst, version, key = sys.argv[1:5]
text = open(src, encoding="utf-8").read().replace("__VERSION__", version).replace("__KEY__", key)
m = json.loads(text)
with open(dst, "w", encoding="utf-8") as f:
    json.dump(m, f, indent=2, ensure_ascii=False)
PY
}
build_dir urlguard-chromium chromium.json browser
build_dir urlguard-firefox firefox.json browser
build_dir mailguard-thunderbird thunderbird.json thunderbird

# ── Archives : XPI (Firefox, Thunderbird) et ZIP (Chrome, « charger l'extension non empaquetée » ou boutique) ──
(cd "$OUT/urlguard-firefox" && zip -qr -X "$OUT/clamav-antivirus-urlguard-firefox.xpi" .)
(cd "$OUT/mailguard-thunderbird" && zip -qr -X "$OUT/clamav-antivirus-mailguard.xpi" .)
(cd "$OUT/urlguard-chromium" && zip -qr -X "$OUT/clamav-antivirus-urlguard-chromium.zip" .)

# ── CRX signé avec la clé (empaqueteur CRX3 en Python) et update.xml pour l'installation par politique ──
CRX_NAME="clamav-antivirus-urlguard-$VERSION.crx"
CRX_OK=false
if CRX_ID="$(python3 "$SCRIPT_DIR/crx3-pack.py" "$OUT/urlguard-chromium" "$KEY" "$OUT/$CRX_NAME" 2>/dev/null)" && [ -s "$OUT/$CRX_NAME" ]; then
    if [ "$CRX_ID" = "$CHROME_ID" ]; then CRX_OK=true; else echo "  ⚠ identifiant CRX $CRX_ID ≠ $CHROME_ID" >&2; rm -f "$OUT/$CRX_NAME"; fi
fi
cat > "$OUT/urlguard-update.xml" <<EOF
<?xml version='1.0' encoding='UTF-8'?>
<gupdate xmlns='http://www.google.com/update2/response' protocol='2.0'>
  <app appid='$CHROME_ID'>
    <updatecheck codebase='$CRX_BASE/$CRX_NAME' version='$VERSION' />
  </app>
</gupdate>
EOF

cat > "$OUT/manifest-info.json" <<EOF
{
  "version": "$VERSION",
  "chrome_id": "$CHROME_ID",
  "gecko_ids": ["urlguard@clamav-antivirus.dukiwi.com", "mailguard@clamav-antivirus.dukiwi.com"],
  "native_host": "clamav_antivirus",
  "update_url": "$UPDATE_URL",
  "crx": $([ "$CRX_OK" = true ] && echo "\"$CRX_NAME\"" || echo null),
  "firefox_xpi_url": "$CRX_BASE/clamav-antivirus-urlguard-firefox.xpi",
  "thunderbird_xpi": "/opt/clamav-antivirus/extensions/clamav-antivirus-mailguard.xpi"
}
EOF
say "  ✅ Extensions $VERSION : chrome id $CHROME_ID, CRX $([ "$CRX_OK" = true ] && echo oui || echo non) → $OUT"
