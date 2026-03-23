# 🛡️ ClamAV Antivirus

Interface graphique moderne pour **ClamAV** sur Linux Mint.
Développé par **Dukiwi SA** — Estavayer-le-Lac, Suisse.

![Interface ClamAV Antivirus](https://www.dukiwi.com/imgs/clamav-antivirus.png)

---

## Fonctionnalités

- **Mise à jour** — Met à jour les signatures virales via `freshclam`
- **Scan rapide** — Analyse `/home`, `/etc`, `/var`, `/opt`, `/usr`, `/tmp` ou un chemin personnalisé
- **Bouclier tray** — Icône dans la barre des tâches avec 3 états :
  - 🟢 **Vert** : Protégé, bases à jour
  - 🔵 **Bleu** : Protégé, mise à jour recommandée
  - 🔴 **Rouge** : Non protégé, MàJ > 2 jours
- **Interface HTML/CSS** — Facilement modifiable (fichiers dans `ui/`)

## Téléchargement

[Télécharger clamav-antivirus_1.3.0_all.deb](https://www.dukiwi.com/repo/clamav-antivirus/clamav-antivirus_1.3.0_all.deb)

---

## Prérequis

```bash
# Installer les dépendances (Linux Mint 22+)
sudo apt install clamav clamav-daemon clamav-freshclam \
    python3-gi gir1.2-webkit2-4.0 gir1.2-appindicator3-0.1
```

---

## Lancement rapide (sans .deb)

```bash
cd clamav-antivirus/
chmod +x clamav-antivirus.py
python3 clamav-antivirus.py
```

---

## Construire le .deb

```bash
chmod +x build-deb.sh
./build-deb.sh
```

Résultat : `clamav-antivirus_1.3.0_all.deb`

### Installer le .deb

```bash
sudo dpkg -i clamav-antivirus_1.3.0_all.deb
sudo apt-get install -f   # résout les dépendances si nécessaire
```

### Désinstaller

```bash
sudo dpkg -r clamav-antivirus
```

---

## Personnalisation de l'interface

L'interface est en **HTML + CSS + JavaScript** dans le dossier `ui/` :

| Fichier        | Rôle                                     |
|----------------|------------------------------------------|
| `ui/index.html`| Structure HTML de l'interface             |
| `ui/style.css` | Thème visuel — modifiez les variables CSS |
| `ui/app.js`    | Logique frontend                          |

### Variables CSS (début de `style.css`)

```css
:root {
    --bg-primary:       #0a0e17;    /* Fond principal */
    --bg-card:          #1a2234;    /* Fond des cartes */
    --accent:           #22c55e;    /* Couleur accent (vert) */
    --accent-blue:      #3b82f6;    /* Bleu */
    --accent-red:       #ef4444;    /* Rouge */
    --font-body:        'Segoe UI'; /* Police du texte */
    --sidebar-width:    260px;      /* Largeur sidebar */
}
```

---

## Architecture

```
clamav-antivirus/
├── clamav-antivirus.py              # App Python (GTK3 + WebKit2 + AppIndicator)
├── ui/
│   ├── index.html                   # Interface HTML
│   ├── style.css                    # Thème CSS (variables modifiables)
│   └── app.js                       # Logique JS frontend
├── icons/
│   ├── shield-green.svg             # Tray: protégé
│   ├── shield-blue.svg              # Tray: MàJ dispo
│   └── shield-red.svg               # Tray: non protégé
├── clamav-antivirus.desktop         # Entrée menu applications
├── clamav-antivirus-autostart.desktop
├── build-deb.sh                     # Script de build .deb
└── README.md
```

---

## Licence

Ce projet est distribué sous licence **GNU General Public License v3.0** (GPL v3).
Voir le fichier [LICENSE](LICENSE) pour les détails.

© 2026 Dukiwi SA — Estavayer-le-Lac, Suisse.
