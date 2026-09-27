# 🛡️ ClamAV Antivirus

Interface graphique moderne pour **ClamAV** sur Linux Mint.
Développé par **Dukiwi SA** — Estavayer-le-Lac, Suisse.

![Interface ClamAV Antivirus](https://www.dukiwi.com/imgs/clamav-antivirus.png)

---

## Fonctionnalités

- **Service système** (`clamav-antivirus-daemon`) — tourne en permanence en root et exécute
  les scans complets et les mises à jour à la demande d'un utilisateur **sans droits admin**,
  donc **sans mot de passe**. Si le service est absent, l'application demande le mot de passe
  administrateur (`pkexec`).
- **Mises à jour planifiées** — recherche de signatures **tous les jours à 07:00** et
  **5 minutes après chaque démarrage** (timer systemd, rattrapage si l'ordinateur était éteint).
- **Scan initial automatique** — un scan complet du système démarre tout seul après la
  première installation (repris automatiquement s'il est interrompu par un arrêt).
- **Scan moderne** — anneau de progression, étapes (inventaire → analyse), fichiers/s,
  temps restant estimé, menaces en direct, annulation et reprise, résumé de fin,
  historique des analyses, notifications bureau.
- **Scan rapide** — `/home`, `/etc`, `/var`, `/opt`, `/usr`, `/tmp` ou un dossier choisi
  via le sélecteur natif.
- **Quarantaine** — fichiers infectés isolés (quarantaine système et quarantaine utilisateur).
- **Bouclier tray** — Icône dans la barre des tâches avec 3 états :
  - 🟢 **Vert** : Protégé, bases à jour
  - 🔵 **Bleu** : Protégé, mise à jour recommandée
  - 🔴 **Rouge** : Non protégé, MàJ > 2 jours
- **Interface HTML/CSS** — Facilement modifiable (fichiers dans `ui/`)

## Téléchargement

[Télécharger clamav-antivirus_1.4.0_all.deb](https://www.dukiwi.com/repo/clamav-antivirus/clamav-antivirus_1.4.0_all.deb)

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

Résultat : `clamav-antivirus_1.4.0_all.deb`

### Installer le .deb

```bash
sudo dpkg -i clamav-antivirus_1.4.0_all.deb
sudo apt-get install -f   # résout les dépendances si nécessaire
```

L'installation active le service système et le planificateur, puis lance le scan initial :

```bash
systemctl status clamav-antivirus-daemon      # service (root)
systemctl list-timers clamav-antivirus-update # prochaine recherche de MàJ
journalctl -u clamav-antivirus-daemon -f      # suivre le scan initial
```

### Désinstaller

```bash
sudo dpkg -r clamav-antivirus
```

---

## Service système et planification

| Unité systemd                      | Rôle                                                                 |
|------------------------------------|----------------------------------------------------------------------|
| `clamav-antivirus-daemon.service`  | Daemon root, socket `/run/clamav-antivirus/daemon.sock` (mode 0666)   |
| `clamav-antivirus-update.timer`    | `OnCalendar=07:00` + `OnBootSec=5min` + `Persistent=true`             |
| `clamav-antivirus-update.service`  | Oneshot : demande la mise à jour au daemon (`--request update`)       |

Le daemon accepte, de n'importe quel utilisateur local, un scan de `/` et des répertoires
système (`/home`, `/etc`, `/var`, `/opt`, `/usr`, `/tmp`, `/boot`, `/root`, `/srv`) ainsi que
de tout dossier situé dans le répertoire personnel du demandeur (identifié via `SO_PEERCRED`).
Les autres chemins sont analysés localement avec les droits de l'utilisateur.

Fichiers du service : état et quarantaine dans `/var/lib/clamav-antivirus/`, journal dans
`/var/log/clamav-antivirus/scan.log`.

Client en ligne de commande (diagnostic) :

```bash
/opt/clamav-antivirus/clamav-antivirus-daemon.py --request status
/opt/clamav-antivirus/clamav-antivirus-daemon.py --request scan /home
/opt/clamav-antivirus/clamav-antivirus-daemon.py --request update
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
├── clamav-antivirus-daemon.py       # Service système root (socket Unix) + client --request
├── clamav_common.py                 # Chemins, exclusions, protocole partagés
├── systemd/
│   ├── clamav-antivirus-daemon.service
│   ├── clamav-antivirus-update.service
│   └── clamav-antivirus-update.timer # 07:00 quotidien + 5 min après le boot
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
