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
- **Détection comportementale** — le service surveille (fanotify) les programmes qui
  modifient beaucoup de fichiers en peu de temps : popup d'information (même pour le
  système), ou **danger potentiel** si le programme est inconnu du système (hors paquet
  dpkg, lancé depuis /tmp ou le home) ou si `clamd` reconnaît son exécutable / ses fichiers.
- **Clés USB** — analysées **avant** leur mise à disposition (règle udev + montage privé par
  le service), popup de progression, puis montage et ouverture automatiques. Les disques
  durs USB (> 128 Gio) déclenchent une **question** « analyser ou non ».
- **État du système** — mises à jour de sécurité en attente et **CVE** qu'elles corrigent
  (extraites des changelogs apt), redémarrage requis, bouton vers le gestionnaire de
  mises à jour, historique des alertes.
- **Popups glissants** — en bas à droite, ils sortent de derrière la barre des tâches :
  signatures à jour, scan terminé sans menace, menaces, activité inhabituelle, USB.
- **Quatre langues** — français, anglais, allemand, italien (détection de la locale,
  sélecteur dans la barre latérale).
- **Vue simple / vue avancée** — la vue simple (par défaut) tient dans la fenêtre sans
  défilement et rassure un non-initié : « Votre système est protégé », six voyants
  (antivirus, surveillance, pare-feu, accès à distance, mises à jour, menaces) avec un
  bouton de correction quand quelque chose cloche. La vue avancée expose tous les onglets.
- **Paramètres** — seuil d'envoi Internet déclenchant un popup (5 Go par défaut, fenêtre
  d'observation réglable), seuils de détection comportementale, USB, heure de la recherche
  de mises à jour, scan complet hebdomadaire, popups à afficher, langue et vue. Les réglages
  système sont appliqués par le service, sans mot de passe.
- **Pare-feu et SSH** — état d'UFW (politiques, règles) et du service SSH, activation ou
  désactivation, règles simples (port, protocole, action) et politiques par défaut, le tout
  via le service. L'accès à distance est signalé s'il est actif.
- **Envoi Internet** — le service mesure le volume envoyé (`/proc/net/dev`) et affiche un
  popup au-delà du seuil, avec la liste des programmes connectés (`ss`).
- **Scan moderne** — anneau de progression, étapes (inventaire → analyse), fichiers/s,
  temps restant estimé, menaces en direct, annulation et reprise, résumé de fin,
  historique des analyses.
- **Scan rapide** — `/home`, `/etc`, `/var`, `/opt`, `/usr`, `/tmp` ou un dossier choisi
  via le sélecteur natif.
- **Quarantaine** — fichiers infectés isolés (quarantaine système et quarantaine utilisateur).
- **Bouclier tray** — Icône dans la barre des tâches avec 3 états :
  - 🟢 **Vert** : Protégé, bases à jour
  - 🔵 **Bleu** : Protégé, mise à jour recommandée
  - 🔴 **Rouge** : Non protégé, MàJ > 2 jours
- **Interface HTML/CSS** — Facilement modifiable (fichiers dans `ui/`)

## Téléchargement

[Télécharger clamav-antivirus_1.6.0_all.deb](https://www.dukiwi.com/repo/clamav-antivirus/clamav-antivirus_1.6.0_all.deb)

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

Résultat : `clamav-antivirus_1.6.0_all.deb`

### Installer le .deb

```bash
sudo dpkg -i clamav-antivirus_1.6.0_all.deb
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
système (`/home`, `/etc`, `/var`, `/opt`, `/usr`, `/tmp`, `/boot`, `/root`, `/srv`), des
supports montés sous `/media` et `/mnt`, ainsi que de tout dossier situé dans le répertoire
personnel du demandeur (identifié via `SO_PEERCRED`). Les autres chemins sont analysés
localement avec les droits de l'utilisateur.

| Fichier                                  | Rôle                                                              |
|------------------------------------------|-------------------------------------------------------------------|
| `/lib/udev/rules.d/80-clamav-antivirus-usb.rules` | Désactive le montage automatique udisks des périphériques USB **uniquement** quand le socket du service existe |
| `ui/i18n.js`                             | Traductions FR/EN/DE/IT (JSON) partagées par la page et Python    |

Réglages système (page Paramètres, fichier `/var/lib/clamav-antivirus/settings.json`,
valeurs par défaut dans `DEFAULT_SETTINGS` de `clamav_common.py`) : seuil et fenêtre d'envoi
Internet (5 Go / 1 h), seuils de rafale (50 fichiers info, 25 fichiers du home pour un
programme non fiable, fenêtre 15 s), scan USB automatique et taille limite (128 Gio), heure
de la recherche de MàJ (07:00, appliquée via un drop-in systemd), scan hebdomadaire.

Les commandes pare-feu/SSH du socket (`firewall_set`, `firewall_defaults`,
`firewall_rule_add`, `firewall_rule_delete`, `ssh_set`) sont acceptées de tout utilisateur
local réel (uid ≥ 1000) : c'est voulu (« sans root »), mais à connaître sur une machine
multi-utilisateurs.

Fichiers du service : état et quarantaine dans `/var/lib/clamav-antivirus/`, journal dans
`/var/log/clamav-antivirus/scan.log`.

Client en ligne de commande (diagnostic) :

```bash
/opt/clamav-antivirus/clamav-antivirus-daemon.py --request status
/opt/clamav-antivirus/clamav-antivirus-daemon.py --request scan /home
/opt/clamav-antivirus/clamav-antivirus-daemon.py --request update
/opt/clamav-antivirus/clamav-antivirus-daemon.py --request system-status
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
├── udev/80-clamav-antivirus-usb.rules # Analyse des clés USB avant montage
├── ui/
│   ├── index.html                   # Interface HTML
│   ├── style.css                    # Thème CSS (variables modifiables)
│   ├── app.js                       # Logique JS frontend
│   └── i18n.js                      # Traductions FR/EN/DE/IT
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
