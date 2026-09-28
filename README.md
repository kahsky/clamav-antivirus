# 🛡️ ClamAV Antivirus GUI

Interface graphique moderne pour **ClamAV** sur Linux Mint.
Développé par **Dukiwi SA** — Estavayer-le-Lac, Suisse.

![Interface ClamAV Antivirus GUI](https://www.dukiwi.com/imgs/clamav-antivirus.png?v=1.14.4)

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
- **Centre de sécurité** (onglet Sécurité) — score et checklist (pare-feu, SSH, chiffrement
  LUKS, Secure Boot, AppArmor, mises à jour automatiques — bouton « Activer » qui enclenche
  l'automatisation du Gestionnaire de mises à jour de Mint (ou unattended-upgrades) puis les mises à jour
  automatiques des Spices Cinnamon et des Flatpak —, comptes sans mot de passe, sudo
  sans mot de passe, ports exposés, services exposés, `ld.so.preload`, antivirus…), inventaire
  des **failles ouvertes** des paquets installés via OSV.dev (sans correctif / Ubuntu Pro /
  correctif disponible, priorité Ubuntu et vecteur CVSS), mises à jour Flatpak/Snap, vérification
  d'intégrité (Lynis, chkrootkit, debsums, fichiers de l'application vs manifeste signé).
- **Connexions sortantes** — programmes connectés à Internet avec pays/opérateur, alerte pour un
  programme inconnu du système ou une adresse des listes Feodo Tracker / SSLBL. Géolocalisation via
  ip-api.com : service gratuit par défaut (HTTP, 15 requêtes groupées/min, usage non commercial), au plus
  une requête toutes les 5 s, une adresse demandée une fois par 24 h, cache persistant ; une clé
  **ip-api.com Pro** (HTTPS, sans limite) se saisit dans Paramètres. Le nombre de requêtes sur 24 h est
  affiché sous la clé.
- **Persistance** — autostart, unités systemd, cron, `rc.local`, `ld.so.preload`, extensions
  Chrome/Firefox (hors store signalées) ; alerte à chaque nouvelle entrée.
- **Réponse automatique** — un programme jugé dangereux est suspendu (SIGSTOP) et le popup propose
  Terminer / Mettre en quarantaine / Reprendre.
- **Mode famille et verrouillage admin** — désactiver le pare-feu, ouvrir un port, activer SSH,
  installer une mise à jour ou changer les réglages (mode famille) exige l'authentification d'un
  administrateur via polkit (`pkexec`), valable 15 minutes.
- **Bonnes pratiques (security awareness)** — page visible dès la vue simple (« Apprendre à me
  protéger ») avec 18 leçons pour utilisateurs non initiés : ne pas cliquer sans lire, phishing,
  fraude au président, e-mail inhabituel, `salaires.xlsx.exe`, clés USB piégées, virus / ver /
  cheval de Troie / cryptolocker, qu'est-ce qu'une faille, importance des mises à jour, mots de
  passe, sauvegardes, faux support, ingénierie sociale, Wi-Fi public, mot de passe admin, réaction
  à une attaque, extensions. Un **conseil du jour** apparaît en popup au démarrage (bouton
  « Lire plus » ouvre la leçon ; désactivable dans Paramètres). Contenu dans `ui/awareness.js`.
- **Type de réseau (pare-feu)** — Maison, Public ou Entreprise, comme sur Windows. Public : aucune
  connexion entrante. Maison : SSH (s'il est actif), impression CUPS, partage Samba, découverte mDNS et
  KDE Connect autorisés depuis les plages privées (10/8, 172.16/12, 192.168/16, fe80::/10), selon ce qui
  est installé. Entreprise : SSH, CUPS et Samba depuis le sous-réseau actuel seulement, journalisation
  UFW renforcée. Les règles du profil sont taguées `cav-profile` et remplacées à chaque changement ; les
  règles personnelles restent, et en Public l'application signale celles ouvertes à tout Internet.
  Passer en Public ne demande rien ; Maison et Entreprise demandent l'authentification administrateur.
- **Durcissement Lynis applicable d'un clic** — la carte « Durcissement (Lynis) » de l'onglet Sécurité liste
  chaque suggestion de l'audit avec une explication en clair : les recommandations sans risque (paramètres
  sysctl, core dumps, bannières légales, protocoles inutiles, outils d'audit, anciens noyaux, permissions…)
  s'appliquent d'un clic ou toutes ensemble (`clamav_harden.py` : fichiers `90-clamav-antivirus-*`, valeurs
  précédentes retenues pour « Annuler »), celles à lire avant d'appliquer (umask, SSH, TMPDIR) restent
  manuelles, les autres sont expliquées (faux positifs, sans objet sur un poste de travail). Lynis est relancé
  après chaque application ; réglage « appliquer automatiquement après chaque audit » dans les paramètres.
- **Moteur d'analyse rapide** — le service analyse par clamd (base de signatures en mémoire, démarré au besoin)
  avec plusieurs `clamdscan --fdpass` en parallèle (jusqu'à 8 lots de 100 fichiers, 3 pour une clé USB), repli
  `clamscan --file-list` si clamd manque. **Cache des fichiers sains** : l'empreinte (taille, mtime, ctime,
  inode) de chaque fichier analysé sain est gardée dans `scan-cache.db` (SQLite) ; un fichier inchangé n'est
  pas relu pendant `scan_cache_days` jours (30 par défaut, réglable, case « Tout ré-analyser » sur le scan).
  **Clés USB** : un fichier caché `.clamav` (JSON signé HMAC avec un secret propre à l'installation, jamais sur
  la clé) liste les fichiers sains ; à la prochaine insertion, seuls les fichiers nouveaux ou modifiés sont
  lus. **Clé pendant un scan** : le scan en cours est mis en pause (workers suspendus), la clé est analysée
  tout de suite, puis le scan reprend.
- **Profil mémorisé par réseau** — le service identifie le réseau courant (connexion NetworkManager qui porte la
  route par défaut, sinon adresse MAC de la passerelle) et mémorise le profil choisi pour chaque réseau. Un réseau
  inconnu passe toujours en Public (popup « Nouveau réseau », bouton « Changer » vers l'onglet Pare-feu) ; un
  réseau connu retrouve son profil à chaque connexion ; « Oublier » un réseau le ramène à Public. À la première
  mise à jour, le réseau courant hérite du profil déjà choisi.
- **Règles UFW réellement appliquées** — le service appelle `ufw --force rule allow …` : sans le mot-clé `rule`
  explicite, ufw ne reconnaît pas une règle placée après `--force` (« Invalid syntax »), ce qui faisait échouer
  les profils réseau et les règles ajoutées depuis l'application ; le message d'erreur d'ufw est désormais
  journalisé et affiché.
- **Avertissements d'intégrité lisibles** — le texte complet est affiché (chkrootkit liste les chemins sous
  son en-tête « suspicious files » : ils sont conservés), les faux positifs connus sont expliqués (.build-id,
  .packlist…) et « C'est normal » approuve un avertissement : mis à part, il ne compte plus dans l'état ni
  dans les prochains relevés (« Retirer » le réactive). Le service classe lui-même les fichiers cachés signalés
  par chkrootkit : livré par un paquet installé (`dpkg -S`), nom connu (.build-id, .packlist, marqueurs npm/Python)
  ou inconnu (à vérifier) ; même traitement pour « Linux.Xor.DDoS » (chkrootkit liste tout fichier exécutable de
  /tmp : extensions Chrome, scripts Timeshift, fichiers texte et dossiers de compilation sont bénins, seul un
  binaire ELF inconnu reste à vérifier) ; un constat entièrement bénin devient « faux positif connu » sans intervention, et un
  relevé chkrootkit incomplet (ancienne version) est relancé seul au démarrage.
- **Failles** — les noyaux installés mais non démarrés ne sont plus interrogés sur OSV (ni comptés, ni
  affichés) ; les réponses OSV sont paginées, un noyau dépassant les 1000 fiches d'une page. Les failles du
  moteur JavaScript `mozjs*` (SpiderMonkey extrait de Firefox ESR, utilisé par cjs/gjs/polkit) qui décrivent
  le navigateur (contenu web, médias, onglets…) sont classées « Non applicables (moteur intégré) » avec la
  liste des programmes qui l'utilisent ; celles propres au moteur (JIT, WebAssembly, ramasse-miettes) restent
  « Sans correctif » ; badge « moteur JS intégré, pas Firefox ni Thunderbird » sur ces lignes, relevé existant
  reclassé au démarrage du service. Les paquets construits par Linux Mint (version `+linuxmint`, Thunderbird,
  Firefox…) sont hors du suivi CVE d'Ubuntu : leurs failles « needed » sont classées non applicables avec la
  version installée en note.
- **Moteur résilient** — un lot que clamd refuse (service injoignable, descripteur refusé) est réessayé après
  attente de clamd, puis confié à clamscan ; au cinquième lot en échec, le reste du scan bascule sur clamscan
  au lieu d'échouer. chkrootkit : lignes d'outils système (« RTNETLINK answers… ») ignorées, constat
  « ifpromisc » classé (NetworkManager/wpa_supplicant sur le Wi-Fi = bénin, processus inconnu = à vérifier).
  L'état global ne passe au rouge que pour des indices de compromission (rootkits, fichiers modifiés) ; les
  avertissements Lynis seuls donnent du jaune.
- **Activer Timeshift en un clic** — bouton dans l'onglet Sauvegardes et dans l'assistant de la vue
  simple, sans mot de passe : le service écrit la configuration recommandée (instantanés du système sur le
  disque principal, quotidiens 5, hebdomadaires 3, mensuels 2, mode btrfs si la racine est un sous-volume
  @, sinon rsync en excluant les dossiers personnels), installe la tâche cron horaire et lance le
  premier instantané. Désactiver demande l'authentification administrateur. **Garde-fou d'espace** : la
  taille du système est mesurée (`du`, mise en cache une semaine) et l'activation est refusée s'il ne reste
  pas 1,2 × cette taille + 10 Go libres (message avec les chiffres, bouton « Ouvrir Timeshift » pour
  choisir un disque dédié) ; la tâche cron ne lance un instantané que s'il reste 10 Go, et le service
  suspend les planifications (popup, voyant orange) si le disque passe sous ce seuil.
- **Bilan de la semaine** — popup hebdomadaire (et bouton dans l'onglet Sécurité) : analyses, menaces,
  alertes, score et sa variation, sauvegarde, conseils lus.
- **Fuites de données** — test d'un mot de passe via Have I Been Pwned en k-anonymity (5 caractères
  du SHA-1, jamais le mot de passe) ; surveillance d'adresses e-mail via la base gratuite XposedOrNot, ou Have I Been Pwned avec
  une clé API personnelle ; revérification hebdomadaire et popup à chaque nouvelle fuite. Seule l'adresse
  est transmise au service consulté. (Le relais `repo/api/hibp.php` reste disponible si Dukiwi obtient
  une clé un jour.)
- **Applications hors dépôts** — inventaire Flatpak (permissions larges, source hors Flathub), Snap
  (confinement classic, plugs sensibles) et AppImage (sans bac à sable), avec « Faire confiance ».
- **Coffre chiffré** — dossier gocryptfs (`~/.coffre` chiffré, monté sur `~/Coffre`), création,
  ouverture et fermeture depuis la vue simple ou l'onglet Sauvegardes, mot de passe saisi dans une
  boîte de dialogue native, fermeture automatique après 30 min, inclus dans les sauvegardes.
- **Restauration guidée** — choix de la destination, de la sauvegarde et du dossier, copie dans
  `~/Restauration` sans jamais écraser les fichiers actuels.
- **Mode voyage** — un bouton : profil pare-feu Public, sauvegarde si un support est branché, mises
  à jour, rappels (VPN, verrouillage, double authentification, clés USB) ; le retour rétablit le profil.
- **Télémétrie anonyme opt-in** — désactivée par défaut ; une fois par semaine : version, système,
  score, types d'alertes, programmes et entrées approuvés (chemins anonymisés), sans identifiant
  personnel. Reçue par `repo/api/telemetry.php` (fichiers `api/data/*.jsonl`, résumé avec
  `api/summarize.py`) pour alimenter la **liste blanche centrale signée** (`api/allowlist.json` +
  `.sig`, vérifiée avec la clé Dukiwi, téléchargée chaque jour).
- **Politique d'entreprise** — `/etc/clamav-antivirus/policy.json` déployé par dukiwi-kit (fichier
  root, signature détachée facultative) : réglages imposés et verrouillés, profil pare-feu, programmes
  de confiance ; voir `policy.example.json`. Les réglages verrouillés apparaissent grisés.
- **Noyaux inactifs** — les failles des noyaux installés mais non démarrés (par exemple le 6.8 GA
  quand le système tourne sur un noyau HWE 7.0) sont comptées à part et n'entrent plus dans le total ;
  une note indique le noyau en cours (`uname -r`) et comment retirer les anciens.
- **Noyau HWE** — les failles du noyau 6.8 de Mint déjà corrigées dans un noyau HWE (6.11, 6.14) sont
  marquées « corrigée dans le noyau HWE » et comptées ; la carte des failles explique comment installer
  ce noyau (Gestionnaire de mises à jour → Noyaux Linux, ou `linux-generic-hwe-24.04`).
- **Bouton « Régler »** — chaque contrôle de la checklist qui n'est pas au vert propose « Régler »
  (action directe : pare-feu, mise à jour, scan, paramètres, liste des ports…) ou « Comment faire »
  (explication pas à pas : chiffrement, Secure Boot, AppArmor, sudo, comptes…). La liste des ports
  donne un verdict par port : local seulement, filtré par le pare-feu (rien à faire) ou joignable
  depuis le réseau, avec une explication par service (SMTP, Apache, Avahi, CUPS, Samba…) et un
  bouton « Bloquer ce port ». Les règles sudo NOPASSWD livrées par un paquet du système (mintupdate, mintdrivers, mintsystem) et
  inchangées (vérification dpkg) sont reconnues comme normales ; seules les règles ajoutées à la main ou
  modifiées sont signalées.
- **Sauvegardes (disponibilité, le « A » du triptyque CIA)** — tuile « Sauvegardes » en vue simple et
  page complète en vue avancée. Le service lit l'état de **Timeshift** (installé, planification, dernier
  instantané) ; l'application copie les dossiers personnels (Documents, Images, Vidéos, Musique, Bureau,
  modifiables) vers une **clé USB / un disque externe** (instantanés rsync incrémentaux avec liens durs,
  rétention réglable, miroir simple sur FAT/NTFS), un **dossier** (NAS) ou un **cloud** via rclone
  (S3 compatible, Infomaniak Swiss Backup S3 ou Swift, kDrive WebDAV, remote rclone existant ; archivage
  des fichiers remplacés). Assistant minimal en vue simple (« Sauvegarder ici » sur le support détecté),
  planification automatique quotidienne/hebdomadaire/mensuelle dès que la destination est branchée,
  historique, consignes de restauration. Fichiers jamais sauvegardés ou Timeshift non planifié : voyant
  jaune (désactivable dans Paramètres). Tout tourne avec les droits de l'utilisateur, sans mot de passe.
- **Analyse complète** — « Analyser mon ordinateur » (vue simple, tableau de bord, tray) commence par
  la vérification d'intégrité (Lynis, chkrootkit, debsums, fichiers de l'application), puis lance le
  scan antivirus en **ignorant les fichiers système que debsums a confirmés identiques à leur paquet**
  (plusieurs centaines de milliers de fichiers), d'où une analyse bien plus rapide. Le popup final
  résume menaces, intégrité et nombre de fichiers ignorés. En vue avancée, l'onglet Scanner propose
  « Scan complet (intégrité + fichiers) », « Fichiers uniquement » et « Intégrité uniquement ». Lynis,
  chkrootkit et debsums sont désormais des dépendances du paquet ; Lynis est initialisé à
  l'installation et remis à jour après chaque passage d'apt (`APT_AUTOGEN`). Comme Lynis, unhide et
  chkrootkit recommandent un serveur de courrier (apt installerait Postfix, qui ouvre le port 25), le
  paquet dépend de `msmtp-mta`, un simple client sans démon ni port, qui satisfait cette recommandation.
- **Installer les mises à jour** — le bouton « Mettre à jour » (vue simple) et « Installer les mises à
  jour » (État du système) lancent `apt-get update` puis `apt-get upgrade` via le service, dans une unité
  systemd transitoire ; un popup confirme la fin. Les paquets **décalés** (phasing Ubuntu) ou **retenus**
  par apt (dépendances, « kept back ») ne comptent pas comme mises à jour manquantes : le voyant reste vert
  avec la mention « on attend notre tour ». La détection simule `apt upgrade` en mémoire (python3-apt),
  donc elle reflète exactement ce que la machine installerait.
- **« C'est moi »** — chaque alerte (programme inconnu du système qui modifie des fichiers ou se
  connecte à Internet, entrée de démarrage inconnue, extension hors store) propose un bouton
  « C'est moi » : le programme ou l'entrée passe en liste d'approbation (Paramètres → Programmes
  approuvés) et ne déclenche plus jamais de message ; un processus suspendu est repris. Un binaire
  remplacé pendant son exécution (Chrome mis à jour, par exemple) n'est plus considéré comme inconnu.
- **Conseils lus** — une leçon ouverte au moins 5 secondes via « Lire plus » est marquée « Lu » et ne
  revient plus en popup ; quand tout est lu, le popup du jour disparaît (badge cliquable pour
  remettre une leçon en non lu).
- **Paquets classés** (État du système) — chaque mise à jour en attente est étiquetée
  **Sécurité** (correctif de faille), **Recommandé** (application / bibliothèque) ou **Décalé**
  (phased update Ubuntu, avec le pourcentage de déploiement). Si rien n'est en attente, la carte
  affiche « Tout est à jour » ; sinon un bouton **Installer les paquets décalés** force leur
  installation (`APT::Get::Always-Include-Phased-Updates=true`, authentification admin).
- **Avertissement juridique** — affiché au premier lancement (à accepter) et disponible à tout
  moment via Crédits → Avertissement : logiciel fourni « en l'état », première barrière seulement,
  exclusion de responsabilité de Dukiwi SA (voir plus bas).
- **Icône tray** — vert : tout est en ordre ; jaune : mises à jour non critiques, redémarrage,
  SSH actif, mise à jour de l'app ; bleu : signatures anciennes ou failles ouvertes sans correctif ;
  rouge : pare-feu inactif, mises à jour de sécurité, danger détecté, intégrité compromise.
- **Scan moderne** — anneau de progression, étapes (inventaire → analyse), fichiers/s,
  temps restant estimé, menaces en direct, annulation et reprise, résumé de fin,
  historique des analyses.
- **Scan rapide** — `/home`, `/etc`, `/var`, `/opt`, `/usr`, `/tmp` ou un dossier choisi
  via le sélecteur natif.
- **Quarantaine** — fichiers infectés isolés (quarantaine système et quarantaine utilisateur).
- **Interface HTML/CSS** — Facilement modifiable (fichiers dans `ui/`)

## Avertissement et limitation de responsabilité

ClamAV Antivirus GUI est fourni par **Dukiwi SA « EN L'ÉTAT » (as is)**, sans aucune garantie,
expresse ou implicite. Il constitue tout au plus une **première barrière** : aucun antivirus,
pare-feu ou outil de détection ne peut identifier toutes les menaces, et un voyant vert ne
garantit en rien qu'un ordinateur est sain. Seul un comportement prudent et informé de
l'utilisateur (security awareness) limite réellement les risques.

**Dans toute la mesure permise par le droit applicable, Dukiwi SA ne pourra être tenue
responsable** d'aucun dommage direct ou indirect (perte, chiffrement ou divulgation de données,
infection non détectée, piratage, hameçonnage, fraude, interruption d'activité, faux positif,
action déclenchée par le logiciel telle qu'un arrêt de processus, une mise en quarantaine ou une
règle de pare-feu…) découlant de l'utilisation, de la mauvaise utilisation ou de l'impossibilité
d'utiliser le logiciel. L'utilisateur est seul responsable de ses sauvegardes, de ses réglages et
de ses actes. Le texte complet (12 articles, FR/EN/DE/IT) est affiché dans l'application au
premier lancement et sous Crédits → Avertissement ; en l'utilisant, vous l'acceptez. Ce texte
n'est pas un avis juridique.

## Installation via le dépôt APT (recommandé)

Dépôt signé pour Ubuntu 24.04 « noble » et Linux Mint 22 :

```bash
sudo mkdir -p /usr/share/keyrings
curl -fsSL https://www.dukiwi.com/repo/apt/dukiwi-clamav.gpg | sudo tee /usr/share/keyrings/dukiwi-clamav.gpg > /dev/null
echo "deb [signed-by=/usr/share/keyrings/dukiwi-clamav.gpg] https://www.dukiwi.com/repo/apt noble main" | sudo tee /etc/apt/sources.list.d/dukiwi-clamav.list
sudo apt update && sudo apt install clamav-antivirus
```

Les mises à jour arrivent ensuite par le Gestionnaire de mises à jour de Mint. L'application
signale aussi elle-même les nouvelles versions (popup ou onglet Sécurité) ; leur installation
demande une authentification administrateur.

## Téléchargement

[Télécharger clamav-antivirus_1.14.4_all.deb](https://www.dukiwi.com/repo/clamav-antivirus/clamav-antivirus_1.14.4_all.deb)

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

Résultat : `clamav-antivirus_1.14.4_all.deb`

### Installer le .deb

```bash
sudo dpkg -i clamav-antivirus_1.14.4_all.deb
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
| `ui/awareness.js`                        | Leçons de sensibilisation FR/EN/DE/IT (popup « conseil du jour » et page Bonnes pratiques) |
| `clamav_backup.py`                       | Moteur de sauvegarde utilisateur (rsync incrémental, rclone cloud, détection des supports) |
| `clamav_extras.py`                       | Fuites de données (HIBP), applications hors dépôts, coffre gocryptfs, bilan hebdomadaire |
| `policy.example.json`                    | Exemple de politique d'entreprise pour dukiwi-kit |

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
├── clamav-antivirus-unlock          # Helper pkexec : session administrateur pour le daemon
├── polkit/com.dukiwi.clamav-antivirus.policy
├── keys/dukiwi-clamav.gpg           # Clé publique de vérification des mises à jour
├── ui/
│   ├── index.html                   # Interface HTML
│   ├── style.css                    # Thème CSS (variables modifiables)
│   ├── app.js                       # Logique JS frontend
│   ├── i18n.js                      # Traductions FR/EN/DE/IT
│   └── awareness.js                 # Leçons de sensibilisation FR/EN/DE/IT
├── icons/
│   ├── logo.svg                     # Logo de l'application (fenêtre, menu, .desktop)
│   ├── shield-green.svg             # Tray : tout est en ordre
│   ├── shield-yellow.svg            # Tray : MàJ non critiques, redémarrage, SSH actif
│   ├── shield-blue.svg              # Tray : signatures anciennes, failles sans correctif
│   └── shield-red.svg               # Tray : pare-feu inactif, MàJ de sécurité, danger
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
