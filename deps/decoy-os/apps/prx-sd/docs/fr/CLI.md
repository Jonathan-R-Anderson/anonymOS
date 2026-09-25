> Ce document est une traduction en francais de la version [English](../CLI.md).

# Reference CLI

PRX-SD fournit l'outil en ligne de commande `sd` pour la detection des menaces et la protection du systeme.

## Options globales

| Drapeau | Description | Defaut |
|---------|-------------|--------|
| `--log-level <LEVEL>` | Niveau de verbossite des journaux : `trace`, `debug`, `info`, `warn`, `error` | `warn` |
| `--data-dir <PATH>` | Repertoire de donnees pour les signatures, la quarantaine et la configuration | `~/.prx-sd/` |

---

## Analyse

### `sd scan <PATH>`

Analyser un fichier ou un repertoire a la recherche de menaces.

```bash
sd scan /path/to/file
sd scan /home --recursive
sd scan /tmp --auto-quarantine --remediate
sd scan /path --json
sd scan /path --report report.html
```

| Option | Description | Defaut |
|--------|-------------|--------|
| `-r, --recursive <BOOL>` | Parcourir les sous-repertoires de maniere recursive | `true` pour les repertoires |
| `--json` | Afficher les resultats au format JSON | |
| `-t, --threads <NUM>` | Nombre de threads d'analyse | Nombre de CPU |
| `--auto-quarantine` | Mettre automatiquement en quarantaine les fichiers malveillants | |
| `--remediate` | Remediation automatique : arreter les processus, quarantaine, nettoyage de la persistance | |
| `-e, --exclude <PATTERN>` | Motifs glob a exclure (repetable) | |
| `--report <PATH>` | Exporter les resultats sous forme de rapport HTML autonome | |

### `sd scan-memory`

Analyser la memoire des processus en cours d'execution (Linux uniquement, necessite les droits root).

```bash
sudo sd scan-memory
sudo sd scan-memory --pid 1234
sudo sd scan-memory --json
```

| Option | Description |
|--------|-------------|
| `--pid <PID>` | Analyser un processus specifique (omettre pour analyser tous les processus) |
| `--json` | Sortie au format JSON |

### `sd scan-usb [DEVICE]`

Analyser les peripheriques USB/amovibles.

```bash
sd scan-usb
sd scan-usb /dev/sdb1 --auto-quarantine
```

| Option | Description |
|--------|-------------|
| `--auto-quarantine` | Mettre automatiquement en quarantaine les menaces detectees |

### `sd check-rootkit`

Verifier la presence d'indicateurs de rootkit (Linux uniquement).

```bash
sudo sd check-rootkit
sudo sd check-rootkit --json
```

Verifications effectuees : processus caches, integrite des modules noyau, hooks LD_PRELOAD, anomalies /proc.

---

## Protection en temps reel

### `sd monitor <PATHS...>`

Surveillance du systeme de fichiers en temps reel.

```bash
sd monitor /home /tmp
sd monitor /home --block
sd monitor /home --daemon
```

| Option | Description |
|--------|-------------|
| `--block` | Bloquer les fichiers malveillants avant l'acces (necessite root + fanotify sous Linux) |
| `--daemon` | Executer en tant que daemon en arriere-plan |

### `sd daemon [PATHS...]`

Executer en tant que daemon en arriere-plan avec surveillance en temps reel et mises a jour automatiques.

```bash
sd daemon
sd daemon /home /tmp --update-hours 2
```

| Option | Description | Defaut |
|--------|-------------|--------|
| `--update-hours <NUM>` | Intervalle de verification des mises a jour de signatures en heures | `4` |

Chemins surveilles par defaut : `/home`, `/tmp`.

---

## Gestion de la quarantaine

### `sd quarantine <SUBCOMMAND>`

Gerer le coffre-fort de quarantaine chiffre (AES-256-GCM).

```bash
sd quarantine list
sd quarantine restore <ID>
sd quarantine restore <ID> --to /safe/path
sd quarantine delete <ID>
sd quarantine delete-all --yes
sd quarantine stats
```

| Sous-commande | Description |
|---------------|-------------|
| `list` | Lister tous les fichiers en quarantaine |
| `restore <ID>` | Restaurer un fichier en quarantaine (`--to <PATH>` pour un emplacement alternatif) |
| `delete <ID>` | Supprimer definitivement un fichier en quarantaine |
| `delete-all` | Supprimer tous les fichiers en quarantaine (`--yes` pour ignorer la confirmation) |
| `stats` | Afficher les statistiques de quarantaine |

---

## Base de donnees de signatures

### `sd update`

Verifier et appliquer les mises a jour de la base de donnees de signatures.

```bash
sd update
sd update --check-only
sd update --force
sd update --server-url https://custom-server.example.com
```

| Option | Description |
|--------|-------------|
| `--check-only` | Verifier uniquement si une mise a jour est disponible |
| `--force` | Forcer le re-telechargement meme si deja a jour |
| `--server-url <URL>` | Remplacer l'URL du serveur de mise a jour |

### `sd import <PATH>`

Importer des signatures de hachage depuis un fichier de liste de blocage.

```bash
sd import /path/to/blocklist.txt
```

Format du fichier : une entree par ligne au format `hex_hash malware_name`. Les lignes commencant par `#` sont des commentaires.

```
# Example blocklist
275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f EICAR.Test
ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa Ransom.WannaCry
```

### `sd import-clamav <PATHS...>`

Importer des fichiers de base de donnees de signatures ClamAV.

```bash
sd import-clamav main.cvd daily.cvd
sd import-clamav custom.hdb custom.hsb
```

Formats pris en charge : `.cvd`, `.cld`, `.hdb`, `.hsb`.

### `sd info`

Afficher la version du moteur, l'etat de la base de donnees de signatures et les informations systeme.

```bash
sd info
```

Affiche : version, nombre de regles YARA, nombre de signatures de hachage, statistiques de quarantaine, informations sur la plateforme.

---

## Configuration

### `sd config <SUBCOMMAND>`

Gerer la configuration du moteur.

```bash
sd config show
sd config set scan.max_file_size 104857600
sd config set scan.follow_symlinks true
sd config reset
```

| Sous-commande | Description |
|---------------|-------------|
| `show` | Afficher la configuration actuelle |
| `set <KEY> <VALUE>` | Definir une cle de configuration (chemin separe par des points) |
| `reset` | Reinitialiser la configuration par defaut |

Les valeurs prennent en charge les types JSON : booleen (`true`/`false`), nombres, `null`, tableaux, objets.

---

## Politique de remediation

### `sd policy <ACTION> [KEY] [VALUE]`

Gerer les politiques de remediation des menaces.

```bash
sd policy show
sd policy set on_malicious "kill,quarantine,clean"
sd policy set on_suspicious "report,quarantine"
sd policy set kill_processes true
sd policy reset
```

| Action | Description |
|--------|-------------|
| `show` | Afficher la politique actuelle |
| `set <KEY> <VALUE>` | Definir un champ de politique |
| `reset` | Reinitialiser la politique par defaut |

**Cles de politique :**

| Cle | Description | Valeurs |
|-----|-------------|---------|
| `on_malicious` | Actions pour les menaces malveillantes | Separees par des virgules : `report`, `quarantine`, `block`, `kill`, `clean`, `delete`, `isolate`, `blocklist` |
| `on_suspicious` | Actions pour les menaces suspectes | Identiques a ci-dessus |
| `kill_processes` | Arreter les processus associes | `true` / `false` |
| `clean_persistence` | Nettoyer les mecanismes de persistance | `true` / `false` |
| `network_isolation` | Isoler les connexions reseau | `true` / `false` |
| `audit_logging` | Journaliser toutes les actions dans une piste d'audit | `true` / `false` |

---

## Planification

### `sd schedule <SUBCOMMAND>`

Gerer les analyses planifiees. Utilise les planificateurs natifs de la plateforme : systemd timers (Linux), cron (Linux/macOS), launchd (macOS), Task Scheduler (Windows).

```bash
sd schedule add /home --frequency daily
sd schedule add /tmp --frequency hourly
sd schedule status
sd schedule remove
```

| Sous-commande | Description |
|---------------|-------------|
| `add <PATH>` | Enregistrer une analyse recurrente planifiee |
| `remove` | Supprimer l'analyse planifiee |
| `status` | Afficher l'etat de la planification actuelle |

**Frequences :** `hourly`, `4h`, `12h`, `daily`, `weekly` (par defaut : `weekly`).

---

## Alertes

### `sd webhook <SUBCOMMAND>`

Gerer les points de terminaison d'alerte webhook.

```bash
sd webhook list
sd webhook add my-slack https://hooks.slack.com/services/... --format slack
sd webhook add my-discord https://discord.com/api/webhooks/... --format discord
sd webhook add custom https://example.com/alert --format generic
sd webhook remove my-slack
sd webhook test
```

| Sous-commande | Description |
|---------------|-------------|
| `list` | Lister les webhooks configures |
| `add <NAME> <URL>` | Ajouter un webhook (`--format` : `slack`, `discord`, `generic`) |
| `remove <NAME>` | Supprimer un webhook par nom |
| `test` | Envoyer une alerte de test a tous les webhooks |

### `sd email-alert <SUBCOMMAND>`

Gerer la configuration des alertes par e-mail.

```bash
sd email-alert configure
sd email-alert test
sd email-alert send "Trojan.Generic" "high" "/tmp/malware.exe"
```

| Sous-commande | Description |
|---------------|-------------|
| `configure` | Creer ou afficher la configuration SMTP pour les e-mails |
| `test` | Envoyer un e-mail d'alerte de test |
| `send <NAME> <LEVEL> <PATH>` | Envoyer un e-mail d'alerte personnalise |

---

## Filtrage DNS et reseau

### `sd adblock <SUBCOMMAND>`

Gerer le filtrage des publicites et des domaines malveillants.

```bash
sd adblock enable
sd adblock disable
sd adblock sync
sd adblock stats
sd adblock check https://suspicious-site.example.com
sd adblock log --count 100
sd adblock add custom-list https://example.com/blocklist.txt --category malware
sd adblock remove custom-list
```

| Sous-commande | Description |
|---------------|-------------|
| `enable` | Telecharger les listes de blocage et installer le blocage DNS (`/etc/hosts`) |
| `disable` | Supprimer les entrees de blocage DNS |
| `sync` | Forcer le re-telechargement de toutes les listes de filtres |
| `stats` | Afficher les statistiques de filtrage |
| `check <URL>` | Verifier si une URL/un domaine est bloque |
| `log` | Afficher les entrees recemment bloquees (`-c, --count <NUM>`, par defaut : 50) |
| `add <NAME> <URL>` | Ajouter une liste de filtres personnalisee (`--category` : `ads`, `tracking`, `malware`, `social`) |
| `remove <NAME>` | Supprimer une liste de filtres |

### `sd dns-proxy`

Demarrer un proxy DNS local avec filtrage adblock, IOC et liste de blocage personnalisee.

```bash
sudo sd dns-proxy
sudo sd dns-proxy --listen 127.0.0.1:5353 --upstream 1.1.1.1:53
```

| Option | Description | Defaut |
|--------|-------------|--------|
| `--listen <ADDR>` | Adresse d'ecoute | `127.0.0.1:53` |
| `--upstream <ADDR>` | Serveur DNS en amont | `8.8.8.8:53` |
| `--log-path <PATH>` | Chemin du journal de requetes JSONL | `/tmp/prx-sd-dns.log` |

---

## Rapports

### `sd report <OUTPUT>`

Generer un rapport HTML autonome a partir des resultats d'analyse au format JSON.

```bash
sd scan /path --json | sd report report.html
sd report report.html --input results.json
```

| Option | Description | Defaut |
|--------|-------------|--------|
| `--input <FILE>` | Fichier JSON d'entree (`-` pour stdin) | `-` (stdin) |

### `sd status`

Afficher l'etat du daemon, y compris le PID, le temps d'activite, la version des signatures et les menaces bloquees.

```bash
sd status
```

---

## Integration

### `sd install-integration`

Installer l'integration d'analyse par clic droit dans le gestionnaire de fichiers.

```bash
sd install-integration
```

Gestionnaires de fichiers pris en charge :
- **Linux :** Nautilus (GNOME Files), Dolphin (KDE), Nemo (Cinnamon)
- **macOS :** Finder Quick Action

### `sd self-update`

Verifier et appliquer les mises a jour du binaire depuis GitHub Releases.

```bash
sd self-update
sd self-update --check-only
```

| Option | Description |
|--------|-------------|
| `--check-only` | Verifier uniquement si une mise a jour est disponible |

---

## Exemples

### Configuration initiale

```bash
# Install
curl -fsSL https://raw.githubusercontent.com/openprx/prx-sd/main/install.sh | bash

# Import additional signatures
sd import my-custom-hashes.txt
sd import-clamav main.cvd daily.cvd

# Verify setup
sd info
```

### Protection quotidienne

```bash
# Start daemon (monitors /home and /tmp, updates every 4h)
sd daemon

# Or manual scan
sd scan /home --recursive --auto-quarantine

# Check status
sd status
```

### Reponse aux incidents

```bash
# Scan with full remediation
sudo sd scan /tmp --auto-quarantine --remediate

# Check memory for in-memory threats
sudo sd scan-memory

# Check for rootkits
sudo sd check-rootkit

# Review quarantine
sd quarantine list
sd quarantine restore <ID> --to /safe/location
```

### Automatisation

```bash
# Schedule weekly scan
sd schedule add /home --frequency weekly

# Set up alerts
sd webhook add slack https://hooks.slack.com/services/T.../B.../xxx --format slack
sd email-alert configure

# JSON output for scripts
sd scan /path --json | jq '.threats[] | .name'
```
