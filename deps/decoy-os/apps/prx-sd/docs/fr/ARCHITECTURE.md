> Ce document est une traduction en francais de la version [English](../ARCHITECTURE.md).

# Architecture

PRX-SD est structure comme un espace de travail Cargo avec des crates modulaires, chacune responsable d'un domaine specifique.

## Organisation de l'espace de travail

```
prx-sd/
├── crates/
│   ├── cli/           # Binaire "sd" — interface en ligne de commande
│   ├── core/          # Coordination du moteur d'analyse
│   ├── signatures/    # Base de hachage (LMDB) + moteur de regles YARA-X
│   ├── parsers/       # Analyseurs de formats binaires
│   ├── heuristic/     # Notation heuristique + inference ML
│   ├── realtime/      # Surveillance du systeme de fichiers + filtrage reseau
│   ├── quarantine/    # Coffre-fort de quarantaine chiffre
│   ├── remediation/   # Actions de reponse aux menaces
│   ├── sandbox/       # Isolation de processus + analyse comportementale
│   ├── plugins/       # Environnement d'execution de plugins WebAssembly
│   └── updater/       # Client de mise a jour des signatures
├── update-server/     # Serveur de distribution des signatures (Axum)
├── gui/               # Interface graphique de bureau (Tauri 2 + Vue 3)
├── drivers/           # Pilotes noyau du systeme d'exploitation
│   └── windows-minifilter/  # Minifiltre de systeme de fichiers Windows (C)
├── signatures-db/     # Signatures minimales integrees
├── packaging/         # Empaquetage pour la distribution
├── tests/             # Tests d'integration
├── tools/             # Scripts de compilation et utilitaires
├── install.sh         # Script d'installation
└── uninstall.sh       # Script de desinstallation
```

## Graphe de dependances des crates

```
cli
 ├── core
 │    ├── signatures
 │    │    └── (heed, yara-x, sha2, md5)
 │    ├── parsers
 │    │    └── (goblin)
 │    └── heuristic
 │         └── (tract-onnx [optional])
 ├── realtime
 │    ├── core
 │    └── (notify, nix [linux], adblock)
 ├── quarantine
 │    └── (aes-gcm, rand)
 ├── remediation
 │    ├── quarantine
 │    └── (nix [unix])
 ├── sandbox
 │    └── (nix [unix])
 ├── plugins
 │    └── (wasmtime, wasmtime-wasi)
 └── updater
      └── (ed25519-dalek, zstd, reqwest)
```

## Pipeline de detection

Le moteur d'analyse (`core`) coordonne un pipeline de detection multi-couches :

```
                    ┌──────────────┐
                    │  File Input  │
                    └──────┬───────┘
                           │
                    ┌──────▼───────┐
                    │ Magic Number │  Identifier : PE, ELF, MachO,
                    │  Detection   │  PDF, ZIP, Office, inconnu
                    └──────┬───────┘
                           │
              ┌────────────┼────────────┐
              │            │            │
       ┌──────▼──────┐    │     ┌──────▼──────┐
       │    Hash      │    │     │   YARA-X    │
       │  Matching    │    │     │   Rules     │
       │  (LMDB)     │    │     │  (38K+)     │
       └──────┬──────┘    │     └──────┬──────┘
              │     ┌─────▼─────┐      │
              │     │ Heuristic │      │
              │     │ Analysis  │      │
              │     └─────┬─────┘      │
              │           │            │
              │    ┌──────▼──────┐     │
              │    │ ML Inference│     │
              │    │  (ONNX)    │     │
              │    └──────┬─────┘     │
              │           │            │
              │    ┌──────▼──────┐     │
              │    │ VirusTotal  │     │
              │    │ Cloud Query │     │
              │    └──────┬─────┘     │
              │           │            │
              └───────────┼────────────┘
                          │
                   ┌──────▼──────┐
                   │  Aggregate  │
                   │   Verdict   │
                   └─────────────┘
                   Clean / Suspicious / Malicious
```

### Details des couches

1. **Correspondance de hachage** -- Recherche en O(1) dans la base de donnees LMDB contenant les hachages SHA-256 et MD5 provenant de ClamAV, abuse.ch, VirusShare et des listes de blocage personnalisees.

2. **Regles YARA-X** -- Correspondance de motifs a l'aide du moteur YARA-X (implementation native en Rust de YARA). Les regles sont chargees depuis les valeurs par defaut integrees et le depot externe de signatures.

3. **Analyse heuristique** -- Analyse specifique au type de fichier :
   - **PE :** Entropie des sections, imports d'API suspectes (CreateRemoteThread, VirtualAllocEx), detection de packers (UPX, Themida), anomalies d'horodatage
   - **ELF :** Entropie des sections, references LD_PRELOAD, persistance cron/systemd, motifs de portes derobees SSH
   - **MachO :** Entropie des sections, injection dylib, persistance LaunchAgent, acces au Keychain

4. **Inference ML** (optionnel, feature flag `onnx`) -- Evaluation de modeles ONNX via tract :
   - PE : vecteur de caracteristiques a 64 dimensions (hachages de la table d'imports, entropie des sections, signatures d'API)
   - ELF : vecteur de caracteristiques a 48 dimensions (entropie des sections, table des symboles, bibliotheques dynamiques)

5. **VirusTotal Cloud** -- Solution de repli pour les fichiers non identifies localement. Interroge l'API VirusTotal (niveau gratuit : 500 requetes/jour). Les resultats sont mis en cache dans LMDB.

### Notation

- Score >= 60 : **Malveillant**
- Score 30-59 : **Suspect**
- Score < 30 : **Sain**

Le verdict final correspond au niveau de menace le plus eleve parmi toutes les couches de detection.

## Protection en temps reel

La crate `realtime` fournit une protection continue a travers plusieurs sous-systemes :

| Sous-systeme | Linux | macOS | Windows |
|--------------|-------|-------|---------|
| Surveillance des fichiers | fanotify + epoll | FSEvents (notify) | ReadDirectoryChangesW (notify) |
| Interception de processus | FAN_OPEN_EXEC_PERM | - | Minifilter (prevu) |
| Analyse de la memoire | /proc/pid/mem | - | - |
| Detection de ransomware | Surveillance des motifs ecriture+renommage | Surveillance des motifs ecriture+renommage | Surveillance des motifs ecriture+renommage |
| Repertoires proteges | ~/.ssh, /etc/shadow, /etc/systemd | ~/Library, /etc | Cles de registre Run |
| Filtrage DNS | Moteur adblock + listes IOC | Moteur adblock + listes IOC | Moteur adblock + listes IOC |
| Surveillance comportementale | /proc + audit (execve/connect/open) | - | - |

## Coffre-fort de quarantaine

Les fichiers sont mis en quarantaine a l'aide du chiffrement authentifie AES-256-GCM :

1. Generation d'une cle aleatoire de 256 bits + nonce de 96 bits
2. Chiffrement du contenu du fichier avec AES-256-GCM
3. Stockage du fichier chiffre avec un nom de fichier UUID
4. Sauvegarde des metadonnees JSON (chemin d'origine, hachage, nom de la menace, horodatage)
5. La restauration dechiffre et verifie l'integrite avant de reecrire le fichier

## Pipeline de remediation

Lorsque `--remediate` est utilise :

```
Threat Detected
  ├── 1. Kill Process     (SIGKILL on Linux/macOS, TerminateProcess on Windows)
  ├── 2. Quarantine File  (AES-256-GCM encrypted vault)
  └── 3. Clean Persistence
        ├── Linux:   cron jobs, systemd services, LD_PRELOAD
        ├── macOS:   LaunchAgents, plist entries, Keychain
        └── Windows: Run/RunOnce registry, scheduled tasks, services
```

Les actions sont configurables via `sd policy set`.

## Base de donnees de signatures

### Signatures integrees (`signatures-db/`)

Ensemble minimal de signatures compile dans le binaire `sd` via `include_str!` :
- Signature de test EICAR
- Regles YARA de base (ransomware, trojan, backdoor, etc.)
- Hachages de malwares connus (WannaCry, Emotet, NotPetya)

### Signatures externes ([prx-sd-signatures](https://github.com/openprx/prx-sd-signatures))

Renseignements sur les menaces complets et frequemment mis a jour :
- Plus de 38 800 regles YARA provenant de 9 sources
- Listes de blocage de hachages provenant des flux abuse.ch
- Listes IOC : plus de 585 000 adresses IP, domaines et URL malveillants

### Stockage

- **Hachages :** LMDB (crate heed) pour des recherches cle-valeur en O(1)
- **Regles YARA :** Chargees et compilees par YARA-X au demarrage
- **Listes IOC :** HashSet en memoire pour une correspondance rapide des adresses IP/domaines/URL

## Systeme de plugins

PRX-SD prend en charge les plugins WebAssembly via Wasmtime :

- Les plugins sont des fichiers `.wasm` accompagnes d'un manifeste (`plugin.json`)
- Prise en charge de WASI pour l'acces au systeme de fichiers et a l'environnement
- Registre de plugins pour la decouverte et le chargement
- Fonctions hote exposees aux plugins pour les resultats d'analyse et la configuration

## Systeme de mise a jour

La crate `updater` et le `update-server` fournissent un pipeline de mise a jour securise :

1. Le client verifie aupres du serveur de mise a jour la disponibilite de nouvelles versions de signatures
2. Le serveur repond avec les informations de version et l'URL de telechargement
3. Le client telecharge le paquet de signatures compresse avec zstd
4. La signature du paquet est verifiee avec Ed25519 (ed25519-dalek)
5. Les signatures sont extraites et chargees dans LMDB

## Application graphique

Construite avec Tauri 2 (backend Rust) + Vue 3 (frontend TypeScript) :

- Integration dans la barre systeme avec indicateur d'etat
- Tableau de bord avec statistiques sur les menaces
- Analyse de fichiers par glisser-deposer
- Navigateur de quarantaine avec restauration/suppression
- Controles de surveillance en temps reel
- Parametres et configuration
- Prise en charge multilingue (10 langues)

## Dependances principales

| Categorie | Crate | Version | Fonction |
|-----------|-------|---------|----------|
| Asynchrone | tokio | 1.x | Environnement d'execution asynchrone |
| Parallelisme | rayon | - | Pool de threads pour l'analyse |
| YARA | yara-x | 1.14 | Moteur de correspondance de regles |
| Base de donnees | heed | - | Bindings LMDB |
| Analyse binaire | goblin | 0.9 | Analyseur PE/ELF/MachO |
| Cryptographie | aes-gcm | - | Chiffrement de quarantaine |
| Cryptographie | ed25519-dalek | - | Verification des mises a jour |
| ML | tract-onnx | - | Inference ONNX (optionnel) |
| WASM | wasmtime | 29 | Environnement d'execution des plugins |
| DNS | adblock | 0.12 | Moteur adblock Brave |
| CLI | clap | 4.x | Analyse des arguments |
| HTTP | axum | 0.8 | Serveur de mise a jour |
