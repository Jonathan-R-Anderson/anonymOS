> Dieses Dokument ist eine deutsche Ubersetzung der [English](../ARCHITECTURE.md) Version.

# Architektur

PRX-SD ist als Cargo-Workspace mit modularen Crates aufgebaut, wobei jedes Crate fuer einen bestimmten Aufgabenbereich verantwortlich ist.

## Workspace-Struktur

```
prx-sd/
├── crates/
│   ├── cli/           # "sd"-Binaerdatei — Kommandozeilenschnittstelle
│   ├── core/          # Koordination der Scan-Engine
│   ├── signatures/    # Hash-Datenbank (LMDB) + YARA-X-Regelengine
│   ├── parsers/       # Parser fuer Binaerformate
│   ├── heuristic/     # Heuristische Bewertung + ML-Inferenz
│   ├── realtime/      # Dateisystemueberwachung + Netzwerkfilterung
│   ├── quarantine/    # Verschluesselter Quarantaenetresor
│   ├── remediation/   # Massnahmen zur Bedrohungsbehandlung
│   ├── sandbox/       # Prozessisolierung + Verhaltensanalyse
│   ├── plugins/       # WebAssembly-Plugin-Laufzeitumgebung
│   └── updater/       # Signatur-Update-Client
├── update-server/     # Signaturverteilungsserver (Axum)
├── gui/               # Desktop-GUI (Tauri 2 + Vue 3)
├── drivers/           # Betriebssystem-Kerneltreiber
│   └── windows-minifilter/  # Windows-Dateisystem-Minifilter (C)
├── signatures-db/     # Eingebettete Minimalsignaturen
├── packaging/         # Distributionspaketierung
├── tests/             # Integrationstests
├── tools/             # Build- und Hilfsskripte
├── install.sh         # Installationsskript
└── uninstall.sh       # Deinstallationsskript
```

## Crate-Abhaengigkeitsgraph

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

## Erkennungspipeline

Die Scan-Engine (`core`) koordiniert eine mehrstufige Erkennungspipeline:

```
                    ┌──────────────┐
                    │  Dateieingabe │
                    └──────┬───────┘
                           │
                    ┌──────▼───────┐
                    │  Magic Number │  Erkennung: PE, ELF, MachO,
                    │  Erkennung    │  PDF, ZIP, Office, unbekannt
                    └──────┬───────┘
                           │
              ┌────────────┼────────────┐
              │            │            │
       ┌──────▼──────┐    │     ┌──────▼──────┐
       │    Hash-     │    │     │   YARA-X-   │
       │  Abgleich    │    │     │   Regeln    │
       │  (LMDB)     │    │     │  (38K+)     │
       └──────┬──────┘    │     └──────┬──────┘
              │     ┌─────▼─────┐      │
              │     │Heuristische│      │
              │     │  Analyse   │      │
              │     └─────┬─────┘      │
              │           │            │
              │    ┌──────▼──────┐     │
              │    │ ML-Inferenz │     │
              │    │  (ONNX)    │     │
              │    └──────┬─────┘     │
              │           │            │
              │    ┌──────▼──────┐     │
              │    │ VirusTotal  │     │
              │    │ Cloud-Abfr. │     │
              │    └──────┬─────┘     │
              │           │            │
              └───────────┼────────────┘
                          │
                   ┌──────▼──────┐
                   │ Aggregiertes │
                   │   Ergebnis   │
                   └─────────────┘
                   Clean / Suspicious / Malicious
```

### Ebenen im Detail

1. **Hash-Abgleich** — O(1)-Suche in der LMDB-Datenbank mit SHA-256- und MD5-Hashes aus ClamAV, abuse.ch, VirusShare und benutzerdefinierten Sperrlisten.

2. **YARA-X-Regeln** — Mustererkennung mit der YARA-X-Engine (native Rust-Implementierung von YARA). Regeln werden aus eingebetteten Standardregeln und dem externen Signatur-Repository geladen.

3. **Heuristische Analyse** — Dateityp-spezifische Analyse:
   - **PE:** Sektionsentropie, verdaechtige API-Importe (CreateRemoteThread, VirtualAllocEx), Packer-Erkennung (UPX, Themida), Zeitstempel-Anomalien
   - **ELF:** Sektionsentropie, LD_PRELOAD-Referenzen, cron/systemd-Persistenz, SSH-Backdoor-Muster
   - **MachO:** Sektionsentropie, dylib-Injektion, LaunchAgent-Persistenz, Keychain-Zugriff

4. **ML-Inferenz** (optional, Feature-Flag `onnx`) — ONNX-Modellauswertung ueber tract:
   - PE: 64-dimensionaler Merkmalsvektor (Import-Tabellen-Hashes, Sektionsentropie, API-Signaturen)
   - ELF: 48-dimensionaler Merkmalsvektor (Sektionsentropie, Symboltabelle, dynamische Bibliotheken)

5. **VirusTotal Cloud** — Rueckfalloption fuer lokal nicht erkannte Dateien. Abfrage der VirusTotal-API (kostenlose Stufe: 500 Abfragen/Tag). Ergebnisse werden in LMDB zwischengespeichert.

### Bewertung

- Punktzahl >= 60: **Malicious** (Schaedlich)
- Punktzahl 30-59: **Suspicious** (Verdaechtig)
- Punktzahl < 30: **Clean** (Sauber)

Das endgueltige Ergebnis entspricht der hoechsten Bedrohungsstufe aller Erkennungsebenen.

## Echtzeitschutz

Das `realtime`-Crate bietet kontinuierlichen Schutz durch mehrere Teilsysteme:

| Teilsystem | Linux | macOS | Windows |
|------------|-------|-------|---------|
| Dateisystemueberwachung | fanotify + epoll | FSEvents (notify) | ReadDirectoryChangesW (notify) |
| Prozess-Abfangen | FAN_OPEN_EXEC_PERM | - | Minifilter (geplant) |
| Speicher-Scan | /proc/pid/mem | - | - |
| Ransomware-Erkennung | Schreib-+Umbenennungsmuster-Ueberwachung | Schreib-+Umbenennungsmuster-Ueberwachung | Schreib-+Umbenennungsmuster-Ueberwachung |
| Geschuetzte Verzeichnisse | ~/.ssh, /etc/shadow, /etc/systemd | ~/Library, /etc | Registry Run Keys |
| DNS-Filterung | Adblock-Engine + IOC-Listen | Adblock-Engine + IOC-Listen | Adblock-Engine + IOC-Listen |
| Verhaltensueberwachung | /proc + audit (execve/connect/open) | - | - |

## Quarantaenetresor

Dateien werden mittels AES-256-GCM-authentifizierter Verschluesselung unter Quarantaene gestellt:

1. Zufaelligen 256-Bit-Schluessel + 96-Bit-Nonce generieren
2. Dateiinhalt mit AES-256-GCM verschluesseln
3. Verschluesselte Datei mit UUID-Dateiname speichern
4. JSON-Metadaten speichern (Originalpfad, Hash, Bedrohungsname, Zeitstempel)
5. Wiederherstellung entschluesselt und prueft die Integritaet vor dem Zurueckschreiben

## Bereinigungspipeline

Bei Verwendung von `--remediate`:

```
Bedrohung erkannt
  ├── 1. Prozess beenden   (SIGKILL unter Linux/macOS, TerminateProcess unter Windows)
  ├── 2. Datei unter Quarantaene stellen  (AES-256-GCM-verschluesselter Tresor)
  └── 3. Persistenz bereinigen
        ├── Linux:   Cron-Jobs, systemd-Dienste, LD_PRELOAD
        ├── macOS:   LaunchAgents, plist-Eintraege, Keychain
        └── Windows: Run/RunOnce-Registry, geplante Aufgaben, Dienste
```

Aktionen sind ueber `sd policy set` konfigurierbar.

## Signaturdatenbank

### Eingebettete Signaturen (`signatures-db/`)

Minimaler Signatursatz, der ueber `include_str!` in die `sd`-Binaerdatei kompiliert wird:
- EICAR-Testsignatur
- Kern-YARA-Regeln (Ransomware, Trojaner, Backdoor usw.)
- Bekannte Malware-Hashes (WannaCry, Emotet, NotPetya)

### Externe Signaturen ([prx-sd-signatures](https://github.com/openprx/prx-sd-signatures))

Umfassende, regelmaessig aktualisierte Bedrohungsintelligenz:
- 38.800+ YARA-Regeln aus 9 Quellen
- Hash-Sperrlisten aus abuse.ch-Feeds
- IOC-Listen: 585K+ schaedliche IPs, Domains, URLs

### Speicherung

- **Hashes:** LMDB (heed-Crate) fuer O(1)-Schluessel-Wert-Suchen
- **YARA-Regeln:** Von YARA-X beim Start geladen und kompiliert
- **IOC-Listen:** In-Memory-HashSet fuer schnelle IP-/Domain-/URL-Zuordnung

## Plugin-System

PRX-SD unterstuetzt WebAssembly-Plugins ueber Wasmtime:

- Plugins sind `.wasm`-Dateien mit einem Manifest (`plugin.json`)
- WASI-Unterstuetzung fuer Dateisystem- und Umgebungszugriff
- Plugin-Registry zur Erkennung und zum Laden
- Host-Funktionen, die Plugins fuer Scan-Ergebnisse und Konfiguration bereitgestellt werden

## Update-System

Das `updater`-Crate und der `update-server` bieten eine sichere Update-Pipeline:

1. Client prueft beim Update-Server auf neue Signaturversionen
2. Server antwortet mit Versionsinformationen und Download-URL
3. Client laedt zstd-komprimiertes Signaturpaket herunter
4. Paketsignatur wird mit Ed25519 (ed25519-dalek) verifiziert
5. Signaturen werden extrahiert und in LMDB geladen

## GUI-Anwendung

Erstellt mit Tauri 2 (Rust-Backend) + Vue 3 (TypeScript-Frontend):

- Systemleisten-Integration mit Statusanzeige
- Dashboard mit Bedrohungsstatistiken
- Drag-and-Drop-Dateiscan
- Quarantaene-Browser mit Wiederherstellung/Loeschung
- Echtzeituberwachungs-Steuerung
- Einstellungen und Konfiguration
- Mehrsprachige Unterstuetzung (10 Sprachen)

## Wichtige Abhaengigkeiten

| Kategorie | Crate | Version | Zweck |
|-----------|-------|---------|-------|
| Async | tokio | 1.x | Asynchrone Laufzeitumgebung |
| Parallelitaet | rayon | - | Thread-Pool fuer Scans |
| YARA | yara-x | 1.14 | Regelabgleich-Engine |
| Datenbank | heed | - | LMDB-Bindings |
| Binaeranalyse | goblin | 0.9 | PE/ELF/MachO-Parser |
| Kryptographie | aes-gcm | - | Quarantaene-Verschluesselung |
| Kryptographie | ed25519-dalek | - | Update-Verifizierung |
| ML | tract-onnx | - | ONNX-Inferenz (optional) |
| WASM | wasmtime | 29 | Plugin-Laufzeitumgebung |
| DNS | adblock | 0.12 | Brave-Adblock-Engine |
| CLI | clap | 4.x | Argumentverarbeitung |
| HTTP | axum | 0.8 | Update-Server |
