> Dieses Dokument ist eine deutsche Ubersetzung der [English](../CLI.md) Version.

# CLI-Referenz

PRX-SD stellt das Kommandozeilenwerkzeug `sd` zur Bedrohungserkennung und zum Systemschutz bereit.

## Globale Optionen

| Flag | Beschreibung | Standard |
|------|--------------|----------|
| `--log-level <LEVEL>` | Protokollierungsstufe: `trace`, `debug`, `info`, `warn`, `error` | `warn` |
| `--data-dir <PATH>` | Datenverzeichnis fuer Signaturen, Quarantaene, Konfiguration | `~/.prx-sd/` |

---

## Scannen

### `sd scan <PATH>`

Eine Datei oder ein Verzeichnis auf Bedrohungen scannen.

```bash
sd scan /path/to/file
sd scan /home --recursive
sd scan /tmp --auto-quarantine --remediate
sd scan /path --json
sd scan /path --report report.html
```

| Option | Beschreibung | Standard |
|--------|--------------|----------|
| `-r, --recursive <BOOL>` | Unterverzeichnisse rekursiv durchsuchen | `true` fuer Verzeichnisse |
| `--json` | Ergebnisse als JSON ausgeben | |
| `-t, --threads <NUM>` | Anzahl der Scanner-Threads | CPU-Anzahl |
| `--auto-quarantine` | Schaedliche Dateien automatisch unter Quarantaene stellen | |
| `--remediate` | Automatische Bereinigung: Prozesse beenden, Quarantaene, Persistenz entfernen | |
| `-e, --exclude <PATTERN>` | Glob-Muster zum Ausschliessen (wiederholbar) | |
| `--report <PATH>` | Ergebnisse als eigenstaendigen HTML-Bericht exportieren | |

### `sd scan-memory`

Arbeitsspeicher laufender Prozesse auf Bedrohungen scannen (nur Linux, Root-Rechte erforderlich).

```bash
sudo sd scan-memory
sudo sd scan-memory --pid 1234
sudo sd scan-memory --json
```

| Option | Beschreibung |
|--------|--------------|
| `--pid <PID>` | Einen bestimmten Prozess scannen (ohne Angabe werden alle gescannt) |
| `--json` | Ausgabe als JSON |

### `sd scan-usb [DEVICE]`

USB-/Wechseldatentraeger scannen.

```bash
sd scan-usb
sd scan-usb /dev/sdb1 --auto-quarantine
```

| Option | Beschreibung |
|--------|--------------|
| `--auto-quarantine` | Erkannte Bedrohungen automatisch unter Quarantaene stellen |

### `sd check-rootkit`

Auf Rootkit-Indikatoren pruefen (nur Linux).

```bash
sudo sd check-rootkit
sudo sd check-rootkit --json
```

Prueft: Versteckte Prozesse, Kernelmodul-Integritaet, LD_PRELOAD-Hooks, /proc-Anomalien.

---

## Echtzeitschutz

### `sd monitor <PATHS...>`

Echtzeit-Dateisystemueberwachung.

```bash
sd monitor /home /tmp
sd monitor /home --block
sd monitor /home --daemon
```

| Option | Beschreibung |
|--------|--------------|
| `--block` | Schaedliche Dateien vor dem Zugriff blockieren (erfordert Root + fanotify unter Linux) |
| `--daemon` | Als Hintergrund-Daemon ausfuehren |

### `sd daemon [PATHS...]`

Als Hintergrund-Daemon mit Echtzeituberwachung und automatischen Updates ausfuehren.

```bash
sd daemon
sd daemon /home /tmp --update-hours 2
```

| Option | Beschreibung | Standard |
|--------|--------------|----------|
| `--update-hours <NUM>` | Pruefintervall fuer Signatur-Updates in Stunden | `4` |

Standardmaessig ueberwachte Pfade: `/home`, `/tmp`.

---

## Quarantaeneverwaltung

### `sd quarantine <SUBCOMMAND>`

Den verschluesselten Quarantaenetresor verwalten (AES-256-GCM).

```bash
sd quarantine list
sd quarantine restore <ID>
sd quarantine restore <ID> --to /safe/path
sd quarantine delete <ID>
sd quarantine delete-all --yes
sd quarantine stats
```

| Unterbefehl | Beschreibung |
|-------------|--------------|
| `list` | Alle unter Quarantaene gestellten Dateien auflisten |
| `restore <ID>` | Eine Datei aus der Quarantaene wiederherstellen (`--to <PATH>` fuer alternativen Speicherort) |
| `delete <ID>` | Eine Datei dauerhaft aus der Quarantaene loeschen |
| `delete-all` | Alle Dateien in der Quarantaene loeschen (`--yes` um Bestaetigung zu ueberspringen) |
| `stats` | Quarantaene-Statistiken anzeigen |

---

## Signaturdatenbank

### `sd update`

Auf Signatur-Updates pruefen und diese anwenden.

```bash
sd update
sd update --check-only
sd update --force
sd update --server-url https://custom-server.example.com
```

| Option | Beschreibung |
|--------|--------------|
| `--check-only` | Nur pruefen, ob ein Update verfuegbar ist |
| `--force` | Erneuten Download erzwingen, auch wenn bereits aktuell |
| `--server-url <URL>` | URL des Update-Servers ueberschreiben |

### `sd import <PATH>`

Hash-Signaturen aus einer Sperrlisten-Datei importieren.

```bash
sd import /path/to/blocklist.txt
```

Dateiformat: Ein Eintrag pro Zeile im Format `hex_hash malware_name`. Zeilen, die mit `#` beginnen, sind Kommentare.

```
# Beispiel-Sperrliste
275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f EICAR.Test
ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa Ransom.WannaCry
```

### `sd import-clamav <PATHS...>`

ClamAV-Signaturdatenbankdateien importieren.

```bash
sd import-clamav main.cvd daily.cvd
sd import-clamav custom.hdb custom.hsb
```

Unterstuetzte Formate: `.cvd`, `.cld`, `.hdb`, `.hsb`.

### `sd info`

Engine-Version, Signaturdatenbank-Status und Systeminformationen anzeigen.

```bash
sd info
```

Zeigt: Version, Anzahl der YARA-Regeln, Anzahl der Hash-Signaturen, Quarantaene-Statistiken, Plattforminformationen.

---

## Konfiguration

### `sd config <SUBCOMMAND>`

Engine-Konfiguration verwalten.

```bash
sd config show
sd config set scan.max_file_size 104857600
sd config set scan.follow_symlinks true
sd config reset
```

| Unterbefehl | Beschreibung |
|-------------|--------------|
| `show` | Aktuelle Konfiguration anzeigen |
| `set <KEY> <VALUE>` | Einen Konfigurationswert setzen (punktgetrennte Pfadangabe) |
| `reset` | Auf Standardkonfiguration zuruecksetzen |

Werte unterstuetzen JSON-Typen: Boolean (`true`/`false`), Zahlen, `null`, Arrays, Objekte.

---

## Bereinigungsrichtlinie

### `sd policy <ACTION> [KEY] [VALUE]`

Richtlinien zur Bedrohungsbereinigung verwalten.

```bash
sd policy show
sd policy set on_malicious "kill,quarantine,clean"
sd policy set on_suspicious "report,quarantine"
sd policy set kill_processes true
sd policy reset
```

| Aktion | Beschreibung |
|--------|--------------|
| `show` | Aktuelle Richtlinie anzeigen |
| `set <KEY> <VALUE>` | Einen Richtlinienwert setzen |
| `reset` | Auf Standard-Richtlinie zuruecksetzen |

**Richtlinienschluessel:**

| Schluessel | Beschreibung | Werte |
|------------|--------------|-------|
| `on_malicious` | Aktionen bei schaedlichen Bedrohungen | Kommagetrennt: `report`, `quarantine`, `block`, `kill`, `clean`, `delete`, `isolate`, `blocklist` |
| `on_suspicious` | Aktionen bei verdaechtigen Bedrohungen | Wie oben |
| `kill_processes` | Zugehoerige Prozesse beenden | `true` / `false` |
| `clean_persistence` | Persistenzmechanismen bereinigen | `true` / `false` |
| `network_isolation` | Netzwerkverbindungen isolieren | `true` / `false` |
| `audit_logging` | Alle Aktionen im Audit-Protokoll festhalten | `true` / `false` |

---

## Zeitplanung

### `sd schedule <SUBCOMMAND>`

Geplante Scans verwalten. Verwendet plattformnative Planer: systemd-Timer (Linux), cron (Linux/macOS), launchd (macOS), Aufgabenplanung (Windows).

```bash
sd schedule add /home --frequency daily
sd schedule add /tmp --frequency hourly
sd schedule status
sd schedule remove
```

| Unterbefehl | Beschreibung |
|-------------|--------------|
| `add <PATH>` | Einen wiederkehrenden geplanten Scan registrieren |
| `remove` | Den geplanten Scan entfernen |
| `status` | Aktuellen Planungsstatus anzeigen |

**Haeufigkeiten:** `hourly`, `4h`, `12h`, `daily`, `weekly` (Standard: `weekly`).

---

## Benachrichtigungen

### `sd webhook <SUBCOMMAND>`

Webhook-Benachrichtigungsendpunkte verwalten.

```bash
sd webhook list
sd webhook add my-slack https://hooks.slack.com/services/... --format slack
sd webhook add my-discord https://discord.com/api/webhooks/... --format discord
sd webhook add custom https://example.com/alert --format generic
sd webhook remove my-slack
sd webhook test
```

| Unterbefehl | Beschreibung |
|-------------|--------------|
| `list` | Konfigurierte Webhooks auflisten |
| `add <NAME> <URL>` | Einen Webhook hinzufuegen (`--format`: `slack`, `discord`, `generic`) |
| `remove <NAME>` | Einen Webhook nach Name entfernen |
| `test` | Einen Testalarm an alle Webhooks senden |

### `sd email-alert <SUBCOMMAND>`

E-Mail-Benachrichtigungskonfiguration verwalten.

```bash
sd email-alert configure
sd email-alert test
sd email-alert send "Trojan.Generic" "high" "/tmp/malware.exe"
```

| Unterbefehl | Beschreibung |
|-------------|--------------|
| `configure` | SMTP-E-Mail-Konfiguration erstellen oder anzeigen |
| `test` | Eine Test-Benachrichtigungs-E-Mail senden |
| `send <NAME> <LEVEL> <PATH>` | Eine benutzerdefinierte Benachrichtigungs-E-Mail senden |

---

## DNS- und Netzwerkfilterung

### `sd adblock <SUBCOMMAND>`

Werbeblocker- und Malware-Domain-Filterung verwalten.

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

| Unterbefehl | Beschreibung |
|-------------|--------------|
| `enable` | Sperrlisten herunterladen und DNS-Blockierung installieren (`/etc/hosts`) |
| `disable` | DNS-Blockierungseintraege entfernen |
| `sync` | Alle Filterlisten erneut herunterladen |
| `stats` | Filterstatistiken anzeigen |
| `check <URL>` | Pruefen, ob eine URL/Domain blockiert ist |
| `log` | Letzte blockierte Eintraege anzeigen (`-c, --count <NUM>`, Standard: 50) |
| `add <NAME> <URL>` | Eine benutzerdefinierte Filterliste hinzufuegen (`--category`: `ads`, `tracking`, `malware`, `social`) |
| `remove <NAME>` | Eine Filterliste entfernen |

### `sd dns-proxy`

Einen lokalen DNS-Proxy mit Werbeblocker-, IOC- und benutzerdefinierter Sperrlistenfilterung starten.

```bash
sudo sd dns-proxy
sudo sd dns-proxy --listen 127.0.0.1:5353 --upstream 1.1.1.1:53
```

| Option | Beschreibung | Standard |
|--------|--------------|----------|
| `--listen <ADDR>` | Lausch-Adresse | `127.0.0.1:53` |
| `--upstream <ADDR>` | Vorgelagerter DNS-Server | `8.8.8.8:53` |
| `--log-path <PATH>` | Pfad fuer JSONL-Abfrageprotokoll | `/tmp/prx-sd-dns.log` |

---

## Berichterstattung

### `sd report <OUTPUT>`

Einen eigenstaendigen HTML-Bericht aus JSON-Scan-Ergebnissen erstellen.

```bash
sd scan /path --json | sd report report.html
sd report report.html --input results.json
```

| Option | Beschreibung | Standard |
|--------|--------------|----------|
| `--input <FILE>` | JSON-Eingabedatei (`-` fuer stdin) | `-` (stdin) |

### `sd status`

Daemon-Status anzeigen, einschliesslich PID, Betriebszeit, Signaturversion und blockierter Bedrohungen.

```bash
sd status
```

---

## Integration

### `sd install-integration`

Rechtsklick-Scan-Integration fuer Dateimanager installieren.

```bash
sd install-integration
```

Unterstuetzte Dateimanager:
- **Linux:** Nautilus (GNOME Files), Dolphin (KDE), Nemo (Cinnamon)
- **macOS:** Finder Quick Action

### `sd self-update`

Auf Binaer-Updates von GitHub Releases pruefen und diese anwenden.

```bash
sd self-update
sd self-update --check-only
```

| Option | Beschreibung |
|--------|--------------|
| `--check-only` | Nur pruefen, ob ein Update verfuegbar ist |

---

## Beispiele

### Ersteinrichtung

```bash
# Installieren
curl -fsSL https://raw.githubusercontent.com/openprx/prx-sd/main/install.sh | bash

# Zusaetzliche Signaturen importieren
sd import my-custom-hashes.txt
sd import-clamav main.cvd daily.cvd

# Einrichtung ueberpruefen
sd info
```

### Taeglicher Schutz

```bash
# Daemon starten (ueberwacht /home und /tmp, Updates alle 4 Stunden)
sd daemon

# Oder manueller Scan
sd scan /home --recursive --auto-quarantine

# Status pruefen
sd status
```

### Reaktion auf Sicherheitsvorfaelle

```bash
# Scan mit vollstaendiger Bereinigung
sudo sd scan /tmp --auto-quarantine --remediate

# Arbeitsspeicher auf Bedrohungen pruefen
sudo sd scan-memory

# Auf Rootkits pruefen
sudo sd check-rootkit

# Quarantaene ueberpruefen
sd quarantine list
sd quarantine restore <ID> --to /safe/location
```

### Automatisierung

```bash
# Woechentlichen Scan planen
sd schedule add /home --frequency weekly

# Benachrichtigungen einrichten
sd webhook add slack https://hooks.slack.com/services/T.../B.../xxx --format slack
sd email-alert configure

# JSON-Ausgabe fuer Skripte
sd scan /path --json | jq '.threats[] | .name'
```
