> Este documento es una traduccion al espanol de la version en [English](../CLI.md).

# Referencia de la CLI

PRX-SD proporciona la herramienta de linea de comandos `sd` para la deteccion de amenazas y la proteccion del sistema.

## Opciones Globales

| Bandera | Descripcion | Valor por defecto |
|---------|-------------|-------------------|
| `--log-level <LEVEL>` | Nivel de detalle del registro: `trace`, `debug`, `info`, `warn`, `error` | `warn` |
| `--data-dir <PATH>` | Directorio de datos para firmas, cuarentena y configuracion | `~/.prx-sd/` |

---

## Escaneo

### `sd scan <PATH>`

Escanea un archivo o directorio en busca de amenazas.

```bash
sd scan /path/to/file
sd scan /home --recursive
sd scan /tmp --auto-quarantine --remediate
sd scan /path --json
sd scan /path --report report.html
```

| Opcion | Descripcion | Valor por defecto |
|--------|-------------|-------------------|
| `-r, --recursive <BOOL>` | Recorrer subdirectorios recursivamente | `true` para directorios |
| `--json` | Salida de resultados en formato JSON | |
| `-t, --threads <NUM>` | Numero de hilos del escaner | Cantidad de CPUs |
| `--auto-quarantine` | Poner en cuarentena automaticamente los archivos maliciosos | |
| `--remediate` | Remediacion automatica: terminar procesos, poner en cuarentena, limpiar persistencia | |
| `-e, --exclude <PATTERN>` | Patrones glob a excluir (repetible) | |
| `--report <PATH>` | Exportar resultados como informe HTML independiente | |

### `sd scan-memory`

Escanea la memoria de los procesos en ejecucion en busca de amenazas (solo Linux, requiere root).

```bash
sudo sd scan-memory
sudo sd scan-memory --pid 1234
sudo sd scan-memory --json
```

| Opcion | Descripcion |
|--------|-------------|
| `--pid <PID>` | Escanear un proceso especifico (omitir para escanear todos) |
| `--json` | Salida en formato JSON |

### `sd scan-usb [DEVICE]`

Escanea dispositivos USB/extraibles.

```bash
sd scan-usb
sd scan-usb /dev/sdb1 --auto-quarantine
```

| Opcion | Descripcion |
|--------|-------------|
| `--auto-quarantine` | Poner en cuarentena automaticamente las amenazas detectadas |

### `sd check-rootkit`

Verifica indicadores de rootkit (solo Linux).

```bash
sudo sd check-rootkit
sudo sd check-rootkit --json
```

Verificaciones: procesos ocultos, integridad de modulos del kernel, hooks de LD_PRELOAD, anomalias en /proc.

---

## Proteccion en Tiempo Real

### `sd monitor <PATHS...>`

Monitoreo del sistema de archivos en tiempo real.

```bash
sd monitor /home /tmp
sd monitor /home --block
sd monitor /home --daemon
```

| Opcion | Descripcion |
|--------|-------------|
| `--block` | Bloquear archivos maliciosos antes de su acceso (requiere root + fanotify en Linux) |
| `--daemon` | Ejecutar como demonio en segundo plano |

### `sd daemon [PATHS...]`

Ejecutar como demonio en segundo plano con monitoreo en tiempo real y actualizaciones automaticas.

```bash
sd daemon
sd daemon /home /tmp --update-hours 2
```

| Opcion | Descripcion | Valor por defecto |
|--------|-------------|-------------------|
| `--update-hours <NUM>` | Intervalo de verificacion de actualizaciones de firmas en horas | `4` |

Rutas monitoreadas por defecto: `/home`, `/tmp`.

---

## Gestion de Cuarentena

### `sd quarantine <SUBCOMMAND>`

Gestionar la boveda de cuarentena cifrada (AES-256-GCM).

```bash
sd quarantine list
sd quarantine restore <ID>
sd quarantine restore <ID> --to /safe/path
sd quarantine delete <ID>
sd quarantine delete-all --yes
sd quarantine stats
```

| Subcomando | Descripcion |
|------------|-------------|
| `list` | Listar todos los archivos en cuarentena |
| `restore <ID>` | Restaurar un archivo en cuarentena (`--to <PATH>` para ubicacion alternativa) |
| `delete <ID>` | Eliminar permanentemente un archivo en cuarentena |
| `delete-all` | Eliminar todos los archivos en cuarentena (`--yes` para omitir confirmacion) |
| `stats` | Mostrar estadisticas de cuarentena |

---

## Base de Datos de Firmas

### `sd update`

Verificar y aplicar actualizaciones de la base de datos de firmas.

```bash
sd update
sd update --check-only
sd update --force
sd update --server-url https://custom-server.example.com
```

| Opcion | Descripcion |
|--------|-------------|
| `--check-only` | Solo verificar si hay una actualizacion disponible |
| `--force` | Forzar la descarga aunque ya este actualizado |
| `--server-url <URL>` | Reemplazar la URL del servidor de actualizaciones |

### `sd import <PATH>`

Importar firmas de hash desde un archivo de lista de bloqueo.

```bash
sd import /path/to/blocklist.txt
```

Formato del archivo: una entrada por linea como `hex_hash nombre_malware`. Las lineas que comienzan con `#` son comentarios.

```
# Example blocklist
275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f EICAR.Test
ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa Ransom.WannaCry
```

### `sd import-clamav <PATHS...>`

Importar archivos de base de datos de firmas de ClamAV.

```bash
sd import-clamav main.cvd daily.cvd
sd import-clamav custom.hdb custom.hsb
```

Formatos soportados: `.cvd`, `.cld`, `.hdb`, `.hsb`.

### `sd info`

Mostrar la version del motor, el estado de la base de datos de firmas e informacion del sistema.

```bash
sd info
```

Muestra: version, cantidad de reglas YARA, cantidad de firmas de hash, estadisticas de cuarentena, informacion de la plataforma.

---

## Configuracion

### `sd config <SUBCOMMAND>`

Gestionar la configuracion del motor.

```bash
sd config show
sd config set scan.max_file_size 104857600
sd config set scan.follow_symlinks true
sd config reset
```

| Subcomando | Descripcion |
|------------|-------------|
| `show` | Mostrar la configuracion actual |
| `set <KEY> <VALUE>` | Establecer una clave de configuracion (ruta separada por puntos) |
| `reset` | Restablecer la configuracion predeterminada |

Los valores admiten tipos JSON: booleano (`true`/`false`), numeros, `null`, arreglos, objetos.

---

## Politica de Remediacion

### `sd policy <ACTION> [KEY] [VALUE]`

Gestionar las politicas de remediacion de amenazas.

```bash
sd policy show
sd policy set on_malicious "kill,quarantine,clean"
sd policy set on_suspicious "report,quarantine"
sd policy set kill_processes true
sd policy reset
```

| Accion | Descripcion |
|--------|-------------|
| `show` | Mostrar la politica actual |
| `set <KEY> <VALUE>` | Establecer un campo de la politica |
| `reset` | Restablecer la politica predeterminada |

**Claves de politica:**

| Clave | Descripcion | Valores |
|-------|-------------|---------|
| `on_malicious` | Acciones para amenazas maliciosas | Separados por coma: `report`, `quarantine`, `block`, `kill`, `clean`, `delete`, `isolate`, `blocklist` |
| `on_suspicious` | Acciones para amenazas sospechosas | Igual que arriba |
| `kill_processes` | Terminar procesos asociados | `true` / `false` |
| `clean_persistence` | Limpiar mecanismos de persistencia | `true` / `false` |
| `network_isolation` | Aislar conexiones de red | `true` / `false` |
| `audit_logging` | Registrar todas las acciones en el registro de auditoria | `true` / `false` |

---

## Programacion

### `sd schedule <SUBCOMMAND>`

Gestionar escaneos programados. Utiliza los programadores nativos de la plataforma: systemd timers (Linux), cron (Linux/macOS), launchd (macOS), Task Scheduler (Windows).

```bash
sd schedule add /home --frequency daily
sd schedule add /tmp --frequency hourly
sd schedule status
sd schedule remove
```

| Subcomando | Descripcion |
|------------|-------------|
| `add <PATH>` | Registrar un escaneo programado recurrente |
| `remove` | Eliminar el escaneo programado |
| `status` | Mostrar el estado de la programacion actual |

**Frecuencias:** `hourly`, `4h`, `12h`, `daily`, `weekly` (por defecto: `weekly`).

---

## Alertas

### `sd webhook <SUBCOMMAND>`

Gestionar los endpoints de alerta por webhook.

```bash
sd webhook list
sd webhook add my-slack https://hooks.slack.com/services/... --format slack
sd webhook add my-discord https://discord.com/api/webhooks/... --format discord
sd webhook add custom https://example.com/alert --format generic
sd webhook remove my-slack
sd webhook test
```

| Subcomando | Descripcion |
|------------|-------------|
| `list` | Listar los webhooks configurados |
| `add <NAME> <URL>` | Agregar un webhook (`--format`: `slack`, `discord`, `generic`) |
| `remove <NAME>` | Eliminar un webhook por nombre |
| `test` | Enviar una alerta de prueba a todos los webhooks |

### `sd email-alert <SUBCOMMAND>`

Gestionar la configuracion de alertas por correo electronico.

```bash
sd email-alert configure
sd email-alert test
sd email-alert send "Trojan.Generic" "high" "/tmp/malware.exe"
```

| Subcomando | Descripcion |
|------------|-------------|
| `configure` | Crear o mostrar la configuracion de correo SMTP |
| `test` | Enviar un correo de alerta de prueba |
| `send <NAME> <LEVEL> <PATH>` | Enviar un correo de alerta personalizado |

---

## Filtrado de DNS y Red

### `sd adblock <SUBCOMMAND>`

Gestionar el filtrado de dominios de publicidad y malware.

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

| Subcomando | Descripcion |
|------------|-------------|
| `enable` | Descargar listas de bloqueo e instalar bloqueo DNS (`/etc/hosts`) |
| `disable` | Eliminar las entradas de bloqueo DNS |
| `sync` | Forzar la descarga de todas las listas de filtro |
| `stats` | Mostrar estadisticas de filtrado |
| `check <URL>` | Verificar si una URL/dominio esta bloqueado |
| `log` | Mostrar entradas bloqueadas recientes (`-c, --count <NUM>`, por defecto: 50) |
| `add <NAME> <URL>` | Agregar una lista de filtro personalizada (`--category`: `ads`, `tracking`, `malware`, `social`) |
| `remove <NAME>` | Eliminar una lista de filtro |

### `sd dns-proxy`

Iniciar un proxy DNS local con filtrado de adblock, IOC y listas de bloqueo personalizadas.

```bash
sudo sd dns-proxy
sudo sd dns-proxy --listen 127.0.0.1:5353 --upstream 1.1.1.1:53
```

| Opcion | Descripcion | Valor por defecto |
|--------|-------------|-------------------|
| `--listen <ADDR>` | Direccion de escucha | `127.0.0.1:53` |
| `--upstream <ADDR>` | Servidor DNS de origen | `8.8.8.8:53` |
| `--log-path <PATH>` | Ruta del registro de consultas JSONL | `/tmp/prx-sd-dns.log` |

---

## Informes

### `sd report <OUTPUT>`

Generar un informe HTML independiente a partir de resultados de escaneo en JSON.

```bash
sd scan /path --json | sd report report.html
sd report report.html --input results.json
```

| Opcion | Descripcion | Valor por defecto |
|--------|-------------|-------------------|
| `--input <FILE>` | Archivo JSON de entrada (`-` para stdin) | `-` (stdin) |

### `sd status`

Mostrar el estado del demonio, incluyendo PID, tiempo de actividad, version de firmas y amenazas bloqueadas.

```bash
sd status
```

---

## Integracion

### `sd install-integration`

Instalar la integracion de escaneo con clic derecho en el administrador de archivos.

```bash
sd install-integration
```

Administradores de archivos soportados:
- **Linux:** Nautilus (GNOME Files), Dolphin (KDE), Nemo (Cinnamon)
- **macOS:** Finder Quick Action

### `sd self-update`

Verificar y aplicar actualizaciones del binario desde GitHub Releases.

```bash
sd self-update
sd self-update --check-only
```

| Opcion | Descripcion |
|--------|-------------|
| `--check-only` | Solo verificar si hay una actualizacion disponible |

---

## Ejemplos

### Configuracion Inicial

```bash
# Install
curl -fsSL https://raw.githubusercontent.com/openprx/prx-sd/main/install.sh | bash

# Import additional signatures
sd import my-custom-hashes.txt
sd import-clamav main.cvd daily.cvd

# Verify setup
sd info
```

### Proteccion Diaria

```bash
# Start daemon (monitors /home and /tmp, updates every 4h)
sd daemon

# Or manual scan
sd scan /home --recursive --auto-quarantine

# Check status
sd status
```

### Respuesta a Incidentes

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

### Automatizacion

```bash
# Schedule weekly scan
sd schedule add /home --frequency weekly

# Set up alerts
sd webhook add slack https://hooks.slack.com/services/T.../B.../xxx --format slack
sd email-alert configure

# JSON output for scripts
sd scan /path --json | jq '.threats[] | .name'
```
