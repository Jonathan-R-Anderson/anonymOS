> Este documento es una traduccion al espanol de la version en [English](../ARCHITECTURE.md).

# Arquitectura

PRX-SD esta estructurado como un workspace de Cargo con crates modulares, cada uno responsable de un dominio especifico.

## Estructura del Workspace

```
prx-sd/
├── crates/
│   ├── cli/           # Binario "sd" — interfaz de linea de comandos
│   ├── core/          # Coordinacion del motor de escaneo
│   ├── signatures/    # Base de datos de hashes (LMDB) + motor de reglas YARA-X
│   ├── parsers/       # Analizadores de formatos binarios
│   ├── heuristic/     # Puntuacion heuristica + inferencia ML
│   ├── realtime/      # Monitoreo del sistema de archivos + filtrado de red
│   ├── quarantine/    # Boveda de cuarentena cifrada
│   ├── remediation/   # Acciones de respuesta a amenazas
│   ├── sandbox/       # Aislamiento de procesos + analisis de comportamiento
│   ├── plugins/       # Entorno de ejecucion de plugins WebAssembly
│   └── updater/       # Cliente de actualizacion de firmas
├── update-server/     # Servidor de distribucion de firmas (Axum)
├── gui/               # Interfaz grafica de escritorio (Tauri 2 + Vue 3)
├── drivers/           # Controladores del kernel del SO
│   └── windows-minifilter/  # Minifilter del sistema de archivos de Windows (C)
├── signatures-db/     # Firmas minimas embebidas
├── packaging/         # Empaquetado para distribucion
├── tests/             # Pruebas de integracion
├── tools/             # Scripts de compilacion y utilidades
├── install.sh         # Script de instalacion
└── uninstall.sh       # Script de desinstalacion
```

## Grafo de Dependencias entre Crates

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

## Pipeline de Deteccion

El motor de escaneo (`core`) coordina un pipeline de deteccion multicapa:

```
                    ┌──────────────┐
                    │  File Input  │
                    └──────┬───────┘
                           │
                    ┌──────▼───────┐
                    │ Magic Number │  Identificar: PE, ELF, MachO,
                    │  Detection   │  PDF, ZIP, Office, desconocido
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

### Detalles de las Capas

1. **Hash Matching** -- Busqueda O(1) en la base de datos LMDB que contiene hashes SHA-256 y MD5 provenientes de ClamAV, abuse.ch, VirusShare y listas de bloqueo personalizadas.

2. **Reglas YARA-X** -- Coincidencia de patrones utilizando el motor YARA-X (implementacion nativa en Rust de YARA). Las reglas se cargan desde los valores predeterminados embebidos y el repositorio externo de firmas.

3. **Analisis Heuristico** -- Analisis especifico por tipo de archivo:
   - **PE:** Entropia de secciones, importaciones de API sospechosas (CreateRemoteThread, VirtualAllocEx), deteccion de empaquetadores (UPX, Themida), anomalias de marca de tiempo
   - **ELF:** Entropia de secciones, referencias a LD_PRELOAD, persistencia en cron/systemd, patrones de backdoor SSH
   - **MachO:** Entropia de secciones, inyeccion de dylib, persistencia en LaunchAgent, acceso a Keychain

4. **Inferencia ML** (opcional, feature flag `onnx`) -- Evaluacion de modelos ONNX mediante tract:
   - PE: Vector de caracteristicas de 64 dimensiones (hashes de tabla de importaciones, entropia de secciones, firmas de API)
   - ELF: Vector de caracteristicas de 48 dimensiones (entropia de secciones, tabla de simbolos, bibliotecas dinamicas)

5. **VirusTotal Cloud** -- Respaldo para archivos no coincidentes localmente. Consulta la API de VirusTotal (nivel gratuito: 500 consultas/dia). Los resultados se almacenan en cache en LMDB.

### Puntuacion

- Puntuacion >= 60: **Malicious**
- Puntuacion 30-59: **Suspicious**
- Puntuacion < 30: **Clean**

El veredicto final es el nivel de amenaza mas alto de cualquier capa de deteccion.

## Proteccion en Tiempo Real

El crate `realtime` proporciona proteccion continua a traves de multiples subsistemas:

| Subsistema | Linux | macOS | Windows |
|------------|-------|-------|---------|
| Monitoreo de archivos | fanotify + epoll | FSEvents (notify) | ReadDirectoryChangesW (notify) |
| Intercepcion de procesos | FAN_OPEN_EXEC_PERM | - | Minifilter (planificado) |
| Escaneo de memoria | /proc/pid/mem | - | - |
| Deteccion de ransomware | Monitoreo de patrones de escritura+renombrado | Monitoreo de patrones de escritura+renombrado | Monitoreo de patrones de escritura+renombrado |
| Directorios protegidos | ~/.ssh, /etc/shadow, /etc/systemd | ~/Library, /etc | Registry Run keys |
| Filtrado DNS | Motor Adblock + listas IOC | Motor Adblock + listas IOC | Motor Adblock + listas IOC |
| Monitoreo de comportamiento | /proc + audit (execve/connect/open) | - | - |

## Boveda de Cuarentena

Los archivos se ponen en cuarentena utilizando cifrado autenticado AES-256-GCM:

1. Generar clave aleatoria de 256 bits + nonce de 96 bits
2. Cifrar el contenido del archivo con AES-256-GCM
3. Almacenar el archivo cifrado con nombre de archivo UUID
4. Guardar metadatos JSON (ruta original, hash, nombre de amenaza, marca de tiempo)
5. La restauracion descifra y verifica la integridad antes de escribir de vuelta

## Pipeline de Remediacion

Cuando se utiliza `--remediate`:

```
Threat Detected
  ├── 1. Kill Process     (SIGKILL en Linux/macOS, TerminateProcess en Windows)
  ├── 2. Quarantine File  (boveda cifrada con AES-256-GCM)
  └── 3. Clean Persistence
        ├── Linux:   cron jobs, systemd services, LD_PRELOAD
        ├── macOS:   LaunchAgents, plist entries, Keychain
        └── Windows: Run/RunOnce registry, scheduled tasks, services
```

Las acciones son configurables mediante `sd policy set`.

## Base de Datos de Firmas

### Firmas Embebidas (`signatures-db/`)

Conjunto minimo de firmas compilado en el binario `sd` mediante `include_str!`:
- Firma de prueba EICAR
- Reglas YARA principales (ransomware, trojan, backdoor, etc.)
- Hashes de malware conocido (WannaCry, Emotet, NotPetya)

### Firmas Externas ([prx-sd-signatures](https://github.com/openprx/prx-sd-signatures))

Inteligencia de amenazas completa y actualizada frecuentemente:
- Mas de 38,800 reglas YARA de 9 fuentes
- Listas de bloqueo de hashes de fuentes abuse.ch
- Listas IOC: mas de 585K IPs, dominios y URLs maliciosos

### Almacenamiento

- **Hashes:** LMDB (crate heed) para busquedas clave-valor en O(1)
- **Reglas YARA:** Cargadas y compiladas por YARA-X al inicio
- **Listas IOC:** HashSet en memoria para coincidencia rapida de IP/dominio/URL

## Sistema de Plugins

PRX-SD soporta plugins WebAssembly mediante Wasmtime:

- Los plugins son archivos `.wasm` con un manifiesto (`plugin.json`)
- Soporte WASI para acceso al sistema de archivos y al entorno
- Registro de plugins para descubrimiento y carga
- Funciones del host expuestas a los plugins para resultados de escaneo y configuracion

## Sistema de Actualizaciones

El crate `updater` y el `update-server` proporcionan un pipeline de actualizacion seguro:

1. El cliente consulta al servidor de actualizaciones por nuevas versiones de firmas
2. El servidor responde con informacion de version y URL de descarga
3. El cliente descarga el paquete de firmas comprimido con zstd
4. La firma del paquete se verifica con Ed25519 (ed25519-dalek)
5. Las firmas se extraen y se cargan en LMDB

## Aplicacion GUI

Construida con Tauri 2 (backend en Rust) + Vue 3 (frontend en TypeScript):

- Integracion con la bandeja del sistema con indicador de estado
- Panel de control con estadisticas de amenazas
- Escaneo de archivos mediante arrastrar y soltar
- Explorador de cuarentena con opciones de restaurar/eliminar
- Controles de monitoreo en tiempo real
- Ajustes y configuracion
- Soporte multiidioma (10 idiomas)

## Dependencias Principales

| Categoria | Crate | Version | Proposito |
|-----------|-------|---------|-----------|
| Asincronia | tokio | 1.x | Entorno de ejecucion asincrono |
| Paralelismo | rayon | - | Pool de hilos para escaneo |
| YARA | yara-x | 1.14 | Motor de coincidencia de reglas |
| Base de datos | heed | - | Bindings de LMDB |
| Analisis binario | goblin | 0.9 | Analizador de PE/ELF/MachO |
| Criptografia | aes-gcm | - | Cifrado de cuarentena |
| Criptografia | ed25519-dalek | - | Verificacion de actualizaciones |
| ML | tract-onnx | - | Inferencia ONNX (opcional) |
| WASM | wasmtime | 29 | Entorno de ejecucion de plugins |
| DNS | adblock | 0.12 | Motor adblock de Brave |
| CLI | clap | 4.x | Analisis de argumentos |
| HTTP | axum | 0.8 | Servidor de actualizaciones |
