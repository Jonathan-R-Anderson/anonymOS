> Этот документ является русским переводом версии на [English](../CLI.md).

# Справочник по CLI

PRX-SD предоставляет инструмент командной строки `sd` для обнаружения угроз и защиты системы.

## Глобальные параметры

| Флаг | Описание | По умолчанию |
|------|----------|--------------|
| `--log-level <LEVEL>` | Уровень подробности логирования: `trace`, `debug`, `info`, `warn`, `error` | `warn` |
| `--data-dir <PATH>` | Каталог данных для сигнатур, карантина, конфигурации | `~/.prx-sd/` |

---

## Сканирование

### `sd scan <PATH>`

Сканирование файла или каталога на наличие угроз.

```bash
sd scan /path/to/file
sd scan /home --recursive
sd scan /tmp --auto-quarantine --remediate
sd scan /path --json
sd scan /path --report report.html
```

| Параметр | Описание | По умолчанию |
|----------|----------|--------------|
| `-r, --recursive <BOOL>` | Рекурсивный обход подкаталогов | `true` для каталогов |
| `--json` | Вывод результатов в формате JSON | |
| `-t, --threads <NUM>` | Количество потоков сканирования | Количество ядер CPU |
| `--auto-quarantine` | Автоматическое помещение вредоносных файлов в карантин | |
| `--remediate` | Автоматическое устранение: завершение процессов, карантин, очистка механизмов закрепления | |
| `-e, --exclude <PATTERN>` | Glob-шаблоны для исключения (можно указывать несколько раз) | |
| `--report <PATH>` | Экспорт результатов в виде автономного HTML-отчёта | |

### `sd scan-memory`

Сканирование памяти запущенных процессов на наличие угроз (только Linux, требуются права root).

```bash
sudo sd scan-memory
sudo sd scan-memory --pid 1234
sudo sd scan-memory --json
```

| Параметр | Описание |
|----------|----------|
| `--pid <PID>` | Сканирование конкретного процесса (если не указан, сканируются все) |
| `--json` | Вывод в формате JSON |

### `sd scan-usb [DEVICE]`

Сканирование USB и съёмных устройств.

```bash
sd scan-usb
sd scan-usb /dev/sdb1 --auto-quarantine
```

| Параметр | Описание |
|----------|----------|
| `--auto-quarantine` | Автоматическое помещение обнаруженных угроз в карантин |

### `sd check-rootkit`

Проверка на наличие признаков руткитов (только Linux).

```bash
sudo sd check-rootkit
sudo sd check-rootkit --json
```

Проверяет: скрытые процессы, целостность модулей ядра, перехват LD_PRELOAD, аномалии в /proc.

---

## Защита в реальном времени

### `sd monitor <PATHS...>`

Мониторинг файловой системы в реальном времени.

```bash
sd monitor /home /tmp
sd monitor /home --block
sd monitor /home --daemon
```

| Параметр | Описание |
|----------|----------|
| `--block` | Блокировка вредоносных файлов до их открытия (требуются права root + fanotify на Linux) |
| `--daemon` | Запуск в фоновом режиме |

### `sd daemon [PATHS...]`

Запуск в качестве фонового демона с мониторингом в реальном времени и автоматическими обновлениями.

```bash
sd daemon
sd daemon /home /tmp --update-hours 2
```

| Параметр | Описание | По умолчанию |
|----------|----------|--------------|
| `--update-hours <NUM>` | Интервал проверки обновлений сигнатур в часах | `4` |

Каталоги, отслеживаемые по умолчанию: `/home`, `/tmp`.

---

## Управление карантином

### `sd quarantine <SUBCOMMAND>`

Управление зашифрованным карантинным хранилищем (AES-256-GCM).

```bash
sd quarantine list
sd quarantine restore <ID>
sd quarantine restore <ID> --to /safe/path
sd quarantine delete <ID>
sd quarantine delete-all --yes
sd quarantine stats
```

| Подкоманда | Описание |
|------------|----------|
| `list` | Список всех файлов в карантине |
| `restore <ID>` | Восстановление файла из карантина (`--to <PATH>` для альтернативного расположения) |
| `delete <ID>` | Безвозвратное удаление файла из карантина |
| `delete-all` | Удаление всех файлов из карантина (`--yes` для пропуска подтверждения) |
| `stats` | Статистика карантина |

---

## База сигнатур

### `sd update`

Проверка и применение обновлений базы сигнатур.

```bash
sd update
sd update --check-only
sd update --force
sd update --server-url https://custom-server.example.com
```

| Параметр | Описание |
|----------|----------|
| `--check-only` | Только проверить наличие обновления |
| `--force` | Принудительная повторная загрузка, даже если база актуальна |
| `--server-url <URL>` | Переопределение URL сервера обновлений |

### `sd import <PATH>`

Импорт хеш-сигнатур из файла блоклиста.

```bash
sd import /path/to/blocklist.txt
```

Формат файла: одна запись на строку в виде `hex_hash malware_name`. Строки, начинающиеся с `#`, являются комментариями.

```
# Example blocklist
275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f EICAR.Test
ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa Ransom.WannaCry
```

### `sd import-clamav <PATHS...>`

Импорт файлов базы сигнатур ClamAV.

```bash
sd import-clamav main.cvd daily.cvd
sd import-clamav custom.hdb custom.hsb
```

Поддерживаемые форматы: `.cvd`, `.cld`, `.hdb`, `.hsb`.

### `sd info`

Отображение версии движка, состояния базы сигнатур и информации о системе.

```bash
sd info
```

Показывает: версию, количество YARA-правил, количество хеш-сигнатур, статистику карантина, информацию о платформе.

---

## Конфигурация

### `sd config <SUBCOMMAND>`

Управление конфигурацией движка.

```bash
sd config show
sd config set scan.max_file_size 104857600
sd config set scan.follow_symlinks true
sd config reset
```

| Подкоманда | Описание |
|------------|----------|
| `show` | Отображение текущей конфигурации |
| `set <KEY> <VALUE>` | Установка значения параметра (путь через точку) |
| `reset` | Сброс к конфигурации по умолчанию |

Значения поддерживают типы JSON: логические (`true`/`false`), числа, `null`, массивы, объекты.

---

## Политика реагирования

### `sd policy <ACTION> [KEY] [VALUE]`

Управление политиками реагирования на угрозы.

```bash
sd policy show
sd policy set on_malicious "kill,quarantine,clean"
sd policy set on_suspicious "report,quarantine"
sd policy set kill_processes true
sd policy reset
```

| Действие | Описание |
|----------|----------|
| `show` | Отображение текущей политики |
| `set <KEY> <VALUE>` | Установка значения поля политики |
| `reset` | Сброс к политике по умолчанию |

**Ключи политики:**

| Ключ | Описание | Значения |
|------|----------|----------|
| `on_malicious` | Действия при обнаружении вредоносных угроз | Через запятую: `report`, `quarantine`, `block`, `kill`, `clean`, `delete`, `isolate`, `blocklist` |
| `on_suspicious` | Действия при обнаружении подозрительных угроз | Те же, что выше |
| `kill_processes` | Завершение связанных процессов | `true` / `false` |
| `clean_persistence` | Очистка механизмов закрепления | `true` / `false` |
| `network_isolation` | Изоляция сетевых подключений | `true` / `false` |
| `audit_logging` | Запись всех действий в журнал аудита | `true` / `false` |

---

## Планирование

### `sd schedule <SUBCOMMAND>`

Управление запланированными сканированиями. Использует встроенные планировщики платформы: systemd timers (Linux), cron (Linux/macOS), launchd (macOS), Task Scheduler (Windows).

```bash
sd schedule add /home --frequency daily
sd schedule add /tmp --frequency hourly
sd schedule status
sd schedule remove
```

| Подкоманда | Описание |
|------------|----------|
| `add <PATH>` | Регистрация периодического запланированного сканирования |
| `remove` | Удаление запланированного сканирования |
| `status` | Отображение текущего статуса расписания |

**Частота:** `hourly`, `4h`, `12h`, `daily`, `weekly` (по умолчанию: `weekly`).

---

## Оповещения

### `sd webhook <SUBCOMMAND>`

Управление конечными точками webhook-оповещений.

```bash
sd webhook list
sd webhook add my-slack https://hooks.slack.com/services/... --format slack
sd webhook add my-discord https://discord.com/api/webhooks/... --format discord
sd webhook add custom https://example.com/alert --format generic
sd webhook remove my-slack
sd webhook test
```

| Подкоманда | Описание |
|------------|----------|
| `list` | Список настроенных webhook'ов |
| `add <NAME> <URL>` | Добавление webhook'а (`--format`: `slack`, `discord`, `generic`) |
| `remove <NAME>` | Удаление webhook'а по имени |
| `test` | Отправка тестового оповещения на все webhook'и |

### `sd email-alert <SUBCOMMAND>`

Управление конфигурацией оповещений по электронной почте.

```bash
sd email-alert configure
sd email-alert test
sd email-alert send "Trojan.Generic" "high" "/tmp/malware.exe"
```

| Подкоманда | Описание |
|------------|----------|
| `configure` | Создание или отображение конфигурации SMTP |
| `test` | Отправка тестового оповещения по электронной почте |
| `send <NAME> <LEVEL> <PATH>` | Отправка пользовательского оповещения по электронной почте |

---

## DNS и сетевая фильтрация

### `sd adblock <SUBCOMMAND>`

Управление фильтрацией рекламных и вредоносных доменов.

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

| Подкоманда | Описание |
|------------|----------|
| `enable` | Загрузка блоклистов и установка DNS-блокировки (`/etc/hosts`) |
| `disable` | Удаление записей DNS-блокировки |
| `sync` | Принудительная повторная загрузка всех списков фильтрации |
| `stats` | Отображение статистики фильтрации |
| `check <URL>` | Проверка, заблокирован ли URL/домен |
| `log` | Отображение последних заблокированных записей (`-c, --count <NUM>`, по умолчанию: 50) |
| `add <NAME> <URL>` | Добавление пользовательского списка фильтрации (`--category`: `ads`, `tracking`, `malware`, `social`) |
| `remove <NAME>` | Удаление списка фильтрации |

### `sd dns-proxy`

Запуск локального DNS-прокси с фильтрацией рекламы, IOC и пользовательских блоклистов.

```bash
sudo sd dns-proxy
sudo sd dns-proxy --listen 127.0.0.1:5353 --upstream 1.1.1.1:53
```

| Параметр | Описание | По умолчанию |
|----------|----------|--------------|
| `--listen <ADDR>` | Адрес прослушивания | `127.0.0.1:53` |
| `--upstream <ADDR>` | Вышестоящий DNS-сервер | `8.8.8.8:53` |
| `--log-path <PATH>` | Путь к JSONL-журналу запросов | `/tmp/prx-sd-dns.log` |

---

## Отчёты

### `sd report <OUTPUT>`

Генерация автономного HTML-отчёта из результатов сканирования в формате JSON.

```bash
sd scan /path --json | sd report report.html
sd report report.html --input results.json
```

| Параметр | Описание | По умолчанию |
|----------|----------|--------------|
| `--input <FILE>` | Входной JSON-файл (`-` для stdin) | `-` (stdin) |

### `sd status`

Отображение состояния демона, включая PID, время работы, версию сигнатур и количество заблокированных угроз.

```bash
sd status
```

---

## Интеграция

### `sd install-integration`

Установка интеграции сканирования через контекстное меню файлового менеджера.

```bash
sd install-integration
```

Поддерживаемые файловые менеджеры:
- **Linux:** Nautilus (GNOME Files), Dolphin (KDE), Nemo (Cinnamon)
- **macOS:** Finder Quick Action

### `sd self-update`

Проверка и установка обновлений бинарного файла из GitHub Releases.

```bash
sd self-update
sd self-update --check-only
```

| Параметр | Описание |
|----------|----------|
| `--check-only` | Только проверить наличие обновления |

---

## Примеры

### Первоначальная настройка

```bash
# Установка
curl -fsSL https://raw.githubusercontent.com/openprx/prx-sd/main/install.sh | bash

# Импорт дополнительных сигнатур
sd import my-custom-hashes.txt
sd import-clamav main.cvd daily.cvd

# Проверка настройки
sd info
```

### Ежедневная защита

```bash
# Запуск демона (мониторинг /home и /tmp, обновления каждые 4 часа)
sd daemon

# Или ручное сканирование
sd scan /home --recursive --auto-quarantine

# Проверка состояния
sd status
```

### Реагирование на инциденты

```bash
# Сканирование с полным устранением угроз
sudo sd scan /tmp --auto-quarantine --remediate

# Проверка памяти на наличие угроз в памяти процессов
sudo sd scan-memory

# Проверка на наличие руткитов
sudo sd check-rootkit

# Просмотр карантина
sd quarantine list
sd quarantine restore <ID> --to /safe/location
```

### Автоматизация

```bash
# Планирование еженедельного сканирования
sd schedule add /home --frequency weekly

# Настройка оповещений
sd webhook add slack https://hooks.slack.com/services/T.../B.../xxx --format slack
sd email-alert configure

# JSON-вывод для скриптов
sd scan /path --json | jq '.threats[] | .name'
```
