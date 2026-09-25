> Этот документ является русским переводом версии на [English](../BUILDING.md).

# Сборка из исходного кода

## Предварительные требования

### Обязательные

- **Rust** 1.70+ (установка через [rustup](https://rustup.rs/))
- **pkg-config**
- **Заголовочные файлы OpenSSL** (для reqwest/TLS)

### Необязательные

- **Node.js** 18+ и **npm** (для графического интерфейса)
- **Tauri CLI** (`cargo install tauri-cli`) (для графического интерфейса)

### Специфичные для платформы

**Debian/Ubuntu:**
```bash
sudo apt install -y build-essential pkg-config libssl-dev
```

**Fedora/RHEL:**
```bash
sudo dnf install -y gcc pkg-config openssl-devel
```

**macOS:**
```bash
xcode-select --install
brew install pkg-config openssl
```

**Windows:**
- Установите [Visual Studio Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/)
- Установите [vcpkg](https://github.com/microsoft/vcpkg) и выполните: `vcpkg install openssl`

## Сборка CLI

```bash
git clone https://github.com/openprx/prx-sd.git
cd prx-sd

# Отладочная сборка
cargo build

# Релизная сборка (оптимизированная)
cargo build --release

# Бинарный файл находится по пути:
#   Отладка:  target/debug/sd
#   Релиз:    target/release/sd
```

### Флаги функций

```bash
# Сборка с поддержкой ML-моделей ONNX
cargo build --release --features onnx

# Сборка без поддержки WASM-плагинов (меньший размер бинарного файла)
cargo build --release --no-default-features
```

| Функция | По умолчанию | Описание |
|---------|--------------|----------|
| `wasm-runtime` | Да | Поддержка плагинов WebAssembly (Wasmtime) |
| `onnx` | Нет | ONNX ML-инференс моделей (tract-onnx) |

## Сборка графического интерфейса

Десктопный графический интерфейс использует Tauri 2 (Rust) + Vue 3 (TypeScript).

```bash
# Установка зависимостей фронтенда
cd gui
npm install

# Режим разработки (горячая перезагрузка)
npm run tauri dev

# Продакшн-сборка
npm run tauri build
```

Собранное приложение будет находиться в `gui/src-tauri/target/release/bundle/`.

## Сборка сервера обновлений

```bash
cargo build --release --manifest-path update-server/Cargo.toml
```

## Запуск тестов

```bash
# Запуск всех тестов
cargo test

# Запуск тестов для конкретного крейта
cargo test -p prx-sd-core
cargo test -p prx-sd-signatures

# Запуск интеграционных тестов
cargo test --test '*'
```

## Контроль качества кода

```bash
# Проверка на ошибки компиляции (быстро, без линковки)
cargo check

# Применение автоматических исправлений
cargo fix --allow-dirty

# Форматирование кода
cargo fmt

# Линтинг
cargo clippy -- -D warnings
```

## Кросс-компиляция

Проект включает конфигурацию для кросс-компиляции в `.cargo/config.toml`.

### Linux ARM64 (aarch64)

```bash
# Установка целевой платформы
rustup target add aarch64-unknown-linux-gnu

# Установка инструментов кросс-компиляции
sudo apt install -y gcc-aarch64-linux-gnu

# Сборка
cargo build --release --target aarch64-unknown-linux-gnu
```

### macOS (из Linux)

Кросс-компиляция под macOS из Linux требует наличия [osxcross](https://github.com/tpoechtrager/osxcross).

### Windows (из Linux)

```bash
# Установка целевой платформы
rustup target add x86_64-pc-windows-gnu

# Установка инструментов кросс-компиляции
sudo apt install -y gcc-mingw-w64-x86-64

# Сборка
cargo build --release --target x86_64-pc-windows-gnu
```

## Упаковка

Готовые скрипты упаковки находятся в `tools/`:

```bash
# Пакет Debian (.deb)
./tools/build-deb.sh

# Образ диска macOS (.dmg)
./tools/build-dmg.sh

# Установщик Windows (.msi)
./tools/build-msi.sh

# Linux AppImage
./tools/build-appimage.sh
```

Конфигурации упаковки для конкретных платформ находятся в `packaging/`:

```
packaging/
├── appimage/       # Linux AppImage
├── completions/    # Автодополнение для оболочек (bash, zsh, fish)
├── desktop/        # Файлы .desktop
├── filemanager/    # Скрипты интеграции с файловым менеджером
├── homebrew/       # Формула Homebrew
├── launchd/        # Файл plist агента запуска macOS
├── systemd/        # Юнит-файл сервиса systemd для Linux
├── udev/           # Правила udev для Linux (автосканирование USB)
└── windows/        # Конфигурация установщика WiX MSI
```

## Структура проекта

```
prx-sd/
├── Cargo.toml          # Корень рабочего пространства
├── Cargo.lock          # Файл блокировки зависимостей
├── crates/
│   ├── cli/            # Бинарный файл sd
│   ├── core/           # Движок сканирования
│   ├── signatures/     # База сигнатур
│   ├── parsers/        # Парсеры бинарных форматов
│   ├── heuristic/      # Эвристическое + ML-обнаружение
│   ├── realtime/       # Мониторинг в реальном времени
│   ├── quarantine/     # Карантинное хранилище
│   ├── remediation/    # Реагирование на угрозы
│   ├── sandbox/        # Изоляция процессов
│   ├── plugins/        # Система WASM-плагинов
│   └── updater/        # Клиент обновлений
├── update-server/      # Сервер распространения сигнатур
├── gui/                # Десктопное приложение Tauri + Vue 3
├── drivers/            # Драйверы ядра ОС
├── signatures-db/      # Встроенные сигнатуры
├── tests/              # Интеграционные тесты
├── tools/              # Скрипты сборки
└── packaging/          # Упаковка дистрибутивов
```
