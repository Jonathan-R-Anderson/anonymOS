> هذا المستند هو ترجمة عربية للنسخة [English](../BUILDING.md).

# البناء من المصدر

## المتطلبات الأساسية

### مطلوب

- **Rust** 1.70+ (التثبيت عبر [rustup](https://rustup.rs/))
- **pkg-config**
- **ملفات تطوير OpenSSL** (لـ reqwest/TLS)

### اختياري

- **Node.js** 18+ و**npm** (للواجهة الرسومية)
- **Tauri CLI** (`cargo install tauri-cli`) (للواجهة الرسومية)

### خاص بالمنصة

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
- تثبيت [Visual Studio Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/)
- تثبيت [vcpkg](https://github.com/microsoft/vcpkg) وتشغيل: `vcpkg install openssl`

## بناء واجهة سطر الأوامر

```bash
git clone https://github.com/openprx/prx-sd.git
cd prx-sd

# بناء التصحيح
cargo build

# بناء الإصدار (محسّن)
cargo build --release

# الملف التنفيذي موجود في:
#   التصحيح:  target/debug/sd
#   الإصدار: target/release/sd
```

### أعلام الميزات

```bash
# البناء مع دعم نموذج التعلم الآلي ONNX
cargo build --release --features onnx

# البناء بدون دعم إضافات WASM (ملف تنفيذي أصغر)
cargo build --release --no-default-features
```

| الميزة | افتراضي | الوصف |
|--------|---------|-------|
| `wasm-runtime` | نعم | دعم إضافات WebAssembly (Wasmtime) |
| `onnx` | لا | استدلال نموذج التعلم الآلي ONNX (tract-onnx) |

## بناء الواجهة الرسومية

تستخدم واجهة سطح المكتب الرسومية Tauri 2 (Rust) + Vue 3 (TypeScript).

```bash
# تثبيت تبعيات الواجهة الأمامية
cd gui
npm install

# وضع التطوير (إعادة تحميل فورية)
npm run tauri dev

# بناء الإنتاج
npm run tauri build
```

سيكون التطبيق المبني في `gui/src-tauri/target/release/bundle/`.

## بناء خادم التحديث

```bash
cargo build --release --manifest-path update-server/Cargo.toml
```

## تشغيل الاختبارات

```bash
# تشغيل جميع الاختبارات
cargo test

# تشغيل اختبارات وحدة محددة
cargo test -p prx-sd-core
cargo test -p prx-sd-signatures

# تشغيل اختبارات التكامل
cargo test --test '*'
```

## جودة الشفرة البرمجية

```bash
# التحقق من أخطاء التجميع (سريع، بدون ربط)
cargo check

# تطبيق الإصلاحات التلقائية
cargo fix --allow-dirty

# تنسيق الشفرة البرمجية
cargo fmt

# التدقيق
cargo clippy -- -D warnings
```

## التجميع العابر للمنصات

يتضمن المشروع إعدادات التجميع العابر للمنصات في `.cargo/config.toml`.

### Linux ARM64 (aarch64)

```bash
# تثبيت الهدف
rustup target add aarch64-unknown-linux-gnu

# تثبيت سلسلة أدوات التجميع العابر
sudo apt install -y gcc-aarch64-linux-gnu

# البناء
cargo build --release --target aarch64-unknown-linux-gnu
```

### macOS (من Linux)

التجميع العابر إلى macOS من Linux يتطلب [osxcross](https://github.com/tpoechtrager/osxcross).

### Windows (من Linux)

```bash
# تثبيت الهدف
rustup target add x86_64-pc-windows-gnu

# تثبيت سلسلة أدوات التجميع العابر
sudo apt install -y gcc-mingw-w64-x86-64

# البناء
cargo build --release --target x86_64-pc-windows-gnu
```

## التعبئة

سكريبتات التعبئة الجاهزة موجودة في `tools/`:

```bash
# حزمة Debian (.deb)
./tools/build-deb.sh

# صورة قرص macOS (.dmg)
./tools/build-dmg.sh

# مثبّت Windows (.msi)
./tools/build-msi.sh

# Linux AppImage
./tools/build-appimage.sh
```

إعدادات التعبئة الخاصة بكل منصة موجودة في `packaging/`:

```
packaging/
├── appimage/       # Linux AppImage
├── completions/    # إكمال الأوامر (bash، zsh، fish)
├── desktop/        # ملفات .desktop
├── filemanager/    # سكريبتات تكامل مدير الملفات
├── homebrew/       # وصفة Homebrew
├── launchd/        # ملف plist لوكيل التشغيل في macOS
├── systemd/        # وحدة خدمة systemd في Linux
├── udev/           # قواعد udev في Linux (فحص USB التلقائي)
└── windows/        # إعدادات مثبّت WiX MSI
```

## هيكل المشروع

```
prx-sd/
├── Cargo.toml          # جذر مساحة العمل
├── Cargo.lock          # ملف قفل التبعيات
├── crates/
│   ├── cli/            # الملف التنفيذي sd
│   ├── core/           # محرك الفحص
│   ├── signatures/     # قاعدة بيانات التوقيعات
│   ├── parsers/        # محللات الصيغ الثنائية
│   ├── heuristic/      # الكشف الإرشادي + التعلم الآلي
│   ├── realtime/       # المراقبة في الوقت الفعلي
│   ├── quarantine/     # خزنة الحجر الصحي
│   ├── remediation/    # الاستجابة للتهديدات
│   ├── sandbox/        # عزل العمليات
│   ├── plugins/        # نظام إضافات WASM
│   └── updater/        # عميل التحديث
├── update-server/      # خادم توزيع التوقيعات
├── gui/                # تطبيق سطح المكتب Tauri + Vue 3
├── drivers/            # برامج تشغيل نواة نظام التشغيل
├── signatures-db/      # التوقيعات المدمجة
├── tests/              # اختبارات التكامل
├── tools/              # سكريبتات البناء
└── packaging/          # تعبئة التوزيع
```
