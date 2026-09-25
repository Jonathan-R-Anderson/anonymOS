> ეს დოკუმენტი არის [English](../BUILDING.md) ვერსიის ქართული თარგმანი.

# წყაროდან აგება

## წინაპირობები

### სავალდებულო

- **Rust** 1.70+ (დაყენება [rustup](https://rustup.rs/)-ით)
- **pkg-config**
- **OpenSSL დეველოპერული ჰედერები** (reqwest/TLS-ისთვის)

### არასავალდებულო

- **Node.js** 18+ და **npm** (GUI-სთვის)
- **Tauri CLI** (`cargo install tauri-cli`) (GUI-სთვის)

### პლატფორმის სპეციფიკური

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
- დააყენეთ [Visual Studio Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/)
- დააყენეთ [vcpkg](https://github.com/microsoft/vcpkg) და გაუშვით: `vcpkg install openssl`

## CLI-ის აგება

```bash
git clone https://github.com/openprx/prx-sd.git
cd prx-sd

# Debug აგება
cargo build

# Release აგება (ოპტიმიზირებული)
cargo build --release

# ბინარი მდებარეობს:
#   Debug:   target/debug/sd
#   Release: target/release/sd
```

### ფუნქციის დროშები

```bash
# აგება ONNX ML მოდელის მხარდაჭერით
cargo build --release --features onnx

# აგება WASM მოდულების მხარდაჭერის გარეშე (უფრო მცირე ბინარი)
cargo build --release --no-default-features
```

| ფუნქცია | ნაგულისხმევი | აღწერა |
|---------|-------------|--------|
| `wasm-runtime` | დიახ | WebAssembly მოდულების მხარდაჭერა (Wasmtime) |
| `onnx` | არა | ONNX ML მოდელის გამოყვანა (tract-onnx) |

## GUI-ს აგება

დესკტოპ GUI იყენებს Tauri 2 (Rust) + Vue 3 (TypeScript) ტექნოლოგიებს.

```bash
# ფრონტენდის დამოკიდებულებების დაყენება
cd gui
npm install

# დეველოპერული რეჟიმი (ცხელი გადატვირთვა)
npm run tauri dev

# პროდაქშენ აგება
npm run tauri build
```

აგებული აპლიკაცია განთავსდება `gui/src-tauri/target/release/bundle/` დირექტორიაში.

## განახლების სერვერის აგება

```bash
cargo build --release --manifest-path update-server/Cargo.toml
```

## ტესტების გაშვება

```bash
# ყველა ტესტის გაშვება
cargo test

# კონკრეტული crate-ის ტესტების გაშვება
cargo test -p prx-sd-core
cargo test -p prx-sd-signatures

# ინტეგრაციული ტესტების გაშვება
cargo test --test '*'
```

## კოდის ხარისხი

```bash
# კომპილაციის შეცდომების შემოწმება (სწრაფი, ლინკერის გარეშე)
cargo check

# ავტომატური შესწორებების გამოყენება
cargo fix --allow-dirty

# კოდის ფორმატირება
cargo fmt

# ლინტინგი
cargo clippy -- -D warnings
```

## ჯვარედინი კომპილაცია

პროექტი მოიცავს ჯვარედინი კომპილაციის კონფიგურაციას `.cargo/config.toml` ფაილში.

### Linux ARM64 (aarch64)

```bash
# სამიზნის დაყენება
rustup target add aarch64-unknown-linux-gnu

# ჯვარედინი კომპილაციის ინსტრუმენტარიუმის დაყენება
sudo apt install -y gcc-aarch64-linux-gnu

# აგება
cargo build --release --target aarch64-unknown-linux-gnu
```

### macOS (Linux-იდან)

Linux-იდან macOS-ისთვის ჯვარედინი კომპილაცია საჭიროებს [osxcross](https://github.com/tpoechtrager/osxcross)-ს.

### Windows (Linux-იდან)

```bash
# სამიზნის დაყენება
rustup target add x86_64-pc-windows-gnu

# ჯვარედინი კომპილაციის ინსტრუმენტარიუმის დაყენება
sudo apt install -y gcc-mingw-w64-x86-64

# აგება
cargo build --release --target x86_64-pc-windows-gnu
```

## შეფუთვა

წინასწარ მომზადებული შეფუთვის სკრიპტები მდებარეობს `tools/` დირექტორიაში:

```bash
# Debian პაკეტი (.deb)
./tools/build-deb.sh

# macOS დისკის სურათი (.dmg)
./tools/build-dmg.sh

# Windows ინსტალერი (.msi)
./tools/build-msi.sh

# Linux AppImage
./tools/build-appimage.sh
```

პლატფორმის სპეციფიკური შეფუთვის კონფიგურაციები მდებარეობს `packaging/` დირექტორიაში:

```
packaging/
├── appimage/       # Linux AppImage
├── completions/    # Shell ავტოშევსებები (bash, zsh, fish)
├── desktop/        # .desktop ფაილები
├── filemanager/    # ფაილ-მენეჯერის ინტეგრაციის სკრიპტები
├── homebrew/       # Homebrew ფორმულა
├── launchd/        # macOS გაშვების აგენტის plist
├── systemd/        # Linux systemd სერვისის ფაილი
├── udev/           # Linux udev წესები (USB ავტომატური სკანირება)
└── windows/        # WiX MSI ინსტალერის კონფიგურაცია
```

## პროექტის სტრუქტურა

```
prx-sd/
├── Cargo.toml          # სამუშაო სივრცის ფესვი
├── Cargo.lock          # დამოკიდებულებების ჩაკეტვის ფაილი
├── crates/
│   ├── cli/            # sd ბინარი
│   ├── core/           # სკანირების ძრავი
│   ├── signatures/     # ხელმოწერების მონაცემთა ბაზა
│   ├── parsers/        # ბინარული ფორმატების ანალიზატორები
│   ├── heuristic/      # ევრისტიკული + ML აღმოჩენა
│   ├── realtime/       # რეალურ დროში მონიტორინგი
│   ├── quarantine/     # კარანტინის საცავი
│   ├── remediation/    # საფრთხეებზე რეაგირება
│   ├── sandbox/        # პროცესის იზოლაცია
│   ├── plugins/        # WASM მოდულების სისტემა
│   └── updater/        # განახლების კლიენტი
├── update-server/      # ხელმოწერების განაწილების სერვერი
├── gui/                # Tauri + Vue 3 დესკტოპ აპლიკაცია
├── drivers/            # ოპერაციული სისტემის ბირთვის დრაივერები
├── signatures-db/      # ჩაშენებული ხელმოწერები
├── tests/              # ინტეგრაციული ტესტები
├── tools/              # აგების სკრიპტები
└── packaging/          # განაწილების შეფუთვა
```
