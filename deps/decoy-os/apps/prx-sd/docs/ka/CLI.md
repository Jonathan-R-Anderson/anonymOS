> ეს დოკუმენტი არის [English](../CLI.md) ვერსიის ქართული თარგმანი.

# CLI ცნობარი

PRX-SD გთავაზობთ `sd` ბრძანების ხაზის ინსტრუმენტს საფრთხეების აღმოჩენისა და სისტემის დაცვისთვის.

## გლობალური პარამეტრები

| დროშა | აღწერა | ნაგულისხმევი |
|--------|--------|--------------|
| `--log-level <LEVEL>` | ჟურნალის დეტალურობა: `trace`, `debug`, `info`, `warn`, `error` | `warn` |
| `--data-dir <PATH>` | მონაცემთა დირექტორია ხელმოწერების, კარანტინისა და კონფიგურაციისთვის | `~/.prx-sd/` |

---

## სკანირება

### `sd scan <PATH>`

ფაილის ან დირექტორიის სკანირება საფრთხეების აღმოსაჩენად.

```bash
sd scan /path/to/file
sd scan /home --recursive
sd scan /tmp --auto-quarantine --remediate
sd scan /path --json
sd scan /path --report report.html
```

| პარამეტრი | აღწერა | ნაგულისხმევი |
|-----------|--------|--------------|
| `-r, --recursive <BOOL>` | ქვედირექტორიებში რეკურსიული სკანირება | `true` დირექტორიებისთვის |
| `--json` | შედეგების გამოტანა JSON ფორმატში | |
| `-t, --threads <NUM>` | სკანერის ნაკადების რაოდენობა | CPU ბირთვების რაოდენობა |
| `--auto-quarantine` | მავნე ფაილების ავტომატური კარანტინში მოთავსება | |
| `--remediate` | ავტომატური აღმოფხვრა: პროცესების შეწყვეტა, კარანტინი, მუდმივობის გასუფთავება | |
| `-e, --exclude <PATTERN>` | გამოსარიცხი glob შაბლონები (განმეორებადი) | |
| `--report <PATH>` | შედეგების ექსპორტი დამოუკიდებელ HTML ანგარიშში | |

### `sd scan-memory`

გაშვებული პროცესების მეხსიერების სკანირება საფრთხეების აღმოსაჩენად (მხოლოდ Linux, საჭიროებს root უფლებებს).

```bash
sudo sd scan-memory
sudo sd scan-memory --pid 1234
sudo sd scan-memory --json
```

| პარამეტრი | აღწერა |
|-----------|--------|
| `--pid <PID>` | კონკრეტული პროცესის სკანირება (გამოტოვებისას სკანირდება ყველა) |
| `--json` | გამოტანა JSON ფორმატში |

### `sd scan-usb [DEVICE]`

USB/მოსახსნელი მოწყობილობების სკანირება.

```bash
sd scan-usb
sd scan-usb /dev/sdb1 --auto-quarantine
```

| პარამეტრი | აღწერა |
|-----------|--------|
| `--auto-quarantine` | აღმოჩენილი საფრთხეების ავტომატური კარანტინში მოთავსება |

### `sd check-rootkit`

rootkit-ის ინდიკატორების შემოწმება (მხოლოდ Linux).

```bash
sudo sd check-rootkit
sudo sd check-rootkit --json
```

ამოწმებს: დამალულ პროცესებს, ბირთვის მოდულების მთლიანობას, LD_PRELOAD ჩაჭრებს, /proc ანომალიებს.

---

## რეალურ დროში დაცვა

### `sd monitor <PATHS...>`

ფაილური სისტემის რეალურ დროში მონიტორინგი.

```bash
sd monitor /home /tmp
sd monitor /home --block
sd monitor /home --daemon
```

| პარამეტრი | აღწერა |
|-----------|--------|
| `--block` | მავნე ფაილებზე წვდომის დაბლოკვა წვდომამდე (საჭიროებს root + fanotify Linux-ზე) |
| `--daemon` | ფონურ რეჟიმში გაშვება |

### `sd daemon [PATHS...]`

ფონურ რეჟიმში გაშვება რეალურ დროში მონიტორინგითა და ავტომატური განახლებებით.

```bash
sd daemon
sd daemon /home /tmp --update-hours 2
```

| პარამეტრი | აღწერა | ნაგულისხმევი |
|-----------|--------|--------------|
| `--update-hours <NUM>` | ხელმოწერების განახლების შემოწმების ინტერვალი საათებში | `4` |

ნაგულისხმევი მონიტორინგის ბილიკები: `/home`, `/tmp`.

---

## კარანტინის მართვა

### `sd quarantine <SUBCOMMAND>`

დაშიფრული კარანტინის საცავის მართვა (AES-256-GCM).

```bash
sd quarantine list
sd quarantine restore <ID>
sd quarantine restore <ID> --to /safe/path
sd quarantine delete <ID>
sd quarantine delete-all --yes
sd quarantine stats
```

| ქვებრძანება | აღწერა |
|-------------|--------|
| `list` | კარანტინში მოთავსებული ყველა ფაილის ჩამონათვალი |
| `restore <ID>` | კარანტინიდან ფაილის აღდგენა (`--to <PATH>` ალტერნატიული მდებარეობისთვის) |
| `delete <ID>` | კარანტინიდან ფაილის სამუდამო წაშლა |
| `delete-all` | კარანტინში მოთავსებული ყველა ფაილის წაშლა (`--yes` დადასტურების გამოტოვებისთვის) |
| `stats` | კარანტინის სტატისტიკის ჩვენება |

---

## ხელმოწერების მონაცემთა ბაზა

### `sd update`

ხელმოწერების მონაცემთა ბაზის განახლებების შემოწმება და გამოყენება.

```bash
sd update
sd update --check-only
sd update --force
sd update --server-url https://custom-server.example.com
```

| პარამეტრი | აღწერა |
|-----------|--------|
| `--check-only` | მხოლოდ განახლების ხელმისაწვდომობის შემოწმება |
| `--force` | იძულებითი ხელახალი ჩამოტვირთვა, თუნდაც უკვე განახლებული იყოს |
| `--server-url <URL>` | განახლების სერვერის URL-ის ხელით მითითება |

### `sd import <PATH>`

ჰეშ ხელმოწერების იმპორტი ბლოკ-სიის ფაილიდან.

```bash
sd import /path/to/blocklist.txt
```

ფაილის ფორმატი: თითო ჩანაწერი ხაზზე, ფორმატით `hex_hash malware_name`. `#`-ით დაწყებული ხაზები კომენტარებია.

```
# Example blocklist
275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f EICAR.Test
ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa Ransom.WannaCry
```

### `sd import-clamav <PATHS...>`

ClamAV ხელმოწერების მონაცემთა ბაზის ფაილების იმპორტი.

```bash
sd import-clamav main.cvd daily.cvd
sd import-clamav custom.hdb custom.hsb
```

მხარდაჭერილი ფორმატები: `.cvd`, `.cld`, `.hdb`, `.hsb`.

### `sd info`

ძრავის ვერსიის, ხელმოწერების მონაცემთა ბაზის სტატუსისა და სისტემის ინფორმაციის ჩვენება.

```bash
sd info
```

აჩვენებს: ვერსიას, YARA წესების რაოდენობას, ჰეშ ხელმოწერების რაოდენობას, კარანტინის სტატისტიკას, პლატფორმის ინფორმაციას.

---

## კონფიგურაცია

### `sd config <SUBCOMMAND>`

ძრავის კონფიგურაციის მართვა.

```bash
sd config show
sd config set scan.max_file_size 104857600
sd config set scan.follow_symlinks true
sd config reset
```

| ქვებრძანება | აღწერა |
|-------------|--------|
| `show` | მიმდინარე კონფიგურაციის ჩვენება |
| `set <KEY> <VALUE>` | კონფიგურაციის გასაღების მნიშვნელობის დაყენება (წერტილით გამოყოფილი ბილიკი) |
| `reset` | ნაგულისხმევ კონფიგურაციაზე დაბრუნება |

მნიშვნელობები მხარს უჭერენ JSON ტიპებს: ლოგიკური (`true`/`false`), რიცხვები, `null`, მასივები, ობიექტები.

---

## აღმოფხვრის პოლიტიკა

### `sd policy <ACTION> [KEY] [VALUE]`

საფრთხეების აღმოფხვრის პოლიტიკების მართვა.

```bash
sd policy show
sd policy set on_malicious "kill,quarantine,clean"
sd policy set on_suspicious "report,quarantine"
sd policy set kill_processes true
sd policy reset
```

| მოქმედება | აღწერა |
|-----------|--------|
| `show` | მიმდინარე პოლიტიკის ჩვენება |
| `set <KEY> <VALUE>` | პოლიტიკის ველის დაყენება |
| `reset` | ნაგულისხმევ პოლიტიკაზე დაბრუნება |

**პოლიტიკის გასაღებები:**

| გასაღები | აღწერა | მნიშვნელობები |
|----------|--------|---------------|
| `on_malicious` | მოქმედებები მავნე საფრთხეებისთვის | მძიმით გამოყოფილი: `report`, `quarantine`, `block`, `kill`, `clean`, `delete`, `isolate`, `blocklist` |
| `on_suspicious` | მოქმედებები საეჭვო საფრთხეებისთვის | იგივე, რაც ზემოთ |
| `kill_processes` | დაკავშირებული პროცესების შეწყვეტა | `true` / `false` |
| `clean_persistence` | მუდმივობის მექანიზმების გასუფთავება | `true` / `false` |
| `network_isolation` | ქსელური კავშირების იზოლაცია | `true` / `false` |
| `audit_logging` | ყველა მოქმედების ჩაწერა აუდიტის ჟურნალში | `true` / `false` |

---

## დაგეგმვა

### `sd schedule <SUBCOMMAND>`

დაგეგმილი სკანირებების მართვა. იყენებს პლატფორმის ნატიურ დამგეგმავებს: systemd timers (Linux), cron (Linux/macOS), launchd (macOS), Task Scheduler (Windows).

```bash
sd schedule add /home --frequency daily
sd schedule add /tmp --frequency hourly
sd schedule status
sd schedule remove
```

| ქვებრძანება | აღწერა |
|-------------|--------|
| `add <PATH>` | განმეორებადი დაგეგმილი სკანირების რეგისტრაცია |
| `remove` | დაგეგმილი სკანირების წაშლა |
| `status` | მიმდინარე დაგეგმვის სტატუსის ჩვენება |

**სიხშირეები:** `hourly`, `4h`, `12h`, `daily`, `weekly` (ნაგულისხმევი: `weekly`).

---

## შეტყობინებები

### `sd webhook <SUBCOMMAND>`

webhook შეტყობინებების ბოლო წერტილების მართვა.

```bash
sd webhook list
sd webhook add my-slack https://hooks.slack.com/services/... --format slack
sd webhook add my-discord https://discord.com/api/webhooks/... --format discord
sd webhook add custom https://example.com/alert --format generic
sd webhook remove my-slack
sd webhook test
```

| ქვებრძანება | აღწერა |
|-------------|--------|
| `list` | კონფიგურირებული webhook-ების ჩამონათვალი |
| `add <NAME> <URL>` | webhook-ის დამატება (`--format`: `slack`, `discord`, `generic`) |
| `remove <NAME>` | webhook-ის წაშლა სახელით |
| `test` | სატესტო შეტყობინების გაგზავნა ყველა webhook-ზე |

### `sd email-alert <SUBCOMMAND>`

ელფოსტის შეტყობინებების კონფიგურაციის მართვა.

```bash
sd email-alert configure
sd email-alert test
sd email-alert send "Trojan.Generic" "high" "/tmp/malware.exe"
```

| ქვებრძანება | აღწერა |
|-------------|--------|
| `configure` | SMTP ელფოსტის კონფიგურაციის შექმნა ან ჩვენება |
| `test` | სატესტო შეტყობინების გაგზავნა ელფოსტით |
| `send <NAME> <LEVEL> <PATH>` | მორგებული შეტყობინების გაგზავნა ელფოსტით |

---

## DNS და ქსელური ფილტრაცია

### `sd adblock <SUBCOMMAND>`

რეკლამისა და მავნე დომენების ფილტრაციის მართვა.

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

| ქვებრძანება | აღწერა |
|-------------|--------|
| `enable` | ბლოკ-სიების ჩამოტვირთვა და DNS ბლოკირების დაყენება (`/etc/hosts`) |
| `disable` | DNS ბლოკირების ჩანაწერების წაშლა |
| `sync` | ყველა ფილტრის სიის იძულებითი ხელახალი ჩამოტვირთვა |
| `stats` | ფილტრაციის სტატისტიკის ჩვენება |
| `check <URL>` | URL/დომენის ბლოკირების სტატუსის შემოწმება |
| `log` | ბოლო დაბლოკილი ჩანაწერების ჩვენება (`-c, --count <NUM>`, ნაგულისხმევი: 50) |
| `add <NAME> <URL>` | მორგებული ფილტრის სიის დამატება (`--category`: `ads`, `tracking`, `malware`, `social`) |
| `remove <NAME>` | ფილტრის სიის წაშლა |

### `sd dns-proxy`

ლოკალური DNS პროქსის გაშვება adblock, IOC და მორგებული ბლოკ-სიების ფილტრაციით.

```bash
sudo sd dns-proxy
sudo sd dns-proxy --listen 127.0.0.1:5353 --upstream 1.1.1.1:53
```

| პარამეტრი | აღწერა | ნაგულისხმევი |
|-----------|--------|--------------|
| `--listen <ADDR>` | მოსმენის მისამართი | `127.0.0.1:53` |
| `--upstream <ADDR>` | ზედა დონის DNS სერვერი | `8.8.8.8:53` |
| `--log-path <PATH>` | JSONL მოთხოვნების ჟურნალის ბილიკი | `/tmp/prx-sd-dns.log` |

---

## ანგარიშგება

### `sd report <OUTPUT>`

დამოუკიდებელი HTML ანგარიშის გენერაცია JSON სკანირების შედეგებიდან.

```bash
sd scan /path --json | sd report report.html
sd report report.html --input results.json
```

| პარამეტრი | აღწერა | ნაგულისხმევი |
|-----------|--------|--------------|
| `--input <FILE>` | შემავალი JSON ფაილი (`-` stdin-ისთვის) | `-` (stdin) |

### `sd status`

დემონის სტატუსის ჩვენება, მათ შორის PID, მუშაობის დრო, ხელმოწერების ვერსია და დაბლოკილი საფრთხეები.

```bash
sd status
```

---

## ინტეგრაცია

### `sd install-integration`

ფაილ-მენეჯერში მარჯვენა ღილაკით სკანირების ინტეგრაციის დაყენება.

```bash
sd install-integration
```

მხარდაჭერილი ფაილ-მენეჯერები:
- **Linux:** Nautilus (GNOME Files), Dolphin (KDE), Nemo (Cinnamon)
- **macOS:** Finder Quick Action

### `sd self-update`

GitHub Releases-იდან ბინარული განახლებების შემოწმება და გამოყენება.

```bash
sd self-update
sd self-update --check-only
```

| პარამეტრი | აღწერა |
|-----------|--------|
| `--check-only` | მხოლოდ განახლების ხელმისაწვდომობის შემოწმება |

---

## მაგალითები

### პირველადი დაყენება

```bash
# დაყენება
curl -fsSL https://raw.githubusercontent.com/openprx/prx-sd/main/install.sh | bash

# დამატებითი ხელმოწერების იმპორტი
sd import my-custom-hashes.txt
sd import-clamav main.cvd daily.cvd

# დაყენების გადამოწმება
sd info
```

### ყოველდღიური დაცვა

```bash
# დემონის გაშვება (მონიტორინგი /home და /tmp, განახლება ყოველ 4 საათში)
sd daemon

# ან ხელით სკანირება
sd scan /home --recursive --auto-quarantine

# სტატუსის შემოწმება
sd status
```

### ინციდენტზე რეაგირება

```bash
# სკანირება სრული აღმოფხვრით
sudo sd scan /tmp --auto-quarantine --remediate

# მეხსიერების შემოწმება მეხსიერებაში არსებული საფრთხეებისთვის
sudo sd scan-memory

# rootkit-ების შემოწმება
sudo sd check-rootkit

# კარანტინის გადახედვა
sd quarantine list
sd quarantine restore <ID> --to /safe/location
```

### ავტომატიზაცია

```bash
# ყოველკვირეული სკანირების დაგეგმვა
sd schedule add /home --frequency weekly

# შეტყობინებების დაყენება
sd webhook add slack https://hooks.slack.com/services/T.../B.../xxx --format slack
sd email-alert configure

# JSON გამოტანა სკრიპტებისთვის
sd scan /path --json | jq '.threats[] | .name'
```
