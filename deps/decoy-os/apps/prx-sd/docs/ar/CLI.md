> هذا المستند هو ترجمة عربية للنسخة [English](../CLI.md).

# مرجع واجهة سطر الأوامر

يوفر PRX-SD أداة سطر الأوامر `sd` للكشف عن التهديدات وحماية النظام.

## الخيارات العامة

| العلم | الوصف | القيمة الافتراضية |
|-------|-------|-------------------|
| `--log-level <LEVEL>` | مستوى تفصيل السجلات: `trace`، `debug`، `info`، `warn`، `error` | `warn` |
| `--data-dir <PATH>` | مجلد البيانات للتوقيعات والحجر الصحي والإعدادات | `~/.prx-sd/` |

---

## الفحص

### `sd scan <PATH>`

فحص ملف أو مجلد بحثًا عن التهديدات.

```bash
sd scan /path/to/file
sd scan /home --recursive
sd scan /tmp --auto-quarantine --remediate
sd scan /path --json
sd scan /path --report report.html
```

| الخيار | الوصف | القيمة الافتراضية |
|--------|-------|-------------------|
| `-r, --recursive <BOOL>` | البحث في المجلدات الفرعية بشكل متكرر | `true` للمجلدات |
| `--json` | إخراج النتائج بتنسيق JSON | |
| `-t, --threads <NUM>` | عدد خيوط الفحص | عدد أنوية المعالج |
| `--auto-quarantine` | حجر الملفات الخبيثة تلقائيًا | |
| `--remediate` | معالجة تلقائية: إيقاف العمليات، حجر، تنظيف آليات الاستمرار | |
| `-e, --exclude <PATTERN>` | أنماط glob للاستبعاد (قابل للتكرار) | |
| `--report <PATH>` | تصدير النتائج كتقرير HTML مستقل | |

### `sd scan-memory`

فحص ذاكرة العمليات الجارية بحثًا عن التهديدات (Linux فقط، يتطلب صلاحيات root).

```bash
sudo sd scan-memory
sudo sd scan-memory --pid 1234
sudo sd scan-memory --json
```

| الخيار | الوصف |
|--------|-------|
| `--pid <PID>` | فحص عملية محددة (بدون تحديد يتم فحص الكل) |
| `--json` | الإخراج بتنسيق JSON |

### `sd scan-usb [DEVICE]`

فحص أجهزة USB/الأجهزة القابلة للإزالة.

```bash
sd scan-usb
sd scan-usb /dev/sdb1 --auto-quarantine
```

| الخيار | الوصف |
|--------|-------|
| `--auto-quarantine` | حجر التهديدات المكتشفة تلقائيًا |

### `sd check-rootkit`

الكشف عن مؤشرات وجود rootkit (Linux فقط).

```bash
sudo sd check-rootkit
sudo sd check-rootkit --json
```

يتحقق من: العمليات المخفية، سلامة وحدات النواة، خطافات LD_PRELOAD، شذوذات /proc.

---

## الحماية في الوقت الفعلي

### `sd monitor <PATHS...>`

مراقبة نظام الملفات في الوقت الفعلي.

```bash
sd monitor /home /tmp
sd monitor /home --block
sd monitor /home --daemon
```

| الخيار | الوصف |
|--------|-------|
| `--block` | حظر الملفات الخبيثة قبل الوصول إليها (يتطلب صلاحيات root + fanotify على Linux) |
| `--daemon` | التشغيل كعملية خلفية |

### `sd daemon [PATHS...]`

التشغيل كعملية خلفية مع مراقبة في الوقت الفعلي وتحديثات تلقائية.

```bash
sd daemon
sd daemon /home /tmp --update-hours 2
```

| الخيار | الوصف | القيمة الافتراضية |
|--------|-------|-------------------|
| `--update-hours <NUM>` | فترة التحقق من تحديثات التوقيعات بالساعات | `4` |

المسارات المراقبة افتراضيًا: `/home`، `/tmp`.

---

## إدارة الحجر الصحي

### `sd quarantine <SUBCOMMAND>`

إدارة خزنة الحجر الصحي المشفرة (AES-256-GCM).

```bash
sd quarantine list
sd quarantine restore <ID>
sd quarantine restore <ID> --to /safe/path
sd quarantine delete <ID>
sd quarantine delete-all --yes
sd quarantine stats
```

| الأمر الفرعي | الوصف |
|---------------|-------|
| `list` | عرض جميع الملفات المحجورة |
| `restore <ID>` | استعادة ملف محجور (`--to <PATH>` لتحديد موقع بديل) |
| `delete <ID>` | حذف ملف محجور نهائيًا |
| `delete-all` | حذف جميع الملفات المحجورة (`--yes` لتخطي التأكيد) |
| `stats` | عرض إحصائيات الحجر الصحي |

---

## قاعدة بيانات التوقيعات

### `sd update`

التحقق من تحديثات قاعدة بيانات التوقيعات وتطبيقها.

```bash
sd update
sd update --check-only
sd update --force
sd update --server-url https://custom-server.example.com
```

| الخيار | الوصف |
|--------|-------|
| `--check-only` | التحقق فقط من توفر تحديث |
| `--force` | فرض إعادة التنزيل حتى لو كانت التوقيعات محدّثة |
| `--server-url <URL>` | تجاوز عنوان URL لخادم التحديث |

### `sd import <PATH>`

استيراد توقيعات الهاش من ملف قائمة حظر.

```bash
sd import /path/to/blocklist.txt
```

تنسيق الملف: سطر واحد لكل إدخال بصيغة `hex_hash malware_name`. الأسطر التي تبدأ بـ `#` هي تعليقات.

```
# Example blocklist
275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f EICAR.Test
ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa Ransom.WannaCry
```

### `sd import-clamav <PATHS...>`

استيراد ملفات قاعدة بيانات توقيعات ClamAV.

```bash
sd import-clamav main.cvd daily.cvd
sd import-clamav custom.hdb custom.hsb
```

التنسيقات المدعومة: `.cvd`، `.cld`، `.hdb`، `.hsb`.

### `sd info`

عرض إصدار المحرك وحالة قاعدة بيانات التوقيعات ومعلومات النظام.

```bash
sd info
```

يعرض: الإصدار، عدد قواعد YARA، عدد توقيعات الهاش، إحصائيات الحجر الصحي، معلومات المنصة.

---

## الإعدادات

### `sd config <SUBCOMMAND>`

إدارة إعدادات المحرك.

```bash
sd config show
sd config set scan.max_file_size 104857600
sd config set scan.follow_symlinks true
sd config reset
```

| الأمر الفرعي | الوصف |
|---------------|-------|
| `show` | عرض الإعدادات الحالية |
| `set <KEY> <VALUE>` | تعيين مفتاح إعداد (مسار مفصول بنقاط) |
| `reset` | إعادة تعيين الإعدادات الافتراضية |

تدعم القيم أنواع JSON: منطقي (`true`/`false`)، أرقام، `null`، مصفوفات، كائنات.

---

## سياسة المعالجة

### `sd policy <ACTION> [KEY] [VALUE]`

إدارة سياسات معالجة التهديدات.

```bash
sd policy show
sd policy set on_malicious "kill,quarantine,clean"
sd policy set on_suspicious "report,quarantine"
sd policy set kill_processes true
sd policy reset
```

| الإجراء | الوصف |
|---------|-------|
| `show` | عرض السياسة الحالية |
| `set <KEY> <VALUE>` | تعيين حقل في السياسة |
| `reset` | إعادة تعيين السياسة الافتراضية |

**مفاتيح السياسة:**

| المفتاح | الوصف | القيم |
|---------|-------|-------|
| `on_malicious` | الإجراءات للتهديدات الخبيثة | مفصولة بفواصل: `report`، `quarantine`، `block`، `kill`، `clean`، `delete`، `isolate`، `blocklist` |
| `on_suspicious` | الإجراءات للتهديدات المشبوهة | نفس ما سبق |
| `kill_processes` | إيقاف العمليات المرتبطة | `true` / `false` |
| `clean_persistence` | تنظيف آليات الاستمرار | `true` / `false` |
| `network_isolation` | عزل اتصالات الشبكة | `true` / `false` |
| `audit_logging` | تسجيل جميع الإجراءات في سجل التدقيق | `true` / `false` |

---

## الجدولة

### `sd schedule <SUBCOMMAND>`

إدارة عمليات الفحص المجدولة. يستخدم أدوات الجدولة الأصلية للنظام: systemd timers (Linux)، cron (Linux/macOS)، launchd (macOS)، Task Scheduler (Windows).

```bash
sd schedule add /home --frequency daily
sd schedule add /tmp --frequency hourly
sd schedule status
sd schedule remove
```

| الأمر الفرعي | الوصف |
|---------------|-------|
| `add <PATH>` | تسجيل فحص مجدول متكرر |
| `remove` | إزالة الفحص المجدول |
| `status` | عرض حالة الجدولة الحالية |

**التكرارات:** `hourly`، `4h`، `12h`، `daily`، `weekly` (الافتراضي: `weekly`).

---

## التنبيهات

### `sd webhook <SUBCOMMAND>`

إدارة نقاط نهاية تنبيهات webhook.

```bash
sd webhook list
sd webhook add my-slack https://hooks.slack.com/services/... --format slack
sd webhook add my-discord https://discord.com/api/webhooks/... --format discord
sd webhook add custom https://example.com/alert --format generic
sd webhook remove my-slack
sd webhook test
```

| الأمر الفرعي | الوصف |
|---------------|-------|
| `list` | عرض عناوين webhook المُعدّة |
| `add <NAME> <URL>` | إضافة webhook (`--format`: `slack`، `discord`، `generic`) |
| `remove <NAME>` | إزالة webhook بالاسم |
| `test` | إرسال تنبيه تجريبي لجميع عناوين webhook |

### `sd email-alert <SUBCOMMAND>`

إدارة إعدادات التنبيه بالبريد الإلكتروني.

```bash
sd email-alert configure
sd email-alert test
sd email-alert send "Trojan.Generic" "high" "/tmp/malware.exe"
```

| الأمر الفرعي | الوصف |
|---------------|-------|
| `configure` | إنشاء أو عرض إعدادات بريد SMTP |
| `test` | إرسال بريد تنبيه تجريبي |
| `send <NAME> <LEVEL> <PATH>` | إرسال بريد تنبيه مخصص |

---

## تصفية DNS والشبكة

### `sd adblock <SUBCOMMAND>`

إدارة تصفية الإعلانات ونطاقات البرمجيات الخبيثة.

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

| الأمر الفرعي | الوصف |
|---------------|-------|
| `enable` | تنزيل قوائم الحظر وتثبيت حظر DNS (`/etc/hosts`) |
| `disable` | إزالة إدخالات حظر DNS |
| `sync` | فرض إعادة تنزيل جميع قوائم التصفية |
| `stats` | عرض إحصائيات التصفية |
| `check <URL>` | التحقق مما إذا كان عنوان URL/نطاق محظورًا |
| `log` | عرض الإدخالات المحظورة الأخيرة (`-c, --count <NUM>`، الافتراضي: 50) |
| `add <NAME> <URL>` | إضافة قائمة تصفية مخصصة (`--category`: `ads`، `tracking`، `malware`، `social`) |
| `remove <NAME>` | إزالة قائمة تصفية |

### `sd dns-proxy`

تشغيل وكيل DNS محلي مع تصفية adblock وIOC وقوائم الحظر المخصصة.

```bash
sudo sd dns-proxy
sudo sd dns-proxy --listen 127.0.0.1:5353 --upstream 1.1.1.1:53
```

| الخيار | الوصف | القيمة الافتراضية |
|--------|-------|-------------------|
| `--listen <ADDR>` | عنوان الاستماع | `127.0.0.1:53` |
| `--upstream <ADDR>` | خادم DNS الأعلى | `8.8.8.8:53` |
| `--log-path <PATH>` | مسار سجل الاستعلامات بتنسيق JSONL | `/tmp/prx-sd-dns.log` |

---

## التقارير

### `sd report <OUTPUT>`

إنشاء تقرير HTML مستقل من نتائج الفحص بتنسيق JSON.

```bash
sd scan /path --json | sd report report.html
sd report report.html --input results.json
```

| الخيار | الوصف | القيمة الافتراضية |
|--------|-------|-------------------|
| `--input <FILE>` | ملف JSON المُدخل (`-` للإدخال القياسي) | `-` (الإدخال القياسي) |

### `sd status`

عرض حالة العملية الخلفية بما في ذلك معرف العملية ووقت التشغيل وإصدار التوقيعات والتهديدات المحظورة.

```bash
sd status
```

---

## التكامل

### `sd install-integration`

تثبيت تكامل الفحص بالنقر بزر الفأرة الأيمن في مدير الملفات.

```bash
sd install-integration
```

مديرو الملفات المدعومون:
- **Linux:** Nautilus (GNOME Files)، Dolphin (KDE)، Nemo (Cinnamon)
- **macOS:** Finder Quick Action

### `sd self-update`

التحقق من التحديثات وتطبيقها من إصدارات GitHub.

```bash
sd self-update
sd self-update --check-only
```

| الخيار | الوصف |
|--------|-------|
| `--check-only` | التحقق فقط من توفر تحديث |

---

## أمثلة

### الإعداد الأولي

```bash
# التثبيت
curl -fsSL https://raw.githubusercontent.com/openprx/prx-sd/main/install.sh | bash

# استيراد توقيعات إضافية
sd import my-custom-hashes.txt
sd import-clamav main.cvd daily.cvd

# التحقق من الإعداد
sd info
```

### الحماية اليومية

```bash
# تشغيل العملية الخلفية (تراقب /home و /tmp، تحديث كل 4 ساعات)
sd daemon

# أو الفحص اليدوي
sd scan /home --recursive --auto-quarantine

# التحقق من الحالة
sd status
```

### الاستجابة للحوادث

```bash
# فحص مع معالجة كاملة
sudo sd scan /tmp --auto-quarantine --remediate

# فحص الذاكرة بحثًا عن تهديدات في الذاكرة
sudo sd scan-memory

# التحقق من وجود rootkit
sudo sd check-rootkit

# مراجعة الحجر الصحي
sd quarantine list
sd quarantine restore <ID> --to /safe/location
```

### الأتمتة

```bash
# جدولة فحص أسبوعي
sd schedule add /home --frequency weekly

# إعداد التنبيهات
sd webhook add slack https://hooks.slack.com/services/T.../B.../xxx --format slack
sd email-alert configure

# إخراج JSON للسكريبتات
sd scan /path --json | jq '.threats[] | .name'
```
