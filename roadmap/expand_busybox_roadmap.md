You are working on my custom OS / BusyBox-based userland.

Expand the current minimal BusyBox-style environment into a much more Linux-like embedded userland with a coherent Unix security model, standard account files, login sessions, permissions, ownership, service accounts, init integration, and common administrative tools.

The goal is not to clone GNU/Linux or systemd. The goal is to make the OS feel like a real small Linux system while staying compact, auditable, portable, and suitable for an embedded/custom OS.

Core principles:

* Keep implementation small and readable.
* Prefer centralized security checks over scattered logic.
* Do not make every process root by default.
* Do not store plaintext passwords.
* Avoid large dependencies.
* Make it compatible with a future object-based filesystem and namespace system.
* Keep BusyBox-style applets small and share common security/userland code.
* Every filesystem operation must eventually route through one permission enforcement layer.
* Use Linux/POSIX behavior where reasonable, but document intentional deviations.

Implement the following system.

---

# 1. Core Identity Model

Add Unix-style identity support.

Every user has:

* username
* UID
* primary GID
* gecos/comment field
* home directory
* login shell

Every group has:

* group name
* GID
* member list

Every process has:

* real UID
* effective UID
* saved UID
* real GID
* effective GID
* saved GID
* supplementary groups
* optional capability/privilege set

Reserved IDs:

* UID 0 = root/admin
* GID 0 = root/admin group
* UID/GID 1–999 = system users/groups
* UID/GID 1000+ = normal users/groups
* nobody user should exist, for example UID 65534 / GID 65534

Default initial users/groups:

/etc/passwd:

```text
root:x:0:0:root:/root:/bin/sh
nobody:x:65534:65534:nobody:/nonexistent:/bin/false
```

/etc/group:

```text
root:x:0:
users:x:100:
nogroup:x:65534:
```

---

# 2. Account Database

Implement minimal versions of:

```text
/etc/passwd
/etc/group
/etc/shadow
```

Required formats:

/etc/passwd:

```text
username:x:uid:gid:gecos:home:shell
```

/etc/group:

```text
groupname:x:gid:user1,user2,user3
```

/etc/shadow:

```text
username:password_hash:last_change:min:max:warn:inactive:expire:reserved
```

Rules:

* /etc/passwd is world-readable.
* /etc/group is world-readable.
* /etc/shadow is readable only by root.
* Password hashes must never be stored in /etc/passwd.
* Use a password hashing abstraction.
* Start with a simple backend if necessary, but design for Argon2id, bcrypt, yescrypt, or scrypt later.
* Plaintext password storage is forbidden.
* Account parsers must reject malformed lines safely.
* Duplicate usernames, duplicate UIDs, duplicate group names, and duplicate GIDs must be detected.
* Unknown users/groups should return clean errors.

Implement shared library modules:

```text
libuserdb
libgroupdb
libshadowdb
libauth
libperm
libcred
```

Functions:

```c
getpwnam()
getpwuid()
getgrnam()
getgrgid()
getspnam()
uid_to_name()
gid_to_name()
name_to_uid()
name_to_gid()
load_passwd_db()
load_group_db()
load_shadow_db()
validate_account_files()
```

---

# 3. Filesystem Metadata

Every filesystem object must contain:

```c
uid_t owner_uid;
gid_t group_gid;
mode_t mode;
```

Mode bits must support:

```text
0400 owner read
0200 owner write
0100 owner execute

0040 group read
0020 group write
0010 group execute

0004 other read
0002 other write
0001 other execute

04000 setuid
02000 setgid
01000 sticky
```

Also reserve room for future bits:

```text
immutable
append-only
hidden
system
security label
object namespace ID
```

Directories must behave like Unix:

* read = list entries
* write = modify entries
* execute = traverse/search
* write + execute required to create/delete/rename entries
* sticky bit limits deletion/rename

---

# 4. Permission Model

Implement one central function:

```c
int permission_check(struct cred *cred, struct inode *inode, int mask);
```

Permission masks:

```c
MAY_READ
MAY_WRITE
MAY_EXEC
MAY_CREATE
MAY_DELETE
MAY_RENAME
MAY_CHMOD
MAY_CHOWN
MAY_TRAVERSE
```

Permission algorithm:

1. If credential has CAP_DAC_OVERRIDE or UID 0, allow most checks.
2. For execute checks, require at least one execute bit unless root override is explicitly allowed.
3. If effective UID equals file owner UID, use owner bits.
4. Else if effective GID equals file GID or file GID is in supplementary groups, use group bits.
5. Else use other bits.
6. Compare requested access mask against selected mode bits.
7. Return allow/deny.

Directory rules:

* Traversing `/a/b/c` requires execute permission on `/`, `/a`, and `/a/b`.
* Listing a directory requires read permission on the directory.
* Creating a file requires write + execute on parent directory.
* Deleting a file requires write + execute on parent directory.
* Renaming requires write + execute on source and destination parent directories.
* Sticky directory rule:

  * In a sticky directory, only root, directory owner, or file owner may delete/rename an entry.

Metadata rules:

* chmod:

  * allowed for root or file owner
* chown:

  * allowed only for root or CAP_CHOWN
* chgrp:

  * allowed for root, or file owner if target group is one of user’s groups
* setuid/setgid bits:

  * only preserved when caller has appropriate privilege
  * clear setuid/setgid on write unless caller has privilege

---

# 5. Process Credentials

Add a credential structure:

```c
#define NGROUPS_MAX 32

struct cred {
    uid_t ruid;
    uid_t euid;
    uid_t suid;

    gid_t rgid;
    gid_t egid;
    gid_t sgid;

    gid_t groups[NGROUPS_MAX];
    int ngroups;

    uint64_t caps_effective;
    uint64_t caps_permitted;
    uint64_t caps_inheritable;

    mode_t umask;
};
```

Each process owns credentials.

Rules:

* Credentials are copied on fork.
* Credentials are preserved across exec unless setuid/setgid bits apply.
* Supplementary groups are inherited across fork/exec.
* umask is inherited across fork/exec.
* Only root/CAP_SETUID can arbitrarily change UID.
* Only root/CAP_SETGID can arbitrarily change GID/groups.
* Non-root may only switch between real/effective/saved IDs when POSIX rules allow.

Implement syscalls/internal APIs:

```c
getuid
geteuid
getgid
getegid
setuid
seteuid
setgid
setegid
getgroups
setgroups
setreuid
setregid
umask
```

Exec behavior:

* If file has setuid bit, effective UID becomes file owner UID.
* If file has setgid bit, effective GID becomes file group GID.
* Saved IDs update after exec.
* Future capability model should hook here.

---

# 6. Capabilities / Future Privilege Model

If capabilities already exist, implement:

```text
CAP_CHOWN
CAP_DAC_OVERRIDE
CAP_DAC_READ_SEARCH
CAP_FOWNER
CAP_SETUID
CAP_SETGID
CAP_SYS_ADMIN
CAP_SYS_BOOT
CAP_SYS_TIME
CAP_NET_ADMIN
CAP_KILL
```

If capabilities do not exist yet:

* Keep UID 0 as the superuser.
* Implement capability fields as placeholders.
* Implement helper functions:

```c
cred_has_cap(cred, CAP_X)
is_superuser(cred)
may_override_dac(cred)
may_chown(cred)
may_setuid(cred)
may_setgid(cred)
```

Do not scatter `euid == 0` checks everywhere. Use helper functions.

---

# 7. Login and Sessions

Implement a minimal login flow.

`login` should:

1. Read username.
2. Look up user in /etc/passwd.
3. Read corresponding shadow entry.
4. Prompt for password without echo.
5. Verify password hash.
6. Validate shell and home directory.
7. Set UID/GID/supplementary groups.
8. Set environment:

```text
HOME
USER
LOGNAME
SHELL
PATH
TERM
```

9. chdir to home directory.
10. exec user shell.

Default environment:

```text
PATH=/bin:/sbin:/usr/bin:/usr/sbin
HOME=<user home>
USER=<username>
LOGNAME=<username>
SHELL=<shell>
```

Session support:

* Add a minimal session record system.
* Optional files:

```text
/var/run/utmp
/var/log/wtmp
```

If full utmp/wtmp is too large, implement a simpler file:

```text
/var/run/sessions
```

Session fields:

```text
session_id
uid
username
tty
login_time
pid
```

Add commands:

```text
who
w
users
```

These can be minimal.

---

# 8. BusyBox Applets

Modify or add BusyBox-style applets:

Priority 1:

```text
id
whoami
chmod
chown
chgrp
```

Priority 2:

```text
adduser
addgroup
deluser
delgroup
passwd
login
su
groups
```

Priority 3:

```text
usermod
groupmod
newgrp
umask
ls -l support
stat
namei
find -user
find -group
```

Applet behavior:

`id`:

```text
uid=1000(user) gid=1000(user) groups=1000(user),10(wheel)
```

`whoami`:

```text
prints effective username
```

`groups`:

```text
prints supplementary group names
```

`chmod`:

* symbolic mode support:

  * u+r
  * g-w
  * o+x
  * a+r
  * u+s
  * g+s
  * +t
* octal mode support:

  * 755
  * 0644
  * 4755
  * 1777

`chown`:

Support:

```text
chown user file
chown user:group file
chown :group file
chown -R user:group directory
```

`chgrp`:

```text
chgrp group file
```

`adduser`:

* allocate next UID >= 1000
* create primary group unless disabled
* create home directory
* copy skeleton files from /etc/skel if present
* set ownership
* prompt for password or create locked account

`passwd`:

* verify old password unless root
* update /etc/shadow safely
* use password hashing abstraction
* enforce minimum password rules if configured

`su`:

* verify target user password unless root
* switch UID/GID/groups
* support:

  * `su user`
  * `su - user`
  * `su root`

`login`:

* authenticate
* create session
* exec shell

---

# 9. File Creation Defaults

Implement umask.

Default modes:

```text
files: 0666 & ~umask
directories: 0777 & ~umask
executables: explicit chmod required unless created by loader/tool
```

Ownership rules:

* New file owner = effective UID of creating process.
* New file group = effective GID of creating process.
* If parent directory has setgid bit:

  * new file group = parent directory group
  * new subdirectory inherits setgid bit

Default root umask:

```text
022
```

Default normal user umask:

```text
022
```

Optional private-user umask:

```text
077
```

---

# 10. Standard Filesystem Layout

Move closer to real Linux layout while staying small.

Create:

```text
/
├── bin
├── sbin
├── etc
├── dev
├── proc
├── sys
├── run
├── tmp
├── var
├── home
├── root
├── usr
│   ├── bin
│   └── sbin
└── lib
```

Required permissions:

```text
/               root:root 0755
/bin            root:root 0755
/sbin           root:root 0755
/etc            root:root 0755
/etc/passwd     root:root 0644
/etc/group      root:root 0644
/etc/shadow     root:root 0600
/home           root:root 0755
/root           root:root 0700
/tmp            root:root 1777
/var            root:root 0755
/var/log        root:root 0755
/var/run        root:root 0755
/run            root:root 0755
```

Add minimal config files:

```text
/etc/passwd
/etc/group
/etc/shadow
/etc/shells
/etc/profile
/etc/motd
/etc/issue
/etc/login.defs
/etc/skel/.profile
```

Example `/etc/shells`:

```text
/bin/sh
/bin/false
```

Example `/etc/login.defs`:

```text
UID_MIN 1000
UID_MAX 60000
GID_MIN 1000
GID_MAX 60000
SYS_UID_MIN 1
SYS_UID_MAX 999
SYS_GID_MIN 1
SYS_GID_MAX 999
CREATE_HOME yes
UMASK 022
PASS_MAX_DAYS 99999
PASS_MIN_DAYS 0
PASS_WARN_AGE 7
```

---

# 11. Init and Boot Integration

At boot:

1. Mount root filesystem.
2. Ensure required directories exist.
3. Ensure `/etc/passwd`, `/etc/group`, and `/etc/shadow` exist.
4. Ensure root account exists.
5. Set correct permissions on security-critical files.
6. Start init.
7. Init launches getty/login on console.

Add minimal `/etc/inittab` support if not present:

```text
tty1::respawn:/sbin/getty tty1
```

Add minimal `getty`:

* opens tty
* sets terminal mode
* prints `/etc/issue`
* execs `/bin/login`

---

# 12. Device and TTY Permissions

Add basic device node ownership and modes.

Suggested:

```text
/dev/null     root:root 0666
/dev/zero     root:root 0666
/dev/random   root:root 0666
/dev/urandom  root:root 0666
/dev/console  root:tty  0600
/dev/tty      root:tty  0666
/dev/tty0     root:tty  0600
```

Create groups:

```text
tty
disk
input
video
audio
netdev
wheel
```

Use group-based access for privileged devices.

---

# 13. Privileged Groups

Add common privileged groups:

```text
wheel
sudo
adm
tty
disk
audio
video
input
netdev
```

Do not implement full sudo unless requested.

For now:

* `su root` may optionally require membership in `wheel`.
* log failed `su` attempts.
* root login may be allowed only on console depending on config.

---

# 14. Account File Editing Safety

When modifying account files:

1. Acquire lock:

```text
/etc/.pwd.lock
```

2. Read current files.
3. Validate full database.
4. Write new temp file in same directory.
5. Set correct owner/mode.
6. fsync temp file.
7. Rename atomically.
8. fsync parent directory.
9. Release lock.

Never partially update account files.

Avoid TOCTOU bugs:

* do not follow symlinks for `/etc/shadow`
* verify file owner/mode before reading sensitive files
* use openat-style APIs if available
* reject world-writable account files
* reject non-root-owned account files

---

# 15. Password Hashing Interface

Create:

```c
struct password_hash_backend {
    const char *name;
    int (*hash)(const char *password, char *out, size_t out_len);
    int (*verify)(const char *password, const char *encoded_hash);
    int (*needs_rehash)(const char *encoded_hash);
};
```

Encoded hash format should identify backend:

```text
$argon2id$...
$bcrypt$...
$scrypt$...
$sha256$...
```

Temporary fallback is acceptable only if clearly marked insecure for development.

Do not ship with plaintext or reversible password storage.

---

# 16. Logging and Auditing

Add minimal auth logs:

```text
/var/log/auth.log
```

Log:

* login success
* login failure
* passwd change
* su success
* su failure
* adduser
* deluser
* addgroup
* delgroup
* chmod/chown failures for security-critical files if useful

Log format:

```text
timestamp pid uid euid applet: message
```

Keep logging optional for tiny builds.

---

# 17. VFS Integration Points

All these operations must call centralized permission logic:

```text
open
read
write
exec
mkdir
rmdir
unlink
rename
link
symlink
chmod
chown
truncate
readdir
stat
utime
mount
```

Do not rely only on applet-side checks. Kernel/VFS checks are required.

---

# 18. Testing

Create tests for:

Account parsing:

* valid passwd file
* valid group file
* valid shadow file
* malformed passwd lines
* malformed group lines
* malformed shadow lines
* duplicate usernames
* duplicate UIDs
* duplicate group names
* duplicate GIDs
* unknown shell
* missing home directory

Permission checks:

* owner read/write/execute
* group read/write/execute
* other read/write/execute
* directory traversal
* directory listing
* create requires write+execute
* delete requires write+execute
* sticky directory deletion
* setgid directory inheritance
* chmod owner allowed
* chmod non-owner denied
* chown root allowed
* chown non-root denied
* root override
* setuid exec behavior
* setgid exec behavior

Process credentials:

* fork credential inheritance
* exec credential preservation
* setuid behavior
* seteuid behavior
* setgid behavior
* supplementary group inheritance
* umask inheritance

Commands:

* id
* whoami
* groups
* chmod octal
* chmod symbolic
* chown user
* chown user:group
* chgrp
* adduser
* addgroup
* passwd update
* login success
* login failure
* su success
* su failure

Fuzz tests:

* passwd parser
* group parser
* shadow parser
* chmod mode parser
* chown user/group parser

---

# 19. Suggested Implementation Order

Phase 1: Data structures

* Add UID/GID/mode fields to filesystem metadata.
* Add process credential structure.
* Add root/nobody constants.
* Add umask to credentials.

Phase 2: VFS permissions

* Implement central `permission_check()`.
* Wire it into open/read/write/exec/create/delete/rename/chmod/chown.
* Add directory traversal rules.
* Add sticky directory behavior.
* Add setgid directory inheritance.

Phase 3: Account database

* Implement passwd parser.
* Implement group parser.
* Implement shadow parser.
* Implement lookup helpers.
* Add validation tools.

Phase 4: Basic identity tools

* Implement:

  * id
  * whoami
  * groups
  * ls -l ownership display

Phase 5: Permission tools

* Implement:

  * chmod
  * chown
  * chgrp
  * stat

Phase 6: Account management

* Implement:

  * adduser
  * addgroup
  * deluser
  * delgroup
  * usermod
* Add safe account file locking and atomic update.

Phase 7: Authentication

* Implement password hashing abstraction.
* Implement passwd.
* Implement login.
* Implement su.
* Implement getty if needed.

Phase 8: Linux-like environment polish

* Add filesystem skeleton.
* Add /etc/profile.
* Add /etc/shells.
* Add /etc/login.defs.
* Add /etc/skel.
* Add /tmp sticky permissions.
* Add standard groups.
* Add minimal session tracking.

Phase 9: Hardening

* Add parser fuzzing.
* Add audit logging.
* Add shadow permission checks.
* Add symlink/TOCTOU defenses.
* Review all root bypasses.
* Document limitations.

---

# 20. Deliverables

Produce:

1. Architecture document
2. Threat model
3. Data structure changes
4. Syscall/API list
5. VFS permission algorithm
6. Account file parser implementation
7. Password hashing interface
8. Credential management implementation
9. BusyBox applet implementations
10. Init/login integration notes
11. Filesystem layout/migration script
12. Test suite
13. Fuzz tests
14. Security review checklist
15. TODO list for future capabilities, namespaces, MAC labels, and object filesystem integration

---

# 21. Future TODOs

Design hooks for:

* capabilities replacing all-powerful root
* chroot
* namespaces
* mount permissions
* object-based filesystem ownership
* ACLs
* MAC labels
* per-service users
* seccomp-like syscall filters
* signed executable policy
* immutable files
* append-only files
* sudo/doas-style privilege escalation
* PAM-like authentication modules, but smaller
* network login
* SSH-style remote shell
* audit daemon
* encrypted shadow database
* account expiration
* password aging
* login rate limiting

Keep these as interfaces and TODOs unless they are easy to add without bloating the system.
