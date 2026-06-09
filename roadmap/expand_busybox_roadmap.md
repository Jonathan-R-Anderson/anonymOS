You are working on my custom OS / BusyBox-based userland. Expand the current minimal BusyBox-style environment into a real Linux-like user security system with users, groups, file ownership, permissions, login sessions, and privilege boundaries.

Goal:
Implement a coherent Unix/Linux-style identity and permission model without turning the OS into a full GNU/Linux clone. Keep it small, auditable, and suitable for an embedded/custom OS userland.

Design and implement the following:

1. Core identity model
- Add UID and GID support.
- Support:
  - numeric user IDs
  - numeric group IDs
  - usernames
  - group names
  - primary group
  - supplementary groups
- Define reserved IDs:
  - UID 0 = root/admin
  - GID 0 = root/admin group
  - system users below a chosen threshold, such as UID < 1000
  - normal users starting at UID 1000

2. Account database
Implement minimal equivalents of:

- /etc/passwd
- /etc/group
- /etc/shadow

Use simple parsers first. Do not over-engineer.

Required fields:

/etc/passwd:
username:x:uid:gid:gecos:home:shell

/etc/group:
groupname:x:gid:user1,user2,user3

/etc/shadow:
username:password_hash:last_change:min:max:warn:inactive:expire:reserved

Rules:
- /etc/passwd should be world-readable.
- /etc/shadow should only be readable by root.
- Password hashes must not be stored in /etc/passwd.
- Use a modern password hashing function if available. If not available yet, create an abstraction layer so the hash backend can later become Argon2id, bcrypt, or yescrypt.

3. Permission model
Add Unix-style permission checks to the VFS/filesystem layer.

Each filesystem object should have:
- owner UID
- group GID
- mode bits:
  - read/write/execute for owner
  - read/write/execute for group
  - read/write/execute for others
  - setuid
  - setgid
  - sticky bit

Implement permission checks for:
- opening files
- reading files
- writing files
- executing files
- creating files
- deleting files
- renaming files
- traversing directories
- changing metadata

Directory semantics:
- execute on directory means traversal/search permission.
- write + execute on directory is required to create/delete entries.
- sticky bit on a directory means only root, the directory owner, or the file owner may delete/rename entries.

4. Process credentials
Every process must have credentials:

- real UID
- effective UID
- saved UID
- real GID
- effective GID
- saved GID
- supplementary groups
- capability/privilege set, if the OS already has capabilities

Implement syscalls or internal APIs for:
- getuid
- geteuid
- getgid
- getegid
- setuid
- seteuid
- setgid
- setegid
- getgroups
- setgroups

Rules:
- Only root or a privileged capability may arbitrarily change UID/GID.
- Non-root users may only switch between real/effective/saved IDs when allowed.
- Supplementary groups should be inherited across fork/exec.
- Credentials should be copied safely during fork and preserved or transformed during exec.

5. Login and session system
Implement a minimal login flow:

- login reads username.
- login verifies password using /etc/shadow.
- on success:
  - sets UID/GID/groups
  - sets HOME
  - sets USER
  - sets LOGNAME
  - sets SHELL
  - chdir to home directory
  - exec user shell

Add basic commands:
- login
- passwd
- su
- id
- whoami
- groups
- adduser
- deluser
- addgroup
- delgroup
- usermod
- chown
- chgrp
- chmod

Prioritize:
1. id
2. whoami
3. chmod
4. chown
5. adduser
6. login
7. passwd
8. su

6. File creation defaults
Implement:
- umask
- default file mode
- default directory mode
- inheritance of owner/group on file creation
- setgid directory inheritance, where files created inside a setgid directory inherit the directory group

7. Root and privilege rules
Implement UID 0 as the initial superuser.

Root should bypass normal file permission checks, except:
- keep explicit checks for dangerous operations where appropriate
- do not allow root bypass to corrupt immutable/security-critical objects unless the OS design intentionally allows it

If this OS already has a capability system, split root privileges into capabilities such as:
- CAP_CHOWN
- CAP_DAC_OVERRIDE
- CAP_SETUID
- CAP_SETGID
- CAP_FOWNER
- CAP_SYS_ADMIN

If no capability system exists yet, design the interfaces so capabilities can be added later.

8. BusyBox integration
Modify or add BusyBox applets for:

- id
- whoami
- groups
- chmod
- chown
- chgrp
- passwd
- login
- su
- adduser
- addgroup

Keep applets small and share common code in a user/security library.

Create shared modules:
- userdb parser
- groupdb parser
- shadowdb parser
- password hashing interface
- permission formatting/parsing
- uid/gid lookup helpers
- credential manipulation helpers

9. Security hardening
Add checks for:
- malformed /etc/passwd
- duplicate usernames
- duplicate UIDs
- duplicate group names
- duplicate GIDs
- invalid shells
- missing home directories
- weak password handling
- TOCTOU risks when editing account files

When modifying account files:
- write to temporary file
- fsync
- rename atomically
- preserve permissions
- lock the account database during edits

Implement lock files such as:
- /etc/.pwd.lock

10. Testing
Create tests for:

Account parsing:
- valid passwd/group/shadow files
- malformed entries
- duplicate users/groups
- missing fields

Permission checks:
- owner read/write/execute
- group read/write/execute
- other read/write/execute
- directory traversal
- sticky directory deletion
- setgid directory inheritance
- root override

Process credentials:
- fork inheritance
- exec inheritance
- setuid behavior
- setgid behavior
- supplementary groups

Commands:
- id
- whoami
- chmod
- chown
- adduser
- login success
- login failure
- passwd updates shadow safely

11. Suggested implementation order

Phase 1: Data structures
- Add UID/GID/mode fields to filesystem metadata.
- Add process credential structure.
- Add basic uid/gid constants.

Phase 2: Permission enforcement
- Implement central permission_check() function.
- Call it from VFS open/read/write/exec/create/delete/rename/chmod/chown paths.

Phase 3: Account files
- Implement parsers for passwd, group, and shadow.
- Implement lookup functions:
  - getpwnam
  - getpwuid
  - getgrnam
  - getgrgid
  - getspnam

Phase 4: Basic tools
- Implement id, whoami, groups.
- Implement chmod, chown, chgrp.

Phase 5: Account management
- Implement adduser, addgroup, deluser, delgroup, usermod.
- Add safe file update and locking.

Phase 6: Authentication
- Implement password hashing abstraction.
- Implement passwd.
- Implement login.
- Implement su.

Phase 7: Hardening
- Add tests.
- Add fuzz tests for parsers.
- Add security review comments.
- Document threat model and known limitations.

12. Deliverables

Produce:
- architecture document
- data structure changes
- syscall/API list
- VFS permission algorithm
- account file parser implementation
- BusyBox applet implementations
- test suite
- migration notes
- TODO list for future capability-based privilege separation

Important design constraints:
- Keep the implementation small and auditable.
- Avoid pulling in unnecessary large dependencies.
- Prefer centralized permission logic over scattered checks.
- Do not store plaintext passwords.
- Do not make every process root by default.
- All filesystem operations must eventually route through the same permission enforcement layer.
- Make this compatible with a future object-based filesystem and namespace system.