You are working on the current AnonymOS codebase.

The OS already contains:

* object-oriented system architecture
* immutable kernel
* rootless security model
* Linux compatibility layer
* Domain Manager
* Identity Manager
* Namespace Manager
* Process Manager
* declarative system configuration
* capability-based security
* object tree representing the entire operating system

Your task is to redesign and significantly expand the Domain Manager so that domains become complete reusable operating environments rather than simply isolated execution contexts.

The design should resemble a combination of:

* Qubes OS Templates
* Docker images
* NixOS modules
* virtual desktops
* immutable snapshots

without copying any of those implementations directly.

The implementation must integrate cleanly into the current AnonymOS object architecture.

# High-Level Goal

A domain should be a first-class object that contains everything necessary to create isolated workspaces.

A domain should define:

* installed applications
* default packages
* Linux compatibility configuration
* selected package manager
* environment variables
* filesystem overlays
* restricted filesystem access
* permissions
* policies
* networking
* startup services
* identity inheritance
* appearance
* desktop defaults

Domains should become reusable templates that users can clone, modify, export, import, delete, snapshot, and restore.

# Critical Filesystem Requirement

Each domain must have restricted filesystem visibility.

Even though AnonymOS may use a single global object/filesystem tree internally, each domain must only be able to access the folders, object paths, mounts, overlays, and shared directories explicitly granted to that domain.

Implement domain-local filesystem policy such as:

* allowed read paths
* allowed write paths
* denied paths
* mounted object roots
* shared folders
* temporary folders
* Linux root mounts
* overlay mounts
* read-only mounts
* executable paths
* package-manager writable paths
* user-home visibility
* cross-domain sharing rules

A domain must not be able to freely traverse the entire OS filesystem or object tree unless explicitly granted that capability.

The Domain Manager must enforce this through the Object Manager, Filesystem Manager, Namespace Manager, Security Manager, and Policy Engine.

Access should be mediated by capabilities, not raw path access.

Example:

```json
"filesystemAccess": {
  "defaultPolicy": "deny",
  "readOnly": [
    "/System/Templates/Developer",
    "/Shared/Public"
  ],
  "readWrite": [
    "/Domains/Development/Home",
    "/Domains/Development/Overlay",
    "/Shared/Projects/AnonymOS"
  ],
  "deny": [
    "/System/Kernel",
    "/System/Secrets",
    "/Domains/*/Private"
  ],
  "mounts": [
    {
      "source": "/Objects/Projects/AnonymOS",
      "target": "/home/user/project",
      "mode": "rw"
    },
    {
      "source": "/System/LinuxRoots/Arch",
      "target": "/linux",
      "mode": "ro"
    }
  ],
  "allowTraversalOutsideMounts": false,
  "allowCrossDomainAccess": false
}
```

The filesystem access model must allow a single unified OS filesystem/object tree while giving each domain a constrained view of that tree.

# Template Domains

Implement first-class Template Domains.

Examples:

* Developer Template
* Gaming Template
* Research Template
* Forensics Template
* Office Template
* Anonymous Browsing Template
* Media Editing Template
* Minimal Template
* Recovery Template
* Windows Compatibility Template
* AI Development Template

Every template should be immutable.

A running domain should reference exactly one template.

Changes should live in a writable overlay until committed, discarded, snapshotted, or promoted into a new template.

# Domain Lifecycle APIs

Implement APIs for:

* CreateDomain()
* DeleteDomain()
* CloneDomain()
* RenameDomain()
* PauseDomain()
* ResumeDomain()
* StartDomain()
* ShutdownDomain()
* SnapshotDomain()
* RestoreDomain()
* DuplicateDomain()
* ExportDomain()
* ImportDomain()
* ResetDomain()
* CommitOverlay()
* DiscardOverlay()

Each operation must integrate with the global object tree.

No external component should modify domain internals directly.

# Declarative Domain Configuration

Every domain and template should have a JSON manifest.

Example:

```json
{
  "name": "Development",
  "type": "domain",
  "template": "Developer",

  "linux": {
    "distribution": "Arch",
    "packageManager": "pacman"
  },

  "packages": [
    "git",
    "clang",
    "cmake",
    "python",
    "rust"
  ],

  "applications": [
    "terminal",
    "editor",
    "browser"
  ],

  "services": [
    "ssh-agent"
  ],

  "defaults": {
    "defaultBrowser": "browser",
    "defaultTerminal": "terminal",
    "defaultEditor": "editor",
    "defaultShell": "zsh",
    "defaultCompiler": "clang"
  },

  "startupPrograms": [
    "terminal"
  ],

  "environment": {
    "EDITOR": "editor",
    "SHELL": "/bin/zsh"
  },

  "filesystemAccess": {
    "defaultPolicy": "deny",
    "readOnly": [],
    "readWrite": [],
    "deny": [],
    "mounts": [],
    "allowTraversalOutsideMounts": false,
    "allowCrossDomainAccess": false
  },

  "networkPolicy": {},
  "identity": {},
  "permissions": {},
  "appearance": {},
  "policies": {}
}
```

The Domain Manager should generate runtime objects from this configuration.

# Template Inheritance

Support template inheritance.

Example:

Base Template
→ Developer Template
→ Rust Template
→ Embedded Template
→ Project Domain

Every level inherits configuration from its parent.

Only overrides should be stored.

Implement conflict resolution for:

* packages
* repositories
* services
* environment variables
* default applications
* permissions
* filesystem access
* network rules
* identity inheritance
* Linux compatibility settings
* appearance
* startup applications

Security-sensitive policies must merge using least privilege by default.

For example, child templates may reduce filesystem, network, or device access, but must not expand access unless explicitly allowed by the parent policy.

# Overlay Filesystem

Each running domain should have:

Immutable Template
→ Writable Overlay
→ Merged Runtime View

Support:

* discard overlay
* commit overlay
* snapshot overlay
* rollback overlay
* promote overlay to new template
* inspect overlay diff
* validate overlay before commit

Overlay commits must never mutate immutable templates directly unless a new template version is created.

# Software Management

Domains should define default installed software.

Examples:

Development:

* Git
* Python
* Rust
* VSCode or native editor
* clang
* cmake

Office:

* LibreOffice
* PDF viewer
* scanner tools

Anonymous:

* Tor Browser
* hardened Firefox
* VPN client

Forensics:

* Volatility
* Autopsy
* Wireshark
* binwalk
* sleuthkit

AI Development:

* Python
* CUDA tools if allowed
* PyTorch
* Jupyter
* model-management tools

The Domain Manager should automatically install required software when a domain is first created, subject to policy approval.

# Linux Compatibility Configuration

Each domain may choose its preferred Linux compatibility environment.

Supported distributions:

* Arch
* Debian
* Ubuntu
* Fedora
* Alpine
* Gentoo
* Void
* Nix
* BusyBox-only

Supported package managers:

* apt
* dnf
* pacman
* apk
* xbps
* emerge
* nix

Support:

* multiple repositories
* custom mirrors
* package pinning
* offline repositories
* trusted signing keys
* automatic updates
* manual updates
* frozen packages
* per-domain package caches
* per-domain package allowlists and denylists

# Default Applications

Allow domains to define domain-local defaults:

* defaultBrowser
* defaultTerminal
* defaultEditor
* defaultPDF
* defaultMusicPlayer
* defaultVideoPlayer
* defaultFileManager
* defaultShell
* defaultIDE
* defaultCompiler

These defaults must not affect other domains.

# Startup Configuration

Each domain may specify:

* startup applications
* startup services
* environment variables
* login shell
* desktop layout
* wallpaper
* color scheme
* mounted objects
* mounted Linux roots
* network interfaces
* default workspace
* initial window layout

# Package Profiles

Support reusable package collections.

Examples:

* Development Profile
* Office Profile
* Gaming Profile
* Research Profile
* Security Profile
* Minimal Profile
* AI Profile
* Media Profile

Profiles can be reused across templates and domains.

# Domain Marketplace

Design support for downloadable templates.

Templates should be installable without rebuilding the OS.

Support:

* signed templates
* dependency checking
* semantic versioning
* rollback
* cryptographic verification
* trust policies
* publisher identities
* local template registry
* offline template installation

# Domain Object Tree

Represent domains as first-class objects.

Example:

```text
System
└── Domains
    ├── Development
    │   ├── Template
    │   ├── Overlay
    │   ├── Applications
    │   ├── Packages
    │   ├── Services
    │   ├── Permissions
    │   ├── Identity
    │   ├── Networking
    │   ├── Filesystem
    │   │   ├── AllowedPaths
    │   │   ├── DeniedPaths
    │   │   ├── Mounts
    │   │   ├── Overlay
    │   │   └── RuntimeView
    │   ├── Linux
    │   ├── PackageManager
    │   ├── Appearance
    │   ├── Policies
    │   └── Snapshots
    ├── Research
    ├── Office
    └── Gaming
```

Everything must remain object-oriented and capability-controlled.

# Permissions and Policy Enforcement

The Domain Manager should enforce:

* allowed package managers
* allowed repositories
* allowed software
* maximum storage
* filesystem visibility
* filesystem traversal restrictions
* object tree access restrictions
* network permissions
* USB permissions
* GPU permissions
* shared folders
* clipboard policy
* IPC policy
* identity inheritance
* capabilities
* package installation permissions
* template modification permissions
* export/import permissions

Filesystem traversal must be denied by default outside the domain’s allowed view.

# GUI Integration

Create a graphical Domain Manager.

Support:

* Create Domain
* Delete Domain
* Clone Template
* Create Template
* Snapshot
* Rollback
* Commit
* Discard
* Install Software
* Remove Software
* Select Linux Distribution
* Select Package Manager
* Configure Networking
* Configure Permissions
* Configure Filesystem Access
* Configure Allowed Folders
* Configure Shared Folders
* Select Appearance
* Manage Startup Applications
* Export
* Import
* Template Browser
* Marketplace Browser

Everything should update live.

# CLI Commands

Implement:

```text
domain create
domain delete
domain clone
domain snapshot
domain restore
domain commit
domain discard
domain install
domain uninstall
domain packages
domain applications
domain services
domain templates
domain export
domain import
domain list
domain inspect
domain reset
domain fs allow
domain fs deny
domain fs mount
domain fs unmount
domain fs inspect
domain fs policy
```

# APIs

Design clean APIs for all domain operations.

The following components should interact exclusively through Domain Manager APIs:

* Object Manager
* Identity Manager
* Namespace Manager
* Process Manager
* Linux Compatibility Layer
* Package Manager
* Filesystem Manager
* GUI
* Window Manager
* Security Manager
* Policy Engine
* Installer
* Update Manager
* Configuration Manager

No component should directly mutate domain object internals.

# Deliverables

Produce a complete implementation roadmap that includes:

1. Required architectural changes.
2. New object model and class hierarchy.
3. JSON schema for domain and template manifests.
4. Domain lifecycle state machine.
5. Overlay filesystem design.
6. Restricted filesystem access model.
7. Template inheritance model.
8. Package management integration for multiple Linux package managers.
9. Linux compatibility layer integration.
10. GUI wireframes and workflows.
11. CLI command specifications.
12. Internal APIs and IPC interfaces.
13. Data storage layout on disk.
14. Security model and capability enforcement.
15. Snapshot, rollback, export, and import mechanisms.
16. Domain marketplace design.
17. Prioritized implementation checklist organized into milestones.
18. Dependencies between milestones.
19. Validation criteria.
20. Testing plans suitable for incremental development within the existing AnonymOS codebase.

The roadmap should be detailed enough that another LLM or developer can implement the Domain Manager incrementally without needing to infer missing architecture.
