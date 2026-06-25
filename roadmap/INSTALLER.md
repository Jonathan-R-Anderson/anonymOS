```text
You are integrating the Calamares installer into this operating system. Do NOT treat this as a standalone Linux distribution. Treat this as an installer that becomes a first-class component of the existing project architecture.

Your goal is to completely integrate Calamares while preserving the design philosophy of this operating system:

• Immutable kernel
• Rootless security model
• Object-oriented operating system architecture
• Declarative system configuration
• BusyBox-based userland
• Linux compatibility layer
• Identity-based security model
• Minimal, auditable codebase
• Modular architecture

Before writing code, thoroughly inspect the existing repository and understand:

- Build system
- Boot process
- Init system
- Filesystem layout
- Packaging format
- Existing installer or live environment (if present)
- Current configuration system
- Object model
- Linux compatibility layer
- Security architecture

Never duplicate functionality that already exists.

──────────────────────────────────────────────
PHASE 1 — Repository Analysis
──────────────────────────────────────────────

Determine:

• How installation currently works
• How the live environment boots
• Where the root filesystem is generated
• How packages are installed
• How users are created
• How bootloader configuration is generated
• How configuration files are generated
• How first boot initialization works

Produce a report describing:

- Existing architecture
- Integration points
- Required modifications
- Components that should remain untouched

──────────────────────────────────────────────
PHASE 2 — Add Calamares
──────────────────────────────────────────────

Integrate Calamares as an internal project component.

Create a directory such as:

installer/
    calamares/

Do NOT place configuration throughout the repository.

Everything installer-related should live inside installer/.

Include:

installer/
    calamares/
        branding/
        modules/
        settings.conf
        modules.conf
        branding.desc
        scripts/
        assets/
        translations/
        slides/

The installer should build alongside the rest of the project.

──────────────────────────────────────────────
PHASE 3 — Build Integration
──────────────────────────────────────────────

Modify the project's build system so that:

- Calamares builds automatically
- Installer assets are copied into the live image
- Branding is generated automatically
- Installer modules are compiled
- Packaging is automated

The installer must be built as part of the normal build process.

Do not require manual copying.

──────────────────────────────────────────────
PHASE 4 — Branding
──────────────────────────────────────────────

Replace all Calamares branding.

Replace:

logos

icons

backgrounds

slideshow

window title

distribution name

installer name

version strings

copyright

default colors

with project branding.

No upstream branding should remain visible.

──────────────────────────────────────────────
PHASE 5 — Installation Flow
──────────────────────────────────────────────

Design a modern installation workflow.

Required pages:

Welcome

Language

Keyboard

Timezone

Disk Selection

Filesystem

Encryption

Hostname

Administrator

Identities

Summary

Installation

Finish

The installer should feel like a professional operating system installer.

──────────────────────────────────────────────
PHASE 6 — Identity Manager Page
──────────────────────────────────────────────

Create a completely custom Calamares module.

Instead of traditional Linux user creation only, create an Identity Manager page.

Example:

Administrator Account

Identity Profiles

☑ Personal

☑ Work

☑ Banking

☑ Research

☑ Disposable

☑ Anonymous

Each identity should become a declarative object within the installed system.

Do NOT immediately create every identity.

Instead, generate configuration describing them.

──────────────────────────────────────────────
PHASE 7 — Declarative Configuration
──────────────────────────────────────────────

The installer should NOT perform extensive imperative configuration.

Instead it should generate one declarative configuration file.

Example:

system.json

or

install.json

This configuration should include:

hostname

locale

timezone

filesystem

encryption

bootloader

users

administrator

identity definitions

desktop options

linux compatibility options

security options

package selections

network configuration

Everything should be generated from installer choices.

First boot should consume this configuration.

──────────────────────────────────────────────
PHASE 8 — Disk Installation
──────────────────────────────────────────────

Support:

GPT

MBR

EFI

BIOS

ext4

Btrfs

XFS

LUKS encryption

swapfile

swap partition

Support automatic partitioning and manual partitioning.

Respect immutable filesystem layouts if enabled.

──────────────────────────────────────────────
PHASE 9 — Post-install Scripts
──────────────────────────────────────────────

Implement post-install modules for:

Generating declarative configuration

Installing bootloader

Copying kernel

Generating initramfs

Creating administrator account

Creating initial object tree

Generating identity metadata

Initializing package database

Installing Linux compatibility layer

Preparing first boot

These scripts should be modular.

──────────────────────────────────────────────
PHASE 10 — First Boot Integration
──────────────────────────────────────────────

Instead of performing all configuration during installation:

Installer

↓

Generate configuration

↓

Copy operating system

↓

Reboot

↓

First Boot

↓

Initialize system

↓

Generate object tree

↓

Create identities

↓

Initialize permissions

↓

Enable services

↓

Finalize installation

──────────────────────────────────────────────
PHASE 11 — Security
──────────────────────────────────────────────

Ensure:

No plaintext passwords

Password hashing

Secure temporary files

Least privilege

Installer runs with minimal privileges possible

Validate user input

Verify copied files

Verify package integrity

Support Secure Boot if available

Support encrypted installations

──────────────────────────────────────────────
PHASE 12 — Project Integration
──────────────────────────────────────────────

Integrate with:

Object model

Identity manager

Package manager

Filesystem

Linux compatibility layer

Security manager

Kernel configuration

Init system

Configuration manager

Do not hardcode Linux assumptions if the project already abstracts them.

──────────────────────────────────────────────
PHASE 13 — Documentation
──────────────────────────────────────────────

Generate:

Architecture document

Installer developer guide

Directory structure

Module documentation

Branding guide

Configuration reference

Build instructions

Flow diagrams

First boot sequence

Future extension guide

──────────────────────────────────────────────
PHASE 14 — Validation
──────────────────────────────────────────────

Verify:

✓ Installer builds successfully

✓ Live ISO boots

✓ Installer launches automatically

✓ Installation succeeds

✓ Bootloader installs correctly

✓ System boots

✓ First boot consumes generated configuration

✓ Identities initialize correctly

✓ Object tree initializes

✓ Linux compatibility layer functions

✓ Security configuration is applied

✓ Declarative configuration is preserved

──────────────────────────────────────────────
GENERAL REQUIREMENTS
──────────────────────────────────────────────

- Favor modularity over monolithic code.
- Reuse Calamares modules where possible and create custom modules only for features unique to this operating system.
- Keep all installer-specific code isolated under the `installer/` subtree.
- Document every modification and explain why it is necessary.
- If the existing repository already provides equivalent functionality, extend or integrate with it rather than replacing it.
- At the end, produce a checklist of completed tasks, remaining work, integration risks, and recommended next steps.
```
