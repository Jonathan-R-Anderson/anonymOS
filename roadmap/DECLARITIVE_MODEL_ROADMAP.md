You are helping design and implement anonymOS, a custom OS with an object-based system model, rootless immutable kernel direction, namespaces, process manager, identity manager, secure IPC, and compatibility layers.

Goal:
Create a roadmap for making the entire OS declaratively configurable through one primary JSON configuration file, similar in spirit to NixOS, but adapted to anonymOS.

The system should allow everything customizable about the OS to be declared in one JSON file, including:

- kernel boot options
- enabled kernel features
- object tree layout
- filesystem/object-store mounts
- users and identities
- namespace definitions
- process/service definitions
- startup order
- permissions and capabilities
- IPC policies
- network configuration
- GUI/window identity colors
- security profiles
- immutable system image settings
- Linux compatibility layer settings
- Windows/ReactOS compatibility layer settings
- package/runtime environment definitions
- logging/auditing settings
- rollback/snapshot behavior
- distributed OS features
- decoy OS / honeypot behavior

The roadmap should explain how to implement this based on the current anonymOS architecture.

Important design requirement:
The JSON file should not merely be a boot config. It should be the single declarative source of truth for constructing the entire running system state.

Expected output:
Create a detailed implementation roadmap broken into phases.

Use this structure:

1. Core Philosophy
   - Explain how anonymOS should treat the JSON file as a declarative system graph.
   - Explain how this differs from traditional runtime configuration.
   - Explain how it resembles NixOS but should use anonymOS object-tree concepts.

2. JSON Schema Design
   - Propose a top-level JSON schema.
   - Include sections like:
     - system
     - kernel
     - boot
     - objects
     - identities
     - namespaces
     - services
     - processes
     - capabilities
     - ipc
     - storage
     - networking
     - gui
     - compatibility
     - security
     - logging
     - snapshots
     - distributed
   - Give a realistic example JSON file.

3. Config Compiler
   - Explain how to build a config compiler that validates the JSON and converts it into an internal object graph.
   - The compiler should:
     - parse JSON
     - validate against schema
     - resolve references
     - detect circular references
     - check permissions
     - assign stable object IDs
     - generate a boot plan
     - generate a service graph
     - generate capability manifests
   - Include how circular dependency detection should work.

4. Boot Integration
   - Explain how the bootloader/kernel should locate and verify the JSON config.
   - Explain how early boot should parse a minimal trusted subset.
   - Explain which parts are handled by the kernel and which are handled by user-space init.

5. Declarative Object Tree
   - Explain how the JSON should instantiate the OS object tree.
   - Every service, user, namespace, file mount, process, device, and permission should become an object.
   - Explain parent/child inheritance rules.

6. Declarative Services
   - Design a service manager that works like systemd/NixOS modules but object-native.
   - Services should have:
     - name
     - executable
     - identity
     - namespace
     - capabilities
     - dependencies
     - restart policy
     - IPC permissions
     - filesystem/object permissions
   - Explain startup ordering and dependency resolution.

7. Declarative Identity and Namespace System
   - Explain how identities are declared in JSON.
   - Include GUI border colors per identity.
   - Include per-identity filesystem views, network policies, process permissions, clipboard rules, and IPC permissions.
   - Model it like Qubes-style identities but inside anonymOS.

8. Declarative Capability Security
   - Explain how permissions are declared as capabilities.
   - No process should receive ambient root privileges.
   - Capabilities should be explicit, inherited only when allowed, and reducible by child objects.
   - Explain how the config compiler should reject unsafe privilege escalation.

9. Declarative IPC Security
   - Explain how secure IPC policies are declared.
   - Include which processes may talk to each other.
   - Include whether Diffie-Hellman session setup is required.
   - Include which key-broker/security-service delegates keys.
   - Include audit rules for IPC.

10. Immutable System and Rollback
   - Explain how a JSON config change creates a new system generation.
   - Previous generations should remain bootable.
   - The kernel and core system should be immutable.
   - Runtime state should be separated from declared state.
   - Include rollback strategy.

11. Module System
   - Explain how to avoid one giant unmaintainable JSON file.
   - Design an import/include system:
     - base.json
     - hardware.json
     - identities.json
     - services.json
     - gui.json
   - The final build should still compile into one canonical resolved JSON graph.

12. Validation and Safety
   - Explain checks that must run before applying config:
     - schema validation
     - object reference validation
     - dependency cycle detection
     - privilege escalation detection
     - invalid IPC rule detection
     - namespace isolation checks
     - service boot ordering checks
   - Explain safe failure behavior.

13. Live Reconfiguration
   - Explain which settings can be changed live and which require reboot.
   - Examples:
     - GUI color changes: live
     - service restart policy: live
     - kernel memory layout: reboot
     - immutable image change: reboot
   - Include transaction/rollback behavior for live changes.

14. CLI Tools
   - Design command-line tools:
     - anonymos-config check system.json
     - anonymos-config build system.json
     - anonymos-config diff old.json new.json
     - anonymos-config switch system.json
     - anonymos-config rollback
     - anonymos-config graph system.json
   - Explain what each command does.

15. Example Implementation Phases
   - Phase 1: JSON parser and schema validator
   - Phase 2: internal object graph representation
   - Phase 3: config compiler
   - Phase 4: declarative service manager
   - Phase 5: identity and namespace declaration
   - Phase 6: declarative capability system
   - Phase 7: secure IPC policy integration
   - Phase 8: immutable generations and rollback
   - Phase 9: GUI identity colors
   - Phase 10: module/import system
   - Phase 11: live reconfiguration
   - Phase 12: full system validation and testing

16. Deliverables
   For each phase, provide:
   - goal
   - files/modules likely affected
   - data structures to add
   - APIs to expose
   - tests to write
   - failure cases to handle

17. Constraints
   - The system must stay rootless.
   - The kernel should remain minimal and immutable.
   - Most policy should live outside the kernel.
   - The JSON config must be auditable and reproducible.
   - Avoid hidden mutable global state.
   - Avoid ad-hoc runtime configuration.
   - All system state should be derived from the declared config unless explicitly marked runtime state.