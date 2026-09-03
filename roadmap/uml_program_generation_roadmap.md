You are working on the current AnonymOS codebase.

AnonymOS already has:

- object-oriented system architecture
- immutable kernel
- rootless security model
- object tree representing the entire OS
- Domain Manager
- Identity Manager
- Namespace Manager
- Process Manager
- Linux compatibility layer
- declarative system configuration
- capability-based security
- template domains
- cloneable/deletable domains
- package-manager-aware Linux compatibility layer

Your task is to design and implement a complete UML-driven program generation system for AnonymOS.

There are two major goals:

1. Extend UML into a complete executable design language.
2. Develop an AnonymOS-specialized LLM agent that can read the enhanced UML and generate the full program.

The system must allow an LLM to generate working AnonymOS components by reading the UML alone.

Do not treat UML as simple diagrams. Treat it as a full architectural specification language.

Part 1: Extended UML Construct

Redesign UML support so diagrams can fully describe:

- objects
- classes
- interfaces
- traits/mixins
- services
- managers
- domains
- namespaces
- processes
- capabilities
- permissions
- events
- messages
- syscalls
- lifecycle hooks
- configuration schemas
- persistence rules
- filesystem mappings
- Linux compatibility bindings
- package manager integration
- dependency graph
- error handling
- policy enforcement
- security boundaries
- tests
- generated source layout

Create an AnonymOS UML profile called:

AnonymOS Executable UML Profile

It should support stereotypes such as:

- <<KernelObject>>
- <<ImmutableObject>>
- <<Manager>>
- <<Domain>>
- <<TemplateDomain>>
- <<Namespace>>
- <<Identity>>
- <<Capability>>
- <<Policy>>
- <<Service>>
- <<Process>>
- <<LinuxCompat>>
- <<PackageManager>>
- <<FilesystemOverlay>>
- <<ConfigSchema>>
- <<Syscall>>
- <<Event>>
- <<Message>>
- <<LifecycleHook>>
- <<GeneratedFile>>
- <<TestSpec>>

Each UML element must contain enough metadata for code generation.

For every class/object, support:

- name
- namespace
- parent object path
- inheritance
- implemented interfaces
- owned capabilities
- required capabilities
- constructor parameters
- fields
- methods
- method signatures
- visibility
- mutability
- serialization rules
- persistence rules
- validation rules
- error types
- lifecycle hooks
- generated file path
- test requirements

For every method, support:

- input types
- output type
- permissions required
- preconditions
- postconditions
- side effects
- emitted events
- failure modes
- audit log behavior
- whether it mutates state
- whether it crosses a security boundary

For every domain/template UML element, support:

- installed applications
- default packages
- package manager
- Linux compatibility mode
- filesystem overlays
- environment variables
- networking policy
- identity inheritance
- startup services
- appearance defaults
- desktop defaults
- allowed syscalls
- denied syscalls
- exported capabilities
- imported capabilities

Create a machine-readable UML format using YAML or JSON.

The format should be readable by humans but strict enough that an LLM can generate code from it.

Example format:

```yaml
anonymos_uml_version: 1

object:
  name: DeveloperTemplateDomain
  stereotype: TemplateDomain
  namespace: /System/Domains/Templates
  extends: BaseTemplateDomain

  fields:
    - name: package_manager
      type: PackageManagerKind
      default: apt
      mutable: false

  capabilities:
    provides:
      - domain.clone
      - domain.export
    requires:
      - package.install
      - linux.compat.configure

  methods:
    - name: create_domain_from_template
      visibility: public
      mutates_state: true
      inputs:
        - name: domain_name
          type: string
      output: Domain
      requires_capabilities:
        - domain.create
      preconditions:
        - domain_name must be unique
      postconditions:
        - new domain exists in object tree
      emits:
        - DomainCreated
      errors:
        - DomainAlreadyExists
        - PermissionDenied

  linux_compat:
    package_manager: apt
    default_packages:
      - git
      - clang
      - python3
      - zsh

  generated_files:
    - path: system/domains/templates/developer_template_domain.rs
      language: rust
    - path: tests/domain_templates/developer_template_domain_test.rs
      language: rust

Part 2: UML-to-Code LLM Agent

Design an LLM agent specialized for AnonymOS UML processing.

The agent should be called:

AnonymOS UML Compiler Agent

It must perform these stages:

Parse UML
Validate UML schema
Resolve object tree paths
Resolve inheritance
Resolve capabilities
Resolve security boundaries
Resolve dependencies
Generate implementation plan
Generate source files
Generate configuration files
Generate tests
Generate migration logic if needed
Generate documentation
Run static consistency checks
Report unresolved ambiguity instead of guessing silently

The agent must understand AnonymOS concepts:

immutable kernel objects
rootless security
object tree paths
capability enforcement
domain templates
namespace isolation
identity inheritance
Linux compatibility layer
package manager selection
declarative configuration
process isolation
policy-driven permissions

The agent should never generate code that violates the AnonymOS security model.

Hard rules:

Never create global mutable kernel state.
Never bypass capability checks.
Never give domains implicit root.
Never let Linux compatibility packages escape their domain.
Never allow package managers to modify immutable system objects.
Never generate undocumented syscalls.
Never generate a method without explicit permission behavior.
Never generate domain creation/deletion without audit events.
Never assume identity inheritance unless specified.
Never silently invent object paths.

The agent must output:

generated code
generated tests
generated configuration
generated docs
security review
unresolved questions
confidence report

Part 3: Implementation inside AnonymOS

Implement the following modules:

/System/Tools/UMLCompiler
/System/Tools/UMLValidator
/System/Tools/UMLCodeGenerator
/System/Tools/UMLSecurityAnalyzer
/System/Tools/UMLTestGenerator
/System/Tools/UMLDocGenerator
/System/Tools/UMLPromptCompiler

Each module should be an AnonymOS object.

Create the following core types:

ExecutableUMLDocument
UMLElement
UMLClass
UMLInterface
UMLDomain
UMLTemplateDomain
UMLCapability
UMLPolicy
UMLMethod
UMLField
UMLLifecycleHook
UMLGeneratedFile
UMLTestSpec
UMLSecurityBoundary
UMLValidationError
UMLGenerationReport

Create a compiler pipeline:

ExecutableUMLDocument
        ↓
UMLParser
        ↓
UMLValidator
        ↓
ObjectTreeResolver
        ↓
CapabilityResolver
        ↓
SecurityAnalyzer
        ↓
DependencyResolver
        ↓
GenerationPlanner
        ↓
CodeGenerator
        ↓
TestGenerator
        ↓
DocGenerator
        ↓
GenerationReport

Part 4: Required Features

The system must support:

generating new AnonymOS managers
generating new domain templates
generating domain lifecycle logic
generating capability policies
generating Linux compatibility configuration
generating package manager bindings
generating filesystem overlay rules
generating syscalls
generating event/message handlers
generating tests
generating documentation
validating security before code generation
refusing unsafe UML

Part 5: Example Deliverable

Create one complete example using this system:

A “Research Template Domain” UML spec that generates:

a ResearchTemplateDomain object
default packages:
firefox
libreoffice
zotero
python3
git
package manager:
apt
isolated home overlay
read-only shared documents mount
no raw network access except browser service
inherited identity disabled by default
startup service for notes sync
exported capability:
research.workspace.create
tests for clone, delete, export, package install, policy enforcement

Provide:

The extended UML YAML
The generated object model
The generated source file list
The generated test list
The security validation report

Part 6: Output Format

Return the answer in this order:

Architecture overview
Extended UML schema
AnonymOS UML stereotypes
Compiler agent design
Internal AnonymOS modules
Security rules
Code generation pipeline
Research Template Domain example
Tests
Future extensions

Make the design implementation-ready.
Do not provide vague theory.
Use concrete data structures, schemas, pseudocode, and file paths.
