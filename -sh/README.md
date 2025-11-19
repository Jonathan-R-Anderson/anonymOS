# D-based Lisp/Haskell Interpreter Prototype

This repository contains a minimal prototype for a Lisp-style interpreter written in [D](https://dlang.org/). The project is inspired by [Axel](https://github.com/axellang/axel), which translates a Lisp dialect to Haskell. In this repository we show how D can be used to build similar tooling that targets an environment with limited system commands such as those described in the [`internetcomputer`](https://github.com/Jonathan-R-Anderson/internetcomputer) project.

The implementation is intentionally small and demonstrates how one might begin to build a cross compiler or interpreter that uses the D toolchain. The code is located in `src/interpreter.d`.

## Building

A D compiler such as `dmd` or `ldc2` is required. The shell now uses the
GNU Readline library for interactive input. Install the appropriate
development package (e.g. `libreadline-dev` on Debian-based systems) and
link against it when building. To cross compile for a specific target,
 supply the desired architecture flags to the compiler. For example:

```bash
ldc2 -mtriple=<target> src/*.d -L-lreadline -of=lfe-sh
```

Replace `<target>` with the appropriate triple for the operating system described in the `internetcomputer` repository.

Alternatively, a simple `Makefile` is provided; running `make` builds the
`lfe-sh` binary.

## Usage

```
./lfe-sh "+ 1 2"  # prints 3
```

Input lines beginning with `(` are evaluated directly as LFE forms. The
`:lfe` prefix can force LFE interpretation for non-parenthesized input, and
inline expressions like `$(lfe (+ 1 2))` or `${lfe:(+ 3 4)}` interpolate LFE
results into shell commands.

The shell now supports a broader set of commands:

- `echo` – prints its arguments
- basic arithmetic with `+`, `-`, `*`, and `/`
- variable assignment and expansion using `name=value` and `$name`
- directory commands like `cd`, `pwd`, `ls`, `pushd`, `popd`, and `dirs`
- Haskell-style `for` loops, e.g. `for 1..3 echo hi`
- concurrent commands using `&`, e.g. `echo one & echo two`
- `bg` to run a command in the background or resume a stopped job
- `fg` to bring a background job to the foreground
- `jobs` to list background jobs
- sequential commands separated by `;`
- file utilities such as `cp`, `mv`, `rm`, `mkdir`, `rmdir`, `touch`, `chattr`, and `chown`
 - text display commands like `cat`, `head`, `tail`, `grep`, and `fgrep`
- `date` for the current time
 - schedule commands using `at`
 - run recurring scheduled jobs with `cron`
 - manage cron tables with `crontab`
- compression utilities with `bzip2`
- `dd` to copy and convert data in blocks
- `ddrescue` for data recovery from damaged disks
- `fdformat` to low-level format a floppy disk
- `df` to display free disk space
- `dmesg` to print kernel messages
- `fold` to wrap text to a fixed width
- `fsck` to check and repair filesystems
- `getfacl` to display file access control lists
- `groupadd` to create new groups
- `groupdel` to delete groups
- `eject` to eject removable media
- manage service runlevels with `chkconfig`
- `caller` to display the current call stack frame
- `exit` to terminate the shell with an optional status code

Running `lfe-sh` with no command argument starts an interactive shell.
The prompt is configured via a JSON file so it can be shared between
machines. By default the shell looks for `prompt.json` beside the binary,
`$HOME/.lfe-sh/config.json`, `$HOME/.config/lfe-sh/config.json`, or
`/etc/lfe-sh/prompt.json`. You can override the search path with the
`LFE_SH_CONFIG` environment variable. A sample configuration is provided
in `config/prompt.json` and supports placeholders for username, current
directory, namespace, and permission level along with ANSI colour codes.
The shell now provides interactive line editing with GNU Readline, so
you can navigate command history with the Up and Down arrow keys.
Type `exit` to leave the shell. Command history can also be viewed with
`history`. At startup, the shell executes commands from `~/.shrc` if
present, allowing aliases, variables, and other settings to be configured
similar to zsh. Aliases may be managed with the `alias` builtin and removed using `unalias`.
You can repeat the previous command by typing `!!`.
Key sequences can be associated with commands using the `bind -x` builtin.
The `builtin` command runs one of the shell's builtins directly, bypassing alias expansion.
You can view a list of common Linux commands with the built-in `help` command,
which prints the contents of `commands.txt`.
The `apropos` command searches this help text for matching commands. It now
supports `-e` for exact matches, `-w` for shell wildcards, `-r` for regular
expressions and `-a` to require all keywords.

These examples demonstrate how additional Bash commands can be layered on top of a Haskell-inspired syntax. The goal remains to eventually cover the full Bash command set, including job control and other special operators.

## Building Pseudo Languages

A small lexer and parser framework inspired by Python's SLY is provided in
`src/dlexer.d` and `src/dparser.d`. These modules allow custom token rules and
implement a simple recursive-descent parser.

The sample program `src/example.d` evaluates arithmetic expressions using this
framework:

```bash
ldc2 src/example.d src/dlexer.d src/dparser.d -of=example
./example "1 + 2 * 3"   # prints 7
```

## Lisp Flavored Erlang Translator

The program `src/lfe.d` demonstrates how the lexer can be repurposed to build a
very small subset of [Lisp Flavored Erlang](https://lfe.io/). It parses a minimal
Lisp syntax and emits Erlang source code.

Build and run it with:

```bash
ldc2 src/lfe.d src/dlexer.d src/dparser.d -of=lfe
./lfe "(defmodule sample (export (add 2)) (defun add (x y) (+ x y)))"
```

This will print the generated Erlang code for the given expression.

## LFE REPL

A small interactive interpreter `src/lferepl.d` implements a minimal LFE-like REPL. Build it with:

```bash
ldc2 src/lferepl.d src/dlexer.d src/dparser.d -of=lferepl
./lferepl
```

Inside the REPL you can evaluate prefix expressions, assign variables and define functions:

```
lfe> (* 2 (+ 1 2 3 4 5 6))
42
lfe> (set multiplier 2)
2
lfe> (* multiplier (+ 1 2 3 4 5 6))
42
lfe> (defun double (x) (* 2 x))
0
lfe> (double 21)
42
lfe> (defmacro unless (test body)
      `(if (not ,test) ,body))
0
lfe> (unless (> 3 4) 'yes)
yes
lfe> (exit)
```

The REPL exits when `(exit)` is evaluated.

### Loading Modules

Simple modules can be loaded with `(c "file.lfe")`. Functions defined in a
`defmodule` form are stored using the `module:function` naming convention and can
be invoked after the file is compiled:

```lfe
lfe> (c "tut1.lfe")
#(module tut1)
lfe> (tut1:double 21)
42
```

### Language Features

The REPL implements a small but growing subset of LFE. Features currently
supported include:

- numeric, atom, tuple, list and map values with constructors and `map-update`
- quoting forms with `quote`, `backquote`, `comma` and `comma-at`
- variable binding using `(set ...)` and `(let ...)`
- pattern matching with `case`, `cond` and multi-clause `defun`
- guard expressions on function clauses
- record definitions via `defrecord` with generated accessors and setters
- macros using `defmacro` and `(macroexpand ...)`
- modules defined by `defmodule`; source files can be loaded with `(c "file.lfe")`
- basic I/O through `lfe_io:format` and utilities like `proplists:get_value`
- file operations like `(cp source dest)`
- concurrency primitives: `spawn`, `spawn_link`, `link`, `self`, message
  sending with `!`, `receive` and `process_flag` for `trap_exit`
- `(exit)` to leave the REPL

### Example Programs

Below are small samples demonstrating the syntax supported in the REPL.

#### Quoting and Unquoting

```lfe
lfe> '(1 2 3)
(1 2 3)
lfe> `(a ,(+ 1 1) c)
(a 2 c)
```

#### Variables and Pattern Matching

```lfe
lfe> (set greeting "hi")
"hi"
lfe> (let ((list (tuple 1 2 3)))
       (case list
         ((tuple 1 x y) (+ x y))))
5
```

#### Records and Modules

```lfe
lfe> (defrecord person name age)
#(record person)
lfe> (c "tut24.lfe")
#(module tut24)
lfe> (tut24:demo)
to fred: hello
"goodbye"
```

#### Macros

```lfe
lfe> (defmacro unless (test body)
        `(if (not ,test) ,body))
lfe> (unless (> 2 3) 'ok)
ok
```

#### Concurrency

```lfe
lfe> (c "tut19.lfe")
#(module tut19)
lfe> (tut19:start)
Pong received ping
Ping received pong
Ping finished
Pong finished
```


#### Loop with Continue

```lfe
lfe> (c "tut25.lfe")
#(module tut25)
lfe> (tut25:demo)
1245
```

## Object System

The REPL now includes a minimal object oriented layer implemented in `objectsystem.d`. Objects are referenced by an identifier and can be manipulated through new builtins:

```
(resolve path)           ; locate an object by path
(bind src dst)           ; bind an existing object to a new path
(clone obj)              ; duplicate an object
(delete obj)             ; remove an object
(list obj)               ; list child names
(introspect obj)         ; return object info string
(rename obj new)         ; rename an object
(getType obj)            ; return the type string
(getProp obj key)        ; fetch a property
(setProp obj key val)    ; set a property value
(listProps obj)          ; list property keys
(delProp obj key)        ; delete a property
(listMethods obj)        ; list method names
(call obj method args..) ; invoke a method (placeholder)
(describeMethod obj m)   ; describe a method
(createObject type)      ; create a new object of a type
(instantiate classPath)  ; alias for createObject
(defineClass path def)   ; stub for class definitions
(attach parent child alias)
(detach parent name)
(getParent obj)
(getChildren obj)
(sandbox obj)
(isIsolated obj)
(seal obj)
(verify obj)
(issueCapability obj rights..)
(deriveCapability capability rights..)
(capabilityRights capability)
(capabilityTarget capability)
(capabilityHasRight capability right)
(destroyCapability capability)
```

These commands provide a simple demonstration of integrating an OOP style with the existing LFE interpreter written in D.

### Capability handles

Capabilities are unforgeable handles issued by the object system. When a
capability is created it is bound to a specific object together with a set of
rights drawn from `{read, map, slice, concat, hash, diff, derive, destroy}`.
Deriving a new capability from an existing handle can only remove rights,
ensuring monotonic attenuation. You can inspect handles with
`capabilityRights`, check individual rights with `capabilityHasRight`, and
revoke handles that possess the `destroy` right via `destroyCapability`.
