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
You can customize the prompt text using the `PS1` environment variable and its color with `PS_COLOR` (e.g. `PS_COLOR=green`).
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
```

These commands provide a simple demonstration of integrating an OOP style with the existing LFE interpreter written in D.

## Shell Control Operators

The shell syntax has been expanded to support standard POSIX control operators:

- `|` : Pipeline (stdout of command1 to stdin of command2)
- `|&` : Pipeline with stderr (stdout AND stderr of command1 to stdin of command2)
- `;` : Sequential execution
- `&` : Background execution
- `&&` : Logical AND (execute next command only if previous succeeded)
- `||` : Logical OR (execute next command only if previous failed)
- `case ... esac` : Pattern matching (supports `;;`, `;&`, `;;&` terminators)

### Syntax Notes

**LFE Conflict**: The `|` character is used in LFE for list construction (e.g. `[H|T]`). In `esh`, `|` is now a pipeline operator. To use `|` in LFE expressions directly in the shell, you must quote the expression or invoke it via `lfe -e "..."`.
Example: `lfe -e '[1|2]'`.
Unquoted `[1|2]` will be parsed as a pipeline: command `[1` piped to command `2]`.

**LFE Conflict (<<)**: The `<<` token is used in LFE for binary matching/construction (e.g. `<<1,2>>`). In `esh`, `<<` is now a Here-Document operator. Unquoted `<<` usage will trigger shell parsing. Use quotes or `lfe -e` for LFE binaries.

## Substitution & Expansion

The shell supports standard POSIX-style substitution and expansion operators:

### Command Substitution
- ` `cmd` ` : Legacy command substitution (runs `cmd` and substitutes stdout).
- `$(cmd)` : Modern command substitution.

### Parameter Expansion
- `$var` : Basic variable expansion.
- `${var}` : Explicit variable name expansion.
- `${var:-default}` : Expand to `default` if `var` is unset or null.
- `${var:=default}` : Assign `default` to `var` if unset or null, then expand.
- `${var:+alt}` : Expand to `alt` if `var` is set and not null.
- `${var:?err}` : Display `err` (or default message) and exit if `var` is unset.
- `${#var}` : Expand to the length of the string value of `var`.
- `${var%pattern}`, `${var%%pattern}` : Trim shortest/longest suffix matching `pattern`.
- `${var#pattern}`, `${var##pattern}` : Trim shortest/longest prefix matching `pattern`.
- `${var/pat/repl}`, `${var//pat/repl}` : Replace first/all occurrences of `pat` with `repl`.
- `${var^}`, `${var^^}` : Capitalize first char / Uppercase entire string.
- `${var,}`, `${var,,}` : Lowercase first char / Lowercase entire string.

### Arithmetic Expansion
- `$((expr))` : Evaluate arithmetic expression `expr` and expand to the result.
- `((expr))` : Evaluate arithmetic expression `expr` as a command (returns 0 if result is non-zero, 1 if zero).

### Syntax Conflicts & Changes
- **LFE Integration**: In standard `esh`, `$(...)` and `${...}` are also used for LFE interpolation (e.g. `$(lfe (+ 1 2))`). The new POSIX expansion logic handles these by expanding the inner content. If the content starts with `lfe `, it still triggers the Lisp interpreter as before.
- **Arithmetic Parentheses**: The `((...))` syntax for arithmetic commands is now a reserved keyword sequence.

## Test & Comparison Operators

The shell provides `test`, `[ ... ]`, and `[[ ... ]]` for conditional expressions.

### File Tests
- `-e file` : Exists
- `-f file` : Regular file
- `-d file` : Directory
- `-L file` : Symlink
- `-r file` : Readable
- `-w file` : Writable
- `-x file` : Executable
- `-s file` : Non-zero size
- `file1 -nt file2` : file1 is newer than file2
- `file1 -ot file2` : file1 is older than file2

### String Tests
- `str1 = str2` : Equal
- `str1 != str2` : Not equal
- `str1 < str2` : Lexicographically less
- `str1 > str2` : Lexicographically greater
- `-z str` : String is empty
- `-n str` : String is not empty

### Numeric Tests
- `n1 -eq n2` : Equal
- `n1 -ne n2` : Not equal
- `n1 -lt n2` : Less than
- `n1 -le n2` : Less or equal
- `n1 -gt n2` : Greater than
- `n1 -ge n2` : Greater or equal

### Syntax Conflicts & Changes
- **Redirection Conflict**: In `test` and `[ ... ]`, the `<` and `>` operators conflict with shell redirections. They MUST be quoted (e.g., `[ "$a" "<" "$b" ]`) to be used for string comparison.
- **Double Brackets**: The `[[ ... ]]` syntax is specifically designed to avoid this conflict. Inside `[[ ... ]]`, `<` and `>` are treated as comparison operators.

## Pattern Matching (Globbing) & Brace Expansion

The shell supports advanced pattern matching and expansion features.

### Brace Expansion
- `{a,b,c}` : Expands to `a`, `b`, and `c`.
- `{1..10}` : Expands to a sequence of numbers from 1 to 10.
- `{a..z}` : Expands to a sequence of characters from 'a' to 'z'.

### Pathname Expansion (Globbing)
- `*` : Matches any string (excluding filenames starting with `.` unless explicitly matched).
- `?` : Matches any single character.
- `[abc]` : Matches any character in the set.
- `[!abc]` : Matches any character NOT in the set.

### Extended Globbing (Extglob)
Extended globbing is DISABLED by default. Enable it using `shopt -s extglob`.
- `?(pattern-list)` : Matches zero or one occurrence of the given patterns.
- `*(pattern-list)` : Matches zero or more occurrences.
- `+(pattern-list)` : Matches one or more occurrences.
- `@(pattern-list)` : Matches exactly one of the patterns.
- `!(pattern-list)` : Matches anything EXCEPT the given patterns.

### Syntax Conflicts & Changes
- **Tokenization**: Characters like `(`, `)`, `{`, `}`, `[` , `]` are now significant for expansion. To use them literally, they should be part of a word that doesn't trigger expansion, or eventually quoted (quoting support is limited).
- **Subshell Conflict**: Standard shell subshells `( cmd )` are still supported and take precedence at the start of a command.
- **Brace Conflict**: `{` and `}` are used for both brace expansion `foo{a,b}` and eventually for grouping `{ list; }`. The parser distinguishes these based on whether they are part of a word or separate tokens.

## Quoting & Escaping

The shell supports various quoting mechanisms to preserve literal characters and handle expansions.

### Literal Strings (`'...'`)
- Characters between single quotes are preserved literally.
- No expansions or escapes are performed.

### Interpolated Strings (`"..."`)
- Characters between double quotes are preserved, except for:
    - Variable expansion (`$var`, `${var}`)
    - Command substitution (`$(cmd)`, `` `cmd` ``)
    - Arithmetic expansion (`$((expr))`)
    - Backslash escapes (`\$`, `` \` ``, `\"`, `\\`, `\newline`)
- Double-quoted expansion results are NOT subject to field splitting or pathname expansion.

### Backslash Escape (`\`)
- Preserves the literal value of the following character (except inside single quotes).
- Inside double quotes, it only escapes `$`, `` ` ``, `"`, `\`, and newline.

### ANSI-C Quoting (`$'...'`)
- Expands backslash-escaped characters according to the ANSI C standard:
    - `\n` (newline), `\r` (return), `\t` (tab)
    - `\a` (alert/bell), `\b` (backspace), `\f` (form feed), `\v` (vertical tab)
    - `\e` or `\E` (escape)
    - `\\`, `\'`, `\"`
- Resulting characters are treated as literal (not subject to further expansion).

### Locale-aware Strings (`$"..."`)
- Treated as standard double-quoted strings (localization support is currently not implemented).

### Syntax Conflicts & Changes
- **Expansion Priority**: `$(...)` and `${...}` still trigger expansion. `$'` and `$" ` are now recognized as special quoting starts.
- **Marker Character**: The shell uses internal markers (`\x01`) to track quoted segments during the expansion pipeline. Avoid using this character in literal inputs if possible.

## Job Control

The shell supports standard POSIX job control to manage multiple processes.

### Job Management Commands
- `jobs` : List current background and stopped jobs.
- `fg [%job]` : Bring a job to the foreground. Resumes it if stopped.
- `bg [%job]` : Resume a stopped job in the background.
- `disown [%job]` : Remove a job from the shell's tracking. It will no longer receive SIGHUP on exit.
- `&` : Append to a command to run it in the background.

### Job References
- `%n` : Refer to job by its ID (e.g. `%1`).
- `%prefix` : Refer to job by the prefix of its command string.
- `%` (expansion) : Expands to the PGID of the referenced job (e.g. `kill -9 %1`).

### Shortcuts
- `Ctrl-C` : Send `SIGINT` to the foreground process group.
- `Ctrl-Z` : Send `SIGTSTP` to the foreground process group, stopping it and returning it to the background.

### Syntax Conflicts & Changes
- **Reference Expansion**: The `%` character at the start of a word triggers job reference expansion. To use a literal `%`, escape it `\%` or quote it.
- **Terminal Control**: The shell actively manages terminal process groups (`tcsetpgrp`). This requires a TTY-enabled environment. In non-TTY environments (like simple pipes), job control may be restricted.

## Process Substitution

Process substitution allows the input or output of a command to be referred to using a filename.

### Syntax
- `<(cmd)` : The command `cmd` is run and its output is made available as a temporary file (typically `/dev/fd/N`).
- `>(cmd)` : The command `cmd` is run and its input is connected to a temporary file (pipe).

### Examples
- `diff <(ls folder1) <(ls folder2)` : Compare the outputs of two `ls` commands as if they were files.
- `tee >(grep "error" > errors.log) >(grep "warn" > warns.log) > /dev/null` : Direct output to multiple processing commands.

### Implementation Notes
- **Markers**: Uses `/dev/fd/` entries. This requires the operating system to support the `/dev/fd` filesystem.
- **Cleanup**: The shell monitors the PIDs of process substitution commands and cleans them up after the main command exits.
- **Nesting**: Process substitutions can be nested.

### Syntax Conflicts & Changes
- **Tokenization**: `<(` and `>(` are now recognized as a single operator. If you need a literal `<` followed by `(`, use a space: `< (`.

## Grouping & Blocks

The shell supports standard grouping and test constructs.

### Operators
- `( cmd )` : **Subshell**. Runs `cmd` in a child process. Variables set inside do not affect the parent shell.
- `{ cmd; }` : **Group**. Runs `cmd` in the current shell process. Variables set inside *do* affect the parent.
- `[[ ... ]]` : **Extended Test**. Perform conditional tests with support for enhanced operators like `==` and `=~` (regex). Suppresses field splitting and globbing on its arguments.
- `[ ... ]` : **POSIX Test**. standard conditional test (equivalent to the `test` command).

### Extended Test Operators
- `==` : String equality (alias for `=`).
- `!=` : String inequality.
- `=~` : Regex match (e.g. `[[ $var =~ ^[0-9]+$ ]]`).
- `-nt` / `-ot` : File newer/older than.
- `-eq`, `-ne`, `-lt`, `-le`, `-gt`, `-ge` : Integer comparisons.

### Syntax Conflicts & Changes
- **Grouping Markers**: `(`, `)`, `{`, and `}` are recognized as grouping markers when they appear at the start of a command.
- **Word Embedding**: These characters are still allowed within words (e.g. `echo {a,b}` or `echo (foo)`) for compatibility with brace expansion and general usage. To use them as literals at the *start* of a command, they must be quoted or escaped.

## Miscellaneous Features

### Symbols & Builtins
- `#` : **Comments**. Text following `#` until the end of the line is ignored.
- `!` : **History Expansion**. 
  - `!!` : Repeat the last command.
  - `!pref` : Repeat the last command starting with `pref`.
- `:` : **Null Command**. Does nothing and returns 0.
- `.` / `source` : **Source**. Executes commands from a file in the current shell context.
- `exec [cmd]` : **Replace Process**. Replaces the current shell with the specified command.
- `wait [job]` : **Wait**. Waits for background jobs to finish. If no job is specified, waits for all.

### Select Loop
Syntax: `select name [in word ...]; do list; done`
Displays a numbered menu of `word`s. Reads a choice from stdin, sets `name` to the chosen word, and executes `list`. Sets `REPLY` to the raw input.

### Syntax Conflicts & Changes
- **Keywords**: Keywords like `if`, `for`, `select`, etc., are reserved when they appear at the start of a command. To use them as arguments, they usually don't need quoting unless they are at the start of a subcommand.
- **History**: History expansion is performed before parsing. Currently supports basic `!!` and `!prefix`.

## Special Shell Variables

The shell supports standard special variables for state and positional parameters.

### Variables
- `$0` : **Script Name**. Name of the shell or the script being executed.
- `$1 .. $9` : **Positional Parameters**. Arguments passed to the shell or script.
- `$#` : **Argument Count**. Number of positional parameters (excluding `$0`).
- `$@` / `$*` : **All Arguments**. Expands to all positional parameters separated by spaces.
- `$?` : **Exit Code**. Status of the last executed command.
- `$$` : **PID**. Process ID of the current shell.
- `$!` : **Last Background PID**. PID of the most recently started background job.
- `$-` : **Shell Flags**. Current shell options (e.g., `i` for interactive).
- `$SECONDS` : **Runtime**. Number of seconds since the shell was started.
- `$RANDOM` : **Random Integer**. A random integer between 0 and 32767.
- `$LINENO` : **Line Number**. Current line number in the script or session.


## Bash-Specific Operators (Non-POSIX Extensions)

The shell supports several Bash-specific builtins and indexing for array-like variables.

### Operators
- `declare` / `typeset` : Manage variables and their attributes.
  - `-x` : Mark variables for export.
  - `-i` : Mark variables as integers (currently treated as strings).
- `mapfile` / `readarray` : Read lines from standard input into an indexed array-like variable set.
  - `-t` : Strip trailing newlines.
  - `-n count` : Read at most `count` lines.
  - `-O origin` : Start assignement at index `origin`.
- `coproc [NAME] cmd` : Run a command as a coprocess in the background. Creates a named variable (default `COPROC`) containing the read/write pipes as `VAR[0]` and `VAR[1]`.

### Array Handling
Variables can be indexed using `NAME[index]` syntax within `${...}` expansions.
Example: `${MYARRAY[0]}`.
Internally, these are stored as literal string keys in the variable table.

## Feature Showcase: From Basics to Complexity

This section demonstrates the elegance and robust parsing capabilities of `esh`, moving from simple day-to-day commands to sophisticated process orchestration.

### Level 1: Minimalist Essentials
Classic POSIX operations with standard piping and redirection.
```bash
# Simple listing with output redirection
ls -l /bin > system_bins.txt

# Piped stream with filtering
cat system_bins.txt | grep "esh" | head -n 1

# Append redirection and error suppression
find / -name "config" >> all_configs.txt 2>/dev/null
```

### Level 2: Conditional Logic & Arithmetic
Leveraging the execution graph and the arithmetic evaluation layer.
```bash
# Logical AND/OR chaining
[ -f "os-minimal.iso" ] && echo "Ready to boot" || echo "Image missing"

# Arithmetic command evaluated in the shell context
(( count = 10 + (5 * 2) ))
echo "Result is: $count"

# Sequence with background execution
mkdir -p build && cd build && ( sleep 10; echo "Build complete" ) &
```

### Level 3: Elegant Expansions
Showcasing the expansion pipeline (Brace → Parameter → Arithmetic → Glob).
```bash
# Nested brace expansion for directory scaffolding
mkdir -p project/{src,bin,docs}/{core,util,test}

# Advanced parameter manipulation
FILE="archive.tar.gz"
echo "Basename: ${FILE%%.*}"  # archive
echo "Extension: ${FILE#*.}"  # tar.gz

# Combining arithmetic, variables, and string length
MSG="AnonymOS"
echo "The message '$MSG' is $(( ${#MSG} + (10 - 2) )) chars relative to offset."
```

### Level 4: High-Order Process Orchestration
Utilizing subshells, process substitution, and bash-specific extensions.
```bash
# Comparing outputs of dynamic commands without temporary files
diff <(ls -1 folder_a) <(ls -1 folder_b)

# Process substitution to feed multiple streams
tee >(grep "ERROR" > err.log) >(grep "WARN" > warn.log) < main.log

# Mapfile: Reading a stream directly into indexed "array" variables
ls /bin | head -n 5 | mapfile BIN_LIST
echo "First binary discovered: ${BIN_LIST[0]}"
```

### Level 5: The "Power User" One-Liner
A deeply nested command combining coprocesses, redirection, and variable attributes to illustrate the full depth of the parsing and execution layers.
```bash
# Create a coprocess named 'GEN', send it data, and read back the result
coproc GEN { read x; echo "SYSCALL_READY: ${x^^}"; }; \
echo "initializing" >& ${GEN[1]}; \
read RESULT <& ${GEN[0]}; \
echo "Coprocess status: ${RESULT:-FAILED} (PID: ${GEN_PID})"
```

These examples highlight how `esh` handles multi-layer parsing—ensuring operators are tokenized correctly, expansions are strictly ordered, and the execution graph manages file descriptors with precision.
