# dash — the native shell language of EpinAnonymOS

dash is the shell every terminal starts.  It is **bash where you run programs** and **Haskell where
you compute**, in one language, over the operating system's own object model.  A Linux shell is one
command away (`linux`), and you are back in dash when it exits.

```
λ ls -la /tmp                                   -- a command, exactly as in bash
λ domains |> filter (\d -> d.state == "running") |> map (.name)
["System","Personal"]
λ let w = domain "Work"
λ w.<Tab>                                       -- explore the object: fields, methods, extensions
name  state  identity  color  abbrev  ...  start  stop  pause  route  snapshot  clone  caps
λ w.route "vm:lan-opnsense"                     -- a method: an action on the live system
λ ls /etc |> filter (isSuffixOf ".conf") |> length
12
λ linux                                         -- drop into the Linux shell (zsh); `exit` returns
```

## 1. Statements

Each line is one statement (a statement continues onto the next line when a bracket is open, the
line ends with an operator, `\`, `=`, `->`, `do`, `where`, `of`, `then`, `else`, `|`, `|>`, `&&`
or `||`, or the next line is indented).  `;` separates statements on one line.  dash decides what a
statement is from its first words:

| starts with                                   | it is                                  |
|-----------------------------------------------|----------------------------------------|
| `:`                                           | a meta command (`:t`, `:m`, `:help` …) |
| `let`                                         | a definition                           |
| `name args = …` (spaces around `=`)           | a function/value definition            |
| `name :: Type`                                | a type signature                       |
| `data`                                        | a data type                            |
| `Type.member self args = …`                   | an **extension** of an object type     |
| `NAME=value` (no spaces)                      | a shell variable assignment            |
| `=`                                           | an expression, forced                  |
| a literal, `(`, `[`, `\`, `if`, `case`, or a name defined in dash | an expression          |
| anything else                                 | a command (bash syntax)                |

A name that is both a Unix command and a dash library function (`head`, `sort`, `id`, `find`,
`zip`, `sum`, …) runs the **command** at the start of a statement, and is the **function**
everywhere else (after `|>`, inside parentheses, in definitions).  Force an expression with a
leading `=`:  `= head [1,2,3]`.  Names *you* define in dash always win over commands.

## 2. Commands (the bash half)

```
cmd arg 'single' "double $var ${var}"   ~/path   *.txt
cmd1 | cmd2 | cmd3          cmd1 && cmd2 || cmd3          cmd &          cmd; cmd
cmd > out   cmd >> out   cmd < in   cmd 2> err   cmd 2>&1   cmd &> both
NAME=value                  NAME=value cmd              export NAME=value
$(cmd)                      $?   $$   $HOME
```

* `$name` in a command is a **dash binding** if one is in scope (function parameters, `let`s, shell
  variables), else an environment variable.  Lists expand to one word per element.
* `$((expr))` embeds any dash expression:  `echo "sum: $((sum [1..10]))"`,  `kill $((p.pid))`.
* Builtins: `cd`, `pwd`, `exit`, `export`, `unset`, `source`, `history`, `jobs`, `wait`, `which`,
  `type`, `help`, `linux`.

### Control flow, functions, expansions

The command half is a full shell language:

```
if [ -f notes.txt ]; then echo yes; elif test -d notes; then echo dir; else echo no; fi
for f in *.txt; do echo "$f"; done          for i in {1..5}; do ...; done
while read -r line; do echo "$line"; done < file        until [ $n -le 0 ]; do n=$((n - 1)); done
case $x in a|b) echo ab;; *.gz) echo gz;; *) echo other;; esac
greet() { local who=${1:-world}; echo "hello $who"; return 0; }      function f { ...; }
{ echo a; echo b; } | wc -l          (cd /tmp && ls)          [[ $v == *.gz && -n $v ]]
cat <<EOF                cat <<'EOF'              read a b <<< "one two"
text with $vars          literal $text
EOF                      EOF
```

* `break [n]`, `continue [n]`, `return [n]`, `shift [n]`, `set -- args`, `local`, `read [-r] [-p p]`,
  `test` / `[ ]`, `[[ ]]` (`==` matches a pattern, `=~` a regular expression), `eval`, `source file args`.
* `$1 .. $9 ${10}`, `$#`, `$@`, `"$@"` (one word each), `$*`, `$0`, `$!`, `$?`, `$$`.
* `${v:-w} ${v:=w} ${v:+w} ${v:?w} ${#v} ${v#p} ${v##p} ${v%p} ${v%%p} ${v/p/r} ${v//p/r} ${v:o:l}
  ${v^^} ${v,,}` and brace expansion `{a,b}`, `{1..5}`, `{a..e}`.
* A variable holding a whole number is a number: `n=$((n + 1))` works.

### Object commands

`ls`, `stat`, `find`, `cat FILE`, `mkdir`, `rmdir`, `rm`, `cp`, `mv`, `touch`, `ps`, `kill`, `env` run in
the shell itself and answer with **objects** -- File, Process and records:

```
λ ls /tmp                                     -- a table: mode size modified name kind path owner
λ ls |> filter (\f -> f.size > 1000) |> map (.name)
λ ls | grep txt                               -- into a command, a File is its name
λ find . -name "*.d" |> length
λ (file "notes.txt").lines |> take 3          -- .read .lines .write .append .delete .rename .copy .children .parent
λ ps |> filter (\p -> p.rssKb > 10000)
```

A flag an object command does not implement runs the program of that name instead (`command ls`
always does).

## 3. Expressions (the Haskell half)

```
42   3.14   0xff   "text"   'c'   True   ()   [1,2,3]   [1..10]   (1, "a")
{ name = "x", size = 3 }            -- a record;  r.name  r { size = 4 }
\x y -> x + y                       -- lambda
f x y                               -- application
x `div` 2        (+ 1)   (2 *)   (.name)        -- infix call, sections, field selector
f . g            f $ x            x |> f         -- composition, application, pipe
if c then a else b
case xs of
  []     -> "empty"
  (x:_)  -> "starts with " ++ show x
let y = 2 in y * y
[x * x | x <- [1..10], even x]
```

Operators, loosest first: `|>` · `$` · `||` · `&&` · `== /= < <= > >=` `elem` · `++ :` `<>` ·
`+ -` · `* /` `div mod` · `^` · `.` `!!`.  Application binds tighter than any operator; a field
access `r.name` binds tighter than application (`f r.name` is `f (r.name)`); `f . g` needs spaces.

Evaluation is strict.  Types are checked at run time; `:t expr` shows one.

### Definitions

```
double x = x * 2
fact :: Int -> Int
fact 0 = 1
fact n = n * fact (n - 1)             -- consecutive equations build one function
classify n | n < 0 = "negative" | n == 0 = "zero" | otherwise = "positive"
area r = pi * r ^ 2
  where pi = 3.14159
data Shape = Circle Float | Rect Float Float
```

### do blocks — scripts that mix both halves

A `do` block is a sequence of statements; each one is a command or an expression, and commands see
the block's bindings as `$name`:

```
backup dir = do
  let stamp = show now
  echo "backing up $dir"
  tar czf /tmp/backup-$stamp.tgz $dir
  files <- ls $dir                        -- bind a command's output lines
  putStrLn ("saved " ++ show (length files) ++ " files")
```

## 4. Pipes between the halves

A pipeline's stages are commands (`|`) or functions (`|>`):

* text → function:  `ls |> length`           the function receives the output as `[String]` lines
* value → command:  `domains |> map (.name) | sort`   the value is written as lines of text
* value → function: `[1..5] |> map (*2)`      is `map (*2) [1..5]`
* `$(cmd)` inside an expression is the command's output lines;  `run "cmd"` too.

## 5. The object model

The OS's objects are dash values with **fields** and **methods** (both reached with `.`):

| collection / lookup                 | type        | examples                                                          |
|-------------------------------------|-------------|-------------------------------------------------------------------|
| `domains`, `domain "Work"`          | `Domain`    | `.name .state .color .abbrev .identity .distro` · `.start .stop .route "vm:…" .usbOn "vid:pid" .clone "New" .snapshot .apps .caps .fs` |
| `identities`, `identity "Banking"`  | `Identity`  | `.trust .ceiling .disposable` · `.caps .switch`                    |
| `services`, `service "…"`           | `Service`   | `.state .rights .version` · `.caps`                               |
| `users`, `user "user"`              | `User`      | `.uid .gid .rights` · `.caps`                                     |
| `namespaces`                        | `Namespace` | `.objId` · `.enter`                                               |
| `procs`                             | `Process`   | `.pid .name .domain .state` · `.kill`                             |
| `apps`, `app "wl-files"`            | `App`       | `.delegable .domains` · `.grant "Work" .revoke "Work"`            |
| `usbDevices`                        | `UsbDevice` | `.id .name .domains` · `.allow "Work" .deny "Work"`               |
| `objects`                           | `ObjCount`  | `.type .count` (the live object table)                             |
| `sys`, `whoami`                     | records     | system summary; `user@namespace [rights]`                         |

Printing a list of objects shows a table.  Explore with:

* **Tab after a dot** — `w.<Tab>`, `(domain "Work").<Tab>`, `Domain.<Tab>` list the members with their
  types; Tab inside `domain "` completes domain names.
* `:m value` or `:m Domain` — every field, method and extension, with types and one-line docs.
* `:t expr` — the type of an expression.

**Extensions** add your own members to a type; they appear in Tab completion and `:m`:

```
Domain.running d = d.state == "running"
Domain.restart d = do
  d.stop
  d.start
λ domains |> filter (.running) |> map (.name)
```

Destructive object operations (identity switch, namespace enter, delete) need `--yes` armed first
(`arm`), or report what they would do under `dry-run`; every privileged action is audit-logged by
the kernel.

## 6. Native, and Linux

dash itself runs on the OS's **native object ABI only** -- it makes no Linux system call (the build
checks it, and the kernel logs any): its files, processes, channels, directories, terminal, memory and
signals are native objects and events.  Ordinary programs it starts are Linux programs.

## 6a. Linux

* `linux` — start the Linux shell (zsh) on this terminal; `exit` returns to dash.  The Linux shell
  and everything it starts can never reach the native object ABI (a one-way trapdoor).
* `linux cmd args…` — run one command under the Linux shell.
* Ordinary programs (busybox tools, installed packages) run directly from dash as commands.

## 7. Files

* `~/.dashrc` runs at start-up (definitions, extensions, aliases).
* `~/.dash_history` keeps the history.
* `dash script.dash`, `dash -c 'statement'`, or `#!/bin/dash` scripts.

## 8. Meta commands

`:help [topic]` · `:t expr` · `:m value|Type` · `:doc name` · `:load file` · `:env` · `:quit`
