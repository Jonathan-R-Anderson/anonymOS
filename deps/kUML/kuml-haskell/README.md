# kuml-haskell — the kUML Haskell port

A JVM-free reimplementation of kUML's class-diagram pipeline (DSL → model →
validate → SVG), written in portable Haskell so it runs **natively on
anonymOS**. It compiles two ways:

- **GHC** — the multi-module tree in `src/`, for fast host development and as
  the reference implementation (`make dev` → `build/kuml-ghc`).
- **JHC 0.8.2 + musl-clang** — a fully static, non-PIE musl ELF with no
  `PT_INTERP`, the same boot-module shape as the other anonymOS userland tools
  (hos-ethsign, busybox), so it loads under the kernel's Linux personality
  (`make anos` → `build/kuml`, staged into the ISO as `/kuml`).

Both binaries render **byte-identically** (`make check` asserts it).

## Why a port (not the Kotlin tool)

kUML proper is Kotlin/JVM: no JVM exists on anonymOS, and its `*.kuml.kts`
input is *compiled Kotlin* at runtime, which GraalVM native-image can't host.
This port keeps the parts that matter on-device — the class-diagram metamodel,
sizing/layout, SVG rendering, structured (`KUML-*`) diagnostics — and swaps the
input for a small native DSL that needs no compiler.

Scope is deliberately the V1 class-diagram slice (per kUML ADR-0004). SysML 2,
C4, OCL, transforms, codegen, the web/desktop/MCP/LLM modules are out of scope
for the on-device tool.

## The DSL

Line-oriented, brace-delimited, trivially parseable. Comments are `//` to
end-of-line (so `#` stays free as the protected-visibility glyph).

```
diagram "Order Management" {

  abstract class Entity {
    - id : UUID
    + equals(other : Entity) : Boolean
  }

  class Order {
    - total : Money
    + confirm(item : Item, qty : Int) : Boolean
    + cancel()
  }

  interface Payable {
    + pay(amount : Money) : Boolean
  }

  enum Status { NEW PAID SHIPPED CANCELLED }

  class Logger

  // relationships:  <keyword> <from> <to>
  generalization Order Entity        // Order --|>  Entity   (specific -> general)
  realization    Order Payable       // Order ..|>  Payable  (impl -> interface)
  composition    Order OrderItem     // Order *--   OrderItem (whole owns part)
  aggregation    Order Customer      // Order o--   Customer  (whole, shared)
  dependency     Order Logger        // Order ..>   Logger    (client -> supplier)
  association    Order Customer      // Order --    Customer
}
```

- **Members**: `VIS name : Type` (attribute) or `VIS name(p : T, …) : Ret`
  (operation). `VIS` is `+ - # ~` (public/private/protected/package).
- **Classifiers**: `class`, `abstract class`, `interface`, `enum Name { LIT … }`.
- **Relationships**: `association | composition | aggregation | generalization |
  realization | dependency`, each followed by two classifier names.

See `examples/orders.kuml`.

## Usage

```
kuml render   FILE [--format svg] [-o OUT] [--output json|text]
kuml validate FILE [--output json|text]
kuml gen      FILE [--module NAME] [-o OUT.hs]   (generate Haskell source)
kuml version
kuml help
```

`render` writes SVG to stdout (or `-o OUT`); diagnostics go to **stderr** so the
SVG stream stays clean for piping. `validate` prints diagnostics to stdout and
exits non-zero if any are error-severity. `--output json` emits an array of
`{code, severity, message}` (always an array, `[]` when clean).

Undefined relationship endpoints (`KUML-E-101`) and duplicate names
(`KUML-W-201`) are reported; `render` is best-effort (dangling edges skipped).

## Code generation (`gen`) — the generated programs are Haskell

`kuml gen` is the M2T target: it turns a model into a self-contained, **compilable**
Haskell module (kUML proper generates Kotlin/Java/SQL; this port's target is Haskell).
It mirrors kUML's `KumlCodeGenerator` conventions — a provenance header, sanitized
names — and also accepts kUML-style flags (`-i FILE`, `--package NAME` ≡ `--module`).

Mapping:

| UML | Haskell |
|-----|---------|
| class | `data` record; fields = attributes, prefixed `<lowerClass><Attr>` for module-global uniqueness; `deriving (Eq, Show)` |
| abstract class | same, with an `-- \| abstract (UML)` note |
| interface | typeclass `class <Name> a where …`; methods take the instance `a` first, prefixed `<lowerIface><Op>` |
| enum | sum type `data <Name> = <Name>_LIT … deriving (Eq, Show, Enum, Bounded)` |
| operation (on a class) | top-level function stub `<lowerClass><Op> :: <Class> -> … ; = error "…"` |
| realization (`Class ..\|> Iface`) | `instance <Iface> <Class> where …` (method stubs) |
| generalization / association / dependency | emitted as comments (Haskell has no inheritance; kUML's Java/SQL generators also drop these) |

Type mapping: known primitives → Prelude types (`String`/`Int`/`Integer`/`Float`/
`Double`/`Bool`/`Char`/`()`); a defined class/enum → its generated type; an unknown
type (e.g. `UUID`, `Money`) → an emitted `type <T> = String` stub, so the output has
no dangling references. An attribute/param typed by an *interface* degrades to
`String` (an interface is a typeclass, not a field type). Every body is an `error`
stub — the output is a **skeleton that compiles**, ready to fill in.

`make check` proves it end-to-end: GHC and the anonymOS binary emit byte-identical
Haskell, and that Haskell is fed back to `ghc -c` and must compile.

Example (`kuml gen examples/orders.kuml --module Orders`):

```haskell
-- Generated by kuml-gen-haskell -- do not edit manually.
module Orders where

type UUID = String
type Money = String

data Status = Status_NEW | Status_PAID | Status_SHIPPED | Status_CANCELLED
  deriving (Eq, Show, Enum, Bounded)

class Payable a where
  payablePay :: a -> Money -> Bool

data Order = Order
  { orderId :: UUID
  , orderTotal :: Money
  }
  deriving (Eq, Show)

orderConfirm :: Order -> Item -> Int -> Bool
orderConfirm = error "kuml-gen-haskell: Order.confirm not implemented"

instance Payable Order where
  payablePay = error "kuml-gen-haskell: Order realizes Payable.pay -- not implemented"
```

## Build

```
make dev      # host GHC build            -> build/kuml-ghc
make anos     # anonymOS static-musl ELF  -> build/kuml
make check    # build both, assert byte-parity
make clean
```

`make anos` needs `jhc` on `PATH` and the in-tree `deps/musl/install/bin/musl-clang`
(override with `MUSL_CC=`). From the anonymOS root, `make kuml` drives this, and
`stage-iso-tree` copies `build/kuml` to `/kuml` + registers it as a limine boot
module (guarded/non-fatal if the toolchain is absent). The app grid entry is
`system/applications/kuml.desktop` (`Categories=Development`).

## JHC 0.8.2 constraints (why the code looks the way it does)

JHC is old and its standalone/libc backend has sharp edges. All of these are
worked around in-tree; keep them in mind before "cleaning up" the source:

1. **No `Monad (Either e)` instance** → no `do`/`>>=` over `Either`. The parser
   threads results with fully explicit nested `case`.
2. **Cross-module C codegen mis-links** — it emits calls to worker closures
   (`fx<n>`) it never defines, so `ld` fails with undefined references. Fix:
   `scripts/concat-single.sh` merges the modules into one file for JHC; GHC
   still builds the clean multi-module tree.
3. **`jgc` (default GC) corrupts the heap** on the allocation-heavy render path
   (consistent SIGSEGV mid-output). Fix: `gc=none` in the `[anos]` target — a
   one-shot CLI allocates and exits, so no collection is needed.
4. **Non-ASCII source bytes** break its lexer → source is pure ASCII; the
   `«guillemets»` around stereotype keywords are emitted as XML numeric
   entities (`&#171;`/`&#187;`), which is also encoding-independent across
   GHC's UTF-8 IO and JHC's byte IO.
5. **`1.0e9` mis-lexes** (splits into `1.0` and `e9`) → use plain decimal
   literals.
6. JHC reads custom targets only from `~/.jhc/targets.ini` (no CLI override);
   the Makefile appends an `[anos]` stanza once.
7. **`x == Nothing` (Eq on `Maybe`) mis-evaluates** — the generator's external-type
   filter wrongly kept builtins/defined names as external under JHC (a `type Foo =
   String` clashing with `data Foo`). Consume `Maybe` via `case`, not `==`, and use
   explicit membership recursion instead of multi-guard comprehensions. (`make check`
   catches regressions via GHC↔anos gen parity + compiling the generated code.)

## Next steps (not yet done)

- More diagram kinds (sequence, state, C4) — the model/renderer are structured
  to extend, but only class diagrams are wired.
- Multiplicities / default values in the DSL — would let `gen` emit `Maybe T` /
  `[T]` fields (like kUML's Kotlin generator) instead of plain types.
- `gen`: one-file-per-classifier output (kUML's artifact model) as an option;
  currently one cohesive module (compiles without cross-module import wiring).
- Interop: a reader for kUML's `kuml-io-json` model, so the Kotlin tool can feed
  this renderer / generator.
