#!/bin/sh
# Concatenate the multi-module kUML-hs source into one Main module.
#
# Why: JHC 0.8.2's CROSS-MODULE C backend mis-links (it emits calls to worker
# closures — `fx<n>` — that it never defines, so `ld` fails with undefined
# references). Its single-file path is solid. GHC builds the clean multi-module
# tree directly; only the JHC (anonymOS) build consumes this merged file.
#
# The merge just drops each module header and the internal `import Kuml.*`
# lines, hoisting the external imports to the top. Every top-level name is
# already unique across modules, so no renaming is needed.
set -eu

SRC=${1:-src}
OUT=${2:-build/kuml_single.hs}
mkdir -p "$(dirname "$OUT")"

{
  echo "module Main where"
  echo "import Data.Char (isSpace, isAlpha, isAlphaNum)"
  echo "import System.Environment (getArgs)"
  echo "import System.Exit (exitWith, ExitCode(..), exitSuccess)"
  echo "import System.IO (hPutStr, hPutStrLn, stderr)"
  for m in Kuml/Types.hs Kuml/Lexer.hs Kuml/Parser.hs Kuml/Check.hs Kuml/Render.hs Main.hs; do
    echo "-- ===== $m ====="
    grep -vE '^module |^import Kuml|^import Data\.Char|^import System\.(Environment|Exit|IO)' "$SRC/$m"
  done
} > "$OUT"

echo "wrote $OUT ($(wc -l < "$OUT") lines)"
