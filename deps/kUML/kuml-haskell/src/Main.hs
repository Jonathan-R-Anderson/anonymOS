-- | kuml-hs - the Haskell port of the kUML CLI, scoped to the class-diagram
-- slice that runs standalone on anonymOS (no JVM).
--
-- Usage:
--   kuml render   FILE [--format svg] [-o OUT] [--output json|text]
--   kuml validate FILE [--output json|text]
--   kuml version
--   kuml help
--
-- @render@ writes SVG to stdout (or @-o OUT@); diagnostics go to stderr so the
-- SVG stream stays clean for piping. @validate@ prints diagnostics to stdout
-- and exits non-zero when any error-severity diagnostic is present.
module Main (main) where

import System.Environment (getArgs)
import System.Exit (exitWith, ExitCode(..), exitSuccess)
import System.IO (hPutStr, hPutStrLn, stderr)

import Kuml.Types
import Kuml.Parser (parseDiagram)
import Kuml.Check (validate)
import Kuml.Render (renderSvg)
import Kuml.Gen.Haskell (generateHaskell)

version :: String
version = "kuml-hs 0.1.0 (anonymOS Haskell port; class diagrams)"

main :: IO ()
main = do
  args <- getArgs
  case args of
    []                 -> usage >> exitSuccess
    ("help" : _)       -> usage >> exitSuccess
    ("--help" : _)     -> usage >> exitSuccess
    ("version" : _)    -> putStrLn version >> exitSuccess
    ("--version" : _)  -> putStrLn version >> exitSuccess
    ("render" : rest)  -> cmdRender rest
    ("validate" : rest)-> cmdValidate rest
    ("gen" : rest)     -> cmdGen rest
    ("generate" : rest)-> cmdGen rest
    (other : _)        -> die ("unknown command '" ++ other ++ "' (try: kuml help)")

-- -- options ----------------------------------------------------------------

data Opts = Opts
  { optFile   :: Maybe String
  , optOut    :: Maybe String
  , optJson   :: Bool
  , optFormat :: String
  , optModule :: Maybe String
  }

defOpts :: Opts
defOpts = Opts
  { optFile = Nothing, optOut = Nothing, optJson = False
  , optFormat = "svg", optModule = Nothing }

parseOpts :: [String] -> Either String Opts
parseOpts = go defOpts
  where
    go o [] = Right o
    go o ("-o" : v : xs)        = go o { optOut = Just v } xs
    go o ("-i" : v : xs)        = go o { optFile = Just v } xs
    go o ("--input" : v : xs)   = go o { optFile = Just v } xs
    go o ("--output" : v : xs)  = go o { optJson = v == "json" } xs
    go o ("--format" : v : xs)  = go o { optFormat = v } xs
    go o ("--module" : v : xs)  = go o { optModule = Just v } xs
    go o ("--package" : v : xs) = go o { optModule = Just v } xs
    go o (x : xs)
      | isFlag x  = Left ("unknown or incomplete option '" ++ x ++ "'")
      | otherwise = case optFile o of
                      Nothing -> go o { optFile = Just x } xs
                      Just _  -> Left ("unexpected extra argument '" ++ x ++ "'")
    isFlag ('-' : _) = True
    isFlag _         = False

-- -- render ----------------------------------------------------------------

cmdRender :: [String] -> IO ()
cmdRender argv =
  case parseOpts argv of
    Left e  -> die e
    Right o ->
      if optFormat o /= "svg"
        then die ("unsupported --format '" ++ optFormat o ++ "' (only 'svg')")
        else case optFile o of
          Nothing   -> die "render: missing input FILE"
          Just path -> do
            src <- readFile path
            case parseDiagram src of
              Left perr -> emitDiagnostics True o [parseError perr] >> exitWith (ExitFailure 1)
              Right d   -> do
                let diags = validate d
                emitDiagnostics True o diags   -- to stderr, never stdout
                let svg = renderSvg d
                case optOut o of
                  Nothing  -> putStr svg
                  Just out -> writeFile out svg

-- -- validate -------------------------------------------------------------

cmdValidate :: [String] -> IO ()
cmdValidate argv =
  case parseOpts argv of
    Left e  -> die e
    Right o -> case optFile o of
      Nothing   -> die "validate: missing input FILE"
      Just path -> do
        src <- readFile path
        let diags = case parseDiagram src of
                      Left perr -> [parseError perr]
                      Right d   -> validate d
        -- validate prints to stdout; JSON mode always emits an array (even []).
        if optJson o
          then putStrLn (diagsToJson diags)
          else if null diags
                 then putStrLn "OK: no problems found"
                 else mapM_ (putStrLn . diagLine) diags
        if any isError diags then exitWith (ExitFailure 1) else exitSuccess

-- -- diagnostics output -------------------------------------------------------

-- ── gen (code generation: model -> Haskell source) ──────────────────────────

cmdGen :: [String] -> IO ()
cmdGen argv =
  case parseOpts argv of
    Left e  -> die e
    Right o -> case optFile o of
      Nothing   -> die "gen: missing input FILE"
      Just path -> do
        src <- readFile path
        case parseDiagram src of
          Left perr -> do
            emitDiagnostics True o [parseError perr]
            exitWith (ExitFailure 1)
          Right d -> do
            let diags = validate d
            emitDiagnostics True o diags   -- to stderr; generated code stays clean
            let out = generateHaskell (optModule o) d
            case optOut o of
              Nothing  -> putStr out
              Just f   -> writeFile f out

parseError :: String -> KumlError
parseError msg = KumlError "KUML-E-001" SevError ("parse error: " ++ msg)

isError :: KumlError -> Bool
isError e = errSeverity e == SevError

-- | Emit diagnostics. @toErr@ picks stderr (render) vs stdout (validate).
emitDiagnostics :: Bool -> Opts -> [KumlError] -> IO ()
emitDiagnostics _ _ [] = return ()
emitDiagnostics toErr o diags
  | optJson o = out (diagsToJson diags ++ "\n")
  | otherwise = mapM_ (out . (++ "\n") . diagLine) diags
  where
    out s = if toErr then hPutStr stderr s else putStr s

diagLine :: KumlError -> String
diagLine e =
  errCode e ++ " [" ++ severityText (errSeverity e) ++ "] " ++ errMessage e

diagsToJson :: [KumlError] -> String
diagsToJson diags = "[" ++ commaJoin (map one diags) ++ "]"
  where
    one e = "{\"code\":" ++ jstr (errCode e)
              ++ ",\"severity\":" ++ jstr (severityText (errSeverity e))
              ++ ",\"message\":" ++ jstr (errMessage e) ++ "}"

jstr :: String -> String
jstr s = "\"" ++ concatMap esc s ++ "\""
  where
    esc '"'  = "\\\""
    esc '\\' = "\\\\"
    esc '\n' = "\\n"
    esc '\t' = "\\t"
    esc c    = [c]

commaJoin :: [String] -> String
commaJoin []     = ""
commaJoin [x]    = x
commaJoin (x:xs) = x ++ "," ++ commaJoin xs

-- -- misc --------------------------------------------------------------------

die :: String -> IO ()
die msg = hPutStrLn stderr ("kuml: " ++ msg) >> exitWith (ExitFailure 2)

usage :: IO ()
usage = putStr $ unlines
  [ version
  , ""
  , "usage:"
  , "  kuml render   FILE [--format svg] [-o OUT] [--output json|text]"
  , "  kuml validate FILE [--output json|text]"
  , "  kuml gen      FILE [--module NAME] [-o OUT.hs]   (generate Haskell source)"
  , "  kuml version"
  , "  kuml help"
  , ""
  , "input is the kUML native DSL (see examples/*.kuml)."
  , "gen also accepts kUML-style flags: -i FILE, --package NAME."
  ]
