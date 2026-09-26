-- | Tokenizer for the kUML native text DSL.
--
-- The DSL is a JVM-free stand-in for kUML's @*.kuml.kts@ input: line-oriented,
-- brace-delimited, and trivially lexable without a Kotlin compiler. Comments
-- are @//@ to end-of-line (so @#@ stays free as the protected-visibility glyph).
--
-- Kept to Prelude + Data.Char so it compiles under JHC 0.8.2.
module Kuml.Lexer (Token(..), tokenize, tokLabel) where

import Data.Char (isSpace, isAlpha, isAlphaNum)

-- | A lexical token. Visibility glyphs (@+ - # ~@) are their own token so the
-- parser can key member lines off them; everything else is punctuation,
-- identifiers, or string literals.
--
-- No @deriving Show@: JHC 0.8.2's whole-program C backend mis-links the
-- code it generates for derived @Show@ methods (undefined @fx…@ references at
-- link time). 'tokLabel' is the hand-written substitute the parser uses for
-- error messages.
data Token
  = TLBrace | TRBrace | TLParen | TRParen
  | TColon | TComma | TSemi
  | TVis Char
  | TIdent String
  | TStr String
  deriving (Eq)

-- | Human-readable label for a token (for diagnostics).
tokLabel :: Token -> String
tokLabel TLBrace    = "'{'"
tokLabel TRBrace    = "'}'"
tokLabel TLParen    = "'('"
tokLabel TRParen    = "')'"
tokLabel TColon     = "':'"
tokLabel TComma     = "','"
tokLabel TSemi      = "';'"
tokLabel (TVis c)   = "'" ++ [c] ++ "'"
tokLabel (TIdent s) = s
tokLabel (TStr s)   = "\"" ++ s ++ "\""

isIdentStart :: Char -> Bool
isIdentStart c = isAlpha c || c == '_'

isIdentChar :: Char -> Bool
isIdentChar c = isAlphaNum c || c == '_' || c == '.'

-- | Turn source text into a token stream. Unknown characters are skipped
-- (lenient) rather than raising - parse-level checks catch structural errors.
tokenize :: String -> [Token]
tokenize [] = []
tokenize ('/':'/':cs) = tokenize (dropWhile (/= '\n') cs)
tokenize ('{':cs) = TLBrace : tokenize cs
tokenize ('}':cs) = TRBrace : tokenize cs
tokenize ('(':cs) = TLParen : tokenize cs
tokenize (')':cs) = TRParen : tokenize cs
tokenize (':':cs) = TColon : tokenize cs
tokenize (',':cs) = TComma : tokenize cs
tokenize (';':cs) = TSemi : tokenize cs
tokenize ('+':cs) = TVis '+' : tokenize cs
tokenize ('-':cs) = TVis '-' : tokenize cs
tokenize ('#':cs) = TVis '#' : tokenize cs
tokenize ('~':cs) = TVis '~' : tokenize cs
tokenize ('"':cs) =
  let (s, rest) = spanStr cs
  in TStr s : tokenize rest
tokenize (c:cs)
  | isSpace c      = tokenize cs
  | isIdentStart c = let (nm, rest) = span isIdentChar (c:cs)
                     in TIdent nm : tokenize rest
  | otherwise      = tokenize cs

-- | Read a double-quoted string body up to the closing quote (unterminated
-- strings run to end of input).
spanStr :: String -> (String, String)
spanStr [] = ([], [])
spanStr ('"':cs) = ([], cs)
spanStr (c:cs) = let (s, r) = spanStr cs in (c:s, r)
