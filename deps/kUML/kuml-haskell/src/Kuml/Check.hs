-- | Semantic validation of a parsed 'Diagram', producing structured
-- diagnostics in the spirit of kUML's @KumlError@ (@KUML-E-xxx@ codes).
--
-- Prelude-only; JHC-safe.
module Kuml.Check (validate) where

import Kuml.Types

-- | Check a diagram and return diagnostics (empty = clean).
--
--   KUML-E-101  relationship references an undefined classifier
--   KUML-W-201  duplicate classifier name
--   KUML-E-102  self-relationship on a non-existent endpoint is folded into 101
validate :: Diagram -> [KumlError]
validate d = dupErrors ++ refErrors
  where
    names = map clsName (diagClasses d)

    dupErrors =
      [ KumlError "KUML-W-201" SevWarning
          ("duplicate classifier name '" ++ n ++ "'")
      | n <- distinct (duplicates names)
      ]

    refErrors = concatMap relErrs (diagRels d)

    relErrs r =
      [ KumlError "KUML-E-101" SevError
          ("relationship " ++ relKindText (relKind r)
            ++ " references undefined classifier '" ++ e ++ "'")
      | e <- [relFrom r, relTo r], not (e `elem` names)
      ]

relKindText :: RelKind -> String
relKindText RAssociation    = "association"
relKindText RComposition    = "composition"
relKindText RAggregation    = "aggregation"
relKindText RGeneralization = "generalization"
relKindText RRealization    = "realization"
relKindText RDependency     = "dependency"

-- | Names that appear more than once (each duplicate name reported once).
duplicates :: [String] -> [String]
duplicates xs = go [] xs
  where
    go _ [] = []
    go seen (y:ys)
      | y `elem` seen = y : go seen ys
      | otherwise     = go (y : seen) ys

distinct :: [String] -> [String]
distinct = go []
  where
    go _ [] = []
    go seen (y:ys)
      | y `elem` seen = go seen ys
      | otherwise     = y : go (y : seen) ys
