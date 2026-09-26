-- | Core model types for the kUML Haskell port.
--
-- A faithful, deliberately-small mirror of kUML's pure-Kotlin metamodel
-- (@kuml-metamodel-uml@), scoped to the V1 class-diagram slice: classes,
-- interfaces, enumerations, their attribute/operation compartments, and the
-- six structural relationships. Everything here is Haskell 2010 with plain
-- data types so it compiles under both GHC (host dev) and JHC 0.8.2 (the
-- anonymOS @progs-haskell@ path).
--
-- Kotlin -> Haskell correspondence:
--   Visibility        <-> dev.kuml.uml.Visibility
--   UmlProperty       <-> Attribute
--   UmlOperation      <-> Operation
--   UmlClass/Interface/Enumeration <-> Classifier (tagged by ClassifierKind)
--   UmlAssociation/Generalization/InterfaceRealization/Dependency <-> Relationship
module Kuml.Types where

-- | UML visibility modifiers (mirrors @dev.kuml.uml.Visibility@).
data Visibility = VPublic | VPrivate | VProtected | VPackage
  deriving (Eq)

-- | The single-character visibility glyph, matching @Visibility.symbol()@
-- in @UmlFormatHelpers.kt@.
visSymbol :: Visibility -> String
visSymbol VPublic    = "+"
visSymbol VPrivate   = "-"
visSymbol VProtected = "#"
visSymbol VPackage   = "~"

-- | An operation parameter: @name : Type@ (type may be empty when untyped).
data Param = Param
  { paramName :: String
  , paramType :: String
  } deriving (Eq)

-- | A structural feature (mirrors @UmlProperty@). Empty 'attrType' renders
-- with no @: Type@ suffix.
data Attribute = Attribute
  { attrVis  :: Visibility
  , attrName :: String
  , attrType :: String
  } deriving (Eq)

-- | A behavioural feature (mirrors @UmlOperation@).
data Operation = Operation
  { opVis    :: Visibility
  , opName   :: String
  , opParams :: [Param]
  , opReturn :: Maybe String
  } deriving (Eq)

-- | Which flavour of classifier a box is. @KClass True@ is an abstract class
-- (rendered with an italic name per UML 2.5 - no synthetic <<abstract>> line).
data ClassifierKind
  = KClass Bool
  | KInterface
  | KEnum
  deriving (Eq)

-- | A class-shaped box. For 'KEnum', 'clsLits' holds the literals and the
-- attribute/operation compartments are empty.
data Classifier = Classifier
  { clsKind  :: ClassifierKind
  , clsName  :: String
  , clsAttrs :: [Attribute]
  , clsOps   :: [Operation]
  , clsLits  :: [String]
  } deriving (Eq)

-- | The six structural relationship kinds this port renders.
data RelKind
  = RAssociation
  | RComposition
  | RAggregation
  | RGeneralization
  | RRealization
  | RDependency
  deriving (Eq)

-- | A relationship between two classifiers, referenced by name.
--
-- 'relFrom' / 'relTo' semantics per kind (matching @Relationships.kt@):
--   RAssociation    from -- to
--   RComposition    from (whole, filled diamond) *-- to (part)
--   RAggregation    from (whole, hollow diamond)  o-- to (part)
--   RGeneralization from (specific) --|> to (general)
--   RRealization    from (implementing) ..|> to (interface)
--   RDependency     from (client) ..> to (supplier)
data Relationship = Relationship
  { relKind :: RelKind
  , relFrom :: String
  , relTo   :: String
  } deriving (Eq)

-- | A whole diagram (mirrors @KumlDiagram@ narrowed to the class-diagram case).
data Diagram = Diagram
  { diagName    :: String
  , diagClasses :: [Classifier]
  , diagRels    :: [Relationship]
  } deriving (Eq)

-- | A structured diagnostic, JSON-serialisable, mirroring @KumlError@'s
-- essential fields (code / severity / message).
data Severity = SevError | SevWarning | SevInfo
  deriving (Eq)

data KumlError = KumlError
  { errCode     :: String
  , errSeverity :: Severity
  , errMessage  :: String
  } deriving (Eq)

severityText :: Severity -> String
severityText SevError   = "error"
severityText SevWarning = "warning"
severityText SevInfo    = "info"
