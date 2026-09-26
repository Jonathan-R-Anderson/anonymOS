-- | Layout + SVG rendering for class diagrams.
--
-- Sizing constants and the member-line format are lifted verbatim from kUML's
-- @UmlContentSizeProvider@ and @UmlFormatHelpers.kt@ so boxes size to their
-- text the same way. Layout is a pure grid placement (kUML's GraalVM-safe
-- @GridLayoutEngine@ is the same idea) and edges are drawn with the standard
-- UML markers: hollow triangle (generalization/realization), open arrow
-- (dependency), filled/hollow diamond (composition/aggregation).
--
-- Integer arithmetic for sizing (matching Kotlin's @(len * charPx).toInt()@);
-- 'Double' only for edge geometry, rounded to 'Int' at emit time. Prelude-only.
module Kuml.Render (renderSvg) where

import Kuml.Types

-- -- sizing constants (mirror UmlContentSizeProvider) ------------------------

defaultW, defaultH :: Int
defaultW = 160
defaultH = 80

stereoLineH, nameLineH, featureLineH, dividerGap, boxBottomPad, boxHPadding :: Int
stereoLineH  = 18
nameLineH    = 20
featureLineH = 13
dividerGap   = 14
boxBottomPad = 12
boxHPadding  = 24

-- char-width estimates as (numerator, denominator) of the kUML *_CHAR_PX floats
titleCharPx, bodyCharPx, stereoCharPx :: (Int, Int)
titleCharPx  = (84, 10)   -- 8.4
bodyCharPx   = (66, 10)   -- 6.6
stereoCharPx = (56, 10)   -- 5.6

-- layout constants
margin, hgap, vgap :: Int
margin = 28
hgap   = 64
vgap   = 52

estWidth :: Int -> (Int, Int) -> Int
estWidth len (n, d) = (len * n) `div` d

-- -- model-derived text ------------------------------------------------------

-- | The stereotype keyword shown above the name, if any (plain ASCII; the
-- guillemets are added at emit time as numeric entities so the output is
-- byte-identical under GHC's UTF-8 layer and JHC's byte-oriented IO).
stereoLabelOf :: Classifier -> Maybe String
stereoLabelOf c = case clsKind c of
  KClass _   -> Nothing
  KInterface -> Just "interface"
  KEnum      -> Just "enumeration"

hasStereoOf :: Classifier -> Bool
hasStereoOf c = case stereoLabelOf c of
  Just _  -> True
  Nothing -> False

-- ASCII width proxy for a stereotype line: label + two guillemet glyphs.
stereoWidthProxy :: Classifier -> String
stereoWidthProxy c = maybe "" (\l -> "<" ++ l ++ ">") (stereoLabelOf c)

isAbstractOf :: Classifier -> Bool
isAbstractOf c = case clsKind c of
  KClass True -> True
  _           -> False

-- | The lines shown in the upper (attribute) compartment.
upperLines :: Classifier -> [String]
upperLines c = case clsKind c of
  KEnum -> clsLits c
  _     -> map fmtAttr (clsAttrs c)

-- | The lines shown in the lower (operation) compartment.
lowerLines :: Classifier -> [String]
lowerLines c = case clsKind c of
  KEnum -> []
  _     -> map fmtOp (clsOps c)

fmtAttr :: Attribute -> String
fmtAttr a =
  visSymbol (attrVis a) ++ " " ++ attrName a ++ typeSuffix (attrType a)

fmtOp :: Operation -> String
fmtOp o =
  visSymbol (opVis o) ++ " " ++ opName o
    ++ "(" ++ joinWith ", " (map fmtParam (opParams o)) ++ ")"
    ++ retSuffix (opReturn o)

fmtParam :: Param -> String
fmtParam p = paramName p ++ typeSuffix (paramType p)

typeSuffix :: String -> String
typeSuffix "" = ""
typeSuffix t  = ": " ++ t

retSuffix :: Maybe String -> String
retSuffix Nothing  = ""
retSuffix (Just r) = ": " ++ r

-- -- box sizing ---------------------------------------------------------------

sizeOf :: Classifier -> (Int, Int)
sizeOf c =
  let ups      = upperLines c
      lows     = lowerLines c
      w = boxWidth (clsName c) (stereoWidthProxy c) (ups ++ lows)
      h = boxHeight (hasStereoOf c) (length ups) (length lows)
  in (w, h)

boxWidth :: String -> String -> [String] -> Int
boxWidth name stereo body =
  let titleW  = estWidth (length name) titleCharPx
      stereoW = if null stereo then 0 else estWidth (length stereo) stereoCharPx
      bodyMax = maxInt (0 : map (\s -> estWidth (length s) bodyCharPx) body)
      raw     = maxInt [titleW, stereoW, bodyMax]
  in maxInt [defaultW, raw + boxHPadding]

boxHeight :: Bool -> Int -> Int -> Int
boxHeight hasStereo attrs ops =
  let attrComp = if attrs > 0 then dividerGap + attrs * featureLineH else 0
      opsComp  = if ops  > 0 then dividerGap + ops  * featureLineH else 0
      h = (if hasStereo then stereoLineH else 0) + nameLineH + attrComp + opsComp + boxBottomPad
  in maxInt [h, defaultH]

-- -- grid layout ---------------------------------------------------------------

type Box = (Int, Int, Int, Int)  -- x, y, w, h

layout :: [Classifier] -> [(Classifier, Box)]
layout [] = []
layout cs =
  let n     = length cs
      cols  = ceilSqrt n
      rows  = (n + cols - 1) `div` cols
      sizes = map sizeOf cs
      idx   = zip3 [0 ..] cs sizes
      colW c  = maxInt (0 : [w | (i, _, (w, _)) <- idx, i `mod` cols == c])
      rowH r  = maxInt (0 : [h | (i, _, (_, h)) <- idx, i `div` cols == r])
      colWs = map colW [0 .. cols - 1]
      rowHs = map rowH [0 .. rows - 1]
      colX c = margin + sumInt (take c colWs) + c * hgap
      rowY r = margin + sumInt (take r rowHs) + r * vgap
      place (i, cl, (w, h)) =
        let c = i `mod` cols
            r = i `div` cols
            x = colX c + (nth c colWs - w) `div` 2
            y = rowY r + (nth r rowHs - h) `div` 2
        in (cl, (x, y, w, h))
  in map place idx

-- -- SVG assembly --------------------------------------------------------------

renderSvg :: Diagram -> String
renderSvg d =
  let placed = layout (diagClasses d)
      pm     = [(clsName c, b) | (c, b) <- placed]
      cw = maxInt (defaultW : [x + w + margin | (_, (x, _, w, _)) <- placed])
      ch = maxInt (defaultH : [y + h + margin | (_, (_, y, _, h)) <- placed])
      header =
        "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"" ++ show cw
          ++ "\" height=\"" ++ show ch ++ "\" viewBox=\"0 0 " ++ show cw ++ " " ++ show ch
          ++ "\" font-family=\"sans-serif\">\n"
      titleComment = "<!-- kUML diagram: " ++ escapeXml (diagName d) ++ " -->\n"
      edges = concatMap (renderEdge pm) (diagRels d)
      boxes = concatMap (\(c, b) -> renderBox c b) placed
  in header ++ styleBlock ++ titleComment ++ edges ++ boxes ++ "</svg>\n"

styleBlock :: String
styleBlock = unlines
  [ "<style>"
  , " .kuml-class { fill:#ffffff; stroke:#334155; stroke-width:1; }"
  , " .kuml-title { font-weight:bold; font-size:13px; fill:#0f172a; }"
  , " .kuml-title-abstract { font-style:italic; }"
  , " .kuml-stereo { font-style:italic; font-size:10px; fill:#475569; }"
  , " .kuml-body { font-size:11px; fill:#1e293b; }"
  , " .kuml-divider { stroke:#334155; stroke-width:1; }"
  , " .kuml-edge { stroke:#334155; stroke-width:1; fill:none; }"
  , " .kuml-edge-dashed { stroke:#334155; stroke-width:1; fill:none; stroke-dasharray:5,4; }"
  , " .kuml-marker { fill:#ffffff; stroke:#334155; stroke-width:1; }"
  , " .kuml-marker-filled { fill:#334155; stroke:#334155; stroke-width:1; }"
  , "</style>"
  ]

-- -- class box ------------------------------------------------------------------

renderBox :: Classifier -> Box -> String
renderBox c (x, y, w, h) =
  let hasStereo = hasStereoOf c
      top       = if hasStereo then stereoLineH else 0
      nameY     = top + 15
      headerBot = top + nameLineH
      ups       = upperLines c
      lows      = lowerLines c
      nameCls   = if isAbstractOf c then "kuml-title kuml-title-abstract" else "kuml-title"

      gOpen = "<g transform=\"translate(" ++ show x ++ "," ++ show y ++ ")\">\n"
      rect  = " <rect width=\"" ++ show w ++ "\" height=\"" ++ show h
                ++ "\" class=\"kuml-class\"/>\n"
      stereoT = case stereoLabelOf c of
        Nothing -> ""
        Just l  -> " <text x=\"" ++ show (w `div` 2) ++ "\" y=\"13\" text-anchor=\"middle\" "
                     ++ "class=\"kuml-stereo\">&#171;" ++ escapeXml l ++ "&#187;</text>\n"
      nameT = " <text x=\"" ++ show (w `div` 2) ++ "\" y=\"" ++ show nameY
                ++ "\" text-anchor=\"middle\" class=\"" ++ nameCls ++ "\">"
                ++ escapeXml (clsName c) ++ "</text>\n"

      -- upper compartment
      (upperSvg, afterUpper) = compartment (not (null ups)) headerBot ups
      -- lower compartment (its own divider only when there is content)
      (lowerSvg, _) = compartment (not (null lows)) afterUpper lows

  in gOpen ++ rect ++ stereoT ++ nameT ++ upperSvg ++ lowerSvg ++ "</g>\n"

-- | Draw a compartment: a divider at @yTop@ then one text line per entry.
-- Returns the rendered SVG and the y cursor just past the compartment.
compartment :: Bool -> Int -> [String] -> (String, Int)
compartment False yTop _ = ("", yTop)
compartment True  yTop items =
  let dividerY = yTop
      divider  = " <line x1=\"0\" y1=\"" ++ show dividerY ++ "\" x2=\"100%\" y2=\""
                   ++ show dividerY ++ "\" class=\"kuml-divider\"/>\n"
      firstY   = yTop + dividerGap
      linesSvg = concat
        [ " <text x=\"6\" y=\"" ++ show (firstY + i * featureLineH)
            ++ "\" class=\"kuml-body\">" ++ escapeXml s ++ "</text>\n"
        | (i, s) <- zip [0 ..] items ]
      next = firstY + length items * featureLineH
  in (divider ++ linesSvg, next)

-- -- edges ----------------------------------------------------------------------

renderEdge :: [(String, Box)] -> Relationship -> String
renderEdge pm r =
  case (lookup (relFrom r) pm, lookup (relTo r) pm) of
    (Just ba, Just bb) -> drawRel (relKind r) ba bb
    _                  -> ""

drawRel :: RelKind -> Box -> Box -> String
drawRel kind ba bb =
  let ca = center ba
      cb = center bb
      pA = boxEdge ba cb
      pB = boxEdge bb ca
      dirB = unitVec ca cb   -- pointing into B
      dirA = unitVec cb ca   -- pointing into A
      dashed = kind == RRealization || kind == RDependency
      cls    = if dashed then "kuml-edge-dashed" else "kuml-edge"
      atB = kind == RGeneralization || kind == RRealization || kind == RDependency
      atA = kind == RComposition || kind == RAggregation
      startP = if atA then sub pA (scale dirA diamondLen) else pA
      endP   = if atB then sub pB (scale dirB markerLen)  else pB
      lineSvg = " <line x1=\"" ++ ci (fst startP) ++ "\" y1=\"" ++ ci (snd startP)
                  ++ "\" x2=\"" ++ ci (fst endP) ++ "\" y2=\"" ++ ci (snd endP)
                  ++ "\" class=\"" ++ cls ++ "\"/>\n"
      markerSvg = case kind of
        RGeneralization -> hollowTriangle pB dirB
        RRealization    -> hollowTriangle pB dirB
        RDependency     -> openArrow pB dirB
        RComposition    -> diamond True  pA dirA
        RAggregation    -> diamond False pA dirA
        RAssociation    -> ""
  in lineSvg ++ markerSvg

-- marker sizes
markerLen, markerHalf, diamondLen, diamondHalf :: Double
markerLen   = 12
markerHalf  = 6
diamondLen  = 16
diamondHalf = 6

hollowTriangle :: (Double, Double) -> (Double, Double) -> String
hollowTriangle tip dir =
  let perp  = perpOf dir
      baseC = sub tip (scale dir markerLen)
      b1 = add baseC (scale perp markerHalf)
      b2 = sub baseC (scale perp markerHalf)
  in polygon "kuml-marker" [tip, b1, b2]

diamond :: Bool -> (Double, Double) -> (Double, Double) -> String
diamond filled tip dir =
  let perp = perpOf dir
      back = sub tip (scale dir diamondLen)
      mid  = sub tip (scale dir (diamondLen / 2))
      s1 = add mid (scale perp diamondHalf)
      s2 = sub mid (scale perp diamondHalf)
      cls = if filled then "kuml-marker-filled" else "kuml-marker"
  in polygon cls [tip, s1, back, s2]

openArrow :: (Double, Double) -> (Double, Double) -> String
openArrow tip dir =
  let perp  = perpOf dir
      baseC = sub tip (scale dir markerLen)
      b1 = add baseC (scale perp markerHalf)
      b2 = sub baseC (scale perp markerHalf)
  in " <polyline points=\"" ++ pt b1 ++ " " ++ pt tip ++ " " ++ pt b2
       ++ "\" class=\"kuml-edge\"/>\n"

polygon :: String -> [(Double, Double)] -> String
polygon cls pts =
  " <polygon points=\"" ++ joinWith " " (map pt pts) ++ "\" class=\"" ++ cls ++ "\"/>\n"

-- -- geometry ------------------------------------------------------------------

center :: Box -> (Double, Double)
center (x, y, w, h) =
  (fromIntegral x + fromIntegral w / 2, fromIntegral y + fromIntegral h / 2)

boxEdge :: Box -> (Double, Double) -> (Double, Double)
boxEdge b@(_, _, w, h) (tx, ty) =
  let (cx, cy) = center b
      dx = tx - cx
      dy = ty - cy
      hw = fromIntegral w / 2
      hh = fromIntegral h / 2
      sx = if dx == 0 then bigNum else hw / absD dx
      sy = if dy == 0 then bigNum else hh / absD dy
      s  = minD sx sy
  in (cx + dx * s, cy + dy * s)

unitVec :: (Double, Double) -> (Double, Double) -> (Double, Double)
unitVec (ax, ay) (bx, by) =
  let dx = bx - ax
      dy = by - ay
      len = sqrt (dx * dx + dy * dy)
  in if len == 0 then (0, 0) else (dx / len, dy / len)

perpOf :: (Double, Double) -> (Double, Double)
perpOf (dx, dy) = (negate dy, dx)

add, sub :: (Double, Double) -> (Double, Double) -> (Double, Double)
add (ax, ay) (bx, by) = (ax + bx, ay + by)
sub (ax, ay) (bx, by) = (ax - bx, ay - by)

scale :: (Double, Double) -> Double -> (Double, Double)
scale (ax, ay) k = (ax * k, ay * k)

bigNum :: Double
bigNum = 1000000000.0

absD :: Double -> Double
absD v = if v < 0 then negate v else v

minD :: Double -> Double -> Double
minD a b = if a < b then a else b

-- render a Double coordinate as a rounded Int string
ci :: Double -> String
ci v = show (dround v)

pt :: (Double, Double) -> String
pt (x, y) = ci x ++ "," ++ ci y

dround :: Double -> Int
dround v = floor (v + 0.5)

-- -- small Prelude-only helpers (avoid Data.List for JHC portability) ---------

maxInt :: [Int] -> Int
maxInt []     = 0
maxInt (x:xs) = foldr maxi x xs
  where maxi a b = if a > b then a else b

sumInt :: [Int] -> Int
sumInt = foldr (+) 0

nth :: Int -> [a] -> a
nth i xs = xs !! i

ceilSqrt :: Int -> Int
ceilSqrt n
  | n <= 1    = 1
  | otherwise = go 1
  where go k = if k * k >= n then k else go (k + 1)

joinWith :: String -> [String] -> String
joinWith _   []     = ""
joinWith _   [x]    = x
joinWith sep (x:xs) = x ++ sep ++ joinWith sep xs

escapeXml :: String -> String
escapeXml = concatMap esc
  where
    esc '&'  = "&amp;"
    esc '<'  = "&lt;"
    esc '>'  = "&gt;"
    esc '"'  = "&quot;"
    esc '\'' = "&apos;"
    esc ch    = [ch]
