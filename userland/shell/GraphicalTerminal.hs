{-# LANGUAGE OverloadedStrings #-}
import Graphics.Vty
import qualified Data.Text as T
import qualified Data.Text.IO as TIO
import System.Process (readCreateProcess, shell)
import Control.Monad (void)

-- Terminal state
data TermState = TermState { buffer :: [T.Text], inputLine :: T.Text }

initialState :: TermState
initialState = TermState [] ""

main :: IO ()
main = do
    v <- mkVty defaultConfig
    draw v initialState
    loop v initialState
    shutdown v

loop :: Vty -> TermState -> IO ()
loop v st = do
    e <- nextEvent v
    case e of
        EvKey (KChar 'c') [MCtrl] -> return () -- Ctrl+C to quit
        EvKey KEnter [] -> do
            let cmd = T.unpack (inputLine st)
            out <- readCreateProcess (shell cmd) ""
            let newBuf = buffer st ++ ["> " <> inputLine st] ++ T.lines (T.pack out)
            let st' = TermState newBuf ""
            draw v st'
            loop v st'
        EvKey KBS [] -> do
            let newInput = if T.null (inputLine st) then "" else T.init (inputLine st)
            let st' = st { inputLine = newInput }
            draw v st'
            loop v st'
        EvKey (KChar c) [] -> do
            let st' = st { inputLine = inputLine st `T.snoc` c }
            draw v st'
            loop v st'
        _ -> loop v st

draw :: Vty -> TermState -> IO ()
draw v st = do
    let allLines = buffer st ++ ["> " <> inputLine st]
    let img = vertCat $ map (string defAttr . T.unpack) allLines
    update v (picForImage img)

