{-# LANGUAGE OverloadedStrings #-}
module Main where

import Graphics.Vty
import qualified Data.Text as T
import qualified Data.Text.IO as TIO
import qualified Data.ByteString.Char8 as B
import Crypto.Hash.SHA256 (hash)
import System.Directory (doesFileExist)
import Text.Printf (printf)

shadowFile :: FilePath
shadowFile = "etc/shadow"

main :: IO ()
main = do
    v <- mkVty defaultConfig
    user <- prompt v "Username: " id
    pass <- prompt v "Password: " (T.map (const '*'))
    shutdown v
    ok <- verify user pass
    if ok then startDesktop (T.unpack user) else putStrLn "Invalid credentials"

prompt :: Vty -> String -> (T.Text -> T.Text) -> IO T.Text
prompt v label maskF = loop ""
  where
    loop txt = do
        draw txt
        e <- nextEvent v
        case e of
            EvKey KEnter [] -> return txt
            EvKey KBS [] -> loop (if T.null txt then txt else T.init txt)
            EvKey (KChar c) [] -> loop (txt `T.snoc` c)
            _ -> loop txt
    draw t = do
        let display = T.pack label <> maskF t
        update v (picForImage (string defAttr (T.unpack display)))

verify :: T.Text -> T.Text -> IO Bool
verify u p = do
    exist <- doesFileExist shadowFile
    if not exist then return False else do
        contents <- TIO.readFile shadowFile
        let entries = map (T.splitOn ":") (T.lines contents)
        case lookup u [(usr, pwd) | [usr,pwd] <- entries] of
            Nothing -> return False
            Just hashed -> return (hex (hash (B.pack (T.unpack p))) == T.unpack hashed)

hex :: B.ByteString -> String
hex = concatMap (printf "%02x") . B.unpack

startDesktop :: String -> IO ()
startDesktop user = do
    let cfgPath = "users/" ++ user ++ "/.riced.conf"
    cfgExists <- doesFileExist cfgPath
    conf <- if cfgExists then readFile cfgPath else return ""
    putStrLn ("Loaded riced desktop for " ++ user)
    putStrLn conf
    -- Placeholder for starting actual desktop environment
    return ()
