{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ExtendedDefaultRules #-}
{-# LANGUAGE ForeignFunctionInterface #-}
import Shelly
import qualified Data.Text as T
import qualified Data.Text.IO as TIO
import Control.Monad (unless)
import System.IO (hFlush, stdout, stdin, BufferMode(..), hSetBuffering, isEOF)

default (T.Text)

foreign export ccall ttyShellyMain :: IO ()

ttyShellyMain :: IO ()
ttyShellyMain = shellyNoDir $ do
  liftIO $ do
    hSetBuffering stdout LineBuffering
    hSetBuffering stdin LineBuffering
  loop
  where
    loop :: Sh ()
    loop = do
      liftIO $ putStr "ttyShelly> "
      liftIO $ hFlush stdout
      eof <- liftIO isEOF
      unless eof $ do
        line <- liftIO TIO.getLine
        unless (T.strip line == "exit") $ do
          verbosely $ run_ "bash" ["-c", line]
          loop

main :: IO ()
main = ttyShellyMain
