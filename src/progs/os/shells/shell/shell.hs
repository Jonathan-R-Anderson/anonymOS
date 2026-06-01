module Main where

import Hos.User.SysCall
import Hos.User.Driver.PS2
import Control.Monad

main :: IO ()
main = do
  hosDebugLog "[esh] Enhanced Shell starting..."
  hosRequestIO
  hosDebugLog "[esh] Initializing PS/2..."
  initPS2
  hosDebugLog "[esh] Ready. Type 'help' for available commands."
  doShell

doShell :: IO ()
doShell = do
  hosVGAPut "> "
  line <- getLinePS2
  case line of
    "help" -> do
      hosDebugLog "Available commands:\n"
      hosDebugLog "  help     - Show this help message\n"
      hosDebugLog "  echo     - Echo arguments to screen\n"
      hosDebugLog "  clear    - Clear the screen\n"
      hosDebugLog "  about    - Show shell information\n"
      hosDebugLog "  exit     - Exit the shell\n"
      doShell
    "clear" -> hosDebugLog "\x1b[2J\x1b[H" >> doShell
    "about" -> do
      hosDebugLog "Enhanced Shell (esh) for HaskellOS\n"
      hosDebugLog "Version 0.1.0\n"
      doShell
    "exit" -> hosDebugLog "Shell exiting...\n" >> return ()
    "" -> doShell
    _ -> do
      let (cmd, args) = break (== ' ') line
      case cmd of
        "echo" -> hosDebugLog (drop 1 args ++ "\n") >> doShell
        _ -> hosDebugLog ("Unknown command: " ++ cmd ++ "\n") >> doShell

getLinePS2 :: IO String
getLinePS2 = go ""
  where
    go acc = do
      c <- getCharPS2
      case c of
        '\0' -> hosYield >> go acc
        '\n' -> hosVGAPut "\n" >> return acc
        '\b' -> if null acc
                  then go acc
                  else (hosVGAPut "\b \b" >> go (init acc))
        c'   -> (hosVGAPut [c'] >> go (acc ++ [c']))
