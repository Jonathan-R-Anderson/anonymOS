{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
import Shelly -- From the local Shelly module
import Data.Text (Text, pack, unpack)
import qualified Data.Text as T -- Import Data.Text qualified as T
import qualified Data.Text.IO as TIO
import System.IO (hFlush, stdout)
import Control.Monad (forever)
import Control.Monad.IO.Class (liftIO)

-- A very simple REPL (Read-Eval-Print Loop)
main :: IO ()
main = forever $ do
    putStr "anonym> "
    hFlush stdout
    cmdLine <- TIO.getLine
    case cmdLine of
        "exit" -> shelly $ exit 0
        ""     -> return () -- Do nothing for empty input
        _      -> runCommand cmdLine

runCommand :: Text -> IO ()
runCommand cmdLine = shelly $ silently $ do
    -- Shelly commands are typically run in the Sh monad.
    -- We need to split the command line into command and arguments.
    -- For simplicity, this example doesn't handle complex parsing like quotes.
    let parts = T.words cmdLine
    case parts of
        [] -> return ()
        (cmd:args) -> do
            let cmdString :: String = unpack cmd
            -- Attempt to run the command. Shelly will search PATH.
            -- stdout and stderr will be captured by default unless redirected.
            -- For a real shell, you'd want to handle PATH, pipes, redirections etc.
            result <- errExit False $ run cmdString args -- Pass 'args' ([Text]) directly
            -- For now, just print the output. A real shell would handle this better.
            liftIO $ TIO.putStrLn result
    return ()
