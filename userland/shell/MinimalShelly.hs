{-# LANGUAGE OverloadedStrings #-}
module MinimalShelly
  ( Sh
  , shelly
  , silently
  , run
  , errExit
  , exit
  ) where

import qualified Data.Text as T
import Data.Text (Text)
import System.Exit (exitWith, ExitCode(..))
import System.Process (readProcessWithExitCode)

-- | In this minimal implementation 'Sh' is just 'IO'.
type Sh a = IO a

-- | Execute a Sh action.
shelly :: Sh a -> IO a
shelly = id

-- | Suppress command output. No-op in this minimal version.
silently :: Sh a -> Sh a
silently = id

-- | Run a command with arguments and return its stdout as Text.
run :: FilePath -> [Text] -> Sh Text
run cmd args = do
  (code, out, err) <- readProcessWithExitCode cmd (map T.unpack args) ""
  case code of
    ExitSuccess   -> return (T.pack out)
    ExitFailure _ -> return (T.pack (out ++ err))

-- | Ignore the 'errExit' setting for simplicity.
errExit :: Bool -> Sh a -> Sh a
errExit _ action = action

-- | Exit with the given status.
exit :: Int -> Sh a
exit code = liftIO $ exitWith (if code == 0 then ExitSuccess else ExitFailure code)

-- local helper
liftIO :: IO a -> IO a
liftIO = id
