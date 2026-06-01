module Hos.User.Driver.PS2 where

import Hos.User.IO
import Data.Word
import Data.Bits
import Control.Monad
import System.IO.Unsafe (unsafePerformIO)
import Data.IORef

import Data.Char
import Foreign.Marshal.Alloc
import Foreign.Ptr
import Foreign.Storable
import Control.Exception
import Numeric

-- Ports
ps2DataPort :: Word16
ps2DataPort = 0x60

ps2StatusPort :: Word16
ps2StatusPort = 0x64

-- Status Flags
statusOutputFull :: Word8
statusOutputFull = 0x01

statusInputFull :: Word8
statusInputFull = 0x02

-- Debug logging using klog
debugLogPS2 :: String -> IO ()
debugLogPS2 msg = bracket (mallocBytes (length msg + 1)) free $ \p -> do
  let go _ [] = return ()
      go q (x:xs) = poke q (fromIntegral (ord x) :: Word8) >> go (q `plusPtr` 1) xs
  go p msg
  poke (p `plusPtr` length msg) (0 :: Word8)
  klog (castPtr p)

-- Utils
ioWait :: IO ()
ioWait = outb 0x80 0

ps2WaitInputClear :: IO ()
ps2WaitInputClear = do
  status <- inb ps2StatusPort
  unless ((status .&. statusInputFull) == 0) $ do
    ioWait
    ps2WaitInputClear

ps2WaitOutputFull :: IO Bool
ps2WaitOutputFull = go 1000 -- Reduced timeout for debugging
  where
    go :: Int -> IO Bool
    go 0 = return False
    go n = do
      status <- inb ps2StatusPort
      if (status .&. statusOutputFull) /= 0
        then return True
        else ioWait >> go (n - 1)

ps2WriteCommand :: Word8 -> IO ()
ps2WriteCommand cmd = do
  ps2WaitInputClear
  outb ps2StatusPort cmd

ps2WriteData :: Word8 -> IO ()
ps2WriteData val = do
  ps2WaitInputClear
  outb ps2DataPort val

ps2ReadData :: IO Word8
ps2ReadData = do
  ready <- ps2WaitOutputFull
  if ready
        then inb ps2DataPort
        else return 0

ps2ReadDataBlocking :: IO Word8
ps2ReadDataBlocking = do
  ready <- ps2WaitOutputFull
  if ready
    then inb ps2DataPort
    else ioWait >> ps2ReadDataBlocking

-- Initialization
initPS2 :: IO ()
initPS2 = do
  debugLogPS2 "PS/2: Initializing..."
  -- Disable devices
  ps2WriteCommand 0xAD
  ps2WriteCommand 0xA7
  debugLogPS2 "PS/2: Devices disabled"

  -- Flush
  flushBuffer
  debugLogPS2 "PS/2: Buffer flushed"

  -- Config
  ps2WriteCommand 0x20
  config <- ps2ReadData
  debugLogPS2 ("PS/2: Config read: " ++ showHex config "")
  let config' = (config .&. complement (0x10 .|. 0x20)) .|. 0x03 -- Clear clock disable, enable IRQs (even if we poll)
  debugLogPS2 ("PS/2: Writing config: " ++ showHex config' "")
  ps2WriteCommand 0x60
  ps2WriteData config'

  -- Enable
  ps2WriteCommand 0xAE
  ps2WriteCommand 0xA8
  debugLogPS2 "PS/2: Devices enabled"

  -- Reset Keyboard
  debugLogPS2 "PS/2: Resetting keyboard..."
  ps2WriteData 0xFF
  res <- ps2ReadData -- ACK
  debugLogPS2 ("PS/2: Keyboard reset res: " ++ showHex res "")

  return ()

  where
    flushBuffer = do
      status <- inb ps2StatusPort
      when ((status .&. statusOutputFull) /= 0) $ do
        _ <- inb ps2DataPort
        flushBuffer

-- Scancode Map (Set 1 to ASCII)
-- Simplified for now
scancodeToASCII :: Word8 -> Char
scancodeToASCII 0x1C = '\n'
scancodeToASCII 0x39 = ' '
scancodeToASCII 0x0E = '\b'
scancodeToASCII 0x0F = '\t'
-- QWERTY Row 1
scancodeToASCII 0x10 = 'q'
scancodeToASCII 0x11 = 'w'
scancodeToASCII 0x12 = 'e'
scancodeToASCII 0x13 = 'r'
scancodeToASCII 0x14 = 't'
scancodeToASCII 0x15 = 'y'
scancodeToASCII 0x16 = 'u'
scancodeToASCII 0x17 = 'i'
scancodeToASCII 0x18 = 'o'
scancodeToASCII 0x19 = 'p'
scancodeToASCII 0x1A = '['
scancodeToASCII 0x1B = ']'
-- Row 2
scancodeToASCII 0x1E = 'a'
scancodeToASCII 0x1F = 's'
scancodeToASCII 0x20 = 'd'
scancodeToASCII 0x21 = 'f'
scancodeToASCII 0x22 = 'g'
scancodeToASCII 0x23 = 'h'
scancodeToASCII 0x24 = 'j'
scancodeToASCII 0x25 = 'k'
scancodeToASCII 0x26 = 'l'
scancodeToASCII 0x27 = ';'
scancodeToASCII 0x28 = '\''
-- Row 3
scancodeToASCII 0x2C = 'z'
scancodeToASCII 0x2D = 'x'
scancodeToASCII 0x2E = 'c'
scancodeToASCII 0x2F = 'v'
scancodeToASCII 0x30 = 'b'
scancodeToASCII 0x31 = 'n'
scancodeToASCII 0x32 = 'm'
scancodeToASCII 0x33 = ','
scancodeToASCII 0x34 = '.'
scancodeToASCII 0x35 = '/'
-- Numbers
scancodeToASCII 0x02 = '1'
scancodeToASCII 0x03 = '2'
scancodeToASCII 0x04 = '3'
scancodeToASCII 0x05 = '4'
scancodeToASCII 0x06 = '5'
scancodeToASCII 0x07 = '6'
scancodeToASCII 0x08 = '7'
scancodeToASCII 0x09 = '8'
scancodeToASCII 0x0A = '9'
scancodeToASCII 0x0B = '0'
scancodeToASCII _ = '\0'

-- State for release codes
lastScancode :: IORef Word8
{-# NOINLINE lastScancode #-}
lastScancode = unsafePerformIO (newIORef 0)

getCharPS2 :: IO Char
getCharPS2 = do
  code <- ps2ReadDataBlocking
  prev <- readIORef lastScancode
  writeIORef lastScancode code

  if code == 0xF0
     then getCharPS2
     else if (code .&. 0x80) /= 0
             then getCharPS2
             else if prev == 0xE0
                     then getCharPS2
                     else do
                       let c = scancodeToASCII code
                       if c == '\0'
                          then getCharPS2
                          else return c
