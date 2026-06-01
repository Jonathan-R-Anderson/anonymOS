module Hos.User.IO where

import Data.Word
import Foreign.C.Types
import Foreign.Ptr

foreign import ccall "outb" outb :: Word16 -> Word8 -> IO ()
foreign import ccall "inb" inb :: Word16 -> IO Word8

foreign import ccall "hosIn8" hosIn8 :: Word16 -> IO Word8
foreign import ccall "hosIn16" hosIn16 :: Word16 -> IO Word16
foreign import ccall "hosIn32" hosIn32 :: Word16 -> IO Word32

foreign import ccall "hosOut8" hosOut8 :: Word16 -> Word8 -> IO ()
foreign import ccall "hosOut16" hosOut16 :: Word16 -> Word16 -> IO ()
foreign import ccall "hosOut32" hosOut32 :: Word16 -> Word32 -> IO ()

foreign import ccall "klog" klog :: Ptr Char -> IO ()
