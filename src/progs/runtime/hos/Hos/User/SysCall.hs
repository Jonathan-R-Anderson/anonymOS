{-# LANGUAGE ForeignFunctionInterface #-}
module Hos.User.SysCall where

import Control.Exception
import Control.Applicative

import Data.Word
import Data.Char
import Data.Bits

import Foreign.Marshal.Alloc (alloca, allocaBytes)
import Foreign.Ptr
import Foreign.Storable

import Hos.Common.Types

foreign import ccall "syscall.h syscall" syscall :: Word64 -> Word64 -> Word64 -> Word64 -> Word64 -> Word64 -> IO Word64
foreign import ccall "hos.h ptr_to_word" ptrToWord :: Ptr a -> Word64
foreign import ccall "hos.h word_to_ptr" wordToPtr :: Word64 -> Ptr a
foreign import ccall "hos.h hos_reset_malloc_after_fork" hosResetMallocAfterFork :: IO ()
foreign import ccall "hos.h hos_fork_enter_address_space" hosForkEnterAddressSpaceRaw :: Word64 -> Word64 -> IO Word64
foreign import ccall "hos.h hos_fork_enter_linux_address_space" hosForkEnterLinuxAddressSpaceRaw :: Word64 -> Word64 -> Ptr LinuxStartInfo -> IO Word64
foreign import ccall "hos.h hos_wait_on_channels_raw" hosWaitOnChannelsRaw :: Word64 -> Word64 -> IO Word64
foreign import ccall "hos.h hos_wait_on_channels_task" hosWaitOnChannelsTask :: IO Word32

writeCString :: String -> (Ptr Char -> Int -> IO a) -> IO a
writeCString string f =
    allocaBytes allocLength $ \p ->
      wrstr (castPtr p) string >> f p sLength
    where wrstr p "" = return ()
          wrstr p (x:xs) = poke p (fromIntegral (ord x) :: Word8) >> wrstr (p `plusPtr` 1) xs

          sLength = length string
          allocLength = max 1 sLength

readCStringN :: Ptr Char -> Int -> IO String
readCStringN p n = go (castPtr p) n ""
    where go _ 0 a = return a
          go p n a = do c <- peek (p :: Ptr Word8)
                        if c == 0 then return a else go (p `plusPtr` 1) (n - 1) (a  ++ [chr (fromIntegral c)])

hosRequestIO :: IO Word64
hosRequestIO = syscall 0x300 0 0 0 0 0

hosDebugLog :: String -> IO ()
hosDebugLog x = writeCString x $ \xp len -> syscall 0 (ptrToWord xp) (fromIntegral len) 0 0 0 >> return ()

hosVGAPut :: String -> IO ()
hosVGAPut x = writeCString x $ \xp len -> syscall 1 (ptrToWord xp) (fromIntegral len) 0 0 0 >> return ()

hosPhysAddrFor :: Word64 -> IO Word64
hosPhysAddrFor x = alloca $ \wP -> syscall 8 x (ptrToWord wP) 0 0 0 >> peek wP

hosFork :: IO Int
hosFork = syscall 0x402 0 0 0 0 0 >>= return . fromIntegral

hosYield :: IO ()
hosYield = do x <- syscall 0x403 0 0 0 0 0
              x `seq` return ()

hosModuleCount :: IO Word8
hosModuleCount = do x <- syscall 0xff00 0 0 0 0 0
                    return (fromIntegral x)

-- * Task management

hosCurrentTask :: IO TaskId
hosCurrentTask = TaskId . fromIntegral <$> syscall 0x401 0 0 0 0 0

data TaskPersonality = PersonalityHanonymOS
                     | PersonalityLinux
                       deriving (Show, Eq, Ord)

data ForkResult = ForkChild
                | ForkParent TaskId
                  deriving (Show, Eq, Ord)

hosSetTaskPersonality :: TaskId -> TaskPersonality -> IO ()
hosSetTaskPersonality (TaskId tId) personality =
    let p = case personality of
              PersonalityHanonymOS -> 0
              PersonalityLinux -> 1
    in syscall 0x404 (fromIntegral tId) p 0 0 0 >> return ()

-- Some current kernel fork paths resume the child with the child's TaskId in
-- RAX instead of 0. Treat that specific case as a child return so userland can
-- continue bootstrapping while the kernel bug is still being worked through.
hosForkNormalized :: IO ForkResult
hosForkNormalized = do
    raw <- hosFork
    if raw == 0
       then do
           hosResetMallocAfterFork
           return ForkChild
       else do
           self <- hosCurrentTask
           case self of
             TaskId selfId
               | raw == fromIntegral selfId -> do
                   hosResetMallocAfterFork
                   return ForkChild
             _ -> return (ForkParent (TaskId (fromIntegral raw)))

-- * Memory management

hosCurrentAddressSpace :: TaskId -> IO AddressSpaceRef
hosCurrentAddressSpace (TaskId tId) = AddressSpaceRef . fromIntegral <$> syscall 0x00a (fromIntegral tId) 0 0 0 0

hosEmptyAddressSpace :: IO AddressSpaceRef
hosEmptyAddressSpace = AddressSpaceRef . fromIntegral <$> syscall 0x006 0 0 0 0 0

hosEnterAddressSpace :: AddressSpaceRef -> Word64 -> IO ()
hosEnterAddressSpace (AddressSpaceRef aRef) entry = syscall 0x007 (fromIntegral aRef) entry 0 0 0 >> return ()

data LinuxStartInfo = LinuxStartInfo
                    { lsiMainEntry :: Word64
                    , lsiMainPhdr  :: Word64
                    , lsiMainPhent :: Word64
                    , lsiMainPhnum :: Word64
                    , lsiBase      :: Word64
                    , lsiExecBase  :: Word64  -- PIE load base (0 for ET_EXEC)
                    , lsiExecFn    :: Word64  -- Virtual address of exec filename
                    } deriving (Show, Eq, Ord)

instance Storable LinuxStartInfo where
    sizeOf _ = 56
    alignment _ = 8
    poke p (LinuxStartInfo a b c d e f g) = do
      pokeElemOff (castPtr p :: Ptr Word64) 0 a
      pokeElemOff (castPtr p :: Ptr Word64) 1 b
      pokeElemOff (castPtr p :: Ptr Word64) 2 c
      pokeElemOff (castPtr p :: Ptr Word64) 3 d
      pokeElemOff (castPtr p :: Ptr Word64) 4 e
      pokeElemOff (castPtr p :: Ptr Word64) 5 f
      pokeElemOff (castPtr p :: Ptr Word64) 6 g
    peek p = do
      a <- peekElemOff (castPtr p :: Ptr Word64) 0
      b <- peekElemOff (castPtr p :: Ptr Word64) 1
      c <- peekElemOff (castPtr p :: Ptr Word64) 2
      d <- peekElemOff (castPtr p :: Ptr Word64) 3
      e <- peekElemOff (castPtr p :: Ptr Word64) 4
      f <- peekElemOff (castPtr p :: Ptr Word64) 5
      g <- peekElemOff (castPtr p :: Ptr Word64) 6
      return (LinuxStartInfo a b c d e f g)

hosEnterLinuxAddressSpace :: AddressSpaceRef -> Word64 -> LinuxStartInfo -> IO ()
hosEnterLinuxAddressSpace (AddressSpaceRef aRef) interpEntry info =
    alloca $ \infoP ->
      do poke infoP info
         syscall 0x009 (fromIntegral aRef) interpEntry (ptrToWord infoP) 0 0
         return ()

hosForkEnterAddressSpace :: AddressSpaceRef -> Word64 -> IO TaskId
hosForkEnterAddressSpace (AddressSpaceRef aRef) entry =
    TaskId . fromIntegral <$> hosForkEnterAddressSpaceRaw (fromIntegral aRef) entry

hosForkEnterLinuxAddressSpace :: AddressSpaceRef -> Word64 -> LinuxStartInfo -> IO TaskId
hosForkEnterLinuxAddressSpace (AddressSpaceRef aRef) interpEntry info =
    alloca $ \infoP -> do
        poke infoP info
        TaskId . fromIntegral <$> hosForkEnterLinuxAddressSpaceRaw (fromIntegral aRef) interpEntry infoP

hosAddMapping :: AddressSpaceRef -> Word64 -> Word64 -> Mapping -> IO Word64
hosAddMapping (AddressSpaceRef aRef) start end mapping =
    alloca $ \mappingP ->
        do poke mappingP mapping
           syscall 0x002 (fromIntegral aRef) start end (ptrToWord mappingP) 0

hosSwitchToAddressSpace :: TaskId -> AddressSpaceRef -> IO Word64
hosSwitchToAddressSpace (TaskId tId) (AddressSpaceRef aRef) =
    syscall 0x005 (fromIntegral tId) (fromIntegral aRef) 0 0 0

hosCloseAddressSpace :: AddressSpaceRef -> IO ()
hosCloseAddressSpace (AddressSpaceRef aRef) =
    syscall 0x004 (fromIntegral aRef) 0 0 0 0 >>
    return ()

hosAddMappingToCurTask :: Word64 -> Word64 -> Mapping -> IO Word64
hosAddMappingToCurTask begin end mapping = do
    let pageSz   = 0x1000
        pageMask = complement (pageSz - 1)

        alignDown x = x .&. pageMask
        alignUp x   = (x + pageSz - 1) .&. pageMask

        begin' = alignDown begin
        end'   = alignUp end

    hosAddMapping curAddressSpaceRef begin' end' mapping

data ModuleInfo = ModuleInfo String Word32 Word32
                  deriving Show

instance Storable ModuleInfo where
    sizeOf _ = 128
    alignment _ = 8

    peek p = do start <- peek (castPtr p :: Ptr Word32)
                end <- peek (castPtr p `plusPtr` 4:: Ptr Word32)
                name <- readCStringN (castPtr p `plusPtr` 8) 120
                return (ModuleInfo name start end)

hosGetModuleInfo :: Word8 -> IO ModuleInfo
hosGetModuleInfo i =
    allocaBytes 500 $ \p ->
        do x <- syscall 0xff01 (fromIntegral i) (ptrToWord p) 0 0 0
           x `seq` peek p

-- IPC
hosUnmaskChannel :: ChanId -> IO ()
hosUnmaskChannel (ChanId i) = syscall 0x104 (fromIntegral i) 0 0 0 0 >> return ()

data WaitOnChannelsError = WaitOnChannelsNoMessages
                         | WaitOnChannelsMessageTruncated
                           deriving Show

hosWaitOnChannels :: WaitOnChannelsFlags -> Word64 -> IO (Either WaitOnChannelsError (ChanId, TaskId))
hosWaitOnChannels (WaitOnChannelsFlags waitForever dontTruncate noMask) timeout =
     do status <- hosWaitOnChannelsRaw flags timeout
        if status .&. 0x100000000 /= 0
          then case (status :: Word64) .&. 0xffffffff of
                 0x10301 -> return (Left WaitOnChannelsNoMessages)
                 0x10300 -> return (Left WaitOnChannelsMessageTruncated)
                 _ -> fail "hosWaitOnChannels: Returned bizarre status"
          else do let chanId = ChanId (fromIntegral (status .&. 0xffffffff))
                  taskId <- TaskId <$> hosWaitOnChannelsTask
                  return (Right (chanId, taskId))
    where flags :: Word64
          flags = (if waitForever then bit 0 else 0) .|.
                  (if dontTruncate then bit 1 else 0) .|.
                  (if noMask then bit 2 else 0)

hosDeliverMessage :: ChanId -> TaskId -> ChanId -> IO Word8
hosDeliverMessage (ChanId srcChan) (TaskId dst) (ChanId dstChan) =
    fromIntegral <$> syscall 0x100 (fromIntegral srcChan) (fromIntegral dst) (fromIntegral dstChan) 0 0

hosReplyTo :: ChanId -> IO Word8
hosReplyTo (ChanId onChan) = fromIntegral <$> syscall 0x102 (fromIntegral onChan) 0 0 0 0

hosRouteMsg :: ChanId -> TaskId -> ChanId -> IO Word8
hosRouteMsg (ChanId srcChan) (TaskId dst) (ChanId dstChan) =
    fromIntegral <$> syscall 0x101 (fromIntegral srcChan) (fromIntegral dst) (fromIntegral dstChan) 0 0

-- Object capability namespace
hosRootObject :: IO ObjectId
hosRootObject =
    ObjectId <$> syscall 0x200 0 0 0 0 0

hosLookupObject :: ObjectId -> String -> IO ObjectId
hosLookupObject (ObjectId baseId) path =
    writeCString path $ \pathPtr pathLen ->
      ObjectId <$> syscall 0x201
                            baseId
                            (ptrToWord pathPtr)
                            (fromIntegral pathLen)
                            0
                            0

hosObjectType :: ObjectId -> IO ObjectType
hosObjectType (ObjectId objectId') =
    word64ToObjectType <$> syscall 0x202 objectId' 0 0 0 0

hosObjectChildCount :: ObjectId -> IO Word64
hosObjectChildCount (ObjectId objectId') =
    syscall 0x203 objectId' 0 0 0 0

hosObjectChildAt :: ObjectId -> Word64 -> IO ObjectId
hosObjectChildAt (ObjectId objectId') index =
    ObjectId <$> syscall 0x204 objectId' index 0 0 0

hosObjectNameN :: ObjectId -> Int -> IO String
hosObjectNameN (ObjectId objectId') maxLen =
    allocaBytes (max 1 maxLen) $ \namePtr -> do
      _ <- syscall 0x205 objectId' (ptrToWord namePtr) (fromIntegral maxLen) 0 0
      readCStringN namePtr maxLen

hosObjectName :: ObjectId -> IO String
hosObjectName objectId' = hosObjectNameN objectId' 128

hosInvokeObject :: ObjectId -> Word64 -> Word64 -> Word64 -> Word64 -> IO Word64
hosInvokeObject (ObjectId objectId') method arg1 arg2 arg3 =
    syscall 0x206 objectId' method arg1 arg2 arg3

hosReadBlockObject :: ObjectId -> Word64 -> Word64 -> Ptr Word8 -> IO Word64
hosReadBlockObject objectId' blockNumber blockCount outPtr =
    hosInvokeObject objectId' 30 blockNumber blockCount (ptrToWord outPtr)

hosWriteBlockObject :: ObjectId -> Word64 -> Word64 -> Ptr Word8 -> IO Word64
hosWriteBlockObject objectId' blockNumber blockCount inPtr =
    hosInvokeObject objectId' 31 blockNumber blockCount (ptrToWord inPtr)
