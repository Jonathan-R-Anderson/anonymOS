module Main where

import Hos.User.SysCall
import Hos.Common.Types

import Control.Monad

import Data.Bits
import Data.Char (chr)
import Data.Elf
import Data.List (isSuffixOf)
import Data.Word

import Foreign.Ptr
import Foreign.Marshal.Alloc (free, mallocBytes)
import Foreign.Storable

import Numeric (showHex)

import Hos.Storage hiding
    ( pageSize
    , scratchPageMapBase
    , zeroUserPage
    , copyUserBytes
    , materializePartialSegmentPage
    )

pageSize :: Word64
pageSize = 0x1000

bundleMapBase :: Word64
bundleMapBase = 0xC000000000

busyboxModuleMapBase :: Word64
busyboxModuleMapBase = 0xC000200000

scratchPageMapBase :: Word64
scratchPageMapBase = 0xC100000000

execNameBufferSize :: Int
execNameBufferSize = 512

data SimpleBundleEntry = SimpleBundleEntry
    { sbeName :: String
    , sbeOffset :: Word64
    , sbeSize :: Word64
    }
    deriving Show

main :: IO ()
main = do
    hosDebugLog "[storage] entered main"
    hosDebugLog "[storage] IPC disabled; launching busybox directly"

    hosDebugLog "[storage] before hosModuleCount"
    modCount <- hosModuleCount
    hosDebugLog ("[storage] module count = " ++ show modCount)

    if modCount < 1
       then hosDebugLog "[storage] [FATAL] no boot bundle found"
       else do
           launched <- loadBootBundle
           case launched of
             Just _ -> idleForever
             Nothing -> do
                 fallback <- launchBusyboxFromModule
                 case fallback of
                   Just _ -> idleForever
                   Nothing -> do
                       hosDebugLog "[storage] [FATAL] busybox not found"
                       idleForever

alignToPage :: Word64 -> Word64
alignToPage a = a .&. complement (pageSize - 1)

alignUpToPage :: Word64 -> Word64
alignUpToPage a = alignToPage (a + pageSize - 1)

segmentPerms :: Word32 -> MemoryPermissions
segmentPerms flags
    | flags .&. 0x2 /= 0 = UserSpace ReadWrite
    | otherwise          = UserSpace ReadOnly

zeroUserPage :: Word64 -> IO ()
zeroUserPage base = go 0
  where
    go i
        | i >= pageSize = return ()
        | otherwise = do
            poke (wordToPtr (base + i) :: Ptr Word8) (0 :: Word8)
            go (i + 1)

copyUserBytes :: Word64 -> Word64 -> Word64 -> IO ()
copyUserBytes dst src len = go 0
  where
    go i
        | i >= len = return ()
        | otherwise = do
            b <- peek (wordToPtr (src + i) :: Ptr Word8)
            poke (wordToPtr (dst + i) :: Ptr Word8) b
            go (i + 1)

materializePartialSegmentPage
    :: AddressSpaceRef
    -> Word64
    -> Word64
    -> Word64
    -> Word64
    -> Word64
    -> Word64
    -> MemoryPermissions
    -> IO ()
materializePartialSegmentPage aRef fileVirtBase offset pageOffset alignedVAddr partialPage copyLen perms = do
    let scratchPage = scratchPageMapBase + partialPage
        srcPage = fileVirtBase + offset - pageOffset + (partialPage - alignedVAddr)
    _ <- hosAddMappingToCurTask scratchPage (scratchPage + pageSize)
            (AllocateOnDemand (UserSpace ReadWrite))
    zeroUserPage scratchPage
    copyUserBytes scratchPage srcPage copyLen
    scratchPhys <- hosPhysAddrFor scratchPage
    hosDebugLog ("[storage] partial PT_LOAD page v=0x" ++ showHex partialPage
                 (" src=0x" ++ showHex srcPage
                 (" copy=0x" ++ showHex copyLen
                 (" phys=0x" ++ showHex scratchPhys ""))))
    _ <- hosAddMapping aRef partialPage (partialPage + pageSize)
            (CopyOnWrite perms scratchPhys)
    return ()

loadSegmentDirect :: AddressSpaceRef -> Word64 -> Word64 -> Word64 -> Elf64ProgHdr -> IO ()
loadSegmentDirect aRef fileVirtBase physFileBase loadBase progHdr = do
    let pageSz   = 0x1000
        pageMask = complement (pageSz - 1)

        alignDown x = x .&. pageMask
        alignUp x   = (x + pageSz - 1) .&. pageMask

        vAddr   = ph64VAddr progHdr + loadBase
        offset  = ph64Offset progHdr
        fileSz  = ph64FileSz progHdr
        memSz   = ph64MemSz progHdr
        perms   = segmentPerms (ph64Flags progHdr)

        alignedVAddr = alignDown vAddr
        pageOffset   = vAddr - alignedVAddr
        physOffset   = physFileBase + offset - pageOffset

        fileDataEnd = vAddr + fileSz
        memDataEnd  = vAddr + memSz
        fileEnd     = alignUp fileDataEnd
        memEnd      = alignUp memDataEnd
        bssStartsInFilePage =
            fileSz > 0 &&
            memSz > fileSz &&
            alignDown fileDataEnd < fileEnd
        directFileEnd =
            if bssStartsInFilePage
               then alignDown fileDataEnd
               else fileEnd
        bssStart =
            if bssStartsInFilePage
               then alignDown fileDataEnd + pageSz
               else fileEnd

    hosDebugLog ("[storage] PT_LOAD v=0x" ++ showHex vAddr
                 (" fileSz=0x" ++ showHex fileSz
                 (" memSz=0x" ++ showHex memSz
                 (" directEnd=0x" ++ showHex directFileEnd
                 (" memEnd=0x" ++ showHex memEnd "")))))

    if directFileEnd > alignedVAddr
       then do
           _ <- hosAddMapping aRef alignedVAddr directFileEnd
                   (CopyOnWrite perms physOffset)
           return ()
       else
           return ()

    if bssStartsInFilePage
       then materializePartialSegmentPage
              aRef
              fileVirtBase
              offset
              pageOffset
              alignedVAddr
              (alignDown fileDataEnd)
              (fileDataEnd - alignDown fileDataEnd)
              perms
       else return ()

    if memEnd > bssStart
       then do
           _ <- hosAddMapping aRef bssStart memEnd
                   (AllocateOnDemand perms)
           return ()
       else
           return ()

idleForever :: IO ()
idleForever = do
    hosDebugLog "[storage] idle"
    forever hosYield

readFixedString :: Ptr Word8 -> Word64 -> IO String
readFixedString p len = go 0 ""
  where
    go i acc
        | i >= len = return acc
        | otherwise = do
            c <- peek (p `plusPtr` fromIntegral i)
            go (i + 1) (acc ++ [chr (fromIntegral c)])

readWord64At :: Ptr Word8 -> Word64 -> IO Word64
readWord64At p offset =
    peek (castPtr (p `plusPtr` fromIntegral offset) :: Ptr Word64)

parseSimpleBundle :: Ptr () -> Word64 -> IO [SimpleBundleEntry]
parseSimpleBundle p bundleSize = do
    let base = castPtr p :: Ptr Word8
    magic <- readFixedString base 8
    if magic /= "HOSBNDL1"
       then do
           hosDebugLog "[storage] unsupported bundle format"
           return []
       else do
           count <- readWord64At base 8
           readEntries base bundleSize count 16 []

readEntries :: Ptr Word8 -> Word64 -> Word64 -> Word64 -> [SimpleBundleEntry] -> IO [SimpleBundleEntry]
readEntries _ _ 0 _ entries = return (reverse entries)
readEntries base bundleSize remaining cursor entries =
    if cursor + 8 > bundleSize
       then do
           hosDebugLog "[storage] truncated bundle directory"
           return (reverse entries)
       else do
           nameLen <- readWord64At base cursor
           let nameStart = cursor + 8
               offsetStart = nameStart + nameLen
               sizeStart = offsetStart + 8
               nextCursor = sizeStart + 8
           if nextCursor > bundleSize
              then do
                  hosDebugLog "[storage] truncated bundle entry"
                  return (reverse entries)
              else do
                  name <- readFixedString (base `plusPtr` fromIntegral nameStart) nameLen
                  offset <- readWord64At base offsetStart
                  size <- readWord64At base sizeStart
                  let entry = SimpleBundleEntry name offset size
                  readEntries base bundleSize (remaining - 1) nextCursor (entry:entries)

isBusyboxName :: String -> Bool
isBusyboxName name = name == "busybox" || "/busybox" `isSuffixOf` name

findBusyboxEntry :: [SimpleBundleEntry] -> Maybe SimpleBundleEntry
findBusyboxEntry [] = Nothing
findBusyboxEntry (entry:entries)
    | isBusyboxName (sbeName entry) = Just entry
    | otherwise = findBusyboxEntry entries

findEntryByName :: String -> [SimpleBundleEntry] -> Maybe SimpleBundleEntry
findEntryByName _ [] = Nothing
findEntryByName needle (entry:entries)
    | sbeName entry == needle = Just entry
    | "/" ++ sbeName entry == needle = Just entry
    | otherwise = findEntryByName needle entries

simpleInterpLocator :: [SimpleBundleEntry] -> Word64 -> Word64 -> String -> Maybe (Ptr Elf64Hdr, Word64, Word64)
simpleInterpLocator entries modOffsetPtr physModOffsetPtr path =
    case findEntryByName path entries of
      Just entry ->
          let offset = sbeOffset entry
              size = sbeSize entry
          in Just (wordToPtr (modOffsetPtr + offset), physModOffsetPtr + offset, size)
      Nothing -> Nothing

loadBootBundle :: IO (Maybe TaskId)
loadBootBundle = do
    ModuleInfo _ start end <- hosGetModuleInfo 0
    hosDebugLog ("[storage] found bundle at " ++ show start ++ " - " ++ show end)
    let vBase = bundleMapBase
        bundleSize = fromIntegral (end - start)
        vEnd = bundleSize + vBase
        physBase = fromIntegral start
    _ <- hosAddMappingToCurTask vBase vEnd (FromPhysical RetainInParent (UserSpace ReadOnly) physBase)
    hosDebugLog "[storage] mapped boot bundle. Going to read..."

    entries <- parseSimpleBundle (wordToPtr vBase) bundleSize
    case findBusyboxEntry entries of
      Just entry -> do
          let offset = sbeOffset entry
              size = sbeSize entry
          if offset + size > bundleSize
             then do
                 hosDebugLog "[storage] busybox bundle range is invalid"
                 return Nothing
             else do
                 hosDebugLog "[storage] found busybox"
                 childId <- launchLinuxElf "busybox"
                                           (wordToPtr (vBase + offset))
                                           (physBase + offset)
                                           size
                                           (simpleInterpLocator entries vBase physBase)
                 return (Just childId)
      Nothing -> do
          hosDebugLog "[storage] busybox not present in hos.bundle"
          return Nothing

findModuleBySuffix :: String -> IO (Maybe ModuleInfo)
findModuleBySuffix suffix = do
    modCount <- hosModuleCount
    let go i
            | i >= fromIntegral modCount = return Nothing
            | otherwise = do
                modInfo@(ModuleInfo name _ _) <- hosGetModuleInfo (fromIntegral i)
                if suffix `isSuffixOf` name
                   then return (Just modInfo)
                   else go (i + 1)
    go (0 :: Int)

launchBusyboxFromModule :: IO (Maybe TaskId)
launchBusyboxFromModule = do
    modInfo <- findModuleBySuffix "/busybox"
    case modInfo of
      Nothing -> return Nothing
      Just (ModuleInfo _ start end) -> do
          let vBase = busyboxModuleMapBase
              size = fromIntegral (end - start)
              vEnd = vBase + size
              physBase = fromIntegral start
          _ <- hosAddMappingToCurTask vBase vEnd (FromPhysical RetainInParent (UserSpace ReadOnly) physBase)
          hosDebugLog "[storage] found busybox"
          childId <- launchLinuxElf "busybox"
                                    (wordToPtr vBase)
                                    physBase
                                    size
                                    (const Nothing)
          return (Just childId)

elfEntryPoint :: Ptr Elf64Hdr -> IO Word64
elfEntryPoint vStart = do
    (elfHdr, _) <- elf64ProgHdrs vStart
    let mainLoadBase = if e64Type elfHdr == EtDyn then 0x400000 else 0 :: Word64
    return (mainLoadBase + e64Entry elfHdr)

launchLinuxElf :: String
               -> Ptr Elf64Hdr
               -> Word64
               -> Word64
               -> (String -> Maybe (Ptr Elf64Hdr, Word64, Word64))
               -> IO TaskId
launchLinuxElf name vStart physStart physSize resolveInterp = do
    entry <- elfEntryPoint vStart
    hosDebugLog "[storage] launching busybox"
    hosDebugLog ("[storage] busybox entry=0x" ++ showHex entry "")
    loadLinuxElf name vStart physStart physSize resolveInterp

loadLinuxElf :: String
             -> Ptr Elf64Hdr
             -> Word64
             -> Word64
             -> (String -> Maybe (Ptr Elf64Hdr, Word64, Word64))
             -> IO TaskId
loadLinuxElf name vStart physStart _physSize resolveInterp = do
    (elfHdr, progHdrs) <- elf64ProgHdrs vStart
    interp <- elf64Interp vStart
    withExecNameBuffer name $ \namePtr -> do
        aRef <- hosEmptyAddressSpace
        let elfIsDyn = e64Type elfHdr == EtDyn
            mainLoadBase = if elfIsDyn then 0x400000 else 0 :: Word64
            fileVirtBase = ptrToWord (castPtr vStart)
        forM_ progHdrs $ \progHdr ->
            case ph64Type progHdr of
              PtLoad -> loadSegmentDirect aRef fileVirtBase (fromIntegral physStart) mainLoadBase progHdr
              _ -> return ()
        (entryPoint, startInfo) <- loadInterpAndGetInfo aRef interp resolveInterp namePtr mainLoadBase elfHdr progHdrs
        let linuxInfo =
                case startInfo of
                  Just info -> info
                  Nothing ->
                      LinuxStartInfo
                      { lsiMainEntry = mainLoadBase + e64Entry elfHdr
                      , lsiMainPhdr = findMainPhdrAddr mainLoadBase elfHdr progHdrs
                      , lsiMainPhent = fromIntegral (e64PhEntSize elfHdr)
                      , lsiMainPhnum = fromIntegral (e64PhNum elfHdr)
                      , lsiBase = 0
                      , lsiExecBase = mainLoadBase
                      --, lsiExecFn = ptrToWord (castPtr namePtr)
                      , lsiExecFn = 0
                      }
        childId <- hosForkEnterLinuxAddressSpace aRef entryPoint linuxInfo
        hosCloseAddressSpace aRef
        return childId

withExecNameBuffer :: String -> (Ptr Word8 -> IO a) -> IO a
withExecNameBuffer name f = do
    namePtr <- mallocBytes execNameBufferSize
    zeroBuffer namePtr execNameBufferSize
    pokeString namePtr name
    result <- f namePtr
    free namePtr
    return result

zeroBuffer :: Ptr Word8 -> Int -> IO ()
zeroBuffer _ 0 = return ()
zeroBuffer p n = do
    poke p (0 :: Word8)
    zeroBuffer (p `plusPtr` 1) (n - 1)
