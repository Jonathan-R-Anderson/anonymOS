module Hos.Storage where

import Control.Monad

import Data.Word
import Data.Bits
import Data.Elf

import Hos.User.SysCall
import Hos.Common.Types

import Foreign.Ptr
import Foreign.Storable

import Control.Exception (bracket)
import Data.Char (ord)
import Foreign.Marshal.Alloc (mallocBytes, free)
import Numeric (showHex)

withCString :: String -> (Ptr Word8 -> IO a) -> IO a
withCString str f =
    bracket (mallocBytes (length str + 1)) free $ \p -> do
        pokeString p str
        f p

pokeString :: Ptr Word8 -> String -> IO ()
pokeString p "" = poke p 0
pokeString p (c:cs) =
    poke p (fromIntegral (ord c)) >> pokeString (p `plusPtr` 1) cs

interpBase :: Word64
interpBase = 0x5000000000

scratchPageMapBase :: Word64
scratchPageMapBase = 0xC100000000

pageSize :: Word64
pageSize = 0x1000

-- | Derive MemoryPermissions from ELF segment flags (PF_R=1, PF_W=2, PF_X=4)
elfFlagsToPerms :: Word32 -> MemoryPermissions
elfFlagsToPerms flags
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
    hosDebugLog ("[storage-lib] partial PT_LOAD page v=0x" ++ showHex partialPage
                 (" src=0x" ++ showHex srcPage
                 (" copy=0x" ++ showHex copyLen
                 (" phys=0x" ++ showHex scratchPhys ""))))
    _ <- hosAddMapping aRef partialPage (partialPage + pageSize)
            (CopyOnWrite perms scratchPhys)
    return ()

-- | Load a single PT_LOAD segment with proper alignment and BSS handling
loadSegment :: AddressSpaceRef -> Word64 -> Word64 -> Word64 -> Elf64ProgHdr -> IO ()
loadSegment aRef fileVirtBase physFileBase loadBase progHdr = do
    let pageSz   = 0x1000
        pageMask = complement (pageSz - 1)

        alignDown x = x .&. pageMask
        alignUp x   = (x + pageSz - 1) .&. pageMask

        vAddr   = ph64VAddr progHdr + loadBase
        offset  = ph64Offset progHdr
        fileSz  = ph64FileSz progHdr
        memSz   = ph64MemSz progHdr
        perms   = elfFlagsToPerms (ph64Flags progHdr)

        alignedVAddr = alignDown vAddr
        pageOffset   = vAddr - alignedVAddr

        -- Keep the subtraction after adding the segment offset to avoid underflow.
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

    -- File-backed mapping
    when (directFileEnd > alignedVAddr) $ do
        _ <- hosAddMapping aRef alignedVAddr directFileEnd
                (CopyOnWrite perms physOffset)
        return ()

    when bssStartsInFilePage $
        materializePartialSegmentPage
            aRef
            fileVirtBase
            offset
            pageOffset
            alignedVAddr
            (alignDown fileDataEnd)
            (fileDataEnd - alignDown fileDataEnd)
            perms

    -- BSS / zero-fill mapping
    when (memEnd > bssStart) $ do
        _ <- hosAddMapping aRef bssStart memEnd
                (AllocateOnDemand perms)
        return ()

findMainPhdrAddr :: Word64 -> Elf64Hdr -> [Elf64ProgHdr] -> Word64
findMainPhdrAddr loadBase elfHdr progHdrs =
    case [ ph64VAddr p + loadBase | p <- progHdrs, ph64Type p == PtPhdr ] of
        (x:_) -> x
        [] ->
            case [ p | p <- progHdrs, ph64Type p == PtLoad ] of
                (p:_) -> ph64VAddr p + loadBase + (e64PhOff elfHdr - ph64Offset p)
                []    -> 0

loadElf name vStart physStart _physSize resolveInterp = do
    (elfHdr, progHdrs) <- elf64ProgHdrs vStart

    interp <- elf64Interp vStart

    namePtr <- case interp of
        Just _ -> do
            p <- mallocBytes (length name + 1)
            pokeString p name
            return p
        Nothing -> return nullPtr

    aRef <- hosEmptyAddressSpace

    let elfIsDyn = e64Type elfHdr == EtDyn
        mainLoadBase = if elfIsDyn then 0x400000 else 0
        fileVirtBase = ptrToWord (castPtr vStart)

    forM_ progHdrs $ \progHdr ->
        case ph64Type progHdr of
            PtLoad -> loadSegment aRef fileVirtBase (fromIntegral physStart) mainLoadBase progHdr
            _      -> return ()

    (entryPoint, startInfo) <-
        loadInterpAndGetInfo aRef interp resolveInterp namePtr mainLoadBase elfHdr progHdrs

    childId <- case startInfo of
        Just info -> hosForkEnterLinuxAddressSpace aRef entryPoint info
        Nothing   -> hosForkEnterAddressSpace aRef entryPoint

    hosCloseAddressSpace aRef
    return childId

loadInterpAndGetInfo
    :: AddressSpaceRef
    -> Maybe String
    -> (String -> Maybe (Ptr Elf64Hdr, Word64, Word64))
    -> Ptr Word8
    -> Word64
    -> Elf64Hdr
    -> [Elf64ProgHdr]
    -> IO (Word64, Maybe LinuxStartInfo)

loadInterpAndGetInfo aRef interp resolveInterp namePtr mainLoadBase elfHdr progHdrs =
    case interp of
        Just interpPath ->
            case resolveInterp interpPath of
                Just (interpVStart, interpPhysStart, _) -> do
                    (interpHdr, interpProgHdrs) <- elf64ProgHdrs interpVStart
                    let interpVirtBase = ptrToWord (castPtr interpVStart)

                    forM_ interpProgHdrs $ \progHdr ->
                        case ph64Type progHdr of
                            PtLoad -> loadSegment aRef interpVirtBase (fromIntegral interpPhysStart) interpBase progHdr
                            _      -> return ()

                    let info = LinuxStartInfo
                            { lsiMainEntry = mainLoadBase + e64Entry elfHdr
                            , lsiMainPhdr  = findMainPhdrAddr mainLoadBase elfHdr progHdrs
                            , lsiMainPhent = fromIntegral (e64PhEntSize elfHdr)
                            , lsiMainPhnum = fromIntegral (e64PhNum elfHdr)
                            , lsiBase      = interpBase
                            , lsiExecBase  = mainLoadBase
                            , lsiExecFn    = ptrToWord (castPtr namePtr)
                            }

                    return (interpBase + e64Entry interpHdr, Just info)

                Nothing ->
                    return (mainLoadBase + e64Entry elfHdr, Nothing)

        Nothing ->
            return (mainLoadBase + e64Entry elfHdr, Nothing)
