{-# LANGUAGE ForeignFunctionInterface #-}
module Main where

import Hos.User.SysCall
import Hos.User.IPC
import Hos.Init.Msg
import Hos.Common.Types

import Control.Monad

import Data.Binary
import Data.Bits
import Data.Char (ord)
import Data.Elf
import Data.List (isSuffixOf)
import Data.Monoid
import Data.Word
import qualified Data.Map as M

import Foreign.Marshal.Alloc (mallocBytes, free)
import Foreign.Ptr
import Foreign.Storable
import Numeric (showHex)
import Hos.User.Driver.PS2
import Hos.User.SysCall (hosCurrentAddressSpace)
foreign import ccall "hos.h hos_wait_on_channels_raw" hosWaitOnChannelsRawInit :: Word64 -> Word64 -> IO Word64
foreign import ccall "hos.h hos_wait_on_channels_task" hosWaitOnChannelsTaskInit :: IO Word32
foreign import ccall "hos.h hos_yield_many" hosYieldMany :: Word64 -> IO ()

storageModuleIndex :: Word8
storageModuleIndex = 1

storageModuleMapBase :: Word64
storageModuleMapBase = 0xC000000000

desktopBootModulePaths :: [String]
desktopBootModulePaths =
    [ "/sbin/mutter"
    , "/sbin/gnome-shell"
    , "/sbin/gdm"
    , "/sbin/desktop-stage"
    ]

desktopBootModuleMapBase :: Word64
desktopBootModuleMapBase = 0xC000200000

-- Child user stack.
-- This does not pass RSP directly; it makes sure the common/default
-- userspace stack region exists in the child address space.
userStackTop :: Word64
userStackTop = 0x00007fffffffe000

userStackSize :: Word64
userStackSize = 0x0000000000020000

userStackBottom :: Word64
userStackBottom = userStackTop - userStackSize

mapUserStack :: AddressSpaceRef -> IO ()
mapUserStack aRef = do
    hosDebugLog "[init] mapping child user stack"

    let bottom = userStackBottom
        top    = userStackTop

    -- Ensure page alignment (important)
    let pageSz = 0x1000
        alignDown x = x .&. complement (pageSz - 1)
        alignUp x   = (x + pageSz - 1) .&. complement (pageSz - 1)

        bottom' = alignDown bottom
        top'    = alignUp top

    _ <- hosAddMapping aRef bottom' top'
            (AllocateOnDemand (UserSpace ReadWrite))

    hosDebugLog ("[init] stack mapped: " ++ showHex bottom' "" ++ " - " ++ showHex top' "")

    return ()

joinWith :: String -> [String] -> String
joinWith _ [] = ""
joinWith _ [x] = x
joinWith sep (x:xs) = x ++ sep ++ joinWith sep xs

logCapabilityNamespace :: IO ()
logCapabilityNamespace = do
    rootObj <- hosRootObject
    diskObj <- hosLookupObject rootObj "Hardware/Disk/Disk0"
    diskName <- hosObjectName diskObj
    diskType <- hosObjectType diskObj
    hosDebugLog ("[init] object root = " ++ show rootObj)
    hosDebugLog ("[init] disk object = " ++ show diskObj ++
                 " name=" ++ diskName ++
                 " type=" ++ show diskType)

main :: IO ()
main = do
    hosDebugLog "[init] started"
    hosDebugLog "[init] boot target: init + storage only"
    logCapabilityNamespace
    prepareInitInbox
    launchStorageFromBootModule

data InitState = InitState
               { initServers :: M.Map String TaskId }

initialInitState :: InitState
initialInitState = InitState M.empty

interpBase :: Word64
interpBase = 0x5000000000

scratchPageMapBase :: Word64
scratchPageMapBase = 0xC100000000

pageSize :: Word64
pageSize = 0x1000

parentLoop :: InitState -> IO ()
parentLoop initState = do
    initState' <- doParent initState
    parentLoop initState'

waitOnChannelsNoHeap :: WaitOnChannelsFlags -> Word64 -> IO (Either WaitOnChannelsError (ChanId, TaskId))
waitOnChannelsNoHeap (WaitOnChannelsFlags waitForever dontTruncate noMask) timeout =
    do status <- hosWaitOnChannelsRawInit flags timeout
       if status .&. 0x100000000 /= 0
          then case status .&. 0xffffffff of
                 0x10301 -> return (Left WaitOnChannelsNoMessages)
                 0x10300 -> return (Left WaitOnChannelsMessageTruncated)
                 _ -> fail "waitOnChannelsNoHeap: Returned bizarre status"
          else do let chanId = ChanId (fromIntegral (status .&. 0xffffffff))
                  rawTaskId <- hosWaitOnChannelsTaskInit
                  let taskId = TaskId rawTaskId
                  return (Right (chanId, taskId))
    where flags :: Word64
          flags = (if waitForever then bit 0 else 0) .|.
                  (if dontTruncate then bit 1 else 0) .|.
                  (if noMask then bit 2 else 0)

pokeString :: Ptr Word8 -> String -> IO ()
pokeString p "" = poke p 0
pokeString p (c:cs) = poke p (fromIntegral (ord c)) >> pokeString (p `plusPtr` 1) cs

elfFlagsToPerms :: Word32 -> MemoryPermissions
elfFlagsToPerms flags
    | flags .&. 0x2 /= 0 = UserSpace ReadWrite
    | otherwise = UserSpace ReadOnly

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
    hosDebugLog ("[init] partial PT_LOAD page v=0x" ++ showHex partialPage
                 (" src=0x" ++ showHex srcPage
                 (" copy=0x" ++ showHex copyLen
                 (" phys=0x" ++ showHex scratchPhys ""))))
    _ <- hosAddMapping aRef partialPage (partialPage + pageSize)
            (CopyOnWrite perms scratchPhys)
    return ()

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

    when (memEnd > bssStart) $ do
        _ <- hosAddMapping aRef bssStart memEnd
                (AllocateOnDemand perms)
        return ()
        
findMainPhdrAddr :: Word64 -> Elf64Hdr -> [Elf64ProgHdr] -> Word64
findMainPhdrAddr loadBase elfHdr progHdrs =
    case [ph64VAddr p + loadBase | p <- progHdrs, ph64Type p == PtPhdr] of
      (x:_) -> x
      [] ->
          case [p | p <- progHdrs, ph64Type p == PtLoad] of
            (p:_) -> ph64VAddr p + loadBase + (e64PhOff elfHdr - ph64Offset p)
            [] -> 0

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
    go 0

findFirstModuleBySuffix :: [String] -> IO (Maybe (String, ModuleInfo))
findFirstModuleBySuffix [] = return Nothing
findFirstModuleBySuffix (suffix:suffixes) = do
    modInfo <- findModuleBySuffix suffix
    case modInfo of
      Just info -> return (Just (suffix, info))
      Nothing -> findFirstModuleBySuffix suffixes

loadInterpAndGetInfo :: AddressSpaceRef
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
                let interpPhysBase = fromIntegral interpPhysStart
                    interpVirtBase = ptrToWord (castPtr interpVStart)
                (interpHdr, interpProgHdrs) <- elf64ProgHdrs interpVStart
                forM_ interpProgHdrs $ \progHdr ->
                    case ph64Type progHdr of
                      PtLoad -> loadSegment aRef interpVirtBase interpPhysBase interpBase progHdr
                      _ -> return ()
                let info = LinuxStartInfo
                           { lsiMainEntry = mainLoadBase + e64Entry elfHdr
                           , lsiMainPhdr = findMainPhdrAddr mainLoadBase elfHdr progHdrs
                           , lsiMainPhent = fromIntegral (e64PhEntSize elfHdr)
                           , lsiMainPhnum = fromIntegral (e64PhNum elfHdr)
                           , lsiBase = interpBase
                           , lsiExecBase = mainLoadBase
                           , lsiExecFn = ptrToWord (castPtr namePtr)
                           }
                return (interpBase + e64Entry interpHdr, Just info)
            Nothing ->
                return (mainLoadBase + e64Entry elfHdr, Nothing)
      Nothing ->
          return (mainLoadBase + e64Entry elfHdr, Nothing)

loadElf :: String
        -> Ptr Elf64Hdr
        -> Word64
        -> Word64
        -> (String -> Maybe (Ptr Elf64Hdr, Word64, Word64))
        -> IO TaskId
loadElf name vStart physStart _physSize resolveInterp = do
    hosDebugLog ("[init] loadElf: " ++ name)

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
        mainLoadBase = if elfIsDyn then 0x400000 else 0 :: Word64
        fileVirtBase = ptrToWord (castPtr vStart)

    forM_ progHdrs $ \progHdr ->
        case ph64Type progHdr of
          PtLoad -> loadSegment aRef fileVirtBase (fromIntegral physStart) mainLoadBase progHdr
          _ -> return ()

    mapUserStack aRef

    (entryPoint, startInfo) <- loadInterpAndGetInfo
                                  aRef interp resolveInterp namePtr
                                  mainLoadBase elfHdr progHdrs

    hosDebugLog ("[init] entering child ELF entry=" ++ show entryPoint)

    childId <- case startInfo of
                 Just info -> hosForkEnterLinuxAddressSpace aRef entryPoint info
                 Nothing -> hosForkEnterAddressSpace aRef entryPoint

    hosCloseAddressSpace aRef
    return childId

spawnLinuxStaticElfNoReturn :: String
                            -> Ptr Elf64Hdr
                            -> Word64
                            -> Word64
                            -> IO TaskId
spawnLinuxStaticElfNoReturn name vStart physStart _physSize = do
    hosDebugLog ("[init] spawnLinuxStaticElfNoReturn: " ++ name)

    (elfHdr, progHdrs) <- elf64ProgHdrs vStart

    namePtr <- mallocBytes (length name + 1)
    pokeString namePtr name

    aRef <- hosEmptyAddressSpace

    let elfIsDyn = e64Type elfHdr == EtDyn
        mainLoadBase = if elfIsDyn then 0x400000 else 0 :: Word64
        fileVirtBase = ptrToWord (castPtr vStart)

    forM_ progHdrs $ \progHdr ->
        case ph64Type progHdr of
          PtLoad -> loadSegment aRef fileVirtBase (fromIntegral physStart) mainLoadBase progHdr
          _ -> return ()

    mapUserStack aRef

    let info = LinuxStartInfo
               { lsiMainEntry = mainLoadBase + e64Entry elfHdr
               , lsiMainPhdr = findMainPhdrAddr mainLoadBase elfHdr progHdrs
               , lsiMainPhent = fromIntegral (e64PhEntSize elfHdr)
               , lsiMainPhnum = fromIntegral (e64PhNum elfHdr)
               , lsiBase = 0
               , lsiExecBase = mainLoadBase
               , lsiExecFn = ptrToWord (castPtr namePtr)
               }

    childId <- hosForkEnterLinuxAddressSpace
                  aRef
                  (mainLoadBase + e64Entry elfHdr)
                  info

    hosCloseAddressSpace aRef
    free namePtr
    return childId

prepareInitInbox :: IO ()
prepareInitInbox = do
    _ <- hosAddMappingToCurTask
            0x10000000000
            0x10000001000
            (Message (Incoming (MessageFrom (ChanId 0))) undefined)
    hosUnmaskChannel (ChanId 0)

launchStorageFromBootModule :: IO ()
launchStorageFromBootModule = do
    modCount <- hosModuleCount
    if modCount <= storageModuleIndex
       then do
           hosDebugLog "[init] [FATAL] no storage boot module found"
           hosDebugLog "[init] storage launch failed; falling back to embedded esh"
           bootIntoEsh
       else do
           ModuleInfo name start end <- hosGetModuleInfo storageModuleIndex

           hosDebugLog ("[init] found storage module '" ++ name ++
                        "' at " ++ show start ++ " - " ++ show end)

           let vBase   = storageModuleMapBase
               rawSize = fromIntegral (end - start)
               vEnd    = vBase + ((rawSize + 0xFFF) .&. complement 0xFFF)

           curTask <- hosCurrentTask
           curAS   <- hosCurrentAddressSpace curTask

           hosDebugLog ("[init] current task = " ++ show curTask)
           hosDebugLog ("[init] current address space = " ++ show curAS)

           mapResult <- hosAddMapping
                    curAddressSpaceRef
                    vBase
                    vEnd
                    (FromPhysical RetainInParent
                            (UserSpace ReadOnly)
                            (fromIntegral start))

           hosDebugLog ("[init] storage module map result = " ++ show mapResult)
           
           storageTaskId <- loadElf "hos.storage"
                                    (wordToPtr vBase)
                                    (fromIntegral start)
                                    (fromIntegral (end - start))
                                    (const Nothing)

           hosDebugLog ("[init] storage task started as " ++ show storageTaskId)
           hosDebugLog "[init] storage started; skipping desktop handoff"
           hosDebugLog "[init] entering parent supervisor loop"

           parentLoop initialInitState

launchPreferredDesktopFromBootModule :: IO ()
launchPreferredDesktopFromBootModule = do
    desktopModule <- findFirstModuleBySuffix desktopBootModulePaths
    case desktopModule of
      Nothing ->
          hosDebugLog ("[init] no desktop boot module found; checked " ++
                       joinWith ", " desktopBootModulePaths)

      Just (targetPath, ModuleInfo name start end) -> do
          hosDebugLog ("[init] launching desktop module '" ++ name ++
                       "' for target " ++ targetPath)

          let vBase = desktopBootModuleMapBase
              vEnd = fromIntegral (end - start) + vBase

          _ <- hosAddMappingToCurTask
                    vBase
                    vEnd
                    (FromPhysical RetainInParent
                                  (UserSpace ReadOnly)
                                  (fromIntegral start))

          hosDebugLog "[init] entering desktop child address space"

          _ <- spawnLinuxStaticElfNoReturn name
                                           (wordToPtr vBase)
                                           (fromIntegral start)
                                           (fromIntegral (end - start))

          hosDebugLog "[init] desktop child scheduled"
          hosYieldMany 128

doParent :: InitState -> IO InitState
doParent initState = do
    _ <- hosAddMappingToCurTask
            0x10000000000
            0x10000001000
            (Message (Incoming (MessageFrom (ChanId 0))) undefined)

    hosUnmaskChannel (ChanId 0)

    res <- waitOnChannelsNoHeap (waitForever <> allChannels) 0

    case res of
      Right (_, taskId) -> do
          let msgPtr = wordToPtr 0x10000000000
              replyPtr = wordToPtr 0x10000001000

          msg <- getRoutedMsg "hos.init" msgPtr 0x1000

          case msg of
            Left err ->
                hosDebugLog ("[init] error decoding: " ++ show err) >>
                return initState

            Right (OurMsg routedMsg) -> do
                _ <- hosAddMappingToCurTask
                        0x10000001000
                        0x10000002000
                        (Message (Outgoing (ReplyTo (ChanId 0))) undefined)

                case routedMsg of
                  InitRegisterProvider serverName -> do
                      serializeTo replyPtr 0x1000 InitSuccess
                      hosReplyTo (ChanId 0)
                      return (initState
                              { initServers =
                                  M.insert serverName taskId
                                           (initServers initState)
                              })

                  InitFindProvider serverName ->
                      case M.lookup serverName (initServers initState) of
                        Just serverId -> do
                            serializeTo replyPtr 0x1000
                                        (InitFoundProvider serverId)
                            hosReplyTo (ChanId 0)
                            return initState

                        Nothing -> do
                            serializeTo replyPtr 0x1000 InitNotFound
                            hosReplyTo (ChanId 0)
                            return initState

                  InitSendArgs tId args -> do
                      serializeTo replyPtr 0x1000 InitSuccess
                      hosReplyTo (ChanId 0)

                      _ <- hosAddMappingToCurTask
                              0x10000002000
                              0x10000003000
                              (Message
                                  (Outgoing
                                    (MessageFrom (ChanId 0xBADBEEF)))
                                  undefined)

                      serializeTo (wordToPtr 0x10000002000) 0x1000 args
                      hosDeliverMessage (ChanId 0xBADBEEF) tId (ChanId 0)
                      return initState

            Right (InTransitMsg (ServerName name) chanId) ->
                case M.lookup name (initServers initState) of
                  Nothing -> do
                      _ <- hosAddMappingToCurTask
                              0x10000001000
                              0x10000002000
                              (Message
                                  (Outgoing (ReplyTo (ChanId 0)))
                                  undefined)

                      serializeTo replyPtr 0x1000 InitNotFound
                      hosReplyTo (ChanId 0)
                      return initState

                  Just serverId -> do
                      hosRouteMsg (ChanId 0) serverId chanId
                      return initState

            Right _ -> do
                hosDebugLog "[init] got message that was not for us"
                return initState

      Left err -> do
          hosDebugLog ("[init] wait on channels error: " ++ show err)
          return initState

bootIntoEsh :: IO ()
bootIntoEsh = do
    hosDebugLog "[init] requesting I/O privileges..."
    hosRequestIO
    hosDebugLog "[init] initializing PS/2..."
    initPS2
    hosDebugLog "[init] entering esh interactive shell"
    runEsh

runEsh :: IO ()
runEsh = do
    hosVGAPut "> "
    line <- getLinePS2
    case line of
      "help" ->
          hosDebugLog "esh commands: help, echo <args>, clear, about, exit\n" >>
          runEsh

      "clear" ->
          hosDebugLog "\x1b[2J\x1b[H" >>
          runEsh

      "about" ->
          hosDebugLog "esh (embedded init edition)\n" >>
          runEsh

      "exit" ->
          hosDebugLog "esh: goodbye\n" >>
          return ()

      "" ->
          runEsh

      _ -> do
          let (cmd, args) = break (== ' ') line
          case cmd of
            "echo" ->
                hosDebugLog (drop 1 args ++ "\n") >>
                runEsh

            _ ->
                hosDebugLog ("esh: unknown command: " ++ cmd ++ "\n") >>
                runEsh

getLinePS2 :: IO String
getLinePS2 = go ""
  where
    go acc = do
        c <- getCharPS2
        case c of
          '\0' -> hosYield >> go acc
          '\n' -> hosVGAPut "\n" >> return acc
          '\b' ->
              if null acc
                 then go acc
                 else hosVGAPut "\b \b" >> go (init acc)
          c' -> hosVGAPut [c'] >> go (acc ++ [c'])
