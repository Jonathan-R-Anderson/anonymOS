{-# LANGUAGE CPP #-}
module Hos.Common.Types where

import Control.Applicative

import Data.Word
import Data.Monoid
import Data.Bits

import Foreign.Ptr
import Foreign.Storable
import qualified Hos.Data.Sequence as Seq

#ifndef __GLASGOW_HASKELL__
(<>) :: Monoid a => a -> a -> a
(<>) = mappend
infixr 6 <>
#endif

newtype ChanId = ChanId Word32
    deriving (Show, Read, Eq, Ord)
newtype TaskId = TaskId Word32
    deriving (Show, Read, Eq, Ord)
newtype TaskPriority = TaskPriority Int
    deriving (Show, Eq, Ord)
newtype AddressSpaceRef = AddressSpaceRef Word32
    deriving (Show, Read, Eq, Ord)
newtype ObjectId = ObjectId Word64
    deriving (Show, Read, Eq, Ord)

invalidObjectId :: ObjectId
invalidObjectId = ObjectId 0

data ObjectType
    = ObjRoot
    | ObjDirectory
    | ObjKernel
    | ObjScheduler
    | ObjMemoryManager
    | ObjObjectManager
    | ObjSecurityManager
    | ObjHardware
    | ObjCPU
    | ObjRAM
    | ObjDisk
    | ObjGPU
    | ObjNetworkCard
    | ObjUSB
    | ObjProcess
    | ObjThread
    | ObjAddressSpace
    | ObjPage
    | ObjDevice
    | ObjFramebuffer
    | ObjKeyboard
    | ObjMouse
    | ObjStorageController
    | ObjStorage
    | ObjVolume
    | ObjBlob
    | ObjNetwork
    | ObjNetworkInterface
    | ObjSocket
    | ObjRoute
    | ObjService
    | ObjUser
    | ObjPermissionSet
    | ObjCapability
    | ObjAuditLog
    | ObjUnknown
      deriving (Show, Read, Eq, Ord, Enum)

objectTypeToWord64 :: ObjectType -> Word64
objectTypeToWord64 = fromIntegral . fromEnum

word64ToObjectType :: Word64 -> ObjectType
word64ToObjectType w =
    case w of
      0  -> ObjRoot
      1  -> ObjDirectory
      2  -> ObjKernel
      3  -> ObjScheduler
      4  -> ObjMemoryManager
      5  -> ObjObjectManager
      6  -> ObjSecurityManager
      7  -> ObjHardware
      8  -> ObjCPU
      9  -> ObjRAM
      10 -> ObjDisk
      11 -> ObjGPU
      12 -> ObjNetworkCard
      13 -> ObjUSB
      14 -> ObjProcess
      15 -> ObjThread
      16 -> ObjAddressSpace
      17 -> ObjPage
      18 -> ObjDevice
      19 -> ObjFramebuffer
      20 -> ObjKeyboard
      21 -> ObjMouse
      22 -> ObjStorageController
      23 -> ObjStorage
      24 -> ObjVolume
      25 -> ObjBlob
      26 -> ObjNetwork
      27 -> ObjNetworkInterface
      28 -> ObjSocket
      29 -> ObjRoute
      30 -> ObjService
      31 -> ObjUser
      32 -> ObjPermissionSet
      33 -> ObjCapability
      34 -> ObjAuditLog
      _  -> ObjUnknown

curAddressSpaceRef :: AddressSpaceRef
curAddressSpaceRef = AddressSpaceRef maxBound

data MemoryPermissions = Privileged ReadWrite
                       | UserSpace ReadWrite
                         deriving (Show, Eq, Ord)

data WaitOnChannelsFlags = WaitOnChannelsFlags
                         { wocWaitForever :: Bool
                         , wocDontTruncate :: Bool
                         , wocAllChannels :: Bool }
                           deriving Show

data ReadWrite = ReadOnly | ReadWrite
               deriving (Show, Eq, Ord, Enum)

data MessageType = Outgoing MessageOrReply
                 | Incoming MessageOrReply
                   deriving (Show)

data MessageOrReply = MessageFrom ChanId
                    | ReplyTo ChanId
                      deriving (Show)

-- TODO JHC generates a defective Eq instance for types like message type: sum types where both constructors carry the same subtype
instance Eq MessageType where
    Outgoing a == Outgoing b = a == b
    Incoming a == Incoming b = a == b
    _ == _ = False

instance Eq MessageOrReply where
    MessageFrom a == MessageFrom b = a == b
    ReplyTo a == ReplyTo b = a == b
    _ == _ = False

-- | Some mappings, such as FromPhysical, do not have any sensible forking behavior.
--
--   This data type lets processes specify what should happen to these sorts of mapping
--   when a fork occurs.
data MappingTreatmentOnFork = RetainInParent -- ^ On fork, the parent will keep the region, while the region will be invalid in the child
                            | GiveToChild    -- ^ On fork, the child will be given the region, while the region will be invalid in the parent
                              deriving (Show, Eq, Ord)

data Mapping = AllocateOnDemand MemoryPermissions
             | AllocateImmediately MemoryPermissions (Maybe Word64)
             | FromPhysical MappingTreatmentOnFork MemoryPermissions Word64

             | Message MessageType (Seq.Seq (Maybe Word64))

             | CopyOnWrite MemoryPermissions Word64

               -- These can only be added or manipulated by the kernel, but can be read from userspace, under certain conditions
             | Mapped MemoryPermissions Word64
               deriving (Show, Eq)

#ifdef __GLASGOW_HASKELL__
instance Semigroup WaitOnChannelsFlags where
    a <> b = WaitOnChannelsFlags
                  (wocWaitForever a || wocWaitForever b)
                  (wocDontTruncate a || wocDontTruncate b)
                  (wocAllChannels a || wocAllChannels b)
#endif

instance Monoid WaitOnChannelsFlags where
    mempty = WaitOnChannelsFlags False False False
    mappend a b = WaitOnChannelsFlags
                  (wocWaitForever a || wocWaitForever b)
                  (wocDontTruncate a || wocDontTruncate b)
                  (wocAllChannels a || wocAllChannels b)

waitForever, dontTruncate, allChannels :: WaitOnChannelsFlags
waitForever = WaitOnChannelsFlags True False False
dontTruncate = WaitOnChannelsFlags False True False
allChannels = WaitOnChannelsFlags False False True

instance Storable MemoryPermissions where
    sizeOf _ = 1
    alignment _ = 1

    poke p (Privileged ReadWrite) = poke (castPtr p :: Ptr Word8) 0x1
    poke p (Privileged ReadOnly) = poke (castPtr p :: Ptr Word8) 0x0
    poke p (UserSpace ReadWrite) = poke (castPtr p :: Ptr Word8) 0x3
    poke p (UserSpace ReadOnly) = poke (castPtr p :: Ptr Word8) 0x2

    peek p = do tag <- peek (castPtr p :: Ptr Word8)
                return ((if testBit tag 1 then UserSpace else Privileged) (if testBit tag 0 then ReadWrite else ReadOnly))

instance Storable MappingTreatmentOnFork where
    sizeOf _ = 1
    alignment _ = 1

    poke p RetainInParent = poke (castPtr p :: Ptr Word8) 0x0
    poke p GiveToChild = poke (castPtr p :: Ptr Word8) 0x1

    peek p = do tag <- peek (castPtr p :: Ptr Word8)
                case tag of
                  0x0 -> return RetainInParent
                  0x1 -> return GiveToChild
                  _ -> return RetainInParent

mappingMessageOffset :: Int
mappingMessageOffset = 4

mappingPayloadOffset :: Int
mappingPayloadOffset = 8

instance Storable Mapping where
    sizeOf _ = 16
    alignment _ = 8

    poke p (AllocateOnDemand perms) =
        poke (castPtr p :: Ptr Word8) 0x1 >>
        poke (castPtr p `plusPtr` 1) perms
    poke p (AllocateImmediately perms Nothing) =
        poke (castPtr p :: Ptr Word8) 0x2 >>
        poke (castPtr p `plusPtr` 1) perms >>
        poke (castPtr p `plusPtr` mappingPayloadOffset) (0 :: Word64)
    poke p (AllocateImmediately perms (Just alignment)) =
        poke (castPtr p :: Ptr Word8) 0x3 >>
        poke (castPtr p `plusPtr` 1) perms >>
        poke (castPtr p `plusPtr` mappingPayloadOffset) alignment
    poke p (FromPhysical forkTreatment perms physBase) =
        poke (castPtr p :: Ptr Word8) 0x4 >>
        poke (castPtr p `plusPtr` 1) forkTreatment >>
        poke (castPtr p `plusPtr` 2) perms >>
        poke (castPtr p `plusPtr` mappingPayloadOffset) physBase

    poke p (Message (Outgoing msgDest) _) =
        poke (castPtr p :: Ptr Word8) 0x5 >>
        poke (castPtr p `plusPtr` mappingMessageOffset) msgDest
    poke p (Message (Incoming msgDest) _) =
        poke (castPtr p :: Ptr Word8) 0x6 >>
        poke (castPtr p `plusPtr` mappingMessageOffset) msgDest

    poke p (Mapped perms pageAddr) =
        poke (castPtr p :: Ptr Word8) 0xFF >>
        poke (castPtr p `plusPtr` 1) perms >>
        poke (castPtr p `plusPtr` mappingPayloadOffset) pageAddr
    poke p (CopyOnWrite perms pageAddr) =
        poke (castPtr p :: Ptr Word8) 0x7F >>
        poke (castPtr p `plusPtr` 1) perms >>
        poke (castPtr p `plusPtr` mappingPayloadOffset) pageAddr

    peek p = do tag <- peek (castPtr p :: Ptr Word8)
                case tag of
                  0x1 -> AllocateOnDemand <$> peek (castPtr p `plusPtr` 1)
                  0x2 -> AllocateImmediately <$> peek (castPtr p `plusPtr` 1)
                                             <*> pure Nothing
                  0x3 -> AllocateImmediately <$> peek (castPtr p `plusPtr` 1)
                                             <*> (Just <$> peek (castPtr p `plusPtr` mappingPayloadOffset))
                  0x4 -> FromPhysical <$> peek (castPtr p `plusPtr` 1)
                                      <*> peek (castPtr p `plusPtr` 2)
                                      <*> peek (castPtr p `plusPtr` mappingPayloadOffset)

                  0x5 -> Message <$> (Outgoing <$> peek (castPtr p `plusPtr` mappingMessageOffset)) <*> pure Seq.empty
                  0x6 -> Message <$> (Incoming <$> peek (castPtr p `plusPtr` mappingMessageOffset)) <*> pure Seq.empty

                  0xFF -> Mapped <$> peek (castPtr p `plusPtr` 1)
                                 <*> peek (castPtr p `plusPtr` mappingPayloadOffset)
                  0x7F -> CopyOnWrite <$> peek (castPtr p `plusPtr` 1)
                                      <*> peek (castPtr p `plusPtr` mappingPayloadOffset)
                  _ -> return (AllocateOnDemand (Privileged ReadOnly))

instance Storable MessageOrReply where
    sizeOf _ = 4
    alignment _ = 4

    poke p (MessageFrom (ChanId chanId)) = poke (castPtr p) chanId
    poke p (ReplyTo (ChanId chanId)) = poke (castPtr p) (chanId `setBit` 31)
    peek p = do chanId <- peek (castPtr p)
                return (if testBit chanId 31 then ReplyTo (ChanId (chanId `clearBit` 31)) else MessageFrom (ChanId chanId))
