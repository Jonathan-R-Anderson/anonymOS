{-# LANGUAGE TupleSections, OverloadedStrings #-}
module Main where

import Control.Monad
import Control.Applicative
import Control.Exception

import Data.Bits
import Data.Word
import Data.Scientific (floatingOrInteger)
import Data.Binary
import Data.Binary.Put
import qualified Data.ByteString.Lazy as BL
import qualified Data.ByteString.Char8 as BSC
import Data.Char (ord)
import Data.Yaml
import qualified Data.Aeson.KeyMap as KM
import qualified Data.Aeson.Key as K
import qualified Data.Text as T

import Hos.Common.Bundle

import System.Environment
import System.Exit
import System.IO
import System.Posix.Files

pageSize :: Integral a => a
pageSize = 0x1000

alignToPage :: (Num a, Bits a, Integral a) => a -> a
alignToPage x = (x + pageSize - 1) .&. complement (pageSize - 1)

data ValidationResult l = ValidBundle [TagDescriptor] (Bundle l)

newtype TagsAndBundle = TagsAndBundle ([TagDescriptor], Bundle FilePath)

parseBundleSpec :: FilePath -> IO ([TagDescriptor], Bundle FilePath)
parseBundleSpec fp = do res <- decodeFile fp
                        case res of
                          Just (TagsAndBundle tagsAndBundle) -> return tagsAndBundle
                          Nothing -> do putStrLn "Failed to parse"
                                        exitWith (ExitFailure 1)

validateBundle :: [TagDescriptor] -> Bundle l -> ValidationResult l
validateBundle tagDescs items = ValidBundle tagDescs items

getFileSize :: FilePath -> IO Word64
getFileSize fp = bracket (openBinaryFile fp ReadMode) hClose $ \h -> fromIntegral <$> hFileSize h

-- Simple Bundle Format:
-- Magic: "HOSBNDL1" (8 bytes)
-- File Count: Word64 (8 bytes)
-- [File Entry] * Count
--    NameLen: Word64
--    Name: Bytes (padded to what? no, just bytes)
--    Offset: Word64 (Absolute offset in bundle)
--    Size: Word64
--    Padding: To align next entry? No, let's keep it packed in header, align content.
-- Content starts at next page boundary after header.

embedFile :: Handle -> FilePath -> IO ()
embedFile fh fileToEmbed =
    do embedH <- openBinaryFile fileToEmbed ReadMode
       let copyBytes = do isEof <- hIsEOF embedH
                          if isEof then return () else hGetChar embedH >>= hPutChar fh >> copyBytes
       copyBytes
       hClose embedH

main :: IO ()
main = getArgs >>= \args ->
       case args of
         [fileName, outputFileName] ->
             do (tags, fileBundle) <- parseBundleSpec fileName
                -- Calculate sizes
                fileSizes <- mapM (\bi -> getFileSize (biLocation bi)) (bundleContents fileBundle)
                
                let fileEntries = zip (bundleContents fileBundle) fileSizes
                    
                -- Calculate Header Size
                -- Magic (8) + Count (8)
                let baseHeaderSize = 16
                
                -- Calculate size of directory entries
                let entrySize (bi, _) = 
                        let name = getServiceName bi
                            len = fromIntegral (length name) :: Word64
                        in 8 + len + 8 + 8 -- NameLen + Name + Offset + Size
                
                let dirSize = sum (map entrySize fileEntries)
                let headerSize = baseHeaderSize + dirSize
                let contentStart = alignToPage headerSize
                
                -- Construct Header
                let putHeader = do
                        putByteString (BSC.pack "HOSBNDL1")
                        putWord64le (fromIntegral (length fileEntries))
                        
                        let processEntries currentOffset [] = return ()
                            processEntries currentOffset ((bi, sz):rest) = do
                                let name = getServiceName bi
                                    len = fromIntegral (length name) :: Word64
                                putWord64le len
                                putByteString (BSC.pack name)
                                putWord64le (fromIntegral currentOffset)
                                putWord64le sz
                                processEntries (currentOffset + sz) rest
                                
                        processEntries (fromIntegral contentStart) fileEntries

                let header = runPut putHeader

                fh <- openBinaryFile outputFileName WriteMode
                BL.hPut fh header
                
                -- Pad to content start
                replicateM_ (fromIntegral (contentStart - fromIntegral (BL.length header))) (hPutChar fh '\0')
                
                -- Write contents
                forM_ fileEntries $ \(bi, _) -> do
                    embedFile fh (biLocation bi)
                    -- We packed them tightly in the new format logic above for offsets, 
                    -- so we should NOT align individual files here unless we updated offsets above.
                    -- The loop above: processEntries (currentOffset + sz)
                    -- implies packed tight.
                    
                hClose fh
                
         _ -> do procName <- getProgName
                 putStrLn (procName ++ ": usage")
                 putStrLn ("  " ++ procName ++ " <bundle-spec.yaml> <output.bundle>")
                 exitWith (ExitFailure 1)

getServiceName :: BundleItem l -> String
getServiceName bi = 
    case filter isServiceName (biTags bi) of
        (Tag _ (TextV name) : _) -> name
        _ -> "unknown"
  where
    isServiceName (Tag (TagName "com.hos.service-name") _) = True
    isServiceName _ = False

newtype TagDescriptors = TagDescriptors { unTagDescriptors :: [TagDescriptor] }

instance FromJSON TagsAndBundle where
    parseJSON (Object v) = TagsAndBundle <$> ((,) <$> (unTagDescriptors <$> v .: "tags") <*> v .: "content")
    parseJSON _ = mzero

instance FromJSON TagDescriptors where
    parseJSON (Object v) = TagDescriptors <$> sequenceA (map parseTagDescriptor (KM.toList v))
        where parseTagDescriptor (name, Object v) =
                  TagDescriptor (K.toString name)
                  <$> (v .:? "description" .!= "")
                  <*> (v .:? "default")
                  <*> (v .:? "unique" .!= False)
              parseTagDescriptor _ = mzero
    parseJSON _ = mzero

instance FromJSON a => FromJSON (Bundle a) where
    parseJSON v = Bundle <$> parseJSON v

instance FromJSON a => FromJSON (BundleItem a) where
    parseJSON (Object v) = BundleItem (GUID 0 0 0 0) <$> v .: "tags" <*> v .: "location"
    parseJSON _ = mzero

instance FromJSON Tag where
    parseJSON (Object v) = case KM.toList v of
                             [(key, value)] -> Tag (TagName (K.toString key)) <$> parseJSON value
                             _ -> mzero
    parseJSON (String t) = pure (Tag (TagName (T.unpack t)) (BooleanV True))
    parseJSON _ = mzero

instance FromJSON TagValue where
    parseJSON (String t) = pure (TextV (T.unpack t))
    parseJSON (Bool b) = pure (BooleanV b)
    parseJSON (Number n) = pure $ case floatingOrInteger n of
                                    Left d -> RationalV d
                                    Right i -> IntegerV i
    parseJSON _ = mzero

