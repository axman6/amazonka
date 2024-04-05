{-# LANGUAGE CPP #-}
#ifdef USEBOTAN
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE TypeOperators #-}
#endif

-- |
-- Module      : Amazonka.Crypto
-- Copyright   : (c) 2013-2023 Brendan Hay
-- License     : Mozilla Public License, v. 2.0.
-- Maintainer  : Brendan Hay <brendan.g.hay+amazonka@gmail.com>
-- Stability   : provisional
-- Portability : non-portable (GHC extensions)
module Amazonka.Crypto
  ( -- * HMAC
    Key,
    hmacSHA1,
    hmacSHA256,

    -- * Hashing
    hashSHA1,
    hashSHA256,
    hashMD5,
    hash,
    --- * Incremental Hashing
    sinkSHA256,
    sinkMD5,

    -- * Re-exported
    HashAlgorithm,
    Digest,
    SHA256,
    MD5,
  )
where

import Amazonka.Prelude
#ifdef USEBOTAN
import System.IO.Unsafe (unsafePerformIO)
import qualified Botan.Hash as BHash
import qualified Botan.Hash.SHA1 as BSHA1
import qualified Botan.Hash.SHA2 as BSHA2
import qualified Botan.Hash.MD5 as BMD5
import qualified Botan.Hash.Class as BHashClass
import qualified Botan.MAC as BMAC
#else
import qualified Crypto.Hash as Hash
import qualified Crypto.MAC.HMAC as HMAC
#endif
import qualified Data.ByteArray as BA
import Data.Conduit (ConduitM)
import qualified Data.Conduit as Conduit

type Key = ByteString

#ifdef USEBOTAN
type HMAC_SHA1       = BMAC.MACDigest
type HMAC_SHA256     = BMAC.MACDigest
type Digest a        = BHashClass.Digest a
type SHA1            = BSHA1.SHA1
type SHA256          = BSHA2.SHA2 256
type MD5             = BMD5.MD5
type HashAlgorithm a = BHashClass.Hash a

#else
type HMAC_SHA1       = HMAC.HMAC Hash.SHA1
type HMAC_SHA256     = HMAC.HMAC Hash.SHA256
type Digest a        = Hash.Digest a
type SHA1            = Hash.SHA1
type SHA256          = Hash.SHA256
type MD5             = Hash.MD5
type HashAlgorithm a = Hash.HashAlgorithm a

#endif

hmacSHA1 :: Key -> ByteString -> HMAC_SHA1
hmacSHA256 :: Key -> ByteString -> HMAC_SHA256
hashSHA1 :: ByteString -> Digest SHA1
hashSHA256 :: ByteString -> Digest SHA256
hashMD5 :: ByteString -> Digest MD5

#ifdef USEBOTAN

hmacSHA1   = hmac' "hmacSHA1" BHash.SHA1
hmacSHA256 = hmac' "hmacSHA256" BHash.SHA256
hashSHA1   = BHashClass.hash
hashSHA256 = BHashClass.hash
hashMD5    = BHashClass.hash
-- | A crypton-compatible incremental hash sink.

sinkHash :: forall a m o n. (Monad m, BHashClass.MutableHash a n, n ~ IO)
         => ConduitM ByteString o m (Digest a)
sinkHash = sink (unsafePerformIO BHashClass.hashInit) where
  sink :: BHashClass.MutableCtx a -> ConduitM ByteString o m (Digest a)
  sink ctx = do
      mbs <- Conduit.await

      case mbs of
        Nothing -> pure $! unsafePerformIO (BHashClass.hashFinalize ctx)
        Just bs ->
          let !ctx' = unsafePerformIO (BHashClass.hashUpdate ctx bs >> pure ctx)
          in sink ctx'

hmac' :: String -> BHash.Hash -> Key -> ByteString -> BMAC.MACDigest
hmac' name hash' =
  let mac = BMAC.hmac $ BHash.MkCryptoHash hash'
  in \key bytes -> case BMAC.mac mac key bytes of
      Nothing -> error $ "Amazonka.Crypto." ++ name ++ ": wrong key size:" ++ (show $ BA.length bytes)
      Just ret -> ret

#else

hmacSHA1   = HMAC.hmac
hmacSHA256 = HMAC.hmac
hashSHA1   = Hash.hashWith Hash.SHA1
hashSHA256 = Hash.hashWith Hash.SHA256
hashMD5    = Hash.hashWith Hash.MD5

-- | A crypton-compatible incremental hash sink.
sinkHash :: (Monad m, HashAlgorithm a)
         => ConduitM ByteString o m (Digest a)
sinkHash = sink Hash.hashInit
  where
    sink ctx = do
      mbs <- Conduit.await

      case mbs of
        Nothing -> pure $! Hash.hashFinalize ctx
        Just bs -> sink $! Hash.hashUpdate ctx bs
#endif

-- | Incrementally calculate a 'MD5' 'Digest'.

-- TODO: This currently doesn't work because GHC can't figure out that it
--       can use MutableHash MD5 IO
sinkMD5 :: Monad m => ConduitM ByteString o m (Digest MD5)
sinkMD5 = sinkHash

-- | Incrementally calculate a 'SHA256' 'Digest'.

-- TODO: This currently doesn't work because GHC can't figure out that it
--       can use MutableHash SHA256 IO
sinkSHA256 :: Monad m => ConduitM ByteString o m (Digest SHA256)
#ifdef USEBOTAN
{-# Warning sinkSHA256 "No instance for MutableHash SHA256 in botan" #-}
sinkSHA256 = undefined
#else
sinkSHA256 = sinkHash
#endif
