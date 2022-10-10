{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE PatternSynonyms #-}
{-# LANGUAGE StrictData #-}
{-# LANGUAGE NoImplicitPrelude #-}
{-# OPTIONS_GHC -fno-warn-unused-imports #-}

-- Derived from AWS service descriptions, licensed under Apache 2.0.

-- |
-- Module      : Amazonka.Discovery.Types.BatchDeleteImportDataErrorCode
-- Copyright   : (c) 2013-2022 Brendan Hay
-- License     : Mozilla Public License, v. 2.0.
-- Maintainer  : Brendan Hay <brendan.g.hay+amazonka@gmail.com>
-- Stability   : auto-generated
-- Portability : non-portable (GHC extensions)
module Amazonka.Discovery.Types.BatchDeleteImportDataErrorCode
  ( BatchDeleteImportDataErrorCode
      ( ..,
        BatchDeleteImportDataErrorCode_INTERNAL_SERVER_ERROR,
        BatchDeleteImportDataErrorCode_NOT_FOUND,
        BatchDeleteImportDataErrorCode_OVER_LIMIT
      ),
  )
where

import qualified Amazonka.Core as Core
import qualified Amazonka.Prelude as Prelude

newtype BatchDeleteImportDataErrorCode = BatchDeleteImportDataErrorCode'
  { fromBatchDeleteImportDataErrorCode ::
      Core.Text
  }
  deriving stock
    ( Prelude.Show,
      Prelude.Read,
      Prelude.Eq,
      Prelude.Ord,
      Prelude.Generic
    )
  deriving newtype
    ( Prelude.Hashable,
      Prelude.NFData,
      Core.FromText,
      Core.ToText,
      Core.ToByteString,
      Core.ToLog,
      Core.ToHeader,
      Core.ToQuery,
      Core.FromJSON,
      Core.FromJSONKey,
      Core.ToJSON,
      Core.ToJSONKey,
      Core.FromXML,
      Core.ToXML
    )

pattern BatchDeleteImportDataErrorCode_INTERNAL_SERVER_ERROR :: BatchDeleteImportDataErrorCode
pattern BatchDeleteImportDataErrorCode_INTERNAL_SERVER_ERROR = BatchDeleteImportDataErrorCode' "INTERNAL_SERVER_ERROR"

pattern BatchDeleteImportDataErrorCode_NOT_FOUND :: BatchDeleteImportDataErrorCode
pattern BatchDeleteImportDataErrorCode_NOT_FOUND = BatchDeleteImportDataErrorCode' "NOT_FOUND"

pattern BatchDeleteImportDataErrorCode_OVER_LIMIT :: BatchDeleteImportDataErrorCode
pattern BatchDeleteImportDataErrorCode_OVER_LIMIT = BatchDeleteImportDataErrorCode' "OVER_LIMIT"

{-# COMPLETE
  BatchDeleteImportDataErrorCode_INTERNAL_SERVER_ERROR,
  BatchDeleteImportDataErrorCode_NOT_FOUND,
  BatchDeleteImportDataErrorCode_OVER_LIMIT,
  BatchDeleteImportDataErrorCode'
  #-}
