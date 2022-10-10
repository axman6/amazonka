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
-- Module      : Amazonka.KinesisVideoArchivedMedia.Types.ClipFragmentSelectorType
-- Copyright   : (c) 2013-2022 Brendan Hay
-- License     : Mozilla Public License, v. 2.0.
-- Maintainer  : Brendan Hay <brendan.g.hay+amazonka@gmail.com>
-- Stability   : auto-generated
-- Portability : non-portable (GHC extensions)
module Amazonka.KinesisVideoArchivedMedia.Types.ClipFragmentSelectorType
  ( ClipFragmentSelectorType
      ( ..,
        ClipFragmentSelectorType_PRODUCER_TIMESTAMP,
        ClipFragmentSelectorType_SERVER_TIMESTAMP
      ),
  )
where

import qualified Amazonka.Core as Core
import qualified Amazonka.Prelude as Prelude

newtype ClipFragmentSelectorType = ClipFragmentSelectorType'
  { fromClipFragmentSelectorType ::
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

pattern ClipFragmentSelectorType_PRODUCER_TIMESTAMP :: ClipFragmentSelectorType
pattern ClipFragmentSelectorType_PRODUCER_TIMESTAMP = ClipFragmentSelectorType' "PRODUCER_TIMESTAMP"

pattern ClipFragmentSelectorType_SERVER_TIMESTAMP :: ClipFragmentSelectorType
pattern ClipFragmentSelectorType_SERVER_TIMESTAMP = ClipFragmentSelectorType' "SERVER_TIMESTAMP"

{-# COMPLETE
  ClipFragmentSelectorType_PRODUCER_TIMESTAMP,
  ClipFragmentSelectorType_SERVER_TIMESTAMP,
  ClipFragmentSelectorType'
  #-}
