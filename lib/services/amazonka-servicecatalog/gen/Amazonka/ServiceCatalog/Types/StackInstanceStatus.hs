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
-- Module      : Amazonka.ServiceCatalog.Types.StackInstanceStatus
-- Copyright   : (c) 2013-2021 Brendan Hay
-- License     : Mozilla Public License, v. 2.0.
-- Maintainer  : Brendan Hay <brendan.g.hay+amazonka@gmail.com>
-- Stability   : auto-generated
-- Portability : non-portable (GHC extensions)
module Amazonka.ServiceCatalog.Types.StackInstanceStatus
  ( StackInstanceStatus
      ( ..,
        StackInstanceStatus_CURRENT,
        StackInstanceStatus_INOPERABLE,
        StackInstanceStatus_OUTDATED
      ),
  )
where

import qualified Amazonka.Core as Core
import qualified Amazonka.Prelude as Prelude

newtype StackInstanceStatus = StackInstanceStatus'
  { fromStackInstanceStatus ::
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

pattern StackInstanceStatus_CURRENT :: StackInstanceStatus
pattern StackInstanceStatus_CURRENT = StackInstanceStatus' "CURRENT"

pattern StackInstanceStatus_INOPERABLE :: StackInstanceStatus
pattern StackInstanceStatus_INOPERABLE = StackInstanceStatus' "INOPERABLE"

pattern StackInstanceStatus_OUTDATED :: StackInstanceStatus
pattern StackInstanceStatus_OUTDATED = StackInstanceStatus' "OUTDATED"

{-# COMPLETE
  StackInstanceStatus_CURRENT,
  StackInstanceStatus_INOPERABLE,
  StackInstanceStatus_OUTDATED,
  StackInstanceStatus'
  #-}
