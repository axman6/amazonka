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
-- Module      : Amazonka.EC2.Types.InstanceEventWindowState
-- Copyright   : (c) 2013-2022 Brendan Hay
-- License     : Mozilla Public License, v. 2.0.
-- Maintainer  : Brendan Hay <brendan.g.hay+amazonka@gmail.com>
-- Stability   : auto-generated
-- Portability : non-portable (GHC extensions)
module Amazonka.EC2.Types.InstanceEventWindowState
  ( InstanceEventWindowState
      ( ..,
        InstanceEventWindowState_Active,
        InstanceEventWindowState_Creating,
        InstanceEventWindowState_Deleted,
        InstanceEventWindowState_Deleting
      ),
  )
where

import qualified Amazonka.Core as Core
import Amazonka.EC2.Internal
import qualified Amazonka.Prelude as Prelude

newtype InstanceEventWindowState = InstanceEventWindowState'
  { fromInstanceEventWindowState ::
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

pattern InstanceEventWindowState_Active :: InstanceEventWindowState
pattern InstanceEventWindowState_Active = InstanceEventWindowState' "active"

pattern InstanceEventWindowState_Creating :: InstanceEventWindowState
pattern InstanceEventWindowState_Creating = InstanceEventWindowState' "creating"

pattern InstanceEventWindowState_Deleted :: InstanceEventWindowState
pattern InstanceEventWindowState_Deleted = InstanceEventWindowState' "deleted"

pattern InstanceEventWindowState_Deleting :: InstanceEventWindowState
pattern InstanceEventWindowState_Deleting = InstanceEventWindowState' "deleting"

{-# COMPLETE
  InstanceEventWindowState_Active,
  InstanceEventWindowState_Creating,
  InstanceEventWindowState_Deleted,
  InstanceEventWindowState_Deleting,
  InstanceEventWindowState'
  #-}
