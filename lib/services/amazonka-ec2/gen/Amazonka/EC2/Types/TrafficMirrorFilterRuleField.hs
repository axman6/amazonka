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
-- Module      : Amazonka.EC2.Types.TrafficMirrorFilterRuleField
-- Copyright   : (c) 2013-2022 Brendan Hay
-- License     : Mozilla Public License, v. 2.0.
-- Maintainer  : Brendan Hay <brendan.g.hay+amazonka@gmail.com>
-- Stability   : auto-generated
-- Portability : non-portable (GHC extensions)
module Amazonka.EC2.Types.TrafficMirrorFilterRuleField
  ( TrafficMirrorFilterRuleField
      ( ..,
        TrafficMirrorFilterRuleField_Description,
        TrafficMirrorFilterRuleField_Destination_port_range,
        TrafficMirrorFilterRuleField_Protocol,
        TrafficMirrorFilterRuleField_Source_port_range
      ),
  )
where

import qualified Amazonka.Core as Core
import Amazonka.EC2.Internal
import qualified Amazonka.Prelude as Prelude

newtype TrafficMirrorFilterRuleField = TrafficMirrorFilterRuleField'
  { fromTrafficMirrorFilterRuleField ::
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

pattern TrafficMirrorFilterRuleField_Description :: TrafficMirrorFilterRuleField
pattern TrafficMirrorFilterRuleField_Description = TrafficMirrorFilterRuleField' "description"

pattern TrafficMirrorFilterRuleField_Destination_port_range :: TrafficMirrorFilterRuleField
pattern TrafficMirrorFilterRuleField_Destination_port_range = TrafficMirrorFilterRuleField' "destination-port-range"

pattern TrafficMirrorFilterRuleField_Protocol :: TrafficMirrorFilterRuleField
pattern TrafficMirrorFilterRuleField_Protocol = TrafficMirrorFilterRuleField' "protocol"

pattern TrafficMirrorFilterRuleField_Source_port_range :: TrafficMirrorFilterRuleField
pattern TrafficMirrorFilterRuleField_Source_port_range = TrafficMirrorFilterRuleField' "source-port-range"

{-# COMPLETE
  TrafficMirrorFilterRuleField_Description,
  TrafficMirrorFilterRuleField_Destination_port_range,
  TrafficMirrorFilterRuleField_Protocol,
  TrafficMirrorFilterRuleField_Source_port_range,
  TrafficMirrorFilterRuleField'
  #-}
