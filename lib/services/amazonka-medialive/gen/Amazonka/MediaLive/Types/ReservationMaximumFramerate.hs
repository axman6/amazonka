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
-- Module      : Amazonka.MediaLive.Types.ReservationMaximumFramerate
-- Copyright   : (c) 2013-2022 Brendan Hay
-- License     : Mozilla Public License, v. 2.0.
-- Maintainer  : Brendan Hay <brendan.g.hay+amazonka@gmail.com>
-- Stability   : auto-generated
-- Portability : non-portable (GHC extensions)
module Amazonka.MediaLive.Types.ReservationMaximumFramerate
  ( ReservationMaximumFramerate
      ( ..,
        ReservationMaximumFramerate_MAX_30_FPS,
        ReservationMaximumFramerate_MAX_60_FPS
      ),
  )
where

import qualified Amazonka.Core as Core
import qualified Amazonka.Prelude as Prelude

-- | Maximum framerate in frames per second (Outputs only)
newtype ReservationMaximumFramerate = ReservationMaximumFramerate'
  { fromReservationMaximumFramerate ::
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

pattern ReservationMaximumFramerate_MAX_30_FPS :: ReservationMaximumFramerate
pattern ReservationMaximumFramerate_MAX_30_FPS = ReservationMaximumFramerate' "MAX_30_FPS"

pattern ReservationMaximumFramerate_MAX_60_FPS :: ReservationMaximumFramerate
pattern ReservationMaximumFramerate_MAX_60_FPS = ReservationMaximumFramerate' "MAX_60_FPS"

{-# COMPLETE
  ReservationMaximumFramerate_MAX_30_FPS,
  ReservationMaximumFramerate_MAX_60_FPS,
  ReservationMaximumFramerate'
  #-}
