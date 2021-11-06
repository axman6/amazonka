{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE StrictData #-}
{-# LANGUAGE NoImplicitPrelude #-}
{-# OPTIONS_GHC -fno-warn-unused-imports #-}
{-# OPTIONS_GHC -fno-warn-unused-matches #-}

-- Derived from AWS service descriptions, licensed under Apache 2.0.

-- |
-- Module      : Amazonka.PinpointSMSVoice.Types.SnsDestination
-- Copyright   : (c) 2013-2021 Brendan Hay
-- License     : Mozilla Public License, v. 2.0.
-- Maintainer  : Brendan Hay <brendan.g.hay+amazonka@gmail.com>
-- Stability   : auto-generated
-- Portability : non-portable (GHC extensions)
module Amazonka.PinpointSMSVoice.Types.SnsDestination where

import qualified Amazonka.Core as Core
import qualified Amazonka.Lens as Lens
import qualified Amazonka.Prelude as Prelude

-- | An object that contains information about an event destination that
-- sends data to Amazon SNS.
--
-- /See:/ 'newSnsDestination' smart constructor.
data SnsDestination = SnsDestination'
  { -- | The Amazon Resource Name (ARN) of the Amazon SNS topic that you want to
    -- publish events to.
    topicArn :: Prelude.Maybe Prelude.Text
  }
  deriving (Prelude.Eq, Prelude.Read, Prelude.Show, Prelude.Generic)

-- |
-- Create a value of 'SnsDestination' with all optional fields omitted.
--
-- Use <https://hackage.haskell.org/package/generic-lens generic-lens> or <https://hackage.haskell.org/package/optics optics> to modify other optional fields.
--
-- The following record fields are available, with the corresponding lenses provided
-- for backwards compatibility:
--
-- 'topicArn', 'snsDestination_topicArn' - The Amazon Resource Name (ARN) of the Amazon SNS topic that you want to
-- publish events to.
newSnsDestination ::
  SnsDestination
newSnsDestination =
  SnsDestination' {topicArn = Prelude.Nothing}

-- | The Amazon Resource Name (ARN) of the Amazon SNS topic that you want to
-- publish events to.
snsDestination_topicArn :: Lens.Lens' SnsDestination (Prelude.Maybe Prelude.Text)
snsDestination_topicArn = Lens.lens (\SnsDestination' {topicArn} -> topicArn) (\s@SnsDestination' {} a -> s {topicArn = a} :: SnsDestination)

instance Core.FromJSON SnsDestination where
  parseJSON =
    Core.withObject
      "SnsDestination"
      ( \x ->
          SnsDestination' Prelude.<$> (x Core..:? "TopicArn")
      )

instance Prelude.Hashable SnsDestination

instance Prelude.NFData SnsDestination

instance Core.ToJSON SnsDestination where
  toJSON SnsDestination' {..} =
    Core.object
      ( Prelude.catMaybes
          [("TopicArn" Core..=) Prelude.<$> topicArn]
      )
