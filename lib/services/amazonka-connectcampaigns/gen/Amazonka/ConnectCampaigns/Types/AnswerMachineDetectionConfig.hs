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
-- Module      : Amazonka.ConnectCampaigns.Types.AnswerMachineDetectionConfig
-- Copyright   : (c) 2013-2022 Brendan Hay
-- License     : Mozilla Public License, v. 2.0.
-- Maintainer  : Brendan Hay <brendan.g.hay+amazonka@gmail.com>
-- Stability   : auto-generated
-- Portability : non-portable (GHC extensions)
module Amazonka.ConnectCampaigns.Types.AnswerMachineDetectionConfig where

import qualified Amazonka.Core as Core
import qualified Amazonka.Lens as Lens
import qualified Amazonka.Prelude as Prelude

-- | Answering Machine Detection config
--
-- /See:/ 'newAnswerMachineDetectionConfig' smart constructor.
data AnswerMachineDetectionConfig = AnswerMachineDetectionConfig'
  { -- | Enable or disable answering machine detection
    enableAnswerMachineDetection :: Prelude.Bool
  }
  deriving (Prelude.Eq, Prelude.Read, Prelude.Show, Prelude.Generic)

-- |
-- Create a value of 'AnswerMachineDetectionConfig' with all optional fields omitted.
--
-- Use <https://hackage.haskell.org/package/generic-lens generic-lens> or <https://hackage.haskell.org/package/optics optics> to modify other optional fields.
--
-- The following record fields are available, with the corresponding lenses provided
-- for backwards compatibility:
--
-- 'enableAnswerMachineDetection', 'answerMachineDetectionConfig_enableAnswerMachineDetection' - Enable or disable answering machine detection
newAnswerMachineDetectionConfig ::
  -- | 'enableAnswerMachineDetection'
  Prelude.Bool ->
  AnswerMachineDetectionConfig
newAnswerMachineDetectionConfig
  pEnableAnswerMachineDetection_ =
    AnswerMachineDetectionConfig'
      { enableAnswerMachineDetection =
          pEnableAnswerMachineDetection_
      }

-- | Enable or disable answering machine detection
answerMachineDetectionConfig_enableAnswerMachineDetection :: Lens.Lens' AnswerMachineDetectionConfig Prelude.Bool
answerMachineDetectionConfig_enableAnswerMachineDetection = Lens.lens (\AnswerMachineDetectionConfig' {enableAnswerMachineDetection} -> enableAnswerMachineDetection) (\s@AnswerMachineDetectionConfig' {} a -> s {enableAnswerMachineDetection = a} :: AnswerMachineDetectionConfig)

instance Core.FromJSON AnswerMachineDetectionConfig where
  parseJSON =
    Core.withObject
      "AnswerMachineDetectionConfig"
      ( \x ->
          AnswerMachineDetectionConfig'
            Prelude.<$> (x Core..: "enableAnswerMachineDetection")
      )

instance
  Prelude.Hashable
    AnswerMachineDetectionConfig
  where
  hashWithSalt _salt AnswerMachineDetectionConfig' {..} =
    _salt
      `Prelude.hashWithSalt` enableAnswerMachineDetection

instance Prelude.NFData AnswerMachineDetectionConfig where
  rnf AnswerMachineDetectionConfig' {..} =
    Prelude.rnf enableAnswerMachineDetection

instance Core.ToJSON AnswerMachineDetectionConfig where
  toJSON AnswerMachineDetectionConfig' {..} =
    Core.object
      ( Prelude.catMaybes
          [ Prelude.Just
              ( "enableAnswerMachineDetection"
                  Core..= enableAnswerMachineDetection
              )
          ]
      )
