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
-- Module      : Amazonka.SecurityHub.Types.Remediation
-- Copyright   : (c) 2013-2022 Brendan Hay
-- License     : Mozilla Public License, v. 2.0.
-- Maintainer  : Brendan Hay <brendan.g.hay+amazonka@gmail.com>
-- Stability   : auto-generated
-- Portability : non-portable (GHC extensions)
module Amazonka.SecurityHub.Types.Remediation where

import qualified Amazonka.Core as Core
import qualified Amazonka.Lens as Lens
import qualified Amazonka.Prelude as Prelude
import Amazonka.SecurityHub.Types.Recommendation

-- | Details about the remediation steps for a finding.
--
-- /See:/ 'newRemediation' smart constructor.
data Remediation = Remediation'
  { -- | A recommendation on the steps to take to remediate the issue identified
    -- by a finding.
    recommendation :: Prelude.Maybe Recommendation
  }
  deriving (Prelude.Eq, Prelude.Read, Prelude.Show, Prelude.Generic)

-- |
-- Create a value of 'Remediation' with all optional fields omitted.
--
-- Use <https://hackage.haskell.org/package/generic-lens generic-lens> or <https://hackage.haskell.org/package/optics optics> to modify other optional fields.
--
-- The following record fields are available, with the corresponding lenses provided
-- for backwards compatibility:
--
-- 'recommendation', 'remediation_recommendation' - A recommendation on the steps to take to remediate the issue identified
-- by a finding.
newRemediation ::
  Remediation
newRemediation =
  Remediation' {recommendation = Prelude.Nothing}

-- | A recommendation on the steps to take to remediate the issue identified
-- by a finding.
remediation_recommendation :: Lens.Lens' Remediation (Prelude.Maybe Recommendation)
remediation_recommendation = Lens.lens (\Remediation' {recommendation} -> recommendation) (\s@Remediation' {} a -> s {recommendation = a} :: Remediation)

instance Core.FromJSON Remediation where
  parseJSON =
    Core.withObject
      "Remediation"
      ( \x ->
          Remediation'
            Prelude.<$> (x Core..:? "Recommendation")
      )

instance Prelude.Hashable Remediation where
  hashWithSalt _salt Remediation' {..} =
    _salt `Prelude.hashWithSalt` recommendation

instance Prelude.NFData Remediation where
  rnf Remediation' {..} = Prelude.rnf recommendation

instance Core.ToJSON Remediation where
  toJSON Remediation' {..} =
    Core.object
      ( Prelude.catMaybes
          [ ("Recommendation" Core..=)
              Prelude.<$> recommendation
          ]
      )
