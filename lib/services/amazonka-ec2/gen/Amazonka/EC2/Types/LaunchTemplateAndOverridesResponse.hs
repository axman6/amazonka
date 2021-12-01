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
-- Module      : Amazonka.EC2.Types.LaunchTemplateAndOverridesResponse
-- Copyright   : (c) 2013-2021 Brendan Hay
-- License     : Mozilla Public License, v. 2.0.
-- Maintainer  : Brendan Hay <brendan.g.hay+amazonka@gmail.com>
-- Stability   : auto-generated
-- Portability : non-portable (GHC extensions)
module Amazonka.EC2.Types.LaunchTemplateAndOverridesResponse where

import qualified Amazonka.Core as Core
import Amazonka.EC2.Internal
import Amazonka.EC2.Types.FleetLaunchTemplateOverrides
import Amazonka.EC2.Types.FleetLaunchTemplateSpecification
import qualified Amazonka.Lens as Lens
import qualified Amazonka.Prelude as Prelude

-- | Describes a launch template and overrides.
--
-- /See:/ 'newLaunchTemplateAndOverridesResponse' smart constructor.
data LaunchTemplateAndOverridesResponse = LaunchTemplateAndOverridesResponse'
  { -- | Any parameters that you specify override the same parameters in the
    -- launch template.
    overrides :: Prelude.Maybe FleetLaunchTemplateOverrides,
    -- | The launch template.
    launchTemplateSpecification :: Prelude.Maybe FleetLaunchTemplateSpecification
  }
  deriving (Prelude.Eq, Prelude.Read, Prelude.Show, Prelude.Generic)

-- |
-- Create a value of 'LaunchTemplateAndOverridesResponse' with all optional fields omitted.
--
-- Use <https://hackage.haskell.org/package/generic-lens generic-lens> or <https://hackage.haskell.org/package/optics optics> to modify other optional fields.
--
-- The following record fields are available, with the corresponding lenses provided
-- for backwards compatibility:
--
-- 'overrides', 'launchTemplateAndOverridesResponse_overrides' - Any parameters that you specify override the same parameters in the
-- launch template.
--
-- 'launchTemplateSpecification', 'launchTemplateAndOverridesResponse_launchTemplateSpecification' - The launch template.
newLaunchTemplateAndOverridesResponse ::
  LaunchTemplateAndOverridesResponse
newLaunchTemplateAndOverridesResponse =
  LaunchTemplateAndOverridesResponse'
    { overrides =
        Prelude.Nothing,
      launchTemplateSpecification =
        Prelude.Nothing
    }

-- | Any parameters that you specify override the same parameters in the
-- launch template.
launchTemplateAndOverridesResponse_overrides :: Lens.Lens' LaunchTemplateAndOverridesResponse (Prelude.Maybe FleetLaunchTemplateOverrides)
launchTemplateAndOverridesResponse_overrides = Lens.lens (\LaunchTemplateAndOverridesResponse' {overrides} -> overrides) (\s@LaunchTemplateAndOverridesResponse' {} a -> s {overrides = a} :: LaunchTemplateAndOverridesResponse)

-- | The launch template.
launchTemplateAndOverridesResponse_launchTemplateSpecification :: Lens.Lens' LaunchTemplateAndOverridesResponse (Prelude.Maybe FleetLaunchTemplateSpecification)
launchTemplateAndOverridesResponse_launchTemplateSpecification = Lens.lens (\LaunchTemplateAndOverridesResponse' {launchTemplateSpecification} -> launchTemplateSpecification) (\s@LaunchTemplateAndOverridesResponse' {} a -> s {launchTemplateSpecification = a} :: LaunchTemplateAndOverridesResponse)

instance
  Core.FromXML
    LaunchTemplateAndOverridesResponse
  where
  parseXML x =
    LaunchTemplateAndOverridesResponse'
      Prelude.<$> (x Core..@? "overrides")
      Prelude.<*> (x Core..@? "launchTemplateSpecification")

instance
  Prelude.Hashable
    LaunchTemplateAndOverridesResponse
  where
  hashWithSalt
    salt'
    LaunchTemplateAndOverridesResponse' {..} =
      salt'
        `Prelude.hashWithSalt` launchTemplateSpecification
        `Prelude.hashWithSalt` overrides

instance
  Prelude.NFData
    LaunchTemplateAndOverridesResponse
  where
  rnf LaunchTemplateAndOverridesResponse' {..} =
    Prelude.rnf overrides
      `Prelude.seq` Prelude.rnf launchTemplateSpecification
