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
-- Module      : Amazonka.Greengrass.Types.RuntimeConfiguration
-- Copyright   : (c) 2013-2021 Brendan Hay
-- License     : Mozilla Public License, v. 2.0.
-- Maintainer  : Brendan Hay <brendan.g.hay+amazonka@gmail.com>
-- Stability   : auto-generated
-- Portability : non-portable (GHC extensions)
module Amazonka.Greengrass.Types.RuntimeConfiguration where

import qualified Amazonka.Core as Core
import Amazonka.Greengrass.Types.TelemetryConfiguration
import qualified Amazonka.Lens as Lens
import qualified Amazonka.Prelude as Prelude

-- | Runtime configuration for a thing.
--
-- /See:/ 'newRuntimeConfiguration' smart constructor.
data RuntimeConfiguration = RuntimeConfiguration'
  { -- | Configuration for telemetry service.
    telemetryConfiguration :: Prelude.Maybe TelemetryConfiguration
  }
  deriving (Prelude.Eq, Prelude.Read, Prelude.Show, Prelude.Generic)

-- |
-- Create a value of 'RuntimeConfiguration' with all optional fields omitted.
--
-- Use <https://hackage.haskell.org/package/generic-lens generic-lens> or <https://hackage.haskell.org/package/optics optics> to modify other optional fields.
--
-- The following record fields are available, with the corresponding lenses provided
-- for backwards compatibility:
--
-- 'telemetryConfiguration', 'runtimeConfiguration_telemetryConfiguration' - Configuration for telemetry service.
newRuntimeConfiguration ::
  RuntimeConfiguration
newRuntimeConfiguration =
  RuntimeConfiguration'
    { telemetryConfiguration =
        Prelude.Nothing
    }

-- | Configuration for telemetry service.
runtimeConfiguration_telemetryConfiguration :: Lens.Lens' RuntimeConfiguration (Prelude.Maybe TelemetryConfiguration)
runtimeConfiguration_telemetryConfiguration = Lens.lens (\RuntimeConfiguration' {telemetryConfiguration} -> telemetryConfiguration) (\s@RuntimeConfiguration' {} a -> s {telemetryConfiguration = a} :: RuntimeConfiguration)

instance Core.FromJSON RuntimeConfiguration where
  parseJSON =
    Core.withObject
      "RuntimeConfiguration"
      ( \x ->
          RuntimeConfiguration'
            Prelude.<$> (x Core..:? "TelemetryConfiguration")
      )

instance Prelude.Hashable RuntimeConfiguration

instance Prelude.NFData RuntimeConfiguration
