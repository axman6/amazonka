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
-- Module      : Amazonka.EKS.Types.Compatibility
-- Copyright   : (c) 2013-2021 Brendan Hay
-- License     : Mozilla Public License, v. 2.0.
-- Maintainer  : Brendan Hay <brendan.g.hay+amazonka@gmail.com>
-- Stability   : auto-generated
-- Portability : non-portable (GHC extensions)
module Amazonka.EKS.Types.Compatibility where

import qualified Amazonka.Core as Core
import qualified Amazonka.Lens as Lens
import qualified Amazonka.Prelude as Prelude

-- | Compatibility information.
--
-- /See:/ 'newCompatibility' smart constructor.
data Compatibility = Compatibility'
  { -- | The supported default version.
    defaultVersion :: Prelude.Maybe Prelude.Bool,
    -- | The supported Kubernetes version of the cluster.
    clusterVersion :: Prelude.Maybe Prelude.Text,
    -- | The supported compute platform.
    platformVersions :: Prelude.Maybe [Prelude.Text]
  }
  deriving (Prelude.Eq, Prelude.Read, Prelude.Show, Prelude.Generic)

-- |
-- Create a value of 'Compatibility' with all optional fields omitted.
--
-- Use <https://hackage.haskell.org/package/generic-lens generic-lens> or <https://hackage.haskell.org/package/optics optics> to modify other optional fields.
--
-- The following record fields are available, with the corresponding lenses provided
-- for backwards compatibility:
--
-- 'defaultVersion', 'compatibility_defaultVersion' - The supported default version.
--
-- 'clusterVersion', 'compatibility_clusterVersion' - The supported Kubernetes version of the cluster.
--
-- 'platformVersions', 'compatibility_platformVersions' - The supported compute platform.
newCompatibility ::
  Compatibility
newCompatibility =
  Compatibility'
    { defaultVersion = Prelude.Nothing,
      clusterVersion = Prelude.Nothing,
      platformVersions = Prelude.Nothing
    }

-- | The supported default version.
compatibility_defaultVersion :: Lens.Lens' Compatibility (Prelude.Maybe Prelude.Bool)
compatibility_defaultVersion = Lens.lens (\Compatibility' {defaultVersion} -> defaultVersion) (\s@Compatibility' {} a -> s {defaultVersion = a} :: Compatibility)

-- | The supported Kubernetes version of the cluster.
compatibility_clusterVersion :: Lens.Lens' Compatibility (Prelude.Maybe Prelude.Text)
compatibility_clusterVersion = Lens.lens (\Compatibility' {clusterVersion} -> clusterVersion) (\s@Compatibility' {} a -> s {clusterVersion = a} :: Compatibility)

-- | The supported compute platform.
compatibility_platformVersions :: Lens.Lens' Compatibility (Prelude.Maybe [Prelude.Text])
compatibility_platformVersions = Lens.lens (\Compatibility' {platformVersions} -> platformVersions) (\s@Compatibility' {} a -> s {platformVersions = a} :: Compatibility) Prelude.. Lens.mapping Lens.coerced

instance Core.FromJSON Compatibility where
  parseJSON =
    Core.withObject
      "Compatibility"
      ( \x ->
          Compatibility'
            Prelude.<$> (x Core..:? "defaultVersion")
            Prelude.<*> (x Core..:? "clusterVersion")
            Prelude.<*> ( x Core..:? "platformVersions"
                            Core..!= Prelude.mempty
                        )
      )

instance Prelude.Hashable Compatibility

instance Prelude.NFData Compatibility
