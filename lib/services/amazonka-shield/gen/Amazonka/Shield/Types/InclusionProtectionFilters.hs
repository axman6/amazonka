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
-- Module      : Amazonka.Shield.Types.InclusionProtectionFilters
-- Copyright   : (c) 2013-2022 Brendan Hay
-- License     : Mozilla Public License, v. 2.0.
-- Maintainer  : Brendan Hay <brendan.g.hay+amazonka@gmail.com>
-- Stability   : auto-generated
-- Portability : non-portable (GHC extensions)
module Amazonka.Shield.Types.InclusionProtectionFilters where

import qualified Amazonka.Core as Core
import qualified Amazonka.Lens as Lens
import qualified Amazonka.Prelude as Prelude
import Amazonka.Shield.Types.ProtectedResourceType

-- | Narrows the set of protections that the call retrieves. You can retrieve
-- a single protection by providing its name or the ARN (Amazon Resource
-- Name) of its protected resource. You can also retrieve all protections
-- for a specific resource type. You can provide up to one criteria per
-- filter type. Shield Advanced returns protections that exactly match all
-- of the filter criteria that you provide.
--
-- /See:/ 'newInclusionProtectionFilters' smart constructor.
data InclusionProtectionFilters = InclusionProtectionFilters'
  { -- | The type of protected resource whose protections you want to retrieve.
    resourceTypes :: Prelude.Maybe (Prelude.NonEmpty ProtectedResourceType),
    -- | The name of the protection that you want to retrieve.
    protectionNames :: Prelude.Maybe (Prelude.NonEmpty Prelude.Text),
    -- | The ARN (Amazon Resource Name) of the resource whose protection you want
    -- to retrieve.
    resourceArns :: Prelude.Maybe (Prelude.NonEmpty Prelude.Text)
  }
  deriving (Prelude.Eq, Prelude.Read, Prelude.Show, Prelude.Generic)

-- |
-- Create a value of 'InclusionProtectionFilters' with all optional fields omitted.
--
-- Use <https://hackage.haskell.org/package/generic-lens generic-lens> or <https://hackage.haskell.org/package/optics optics> to modify other optional fields.
--
-- The following record fields are available, with the corresponding lenses provided
-- for backwards compatibility:
--
-- 'resourceTypes', 'inclusionProtectionFilters_resourceTypes' - The type of protected resource whose protections you want to retrieve.
--
-- 'protectionNames', 'inclusionProtectionFilters_protectionNames' - The name of the protection that you want to retrieve.
--
-- 'resourceArns', 'inclusionProtectionFilters_resourceArns' - The ARN (Amazon Resource Name) of the resource whose protection you want
-- to retrieve.
newInclusionProtectionFilters ::
  InclusionProtectionFilters
newInclusionProtectionFilters =
  InclusionProtectionFilters'
    { resourceTypes =
        Prelude.Nothing,
      protectionNames = Prelude.Nothing,
      resourceArns = Prelude.Nothing
    }

-- | The type of protected resource whose protections you want to retrieve.
inclusionProtectionFilters_resourceTypes :: Lens.Lens' InclusionProtectionFilters (Prelude.Maybe (Prelude.NonEmpty ProtectedResourceType))
inclusionProtectionFilters_resourceTypes = Lens.lens (\InclusionProtectionFilters' {resourceTypes} -> resourceTypes) (\s@InclusionProtectionFilters' {} a -> s {resourceTypes = a} :: InclusionProtectionFilters) Prelude.. Lens.mapping Lens.coerced

-- | The name of the protection that you want to retrieve.
inclusionProtectionFilters_protectionNames :: Lens.Lens' InclusionProtectionFilters (Prelude.Maybe (Prelude.NonEmpty Prelude.Text))
inclusionProtectionFilters_protectionNames = Lens.lens (\InclusionProtectionFilters' {protectionNames} -> protectionNames) (\s@InclusionProtectionFilters' {} a -> s {protectionNames = a} :: InclusionProtectionFilters) Prelude.. Lens.mapping Lens.coerced

-- | The ARN (Amazon Resource Name) of the resource whose protection you want
-- to retrieve.
inclusionProtectionFilters_resourceArns :: Lens.Lens' InclusionProtectionFilters (Prelude.Maybe (Prelude.NonEmpty Prelude.Text))
inclusionProtectionFilters_resourceArns = Lens.lens (\InclusionProtectionFilters' {resourceArns} -> resourceArns) (\s@InclusionProtectionFilters' {} a -> s {resourceArns = a} :: InclusionProtectionFilters) Prelude.. Lens.mapping Lens.coerced

instance Prelude.Hashable InclusionProtectionFilters where
  hashWithSalt _salt InclusionProtectionFilters' {..} =
    _salt `Prelude.hashWithSalt` resourceTypes
      `Prelude.hashWithSalt` protectionNames
      `Prelude.hashWithSalt` resourceArns

instance Prelude.NFData InclusionProtectionFilters where
  rnf InclusionProtectionFilters' {..} =
    Prelude.rnf resourceTypes
      `Prelude.seq` Prelude.rnf protectionNames
      `Prelude.seq` Prelude.rnf resourceArns

instance Core.ToJSON InclusionProtectionFilters where
  toJSON InclusionProtectionFilters' {..} =
    Core.object
      ( Prelude.catMaybes
          [ ("ResourceTypes" Core..=) Prelude.<$> resourceTypes,
            ("ProtectionNames" Core..=)
              Prelude.<$> protectionNames,
            ("ResourceArns" Core..=) Prelude.<$> resourceArns
          ]
      )
