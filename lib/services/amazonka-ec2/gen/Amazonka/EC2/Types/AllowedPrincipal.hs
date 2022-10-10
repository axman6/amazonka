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
-- Module      : Amazonka.EC2.Types.AllowedPrincipal
-- Copyright   : (c) 2013-2022 Brendan Hay
-- License     : Mozilla Public License, v. 2.0.
-- Maintainer  : Brendan Hay <brendan.g.hay+amazonka@gmail.com>
-- Stability   : auto-generated
-- Portability : non-portable (GHC extensions)
module Amazonka.EC2.Types.AllowedPrincipal where

import qualified Amazonka.Core as Core
import Amazonka.EC2.Internal
import Amazonka.EC2.Types.PrincipalType
import Amazonka.EC2.Types.Tag
import qualified Amazonka.Lens as Lens
import qualified Amazonka.Prelude as Prelude

-- | Describes a principal.
--
-- /See:/ 'newAllowedPrincipal' smart constructor.
data AllowedPrincipal = AllowedPrincipal'
  { -- | The tags.
    tags :: Prelude.Maybe [Tag],
    -- | The Amazon Resource Name (ARN) of the principal.
    principal :: Prelude.Maybe Prelude.Text,
    -- | The ID of the service permission.
    servicePermissionId :: Prelude.Maybe Prelude.Text,
    -- | The type of principal.
    principalType :: Prelude.Maybe PrincipalType,
    -- | The ID of the service.
    serviceId :: Prelude.Maybe Prelude.Text
  }
  deriving (Prelude.Eq, Prelude.Read, Prelude.Show, Prelude.Generic)

-- |
-- Create a value of 'AllowedPrincipal' with all optional fields omitted.
--
-- Use <https://hackage.haskell.org/package/generic-lens generic-lens> or <https://hackage.haskell.org/package/optics optics> to modify other optional fields.
--
-- The following record fields are available, with the corresponding lenses provided
-- for backwards compatibility:
--
-- 'tags', 'allowedPrincipal_tags' - The tags.
--
-- 'principal', 'allowedPrincipal_principal' - The Amazon Resource Name (ARN) of the principal.
--
-- 'servicePermissionId', 'allowedPrincipal_servicePermissionId' - The ID of the service permission.
--
-- 'principalType', 'allowedPrincipal_principalType' - The type of principal.
--
-- 'serviceId', 'allowedPrincipal_serviceId' - The ID of the service.
newAllowedPrincipal ::
  AllowedPrincipal
newAllowedPrincipal =
  AllowedPrincipal'
    { tags = Prelude.Nothing,
      principal = Prelude.Nothing,
      servicePermissionId = Prelude.Nothing,
      principalType = Prelude.Nothing,
      serviceId = Prelude.Nothing
    }

-- | The tags.
allowedPrincipal_tags :: Lens.Lens' AllowedPrincipal (Prelude.Maybe [Tag])
allowedPrincipal_tags = Lens.lens (\AllowedPrincipal' {tags} -> tags) (\s@AllowedPrincipal' {} a -> s {tags = a} :: AllowedPrincipal) Prelude.. Lens.mapping Lens.coerced

-- | The Amazon Resource Name (ARN) of the principal.
allowedPrincipal_principal :: Lens.Lens' AllowedPrincipal (Prelude.Maybe Prelude.Text)
allowedPrincipal_principal = Lens.lens (\AllowedPrincipal' {principal} -> principal) (\s@AllowedPrincipal' {} a -> s {principal = a} :: AllowedPrincipal)

-- | The ID of the service permission.
allowedPrincipal_servicePermissionId :: Lens.Lens' AllowedPrincipal (Prelude.Maybe Prelude.Text)
allowedPrincipal_servicePermissionId = Lens.lens (\AllowedPrincipal' {servicePermissionId} -> servicePermissionId) (\s@AllowedPrincipal' {} a -> s {servicePermissionId = a} :: AllowedPrincipal)

-- | The type of principal.
allowedPrincipal_principalType :: Lens.Lens' AllowedPrincipal (Prelude.Maybe PrincipalType)
allowedPrincipal_principalType = Lens.lens (\AllowedPrincipal' {principalType} -> principalType) (\s@AllowedPrincipal' {} a -> s {principalType = a} :: AllowedPrincipal)

-- | The ID of the service.
allowedPrincipal_serviceId :: Lens.Lens' AllowedPrincipal (Prelude.Maybe Prelude.Text)
allowedPrincipal_serviceId = Lens.lens (\AllowedPrincipal' {serviceId} -> serviceId) (\s@AllowedPrincipal' {} a -> s {serviceId = a} :: AllowedPrincipal)

instance Core.FromXML AllowedPrincipal where
  parseXML x =
    AllowedPrincipal'
      Prelude.<$> ( x Core..@? "tagSet" Core..!@ Prelude.mempty
                      Prelude.>>= Core.may (Core.parseXMLList "item")
                  )
      Prelude.<*> (x Core..@? "principal")
      Prelude.<*> (x Core..@? "servicePermissionId")
      Prelude.<*> (x Core..@? "principalType")
      Prelude.<*> (x Core..@? "serviceId")

instance Prelude.Hashable AllowedPrincipal where
  hashWithSalt _salt AllowedPrincipal' {..} =
    _salt `Prelude.hashWithSalt` tags
      `Prelude.hashWithSalt` principal
      `Prelude.hashWithSalt` servicePermissionId
      `Prelude.hashWithSalt` principalType
      `Prelude.hashWithSalt` serviceId

instance Prelude.NFData AllowedPrincipal where
  rnf AllowedPrincipal' {..} =
    Prelude.rnf tags
      `Prelude.seq` Prelude.rnf principal
      `Prelude.seq` Prelude.rnf servicePermissionId
      `Prelude.seq` Prelude.rnf principalType
      `Prelude.seq` Prelude.rnf serviceId
