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
-- Module      : Amazonka.EC2.Types.VolumeStatusInfo
-- Copyright   : (c) 2013-2022 Brendan Hay
-- License     : Mozilla Public License, v. 2.0.
-- Maintainer  : Brendan Hay <brendan.g.hay+amazonka@gmail.com>
-- Stability   : auto-generated
-- Portability : non-portable (GHC extensions)
module Amazonka.EC2.Types.VolumeStatusInfo where

import qualified Amazonka.Core as Core
import Amazonka.EC2.Internal
import Amazonka.EC2.Types.VolumeStatusDetails
import Amazonka.EC2.Types.VolumeStatusInfoStatus
import qualified Amazonka.Lens as Lens
import qualified Amazonka.Prelude as Prelude

-- | Describes the status of a volume.
--
-- /See:/ 'newVolumeStatusInfo' smart constructor.
data VolumeStatusInfo = VolumeStatusInfo'
  { -- | The status of the volume.
    status :: Prelude.Maybe VolumeStatusInfoStatus,
    -- | The details of the volume status.
    details :: Prelude.Maybe [VolumeStatusDetails]
  }
  deriving (Prelude.Eq, Prelude.Read, Prelude.Show, Prelude.Generic)

-- |
-- Create a value of 'VolumeStatusInfo' with all optional fields omitted.
--
-- Use <https://hackage.haskell.org/package/generic-lens generic-lens> or <https://hackage.haskell.org/package/optics optics> to modify other optional fields.
--
-- The following record fields are available, with the corresponding lenses provided
-- for backwards compatibility:
--
-- 'status', 'volumeStatusInfo_status' - The status of the volume.
--
-- 'details', 'volumeStatusInfo_details' - The details of the volume status.
newVolumeStatusInfo ::
  VolumeStatusInfo
newVolumeStatusInfo =
  VolumeStatusInfo'
    { status = Prelude.Nothing,
      details = Prelude.Nothing
    }

-- | The status of the volume.
volumeStatusInfo_status :: Lens.Lens' VolumeStatusInfo (Prelude.Maybe VolumeStatusInfoStatus)
volumeStatusInfo_status = Lens.lens (\VolumeStatusInfo' {status} -> status) (\s@VolumeStatusInfo' {} a -> s {status = a} :: VolumeStatusInfo)

-- | The details of the volume status.
volumeStatusInfo_details :: Lens.Lens' VolumeStatusInfo (Prelude.Maybe [VolumeStatusDetails])
volumeStatusInfo_details = Lens.lens (\VolumeStatusInfo' {details} -> details) (\s@VolumeStatusInfo' {} a -> s {details = a} :: VolumeStatusInfo) Prelude.. Lens.mapping Lens.coerced

instance Core.FromXML VolumeStatusInfo where
  parseXML x =
    VolumeStatusInfo'
      Prelude.<$> (x Core..@? "status")
      Prelude.<*> ( x Core..@? "details" Core..!@ Prelude.mempty
                      Prelude.>>= Core.may (Core.parseXMLList "item")
                  )

instance Prelude.Hashable VolumeStatusInfo where
  hashWithSalt _salt VolumeStatusInfo' {..} =
    _salt `Prelude.hashWithSalt` status
      `Prelude.hashWithSalt` details

instance Prelude.NFData VolumeStatusInfo where
  rnf VolumeStatusInfo' {..} =
    Prelude.rnf status
      `Prelude.seq` Prelude.rnf details
