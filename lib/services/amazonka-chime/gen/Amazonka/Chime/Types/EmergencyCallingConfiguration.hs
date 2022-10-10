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
-- Module      : Amazonka.Chime.Types.EmergencyCallingConfiguration
-- Copyright   : (c) 2013-2022 Brendan Hay
-- License     : Mozilla Public License, v. 2.0.
-- Maintainer  : Brendan Hay <brendan.g.hay+amazonka@gmail.com>
-- Stability   : auto-generated
-- Portability : non-portable (GHC extensions)
module Amazonka.Chime.Types.EmergencyCallingConfiguration where

import Amazonka.Chime.Types.DNISEmergencyCallingConfiguration
import qualified Amazonka.Core as Core
import qualified Amazonka.Lens as Lens
import qualified Amazonka.Prelude as Prelude

-- | The emergency calling configuration details associated with an Amazon
-- Chime Voice Connector.
--
-- /See:/ 'newEmergencyCallingConfiguration' smart constructor.
data EmergencyCallingConfiguration = EmergencyCallingConfiguration'
  { -- | The Dialed Number Identification Service (DNIS) emergency calling
    -- configuration details.
    dnis :: Prelude.Maybe [DNISEmergencyCallingConfiguration]
  }
  deriving (Prelude.Eq, Prelude.Show, Prelude.Generic)

-- |
-- Create a value of 'EmergencyCallingConfiguration' with all optional fields omitted.
--
-- Use <https://hackage.haskell.org/package/generic-lens generic-lens> or <https://hackage.haskell.org/package/optics optics> to modify other optional fields.
--
-- The following record fields are available, with the corresponding lenses provided
-- for backwards compatibility:
--
-- 'dnis', 'emergencyCallingConfiguration_dnis' - The Dialed Number Identification Service (DNIS) emergency calling
-- configuration details.
newEmergencyCallingConfiguration ::
  EmergencyCallingConfiguration
newEmergencyCallingConfiguration =
  EmergencyCallingConfiguration'
    { dnis =
        Prelude.Nothing
    }

-- | The Dialed Number Identification Service (DNIS) emergency calling
-- configuration details.
emergencyCallingConfiguration_dnis :: Lens.Lens' EmergencyCallingConfiguration (Prelude.Maybe [DNISEmergencyCallingConfiguration])
emergencyCallingConfiguration_dnis = Lens.lens (\EmergencyCallingConfiguration' {dnis} -> dnis) (\s@EmergencyCallingConfiguration' {} a -> s {dnis = a} :: EmergencyCallingConfiguration) Prelude.. Lens.mapping Lens.coerced

instance Core.FromJSON EmergencyCallingConfiguration where
  parseJSON =
    Core.withObject
      "EmergencyCallingConfiguration"
      ( \x ->
          EmergencyCallingConfiguration'
            Prelude.<$> (x Core..:? "DNIS" Core..!= Prelude.mempty)
      )

instance
  Prelude.Hashable
    EmergencyCallingConfiguration
  where
  hashWithSalt _salt EmergencyCallingConfiguration' {..} =
    _salt `Prelude.hashWithSalt` dnis

instance Prelude.NFData EmergencyCallingConfiguration where
  rnf EmergencyCallingConfiguration' {..} =
    Prelude.rnf dnis

instance Core.ToJSON EmergencyCallingConfiguration where
  toJSON EmergencyCallingConfiguration' {..} =
    Core.object
      ( Prelude.catMaybes
          [("DNIS" Core..=) Prelude.<$> dnis]
      )
