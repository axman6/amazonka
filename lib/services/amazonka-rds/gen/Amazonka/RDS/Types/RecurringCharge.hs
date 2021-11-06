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
-- Module      : Amazonka.RDS.Types.RecurringCharge
-- Copyright   : (c) 2013-2021 Brendan Hay
-- License     : Mozilla Public License, v. 2.0.
-- Maintainer  : Brendan Hay <brendan.g.hay+amazonka@gmail.com>
-- Stability   : auto-generated
-- Portability : non-portable (GHC extensions)
module Amazonka.RDS.Types.RecurringCharge where

import qualified Amazonka.Core as Core
import qualified Amazonka.Lens as Lens
import qualified Amazonka.Prelude as Prelude

-- | This data type is used as a response element in the
-- @DescribeReservedDBInstances@ and @DescribeReservedDBInstancesOfferings@
-- actions.
--
-- /See:/ 'newRecurringCharge' smart constructor.
data RecurringCharge = RecurringCharge'
  { -- | The frequency of the recurring charge.
    recurringChargeFrequency :: Prelude.Maybe Prelude.Text,
    -- | The amount of the recurring charge.
    recurringChargeAmount :: Prelude.Maybe Prelude.Double
  }
  deriving (Prelude.Eq, Prelude.Read, Prelude.Show, Prelude.Generic)

-- |
-- Create a value of 'RecurringCharge' with all optional fields omitted.
--
-- Use <https://hackage.haskell.org/package/generic-lens generic-lens> or <https://hackage.haskell.org/package/optics optics> to modify other optional fields.
--
-- The following record fields are available, with the corresponding lenses provided
-- for backwards compatibility:
--
-- 'recurringChargeFrequency', 'recurringCharge_recurringChargeFrequency' - The frequency of the recurring charge.
--
-- 'recurringChargeAmount', 'recurringCharge_recurringChargeAmount' - The amount of the recurring charge.
newRecurringCharge ::
  RecurringCharge
newRecurringCharge =
  RecurringCharge'
    { recurringChargeFrequency =
        Prelude.Nothing,
      recurringChargeAmount = Prelude.Nothing
    }

-- | The frequency of the recurring charge.
recurringCharge_recurringChargeFrequency :: Lens.Lens' RecurringCharge (Prelude.Maybe Prelude.Text)
recurringCharge_recurringChargeFrequency = Lens.lens (\RecurringCharge' {recurringChargeFrequency} -> recurringChargeFrequency) (\s@RecurringCharge' {} a -> s {recurringChargeFrequency = a} :: RecurringCharge)

-- | The amount of the recurring charge.
recurringCharge_recurringChargeAmount :: Lens.Lens' RecurringCharge (Prelude.Maybe Prelude.Double)
recurringCharge_recurringChargeAmount = Lens.lens (\RecurringCharge' {recurringChargeAmount} -> recurringChargeAmount) (\s@RecurringCharge' {} a -> s {recurringChargeAmount = a} :: RecurringCharge)

instance Core.FromXML RecurringCharge where
  parseXML x =
    RecurringCharge'
      Prelude.<$> (x Core..@? "RecurringChargeFrequency")
      Prelude.<*> (x Core..@? "RecurringChargeAmount")

instance Prelude.Hashable RecurringCharge

instance Prelude.NFData RecurringCharge
