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
-- Module      : Amazonka.EC2.Types.ProcessorInfo
-- Copyright   : (c) 2013-2021 Brendan Hay
-- License     : Mozilla Public License, v. 2.0.
-- Maintainer  : Brendan Hay <brendan.g.hay+amazonka@gmail.com>
-- Stability   : auto-generated
-- Portability : non-portable (GHC extensions)
module Amazonka.EC2.Types.ProcessorInfo where

import qualified Amazonka.Core as Core
import Amazonka.EC2.Internal
import Amazonka.EC2.Types.ArchitectureType
import qualified Amazonka.Lens as Lens
import qualified Amazonka.Prelude as Prelude

-- | Describes the processor used by the instance type.
--
-- /See:/ 'newProcessorInfo' smart constructor.
data ProcessorInfo = ProcessorInfo'
  { -- | The architectures supported by the instance type.
    supportedArchitectures :: Prelude.Maybe [ArchitectureType],
    -- | The speed of the processor, in GHz.
    sustainedClockSpeedInGhz :: Prelude.Maybe Prelude.Double
  }
  deriving (Prelude.Eq, Prelude.Read, Prelude.Show, Prelude.Generic)

-- |
-- Create a value of 'ProcessorInfo' with all optional fields omitted.
--
-- Use <https://hackage.haskell.org/package/generic-lens generic-lens> or <https://hackage.haskell.org/package/optics optics> to modify other optional fields.
--
-- The following record fields are available, with the corresponding lenses provided
-- for backwards compatibility:
--
-- 'supportedArchitectures', 'processorInfo_supportedArchitectures' - The architectures supported by the instance type.
--
-- 'sustainedClockSpeedInGhz', 'processorInfo_sustainedClockSpeedInGhz' - The speed of the processor, in GHz.
newProcessorInfo ::
  ProcessorInfo
newProcessorInfo =
  ProcessorInfo'
    { supportedArchitectures =
        Prelude.Nothing,
      sustainedClockSpeedInGhz = Prelude.Nothing
    }

-- | The architectures supported by the instance type.
processorInfo_supportedArchitectures :: Lens.Lens' ProcessorInfo (Prelude.Maybe [ArchitectureType])
processorInfo_supportedArchitectures = Lens.lens (\ProcessorInfo' {supportedArchitectures} -> supportedArchitectures) (\s@ProcessorInfo' {} a -> s {supportedArchitectures = a} :: ProcessorInfo) Prelude.. Lens.mapping Lens.coerced

-- | The speed of the processor, in GHz.
processorInfo_sustainedClockSpeedInGhz :: Lens.Lens' ProcessorInfo (Prelude.Maybe Prelude.Double)
processorInfo_sustainedClockSpeedInGhz = Lens.lens (\ProcessorInfo' {sustainedClockSpeedInGhz} -> sustainedClockSpeedInGhz) (\s@ProcessorInfo' {} a -> s {sustainedClockSpeedInGhz = a} :: ProcessorInfo)

instance Core.FromXML ProcessorInfo where
  parseXML x =
    ProcessorInfo'
      Prelude.<$> ( x Core..@? "supportedArchitectures"
                      Core..!@ Prelude.mempty
                      Prelude.>>= Core.may (Core.parseXMLList "item")
                  )
      Prelude.<*> (x Core..@? "sustainedClockSpeedInGhz")

instance Prelude.Hashable ProcessorInfo where
  hashWithSalt salt' ProcessorInfo' {..} =
    salt'
      `Prelude.hashWithSalt` sustainedClockSpeedInGhz
      `Prelude.hashWithSalt` supportedArchitectures

instance Prelude.NFData ProcessorInfo where
  rnf ProcessorInfo' {..} =
    Prelude.rnf supportedArchitectures
      `Prelude.seq` Prelude.rnf sustainedClockSpeedInGhz
