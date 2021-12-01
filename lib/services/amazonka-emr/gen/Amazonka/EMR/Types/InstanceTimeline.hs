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
-- Module      : Amazonka.EMR.Types.InstanceTimeline
-- Copyright   : (c) 2013-2021 Brendan Hay
-- License     : Mozilla Public License, v. 2.0.
-- Maintainer  : Brendan Hay <brendan.g.hay+amazonka@gmail.com>
-- Stability   : auto-generated
-- Portability : non-portable (GHC extensions)
module Amazonka.EMR.Types.InstanceTimeline where

import qualified Amazonka.Core as Core
import qualified Amazonka.Lens as Lens
import qualified Amazonka.Prelude as Prelude

-- | The timeline of the instance lifecycle.
--
-- /See:/ 'newInstanceTimeline' smart constructor.
data InstanceTimeline = InstanceTimeline'
  { -- | The date and time when the instance was ready to perform tasks.
    readyDateTime :: Prelude.Maybe Core.POSIX,
    -- | The creation date and time of the instance.
    creationDateTime :: Prelude.Maybe Core.POSIX,
    -- | The date and time when the instance was terminated.
    endDateTime :: Prelude.Maybe Core.POSIX
  }
  deriving (Prelude.Eq, Prelude.Read, Prelude.Show, Prelude.Generic)

-- |
-- Create a value of 'InstanceTimeline' with all optional fields omitted.
--
-- Use <https://hackage.haskell.org/package/generic-lens generic-lens> or <https://hackage.haskell.org/package/optics optics> to modify other optional fields.
--
-- The following record fields are available, with the corresponding lenses provided
-- for backwards compatibility:
--
-- 'readyDateTime', 'instanceTimeline_readyDateTime' - The date and time when the instance was ready to perform tasks.
--
-- 'creationDateTime', 'instanceTimeline_creationDateTime' - The creation date and time of the instance.
--
-- 'endDateTime', 'instanceTimeline_endDateTime' - The date and time when the instance was terminated.
newInstanceTimeline ::
  InstanceTimeline
newInstanceTimeline =
  InstanceTimeline'
    { readyDateTime = Prelude.Nothing,
      creationDateTime = Prelude.Nothing,
      endDateTime = Prelude.Nothing
    }

-- | The date and time when the instance was ready to perform tasks.
instanceTimeline_readyDateTime :: Lens.Lens' InstanceTimeline (Prelude.Maybe Prelude.UTCTime)
instanceTimeline_readyDateTime = Lens.lens (\InstanceTimeline' {readyDateTime} -> readyDateTime) (\s@InstanceTimeline' {} a -> s {readyDateTime = a} :: InstanceTimeline) Prelude.. Lens.mapping Core._Time

-- | The creation date and time of the instance.
instanceTimeline_creationDateTime :: Lens.Lens' InstanceTimeline (Prelude.Maybe Prelude.UTCTime)
instanceTimeline_creationDateTime = Lens.lens (\InstanceTimeline' {creationDateTime} -> creationDateTime) (\s@InstanceTimeline' {} a -> s {creationDateTime = a} :: InstanceTimeline) Prelude.. Lens.mapping Core._Time

-- | The date and time when the instance was terminated.
instanceTimeline_endDateTime :: Lens.Lens' InstanceTimeline (Prelude.Maybe Prelude.UTCTime)
instanceTimeline_endDateTime = Lens.lens (\InstanceTimeline' {endDateTime} -> endDateTime) (\s@InstanceTimeline' {} a -> s {endDateTime = a} :: InstanceTimeline) Prelude.. Lens.mapping Core._Time

instance Core.FromJSON InstanceTimeline where
  parseJSON =
    Core.withObject
      "InstanceTimeline"
      ( \x ->
          InstanceTimeline'
            Prelude.<$> (x Core..:? "ReadyDateTime")
            Prelude.<*> (x Core..:? "CreationDateTime")
            Prelude.<*> (x Core..:? "EndDateTime")
      )

instance Prelude.Hashable InstanceTimeline where
  hashWithSalt salt' InstanceTimeline' {..} =
    salt' `Prelude.hashWithSalt` endDateTime
      `Prelude.hashWithSalt` creationDateTime
      `Prelude.hashWithSalt` readyDateTime

instance Prelude.NFData InstanceTimeline where
  rnf InstanceTimeline' {..} =
    Prelude.rnf readyDateTime
      `Prelude.seq` Prelude.rnf endDateTime
      `Prelude.seq` Prelude.rnf creationDateTime
