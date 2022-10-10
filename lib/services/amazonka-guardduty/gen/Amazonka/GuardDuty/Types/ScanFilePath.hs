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
-- Module      : Amazonka.GuardDuty.Types.ScanFilePath
-- Copyright   : (c) 2013-2022 Brendan Hay
-- License     : Mozilla Public License, v. 2.0.
-- Maintainer  : Brendan Hay <brendan.g.hay+amazonka@gmail.com>
-- Stability   : auto-generated
-- Portability : non-portable (GHC extensions)
module Amazonka.GuardDuty.Types.ScanFilePath where

import qualified Amazonka.Core as Core
import qualified Amazonka.Lens as Lens
import qualified Amazonka.Prelude as Prelude

-- | Contains details of infected file including name, file path and hash.
--
-- /See:/ 'newScanFilePath' smart constructor.
data ScanFilePath = ScanFilePath'
  { -- | The file path of the infected file.
    filePath :: Prelude.Maybe Prelude.Text,
    -- | The hash value of the infected file.
    hash :: Prelude.Maybe Prelude.Text,
    -- | File name of the infected file.
    fileName :: Prelude.Maybe Prelude.Text,
    -- | EBS volume Arn details of the infected file.
    volumeArn :: Prelude.Maybe Prelude.Text
  }
  deriving (Prelude.Eq, Prelude.Read, Prelude.Show, Prelude.Generic)

-- |
-- Create a value of 'ScanFilePath' with all optional fields omitted.
--
-- Use <https://hackage.haskell.org/package/generic-lens generic-lens> or <https://hackage.haskell.org/package/optics optics> to modify other optional fields.
--
-- The following record fields are available, with the corresponding lenses provided
-- for backwards compatibility:
--
-- 'filePath', 'scanFilePath_filePath' - The file path of the infected file.
--
-- 'hash', 'scanFilePath_hash' - The hash value of the infected file.
--
-- 'fileName', 'scanFilePath_fileName' - File name of the infected file.
--
-- 'volumeArn', 'scanFilePath_volumeArn' - EBS volume Arn details of the infected file.
newScanFilePath ::
  ScanFilePath
newScanFilePath =
  ScanFilePath'
    { filePath = Prelude.Nothing,
      hash = Prelude.Nothing,
      fileName = Prelude.Nothing,
      volumeArn = Prelude.Nothing
    }

-- | The file path of the infected file.
scanFilePath_filePath :: Lens.Lens' ScanFilePath (Prelude.Maybe Prelude.Text)
scanFilePath_filePath = Lens.lens (\ScanFilePath' {filePath} -> filePath) (\s@ScanFilePath' {} a -> s {filePath = a} :: ScanFilePath)

-- | The hash value of the infected file.
scanFilePath_hash :: Lens.Lens' ScanFilePath (Prelude.Maybe Prelude.Text)
scanFilePath_hash = Lens.lens (\ScanFilePath' {hash} -> hash) (\s@ScanFilePath' {} a -> s {hash = a} :: ScanFilePath)

-- | File name of the infected file.
scanFilePath_fileName :: Lens.Lens' ScanFilePath (Prelude.Maybe Prelude.Text)
scanFilePath_fileName = Lens.lens (\ScanFilePath' {fileName} -> fileName) (\s@ScanFilePath' {} a -> s {fileName = a} :: ScanFilePath)

-- | EBS volume Arn details of the infected file.
scanFilePath_volumeArn :: Lens.Lens' ScanFilePath (Prelude.Maybe Prelude.Text)
scanFilePath_volumeArn = Lens.lens (\ScanFilePath' {volumeArn} -> volumeArn) (\s@ScanFilePath' {} a -> s {volumeArn = a} :: ScanFilePath)

instance Core.FromJSON ScanFilePath where
  parseJSON =
    Core.withObject
      "ScanFilePath"
      ( \x ->
          ScanFilePath'
            Prelude.<$> (x Core..:? "filePath")
            Prelude.<*> (x Core..:? "hash")
            Prelude.<*> (x Core..:? "fileName")
            Prelude.<*> (x Core..:? "volumeArn")
      )

instance Prelude.Hashable ScanFilePath where
  hashWithSalt _salt ScanFilePath' {..} =
    _salt `Prelude.hashWithSalt` filePath
      `Prelude.hashWithSalt` hash
      `Prelude.hashWithSalt` fileName
      `Prelude.hashWithSalt` volumeArn

instance Prelude.NFData ScanFilePath where
  rnf ScanFilePath' {..} =
    Prelude.rnf filePath
      `Prelude.seq` Prelude.rnf hash
      `Prelude.seq` Prelude.rnf fileName
      `Prelude.seq` Prelude.rnf volumeArn
