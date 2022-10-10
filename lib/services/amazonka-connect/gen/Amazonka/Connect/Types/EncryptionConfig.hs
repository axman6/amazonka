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
-- Module      : Amazonka.Connect.Types.EncryptionConfig
-- Copyright   : (c) 2013-2022 Brendan Hay
-- License     : Mozilla Public License, v. 2.0.
-- Maintainer  : Brendan Hay <brendan.g.hay+amazonka@gmail.com>
-- Stability   : auto-generated
-- Portability : non-portable (GHC extensions)
module Amazonka.Connect.Types.EncryptionConfig where

import Amazonka.Connect.Types.EncryptionType
import qualified Amazonka.Core as Core
import qualified Amazonka.Lens as Lens
import qualified Amazonka.Prelude as Prelude

-- | The encryption configuration.
--
-- /See:/ 'newEncryptionConfig' smart constructor.
data EncryptionConfig = EncryptionConfig'
  { -- | The type of encryption.
    encryptionType :: EncryptionType,
    -- | The full ARN of the encryption key.
    --
    -- Be sure to provide the full ARN of the encryption key, not just the ID.
    keyId :: Prelude.Text
  }
  deriving (Prelude.Eq, Prelude.Read, Prelude.Show, Prelude.Generic)

-- |
-- Create a value of 'EncryptionConfig' with all optional fields omitted.
--
-- Use <https://hackage.haskell.org/package/generic-lens generic-lens> or <https://hackage.haskell.org/package/optics optics> to modify other optional fields.
--
-- The following record fields are available, with the corresponding lenses provided
-- for backwards compatibility:
--
-- 'encryptionType', 'encryptionConfig_encryptionType' - The type of encryption.
--
-- 'keyId', 'encryptionConfig_keyId' - The full ARN of the encryption key.
--
-- Be sure to provide the full ARN of the encryption key, not just the ID.
newEncryptionConfig ::
  -- | 'encryptionType'
  EncryptionType ->
  -- | 'keyId'
  Prelude.Text ->
  EncryptionConfig
newEncryptionConfig pEncryptionType_ pKeyId_ =
  EncryptionConfig'
    { encryptionType =
        pEncryptionType_,
      keyId = pKeyId_
    }

-- | The type of encryption.
encryptionConfig_encryptionType :: Lens.Lens' EncryptionConfig EncryptionType
encryptionConfig_encryptionType = Lens.lens (\EncryptionConfig' {encryptionType} -> encryptionType) (\s@EncryptionConfig' {} a -> s {encryptionType = a} :: EncryptionConfig)

-- | The full ARN of the encryption key.
--
-- Be sure to provide the full ARN of the encryption key, not just the ID.
encryptionConfig_keyId :: Lens.Lens' EncryptionConfig Prelude.Text
encryptionConfig_keyId = Lens.lens (\EncryptionConfig' {keyId} -> keyId) (\s@EncryptionConfig' {} a -> s {keyId = a} :: EncryptionConfig)

instance Core.FromJSON EncryptionConfig where
  parseJSON =
    Core.withObject
      "EncryptionConfig"
      ( \x ->
          EncryptionConfig'
            Prelude.<$> (x Core..: "EncryptionType")
            Prelude.<*> (x Core..: "KeyId")
      )

instance Prelude.Hashable EncryptionConfig where
  hashWithSalt _salt EncryptionConfig' {..} =
    _salt `Prelude.hashWithSalt` encryptionType
      `Prelude.hashWithSalt` keyId

instance Prelude.NFData EncryptionConfig where
  rnf EncryptionConfig' {..} =
    Prelude.rnf encryptionType
      `Prelude.seq` Prelude.rnf keyId

instance Core.ToJSON EncryptionConfig where
  toJSON EncryptionConfig' {..} =
    Core.object
      ( Prelude.catMaybes
          [ Prelude.Just
              ("EncryptionType" Core..= encryptionType),
            Prelude.Just ("KeyId" Core..= keyId)
          ]
      )
