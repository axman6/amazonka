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
-- Module      : Amazonka.Athena.Types.ResultConfiguration
-- Copyright   : (c) 2013-2022 Brendan Hay
-- License     : Mozilla Public License, v. 2.0.
-- Maintainer  : Brendan Hay <brendan.g.hay+amazonka@gmail.com>
-- Stability   : auto-generated
-- Portability : non-portable (GHC extensions)
module Amazonka.Athena.Types.ResultConfiguration where

import Amazonka.Athena.Types.AclConfiguration
import Amazonka.Athena.Types.EncryptionConfiguration
import qualified Amazonka.Core as Core
import qualified Amazonka.Lens as Lens
import qualified Amazonka.Prelude as Prelude

-- | The location in Amazon S3 where query results are stored and the
-- encryption option, if any, used for query results. These are known as
-- \"client-side settings\". If workgroup settings override client-side
-- settings, then the query uses the workgroup settings.
--
-- /See:/ 'newResultConfiguration' smart constructor.
data ResultConfiguration = ResultConfiguration'
  { -- | Indicates that an Amazon S3 canned ACL should be set to control
    -- ownership of stored query results. Currently the only supported canned
    -- ACL is @BUCKET_OWNER_FULL_CONTROL@. This is a client-side setting. If
    -- workgroup settings override client-side settings, then the query uses
    -- the ACL configuration that is specified for the workgroup, and also uses
    -- the location for storing query results specified in the workgroup. For
    -- more information, see
    -- WorkGroupConfiguration$EnforceWorkGroupConfiguration and
    -- <https://docs.aws.amazon.com/athena/latest/ug/workgroups-settings-override.html Workgroup Settings Override Client-Side Settings>.
    aclConfiguration :: Prelude.Maybe AclConfiguration,
    -- | The Amazon Web Services account ID that you expect to be the owner of
    -- the Amazon S3 bucket specified by ResultConfiguration$OutputLocation. If
    -- set, Athena uses the value for @ExpectedBucketOwner@ when it makes
    -- Amazon S3 calls to your specified output location. If the
    -- @ExpectedBucketOwner@ Amazon Web Services account ID does not match the
    -- actual owner of the Amazon S3 bucket, the call fails with a permissions
    -- error.
    --
    -- This is a client-side setting. If workgroup settings override
    -- client-side settings, then the query uses the @ExpectedBucketOwner@
    -- setting that is specified for the workgroup, and also uses the location
    -- for storing query results specified in the workgroup. See
    -- WorkGroupConfiguration$EnforceWorkGroupConfiguration and
    -- <https://docs.aws.amazon.com/athena/latest/ug/workgroups-settings-override.html Workgroup Settings Override Client-Side Settings>.
    expectedBucketOwner :: Prelude.Maybe Prelude.Text,
    -- | The location in Amazon S3 where your query results are stored, such as
    -- @s3:\/\/path\/to\/query\/bucket\/@. To run the query, you must specify
    -- the query results location using one of the ways: either for individual
    -- queries using either this setting (client-side), or in the workgroup,
    -- using WorkGroupConfiguration. If none of them is set, Athena issues an
    -- error that no output location is provided. For more information, see
    -- <https://docs.aws.amazon.com/athena/latest/ug/querying.html Query Results>.
    -- If workgroup settings override client-side settings, then the query uses
    -- the settings specified for the workgroup. See
    -- WorkGroupConfiguration$EnforceWorkGroupConfiguration.
    outputLocation :: Prelude.Maybe Prelude.Text,
    -- | If query results are encrypted in Amazon S3, indicates the encryption
    -- option used (for example, @SSE_KMS@ or @CSE_KMS@) and key information.
    -- This is a client-side setting. If workgroup settings override
    -- client-side settings, then the query uses the encryption configuration
    -- that is specified for the workgroup, and also uses the location for
    -- storing query results specified in the workgroup. See
    -- WorkGroupConfiguration$EnforceWorkGroupConfiguration and
    -- <https://docs.aws.amazon.com/athena/latest/ug/workgroups-settings-override.html Workgroup Settings Override Client-Side Settings>.
    encryptionConfiguration :: Prelude.Maybe EncryptionConfiguration
  }
  deriving (Prelude.Eq, Prelude.Read, Prelude.Show, Prelude.Generic)

-- |
-- Create a value of 'ResultConfiguration' with all optional fields omitted.
--
-- Use <https://hackage.haskell.org/package/generic-lens generic-lens> or <https://hackage.haskell.org/package/optics optics> to modify other optional fields.
--
-- The following record fields are available, with the corresponding lenses provided
-- for backwards compatibility:
--
-- 'aclConfiguration', 'resultConfiguration_aclConfiguration' - Indicates that an Amazon S3 canned ACL should be set to control
-- ownership of stored query results. Currently the only supported canned
-- ACL is @BUCKET_OWNER_FULL_CONTROL@. This is a client-side setting. If
-- workgroup settings override client-side settings, then the query uses
-- the ACL configuration that is specified for the workgroup, and also uses
-- the location for storing query results specified in the workgroup. For
-- more information, see
-- WorkGroupConfiguration$EnforceWorkGroupConfiguration and
-- <https://docs.aws.amazon.com/athena/latest/ug/workgroups-settings-override.html Workgroup Settings Override Client-Side Settings>.
--
-- 'expectedBucketOwner', 'resultConfiguration_expectedBucketOwner' - The Amazon Web Services account ID that you expect to be the owner of
-- the Amazon S3 bucket specified by ResultConfiguration$OutputLocation. If
-- set, Athena uses the value for @ExpectedBucketOwner@ when it makes
-- Amazon S3 calls to your specified output location. If the
-- @ExpectedBucketOwner@ Amazon Web Services account ID does not match the
-- actual owner of the Amazon S3 bucket, the call fails with a permissions
-- error.
--
-- This is a client-side setting. If workgroup settings override
-- client-side settings, then the query uses the @ExpectedBucketOwner@
-- setting that is specified for the workgroup, and also uses the location
-- for storing query results specified in the workgroup. See
-- WorkGroupConfiguration$EnforceWorkGroupConfiguration and
-- <https://docs.aws.amazon.com/athena/latest/ug/workgroups-settings-override.html Workgroup Settings Override Client-Side Settings>.
--
-- 'outputLocation', 'resultConfiguration_outputLocation' - The location in Amazon S3 where your query results are stored, such as
-- @s3:\/\/path\/to\/query\/bucket\/@. To run the query, you must specify
-- the query results location using one of the ways: either for individual
-- queries using either this setting (client-side), or in the workgroup,
-- using WorkGroupConfiguration. If none of them is set, Athena issues an
-- error that no output location is provided. For more information, see
-- <https://docs.aws.amazon.com/athena/latest/ug/querying.html Query Results>.
-- If workgroup settings override client-side settings, then the query uses
-- the settings specified for the workgroup. See
-- WorkGroupConfiguration$EnforceWorkGroupConfiguration.
--
-- 'encryptionConfiguration', 'resultConfiguration_encryptionConfiguration' - If query results are encrypted in Amazon S3, indicates the encryption
-- option used (for example, @SSE_KMS@ or @CSE_KMS@) and key information.
-- This is a client-side setting. If workgroup settings override
-- client-side settings, then the query uses the encryption configuration
-- that is specified for the workgroup, and also uses the location for
-- storing query results specified in the workgroup. See
-- WorkGroupConfiguration$EnforceWorkGroupConfiguration and
-- <https://docs.aws.amazon.com/athena/latest/ug/workgroups-settings-override.html Workgroup Settings Override Client-Side Settings>.
newResultConfiguration ::
  ResultConfiguration
newResultConfiguration =
  ResultConfiguration'
    { aclConfiguration =
        Prelude.Nothing,
      expectedBucketOwner = Prelude.Nothing,
      outputLocation = Prelude.Nothing,
      encryptionConfiguration = Prelude.Nothing
    }

-- | Indicates that an Amazon S3 canned ACL should be set to control
-- ownership of stored query results. Currently the only supported canned
-- ACL is @BUCKET_OWNER_FULL_CONTROL@. This is a client-side setting. If
-- workgroup settings override client-side settings, then the query uses
-- the ACL configuration that is specified for the workgroup, and also uses
-- the location for storing query results specified in the workgroup. For
-- more information, see
-- WorkGroupConfiguration$EnforceWorkGroupConfiguration and
-- <https://docs.aws.amazon.com/athena/latest/ug/workgroups-settings-override.html Workgroup Settings Override Client-Side Settings>.
resultConfiguration_aclConfiguration :: Lens.Lens' ResultConfiguration (Prelude.Maybe AclConfiguration)
resultConfiguration_aclConfiguration = Lens.lens (\ResultConfiguration' {aclConfiguration} -> aclConfiguration) (\s@ResultConfiguration' {} a -> s {aclConfiguration = a} :: ResultConfiguration)

-- | The Amazon Web Services account ID that you expect to be the owner of
-- the Amazon S3 bucket specified by ResultConfiguration$OutputLocation. If
-- set, Athena uses the value for @ExpectedBucketOwner@ when it makes
-- Amazon S3 calls to your specified output location. If the
-- @ExpectedBucketOwner@ Amazon Web Services account ID does not match the
-- actual owner of the Amazon S3 bucket, the call fails with a permissions
-- error.
--
-- This is a client-side setting. If workgroup settings override
-- client-side settings, then the query uses the @ExpectedBucketOwner@
-- setting that is specified for the workgroup, and also uses the location
-- for storing query results specified in the workgroup. See
-- WorkGroupConfiguration$EnforceWorkGroupConfiguration and
-- <https://docs.aws.amazon.com/athena/latest/ug/workgroups-settings-override.html Workgroup Settings Override Client-Side Settings>.
resultConfiguration_expectedBucketOwner :: Lens.Lens' ResultConfiguration (Prelude.Maybe Prelude.Text)
resultConfiguration_expectedBucketOwner = Lens.lens (\ResultConfiguration' {expectedBucketOwner} -> expectedBucketOwner) (\s@ResultConfiguration' {} a -> s {expectedBucketOwner = a} :: ResultConfiguration)

-- | The location in Amazon S3 where your query results are stored, such as
-- @s3:\/\/path\/to\/query\/bucket\/@. To run the query, you must specify
-- the query results location using one of the ways: either for individual
-- queries using either this setting (client-side), or in the workgroup,
-- using WorkGroupConfiguration. If none of them is set, Athena issues an
-- error that no output location is provided. For more information, see
-- <https://docs.aws.amazon.com/athena/latest/ug/querying.html Query Results>.
-- If workgroup settings override client-side settings, then the query uses
-- the settings specified for the workgroup. See
-- WorkGroupConfiguration$EnforceWorkGroupConfiguration.
resultConfiguration_outputLocation :: Lens.Lens' ResultConfiguration (Prelude.Maybe Prelude.Text)
resultConfiguration_outputLocation = Lens.lens (\ResultConfiguration' {outputLocation} -> outputLocation) (\s@ResultConfiguration' {} a -> s {outputLocation = a} :: ResultConfiguration)

-- | If query results are encrypted in Amazon S3, indicates the encryption
-- option used (for example, @SSE_KMS@ or @CSE_KMS@) and key information.
-- This is a client-side setting. If workgroup settings override
-- client-side settings, then the query uses the encryption configuration
-- that is specified for the workgroup, and also uses the location for
-- storing query results specified in the workgroup. See
-- WorkGroupConfiguration$EnforceWorkGroupConfiguration and
-- <https://docs.aws.amazon.com/athena/latest/ug/workgroups-settings-override.html Workgroup Settings Override Client-Side Settings>.
resultConfiguration_encryptionConfiguration :: Lens.Lens' ResultConfiguration (Prelude.Maybe EncryptionConfiguration)
resultConfiguration_encryptionConfiguration = Lens.lens (\ResultConfiguration' {encryptionConfiguration} -> encryptionConfiguration) (\s@ResultConfiguration' {} a -> s {encryptionConfiguration = a} :: ResultConfiguration)

instance Core.FromJSON ResultConfiguration where
  parseJSON =
    Core.withObject
      "ResultConfiguration"
      ( \x ->
          ResultConfiguration'
            Prelude.<$> (x Core..:? "AclConfiguration")
            Prelude.<*> (x Core..:? "ExpectedBucketOwner")
            Prelude.<*> (x Core..:? "OutputLocation")
            Prelude.<*> (x Core..:? "EncryptionConfiguration")
      )

instance Prelude.Hashable ResultConfiguration where
  hashWithSalt _salt ResultConfiguration' {..} =
    _salt `Prelude.hashWithSalt` aclConfiguration
      `Prelude.hashWithSalt` expectedBucketOwner
      `Prelude.hashWithSalt` outputLocation
      `Prelude.hashWithSalt` encryptionConfiguration

instance Prelude.NFData ResultConfiguration where
  rnf ResultConfiguration' {..} =
    Prelude.rnf aclConfiguration
      `Prelude.seq` Prelude.rnf expectedBucketOwner
      `Prelude.seq` Prelude.rnf outputLocation
      `Prelude.seq` Prelude.rnf encryptionConfiguration

instance Core.ToJSON ResultConfiguration where
  toJSON ResultConfiguration' {..} =
    Core.object
      ( Prelude.catMaybes
          [ ("AclConfiguration" Core..=)
              Prelude.<$> aclConfiguration,
            ("ExpectedBucketOwner" Core..=)
              Prelude.<$> expectedBucketOwner,
            ("OutputLocation" Core..=)
              Prelude.<$> outputLocation,
            ("EncryptionConfiguration" Core..=)
              Prelude.<$> encryptionConfiguration
          ]
      )
