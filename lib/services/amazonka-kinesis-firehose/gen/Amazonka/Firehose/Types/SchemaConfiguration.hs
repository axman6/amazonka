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
-- Module      : Amazonka.Firehose.Types.SchemaConfiguration
-- Copyright   : (c) 2013-2022 Brendan Hay
-- License     : Mozilla Public License, v. 2.0.
-- Maintainer  : Brendan Hay <brendan.g.hay+amazonka@gmail.com>
-- Stability   : auto-generated
-- Portability : non-portable (GHC extensions)
module Amazonka.Firehose.Types.SchemaConfiguration where

import qualified Amazonka.Core as Core
import qualified Amazonka.Lens as Lens
import qualified Amazonka.Prelude as Prelude

-- | Specifies the schema to which you want Kinesis Data Firehose to
-- configure your data before it writes it to Amazon S3. This parameter is
-- required if @Enabled@ is set to true.
--
-- /See:/ 'newSchemaConfiguration' smart constructor.
data SchemaConfiguration = SchemaConfiguration'
  { -- | Specifies the AWS Glue table that contains the column information that
    -- constitutes your data schema.
    --
    -- If the @SchemaConfiguration@ request parameter is used as part of
    -- invoking the @CreateDeliveryStream@ API, then the @TableName@ property
    -- is required and its value must be specified.
    tableName :: Prelude.Maybe Prelude.Text,
    -- | The role that Kinesis Data Firehose can use to access AWS Glue. This
    -- role must be in the same account you use for Kinesis Data Firehose.
    -- Cross-account roles aren\'t allowed.
    --
    -- If the @SchemaConfiguration@ request parameter is used as part of
    -- invoking the @CreateDeliveryStream@ API, then the @RoleARN@ property is
    -- required and its value must be specified.
    roleARN :: Prelude.Maybe Prelude.Text,
    -- | Specifies the name of the AWS Glue database that contains the schema for
    -- the output data.
    --
    -- If the @SchemaConfiguration@ request parameter is used as part of
    -- invoking the @CreateDeliveryStream@ API, then the @DatabaseName@
    -- property is required and its value must be specified.
    databaseName :: Prelude.Maybe Prelude.Text,
    -- | If you don\'t specify an AWS Region, the default is the current Region.
    region :: Prelude.Maybe Prelude.Text,
    -- | The ID of the AWS Glue Data Catalog. If you don\'t supply this, the AWS
    -- account ID is used by default.
    catalogId :: Prelude.Maybe Prelude.Text,
    -- | Specifies the table version for the output data schema. If you don\'t
    -- specify this version ID, or if you set it to @LATEST@, Kinesis Data
    -- Firehose uses the most recent version. This means that any updates to
    -- the table are automatically picked up.
    versionId :: Prelude.Maybe Prelude.Text
  }
  deriving (Prelude.Eq, Prelude.Read, Prelude.Show, Prelude.Generic)

-- |
-- Create a value of 'SchemaConfiguration' with all optional fields omitted.
--
-- Use <https://hackage.haskell.org/package/generic-lens generic-lens> or <https://hackage.haskell.org/package/optics optics> to modify other optional fields.
--
-- The following record fields are available, with the corresponding lenses provided
-- for backwards compatibility:
--
-- 'tableName', 'schemaConfiguration_tableName' - Specifies the AWS Glue table that contains the column information that
-- constitutes your data schema.
--
-- If the @SchemaConfiguration@ request parameter is used as part of
-- invoking the @CreateDeliveryStream@ API, then the @TableName@ property
-- is required and its value must be specified.
--
-- 'roleARN', 'schemaConfiguration_roleARN' - The role that Kinesis Data Firehose can use to access AWS Glue. This
-- role must be in the same account you use for Kinesis Data Firehose.
-- Cross-account roles aren\'t allowed.
--
-- If the @SchemaConfiguration@ request parameter is used as part of
-- invoking the @CreateDeliveryStream@ API, then the @RoleARN@ property is
-- required and its value must be specified.
--
-- 'databaseName', 'schemaConfiguration_databaseName' - Specifies the name of the AWS Glue database that contains the schema for
-- the output data.
--
-- If the @SchemaConfiguration@ request parameter is used as part of
-- invoking the @CreateDeliveryStream@ API, then the @DatabaseName@
-- property is required and its value must be specified.
--
-- 'region', 'schemaConfiguration_region' - If you don\'t specify an AWS Region, the default is the current Region.
--
-- 'catalogId', 'schemaConfiguration_catalogId' - The ID of the AWS Glue Data Catalog. If you don\'t supply this, the AWS
-- account ID is used by default.
--
-- 'versionId', 'schemaConfiguration_versionId' - Specifies the table version for the output data schema. If you don\'t
-- specify this version ID, or if you set it to @LATEST@, Kinesis Data
-- Firehose uses the most recent version. This means that any updates to
-- the table are automatically picked up.
newSchemaConfiguration ::
  SchemaConfiguration
newSchemaConfiguration =
  SchemaConfiguration'
    { tableName = Prelude.Nothing,
      roleARN = Prelude.Nothing,
      databaseName = Prelude.Nothing,
      region = Prelude.Nothing,
      catalogId = Prelude.Nothing,
      versionId = Prelude.Nothing
    }

-- | Specifies the AWS Glue table that contains the column information that
-- constitutes your data schema.
--
-- If the @SchemaConfiguration@ request parameter is used as part of
-- invoking the @CreateDeliveryStream@ API, then the @TableName@ property
-- is required and its value must be specified.
schemaConfiguration_tableName :: Lens.Lens' SchemaConfiguration (Prelude.Maybe Prelude.Text)
schemaConfiguration_tableName = Lens.lens (\SchemaConfiguration' {tableName} -> tableName) (\s@SchemaConfiguration' {} a -> s {tableName = a} :: SchemaConfiguration)

-- | The role that Kinesis Data Firehose can use to access AWS Glue. This
-- role must be in the same account you use for Kinesis Data Firehose.
-- Cross-account roles aren\'t allowed.
--
-- If the @SchemaConfiguration@ request parameter is used as part of
-- invoking the @CreateDeliveryStream@ API, then the @RoleARN@ property is
-- required and its value must be specified.
schemaConfiguration_roleARN :: Lens.Lens' SchemaConfiguration (Prelude.Maybe Prelude.Text)
schemaConfiguration_roleARN = Lens.lens (\SchemaConfiguration' {roleARN} -> roleARN) (\s@SchemaConfiguration' {} a -> s {roleARN = a} :: SchemaConfiguration)

-- | Specifies the name of the AWS Glue database that contains the schema for
-- the output data.
--
-- If the @SchemaConfiguration@ request parameter is used as part of
-- invoking the @CreateDeliveryStream@ API, then the @DatabaseName@
-- property is required and its value must be specified.
schemaConfiguration_databaseName :: Lens.Lens' SchemaConfiguration (Prelude.Maybe Prelude.Text)
schemaConfiguration_databaseName = Lens.lens (\SchemaConfiguration' {databaseName} -> databaseName) (\s@SchemaConfiguration' {} a -> s {databaseName = a} :: SchemaConfiguration)

-- | If you don\'t specify an AWS Region, the default is the current Region.
schemaConfiguration_region :: Lens.Lens' SchemaConfiguration (Prelude.Maybe Prelude.Text)
schemaConfiguration_region = Lens.lens (\SchemaConfiguration' {region} -> region) (\s@SchemaConfiguration' {} a -> s {region = a} :: SchemaConfiguration)

-- | The ID of the AWS Glue Data Catalog. If you don\'t supply this, the AWS
-- account ID is used by default.
schemaConfiguration_catalogId :: Lens.Lens' SchemaConfiguration (Prelude.Maybe Prelude.Text)
schemaConfiguration_catalogId = Lens.lens (\SchemaConfiguration' {catalogId} -> catalogId) (\s@SchemaConfiguration' {} a -> s {catalogId = a} :: SchemaConfiguration)

-- | Specifies the table version for the output data schema. If you don\'t
-- specify this version ID, or if you set it to @LATEST@, Kinesis Data
-- Firehose uses the most recent version. This means that any updates to
-- the table are automatically picked up.
schemaConfiguration_versionId :: Lens.Lens' SchemaConfiguration (Prelude.Maybe Prelude.Text)
schemaConfiguration_versionId = Lens.lens (\SchemaConfiguration' {versionId} -> versionId) (\s@SchemaConfiguration' {} a -> s {versionId = a} :: SchemaConfiguration)

instance Core.FromJSON SchemaConfiguration where
  parseJSON =
    Core.withObject
      "SchemaConfiguration"
      ( \x ->
          SchemaConfiguration'
            Prelude.<$> (x Core..:? "TableName")
            Prelude.<*> (x Core..:? "RoleARN")
            Prelude.<*> (x Core..:? "DatabaseName")
            Prelude.<*> (x Core..:? "Region")
            Prelude.<*> (x Core..:? "CatalogId")
            Prelude.<*> (x Core..:? "VersionId")
      )

instance Prelude.Hashable SchemaConfiguration where
  hashWithSalt _salt SchemaConfiguration' {..} =
    _salt `Prelude.hashWithSalt` tableName
      `Prelude.hashWithSalt` roleARN
      `Prelude.hashWithSalt` databaseName
      `Prelude.hashWithSalt` region
      `Prelude.hashWithSalt` catalogId
      `Prelude.hashWithSalt` versionId

instance Prelude.NFData SchemaConfiguration where
  rnf SchemaConfiguration' {..} =
    Prelude.rnf tableName
      `Prelude.seq` Prelude.rnf roleARN
      `Prelude.seq` Prelude.rnf databaseName
      `Prelude.seq` Prelude.rnf region
      `Prelude.seq` Prelude.rnf catalogId
      `Prelude.seq` Prelude.rnf versionId

instance Core.ToJSON SchemaConfiguration where
  toJSON SchemaConfiguration' {..} =
    Core.object
      ( Prelude.catMaybes
          [ ("TableName" Core..=) Prelude.<$> tableName,
            ("RoleARN" Core..=) Prelude.<$> roleARN,
            ("DatabaseName" Core..=) Prelude.<$> databaseName,
            ("Region" Core..=) Prelude.<$> region,
            ("CatalogId" Core..=) Prelude.<$> catalogId,
            ("VersionId" Core..=) Prelude.<$> versionId
          ]
      )
