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
-- Module      : Amazonka.DataBrew.Types.Output
-- Copyright   : (c) 2013-2022 Brendan Hay
-- License     : Mozilla Public License, v. 2.0.
-- Maintainer  : Brendan Hay <brendan.g.hay+amazonka@gmail.com>
-- Stability   : auto-generated
-- Portability : non-portable (GHC extensions)
module Amazonka.DataBrew.Types.Output where

import qualified Amazonka.Core as Core
import Amazonka.DataBrew.Types.CompressionFormat
import Amazonka.DataBrew.Types.OutputFormat
import Amazonka.DataBrew.Types.OutputFormatOptions
import Amazonka.DataBrew.Types.S3Location
import qualified Amazonka.Lens as Lens
import qualified Amazonka.Prelude as Prelude

-- | Represents options that specify how and where in Amazon S3 DataBrew
-- writes the output generated by recipe jobs or profile jobs.
--
-- /See:/ 'newOutput' smart constructor.
data Output = Output'
  { -- | The data format of the output of the job.
    format :: Prelude.Maybe OutputFormat,
    -- | A value that, if true, means that any data in the location specified for
    -- output is overwritten with new output.
    overwrite :: Prelude.Maybe Prelude.Bool,
    -- | The names of one or more partition columns for the output of the job.
    partitionColumns :: Prelude.Maybe [Prelude.Text],
    -- | Represents options that define how DataBrew formats job output files.
    formatOptions :: Prelude.Maybe OutputFormatOptions,
    -- | The compression algorithm used to compress the output text of the job.
    compressionFormat :: Prelude.Maybe CompressionFormat,
    -- | Maximum number of files to be generated by the job and written to the
    -- output folder. For output partitioned by column(s), the MaxOutputFiles
    -- value is the maximum number of files per partition.
    maxOutputFiles :: Prelude.Maybe Prelude.Natural,
    -- | The location in Amazon S3 where the job writes its output.
    location :: S3Location
  }
  deriving (Prelude.Eq, Prelude.Read, Prelude.Show, Prelude.Generic)

-- |
-- Create a value of 'Output' with all optional fields omitted.
--
-- Use <https://hackage.haskell.org/package/generic-lens generic-lens> or <https://hackage.haskell.org/package/optics optics> to modify other optional fields.
--
-- The following record fields are available, with the corresponding lenses provided
-- for backwards compatibility:
--
-- 'format', 'output_format' - The data format of the output of the job.
--
-- 'overwrite', 'output_overwrite' - A value that, if true, means that any data in the location specified for
-- output is overwritten with new output.
--
-- 'partitionColumns', 'output_partitionColumns' - The names of one or more partition columns for the output of the job.
--
-- 'formatOptions', 'output_formatOptions' - Represents options that define how DataBrew formats job output files.
--
-- 'compressionFormat', 'output_compressionFormat' - The compression algorithm used to compress the output text of the job.
--
-- 'maxOutputFiles', 'output_maxOutputFiles' - Maximum number of files to be generated by the job and written to the
-- output folder. For output partitioned by column(s), the MaxOutputFiles
-- value is the maximum number of files per partition.
--
-- 'location', 'output_location' - The location in Amazon S3 where the job writes its output.
newOutput ::
  -- | 'location'
  S3Location ->
  Output
newOutput pLocation_ =
  Output'
    { format = Prelude.Nothing,
      overwrite = Prelude.Nothing,
      partitionColumns = Prelude.Nothing,
      formatOptions = Prelude.Nothing,
      compressionFormat = Prelude.Nothing,
      maxOutputFiles = Prelude.Nothing,
      location = pLocation_
    }

-- | The data format of the output of the job.
output_format :: Lens.Lens' Output (Prelude.Maybe OutputFormat)
output_format = Lens.lens (\Output' {format} -> format) (\s@Output' {} a -> s {format = a} :: Output)

-- | A value that, if true, means that any data in the location specified for
-- output is overwritten with new output.
output_overwrite :: Lens.Lens' Output (Prelude.Maybe Prelude.Bool)
output_overwrite = Lens.lens (\Output' {overwrite} -> overwrite) (\s@Output' {} a -> s {overwrite = a} :: Output)

-- | The names of one or more partition columns for the output of the job.
output_partitionColumns :: Lens.Lens' Output (Prelude.Maybe [Prelude.Text])
output_partitionColumns = Lens.lens (\Output' {partitionColumns} -> partitionColumns) (\s@Output' {} a -> s {partitionColumns = a} :: Output) Prelude.. Lens.mapping Lens.coerced

-- | Represents options that define how DataBrew formats job output files.
output_formatOptions :: Lens.Lens' Output (Prelude.Maybe OutputFormatOptions)
output_formatOptions = Lens.lens (\Output' {formatOptions} -> formatOptions) (\s@Output' {} a -> s {formatOptions = a} :: Output)

-- | The compression algorithm used to compress the output text of the job.
output_compressionFormat :: Lens.Lens' Output (Prelude.Maybe CompressionFormat)
output_compressionFormat = Lens.lens (\Output' {compressionFormat} -> compressionFormat) (\s@Output' {} a -> s {compressionFormat = a} :: Output)

-- | Maximum number of files to be generated by the job and written to the
-- output folder. For output partitioned by column(s), the MaxOutputFiles
-- value is the maximum number of files per partition.
output_maxOutputFiles :: Lens.Lens' Output (Prelude.Maybe Prelude.Natural)
output_maxOutputFiles = Lens.lens (\Output' {maxOutputFiles} -> maxOutputFiles) (\s@Output' {} a -> s {maxOutputFiles = a} :: Output)

-- | The location in Amazon S3 where the job writes its output.
output_location :: Lens.Lens' Output S3Location
output_location = Lens.lens (\Output' {location} -> location) (\s@Output' {} a -> s {location = a} :: Output)

instance Core.FromJSON Output where
  parseJSON =
    Core.withObject
      "Output"
      ( \x ->
          Output'
            Prelude.<$> (x Core..:? "Format")
            Prelude.<*> (x Core..:? "Overwrite")
            Prelude.<*> ( x Core..:? "PartitionColumns"
                            Core..!= Prelude.mempty
                        )
            Prelude.<*> (x Core..:? "FormatOptions")
            Prelude.<*> (x Core..:? "CompressionFormat")
            Prelude.<*> (x Core..:? "MaxOutputFiles")
            Prelude.<*> (x Core..: "Location")
      )

instance Prelude.Hashable Output where
  hashWithSalt _salt Output' {..} =
    _salt `Prelude.hashWithSalt` format
      `Prelude.hashWithSalt` overwrite
      `Prelude.hashWithSalt` partitionColumns
      `Prelude.hashWithSalt` formatOptions
      `Prelude.hashWithSalt` compressionFormat
      `Prelude.hashWithSalt` maxOutputFiles
      `Prelude.hashWithSalt` location

instance Prelude.NFData Output where
  rnf Output' {..} =
    Prelude.rnf format
      `Prelude.seq` Prelude.rnf overwrite
      `Prelude.seq` Prelude.rnf partitionColumns
      `Prelude.seq` Prelude.rnf formatOptions
      `Prelude.seq` Prelude.rnf compressionFormat
      `Prelude.seq` Prelude.rnf maxOutputFiles
      `Prelude.seq` Prelude.rnf location

instance Core.ToJSON Output where
  toJSON Output' {..} =
    Core.object
      ( Prelude.catMaybes
          [ ("Format" Core..=) Prelude.<$> format,
            ("Overwrite" Core..=) Prelude.<$> overwrite,
            ("PartitionColumns" Core..=)
              Prelude.<$> partitionColumns,
            ("FormatOptions" Core..=) Prelude.<$> formatOptions,
            ("CompressionFormat" Core..=)
              Prelude.<$> compressionFormat,
            ("MaxOutputFiles" Core..=)
              Prelude.<$> maxOutputFiles,
            Prelude.Just ("Location" Core..= location)
          ]
      )
