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
-- Module      : Amazonka.DeviceFarm.Types.Artifact
-- Copyright   : (c) 2013-2021 Brendan Hay
-- License     : Mozilla Public License, v. 2.0.
-- Maintainer  : Brendan Hay <brendan.g.hay+amazonka@gmail.com>
-- Stability   : auto-generated
-- Portability : non-portable (GHC extensions)
module Amazonka.DeviceFarm.Types.Artifact where

import qualified Amazonka.Core as Core
import Amazonka.DeviceFarm.Types.ArtifactType
import qualified Amazonka.Lens as Lens
import qualified Amazonka.Prelude as Prelude

-- | Represents the output of a test. Examples of artifacts include logs and
-- screenshots.
--
-- /See:/ 'newArtifact' smart constructor.
data Artifact = Artifact'
  { -- | The artifact\'s ARN.
    arn :: Prelude.Maybe Prelude.Text,
    -- | The presigned Amazon S3 URL that can be used with a GET request to
    -- download the artifact\'s file.
    url :: Prelude.Maybe Prelude.Text,
    -- | The artifact\'s file extension.
    extension :: Prelude.Maybe Prelude.Text,
    -- | The artifact\'s name.
    name :: Prelude.Maybe Prelude.Text,
    -- | The artifact\'s type.
    --
    -- Allowed values include the following:
    --
    -- -   UNKNOWN
    --
    -- -   SCREENSHOT
    --
    -- -   DEVICE_LOG
    --
    -- -   MESSAGE_LOG
    --
    -- -   VIDEO_LOG
    --
    -- -   RESULT_LOG
    --
    -- -   SERVICE_LOG
    --
    -- -   WEBKIT_LOG
    --
    -- -   INSTRUMENTATION_OUTPUT
    --
    -- -   EXERCISER_MONKEY_OUTPUT: the artifact (log) generated by an Android
    --     fuzz test.
    --
    -- -   CALABASH_JSON_OUTPUT
    --
    -- -   CALABASH_PRETTY_OUTPUT
    --
    -- -   CALABASH_STANDARD_OUTPUT
    --
    -- -   CALABASH_JAVA_XML_OUTPUT
    --
    -- -   AUTOMATION_OUTPUT
    --
    -- -   APPIUM_SERVER_OUTPUT
    --
    -- -   APPIUM_JAVA_OUTPUT
    --
    -- -   APPIUM_JAVA_XML_OUTPUT
    --
    -- -   APPIUM_PYTHON_OUTPUT
    --
    -- -   APPIUM_PYTHON_XML_OUTPUT
    --
    -- -   EXPLORER_EVENT_LOG
    --
    -- -   EXPLORER_SUMMARY_LOG
    --
    -- -   APPLICATION_CRASH_REPORT
    --
    -- -   XCTEST_LOG
    --
    -- -   VIDEO
    --
    -- -   CUSTOMER_ARTIFACT
    --
    -- -   CUSTOMER_ARTIFACT_LOG
    --
    -- -   TESTSPEC_OUTPUT
    type' :: Prelude.Maybe ArtifactType
  }
  deriving (Prelude.Eq, Prelude.Read, Prelude.Show, Prelude.Generic)

-- |
-- Create a value of 'Artifact' with all optional fields omitted.
--
-- Use <https://hackage.haskell.org/package/generic-lens generic-lens> or <https://hackage.haskell.org/package/optics optics> to modify other optional fields.
--
-- The following record fields are available, with the corresponding lenses provided
-- for backwards compatibility:
--
-- 'arn', 'artifact_arn' - The artifact\'s ARN.
--
-- 'url', 'artifact_url' - The presigned Amazon S3 URL that can be used with a GET request to
-- download the artifact\'s file.
--
-- 'extension', 'artifact_extension' - The artifact\'s file extension.
--
-- 'name', 'artifact_name' - The artifact\'s name.
--
-- 'type'', 'artifact_type' - The artifact\'s type.
--
-- Allowed values include the following:
--
-- -   UNKNOWN
--
-- -   SCREENSHOT
--
-- -   DEVICE_LOG
--
-- -   MESSAGE_LOG
--
-- -   VIDEO_LOG
--
-- -   RESULT_LOG
--
-- -   SERVICE_LOG
--
-- -   WEBKIT_LOG
--
-- -   INSTRUMENTATION_OUTPUT
--
-- -   EXERCISER_MONKEY_OUTPUT: the artifact (log) generated by an Android
--     fuzz test.
--
-- -   CALABASH_JSON_OUTPUT
--
-- -   CALABASH_PRETTY_OUTPUT
--
-- -   CALABASH_STANDARD_OUTPUT
--
-- -   CALABASH_JAVA_XML_OUTPUT
--
-- -   AUTOMATION_OUTPUT
--
-- -   APPIUM_SERVER_OUTPUT
--
-- -   APPIUM_JAVA_OUTPUT
--
-- -   APPIUM_JAVA_XML_OUTPUT
--
-- -   APPIUM_PYTHON_OUTPUT
--
-- -   APPIUM_PYTHON_XML_OUTPUT
--
-- -   EXPLORER_EVENT_LOG
--
-- -   EXPLORER_SUMMARY_LOG
--
-- -   APPLICATION_CRASH_REPORT
--
-- -   XCTEST_LOG
--
-- -   VIDEO
--
-- -   CUSTOMER_ARTIFACT
--
-- -   CUSTOMER_ARTIFACT_LOG
--
-- -   TESTSPEC_OUTPUT
newArtifact ::
  Artifact
newArtifact =
  Artifact'
    { arn = Prelude.Nothing,
      url = Prelude.Nothing,
      extension = Prelude.Nothing,
      name = Prelude.Nothing,
      type' = Prelude.Nothing
    }

-- | The artifact\'s ARN.
artifact_arn :: Lens.Lens' Artifact (Prelude.Maybe Prelude.Text)
artifact_arn = Lens.lens (\Artifact' {arn} -> arn) (\s@Artifact' {} a -> s {arn = a} :: Artifact)

-- | The presigned Amazon S3 URL that can be used with a GET request to
-- download the artifact\'s file.
artifact_url :: Lens.Lens' Artifact (Prelude.Maybe Prelude.Text)
artifact_url = Lens.lens (\Artifact' {url} -> url) (\s@Artifact' {} a -> s {url = a} :: Artifact)

-- | The artifact\'s file extension.
artifact_extension :: Lens.Lens' Artifact (Prelude.Maybe Prelude.Text)
artifact_extension = Lens.lens (\Artifact' {extension} -> extension) (\s@Artifact' {} a -> s {extension = a} :: Artifact)

-- | The artifact\'s name.
artifact_name :: Lens.Lens' Artifact (Prelude.Maybe Prelude.Text)
artifact_name = Lens.lens (\Artifact' {name} -> name) (\s@Artifact' {} a -> s {name = a} :: Artifact)

-- | The artifact\'s type.
--
-- Allowed values include the following:
--
-- -   UNKNOWN
--
-- -   SCREENSHOT
--
-- -   DEVICE_LOG
--
-- -   MESSAGE_LOG
--
-- -   VIDEO_LOG
--
-- -   RESULT_LOG
--
-- -   SERVICE_LOG
--
-- -   WEBKIT_LOG
--
-- -   INSTRUMENTATION_OUTPUT
--
-- -   EXERCISER_MONKEY_OUTPUT: the artifact (log) generated by an Android
--     fuzz test.
--
-- -   CALABASH_JSON_OUTPUT
--
-- -   CALABASH_PRETTY_OUTPUT
--
-- -   CALABASH_STANDARD_OUTPUT
--
-- -   CALABASH_JAVA_XML_OUTPUT
--
-- -   AUTOMATION_OUTPUT
--
-- -   APPIUM_SERVER_OUTPUT
--
-- -   APPIUM_JAVA_OUTPUT
--
-- -   APPIUM_JAVA_XML_OUTPUT
--
-- -   APPIUM_PYTHON_OUTPUT
--
-- -   APPIUM_PYTHON_XML_OUTPUT
--
-- -   EXPLORER_EVENT_LOG
--
-- -   EXPLORER_SUMMARY_LOG
--
-- -   APPLICATION_CRASH_REPORT
--
-- -   XCTEST_LOG
--
-- -   VIDEO
--
-- -   CUSTOMER_ARTIFACT
--
-- -   CUSTOMER_ARTIFACT_LOG
--
-- -   TESTSPEC_OUTPUT
artifact_type :: Lens.Lens' Artifact (Prelude.Maybe ArtifactType)
artifact_type = Lens.lens (\Artifact' {type'} -> type') (\s@Artifact' {} a -> s {type' = a} :: Artifact)

instance Core.FromJSON Artifact where
  parseJSON =
    Core.withObject
      "Artifact"
      ( \x ->
          Artifact'
            Prelude.<$> (x Core..:? "arn")
            Prelude.<*> (x Core..:? "url")
            Prelude.<*> (x Core..:? "extension")
            Prelude.<*> (x Core..:? "name")
            Prelude.<*> (x Core..:? "type")
      )

instance Prelude.Hashable Artifact

instance Prelude.NFData Artifact
