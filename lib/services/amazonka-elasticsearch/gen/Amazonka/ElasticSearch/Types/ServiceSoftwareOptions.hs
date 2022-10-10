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
-- Module      : Amazonka.ElasticSearch.Types.ServiceSoftwareOptions
-- Copyright   : (c) 2013-2022 Brendan Hay
-- License     : Mozilla Public License, v. 2.0.
-- Maintainer  : Brendan Hay <brendan.g.hay+amazonka@gmail.com>
-- Stability   : auto-generated
-- Portability : non-portable (GHC extensions)
module Amazonka.ElasticSearch.Types.ServiceSoftwareOptions where

import qualified Amazonka.Core as Core
import Amazonka.ElasticSearch.Types.DeploymentStatus
import qualified Amazonka.Lens as Lens
import qualified Amazonka.Prelude as Prelude

-- | The current options of an Elasticsearch domain service software options.
--
-- /See:/ 'newServiceSoftwareOptions' smart constructor.
data ServiceSoftwareOptions = ServiceSoftwareOptions'
  { -- | @True@ if a service software is never automatically updated. @False@ if
    -- a service software is automatically updated after @AutomatedUpdateDate@.
    optionalDeployment :: Prelude.Maybe Prelude.Bool,
    -- | The new service software version if one is available.
    newVersion' :: Prelude.Maybe Prelude.Text,
    -- | @True@ if you are able to update you service software version. @False@
    -- if you are not able to update your service software version.
    updateAvailable :: Prelude.Maybe Prelude.Bool,
    -- | @True@ if you are able to cancel your service software version update.
    -- @False@ if you are not able to cancel your service software version.
    cancellable :: Prelude.Maybe Prelude.Bool,
    -- | The status of your service software update. This field can take the
    -- following values: @ELIGIBLE@, @PENDING_UPDATE@, @IN_PROGRESS@,
    -- @COMPLETED@, and @NOT_ELIGIBLE@.
    updateStatus :: Prelude.Maybe DeploymentStatus,
    -- | Timestamp, in Epoch time, until which you can manually request a service
    -- software update. After this date, we automatically update your service
    -- software.
    automatedUpdateDate :: Prelude.Maybe Core.POSIX,
    -- | The description of the @UpdateStatus@.
    description :: Prelude.Maybe Prelude.Text,
    -- | The current service software version that is present on the domain.
    currentVersion :: Prelude.Maybe Prelude.Text
  }
  deriving (Prelude.Eq, Prelude.Read, Prelude.Show, Prelude.Generic)

-- |
-- Create a value of 'ServiceSoftwareOptions' with all optional fields omitted.
--
-- Use <https://hackage.haskell.org/package/generic-lens generic-lens> or <https://hackage.haskell.org/package/optics optics> to modify other optional fields.
--
-- The following record fields are available, with the corresponding lenses provided
-- for backwards compatibility:
--
-- 'optionalDeployment', 'serviceSoftwareOptions_optionalDeployment' - @True@ if a service software is never automatically updated. @False@ if
-- a service software is automatically updated after @AutomatedUpdateDate@.
--
-- 'newVersion'', 'serviceSoftwareOptions_newVersion' - The new service software version if one is available.
--
-- 'updateAvailable', 'serviceSoftwareOptions_updateAvailable' - @True@ if you are able to update you service software version. @False@
-- if you are not able to update your service software version.
--
-- 'cancellable', 'serviceSoftwareOptions_cancellable' - @True@ if you are able to cancel your service software version update.
-- @False@ if you are not able to cancel your service software version.
--
-- 'updateStatus', 'serviceSoftwareOptions_updateStatus' - The status of your service software update. This field can take the
-- following values: @ELIGIBLE@, @PENDING_UPDATE@, @IN_PROGRESS@,
-- @COMPLETED@, and @NOT_ELIGIBLE@.
--
-- 'automatedUpdateDate', 'serviceSoftwareOptions_automatedUpdateDate' - Timestamp, in Epoch time, until which you can manually request a service
-- software update. After this date, we automatically update your service
-- software.
--
-- 'description', 'serviceSoftwareOptions_description' - The description of the @UpdateStatus@.
--
-- 'currentVersion', 'serviceSoftwareOptions_currentVersion' - The current service software version that is present on the domain.
newServiceSoftwareOptions ::
  ServiceSoftwareOptions
newServiceSoftwareOptions =
  ServiceSoftwareOptions'
    { optionalDeployment =
        Prelude.Nothing,
      newVersion' = Prelude.Nothing,
      updateAvailable = Prelude.Nothing,
      cancellable = Prelude.Nothing,
      updateStatus = Prelude.Nothing,
      automatedUpdateDate = Prelude.Nothing,
      description = Prelude.Nothing,
      currentVersion = Prelude.Nothing
    }

-- | @True@ if a service software is never automatically updated. @False@ if
-- a service software is automatically updated after @AutomatedUpdateDate@.
serviceSoftwareOptions_optionalDeployment :: Lens.Lens' ServiceSoftwareOptions (Prelude.Maybe Prelude.Bool)
serviceSoftwareOptions_optionalDeployment = Lens.lens (\ServiceSoftwareOptions' {optionalDeployment} -> optionalDeployment) (\s@ServiceSoftwareOptions' {} a -> s {optionalDeployment = a} :: ServiceSoftwareOptions)

-- | The new service software version if one is available.
serviceSoftwareOptions_newVersion :: Lens.Lens' ServiceSoftwareOptions (Prelude.Maybe Prelude.Text)
serviceSoftwareOptions_newVersion = Lens.lens (\ServiceSoftwareOptions' {newVersion'} -> newVersion') (\s@ServiceSoftwareOptions' {} a -> s {newVersion' = a} :: ServiceSoftwareOptions)

-- | @True@ if you are able to update you service software version. @False@
-- if you are not able to update your service software version.
serviceSoftwareOptions_updateAvailable :: Lens.Lens' ServiceSoftwareOptions (Prelude.Maybe Prelude.Bool)
serviceSoftwareOptions_updateAvailable = Lens.lens (\ServiceSoftwareOptions' {updateAvailable} -> updateAvailable) (\s@ServiceSoftwareOptions' {} a -> s {updateAvailable = a} :: ServiceSoftwareOptions)

-- | @True@ if you are able to cancel your service software version update.
-- @False@ if you are not able to cancel your service software version.
serviceSoftwareOptions_cancellable :: Lens.Lens' ServiceSoftwareOptions (Prelude.Maybe Prelude.Bool)
serviceSoftwareOptions_cancellable = Lens.lens (\ServiceSoftwareOptions' {cancellable} -> cancellable) (\s@ServiceSoftwareOptions' {} a -> s {cancellable = a} :: ServiceSoftwareOptions)

-- | The status of your service software update. This field can take the
-- following values: @ELIGIBLE@, @PENDING_UPDATE@, @IN_PROGRESS@,
-- @COMPLETED@, and @NOT_ELIGIBLE@.
serviceSoftwareOptions_updateStatus :: Lens.Lens' ServiceSoftwareOptions (Prelude.Maybe DeploymentStatus)
serviceSoftwareOptions_updateStatus = Lens.lens (\ServiceSoftwareOptions' {updateStatus} -> updateStatus) (\s@ServiceSoftwareOptions' {} a -> s {updateStatus = a} :: ServiceSoftwareOptions)

-- | Timestamp, in Epoch time, until which you can manually request a service
-- software update. After this date, we automatically update your service
-- software.
serviceSoftwareOptions_automatedUpdateDate :: Lens.Lens' ServiceSoftwareOptions (Prelude.Maybe Prelude.UTCTime)
serviceSoftwareOptions_automatedUpdateDate = Lens.lens (\ServiceSoftwareOptions' {automatedUpdateDate} -> automatedUpdateDate) (\s@ServiceSoftwareOptions' {} a -> s {automatedUpdateDate = a} :: ServiceSoftwareOptions) Prelude.. Lens.mapping Core._Time

-- | The description of the @UpdateStatus@.
serviceSoftwareOptions_description :: Lens.Lens' ServiceSoftwareOptions (Prelude.Maybe Prelude.Text)
serviceSoftwareOptions_description = Lens.lens (\ServiceSoftwareOptions' {description} -> description) (\s@ServiceSoftwareOptions' {} a -> s {description = a} :: ServiceSoftwareOptions)

-- | The current service software version that is present on the domain.
serviceSoftwareOptions_currentVersion :: Lens.Lens' ServiceSoftwareOptions (Prelude.Maybe Prelude.Text)
serviceSoftwareOptions_currentVersion = Lens.lens (\ServiceSoftwareOptions' {currentVersion} -> currentVersion) (\s@ServiceSoftwareOptions' {} a -> s {currentVersion = a} :: ServiceSoftwareOptions)

instance Core.FromJSON ServiceSoftwareOptions where
  parseJSON =
    Core.withObject
      "ServiceSoftwareOptions"
      ( \x ->
          ServiceSoftwareOptions'
            Prelude.<$> (x Core..:? "OptionalDeployment")
            Prelude.<*> (x Core..:? "NewVersion")
            Prelude.<*> (x Core..:? "UpdateAvailable")
            Prelude.<*> (x Core..:? "Cancellable")
            Prelude.<*> (x Core..:? "UpdateStatus")
            Prelude.<*> (x Core..:? "AutomatedUpdateDate")
            Prelude.<*> (x Core..:? "Description")
            Prelude.<*> (x Core..:? "CurrentVersion")
      )

instance Prelude.Hashable ServiceSoftwareOptions where
  hashWithSalt _salt ServiceSoftwareOptions' {..} =
    _salt `Prelude.hashWithSalt` optionalDeployment
      `Prelude.hashWithSalt` newVersion'
      `Prelude.hashWithSalt` updateAvailable
      `Prelude.hashWithSalt` cancellable
      `Prelude.hashWithSalt` updateStatus
      `Prelude.hashWithSalt` automatedUpdateDate
      `Prelude.hashWithSalt` description
      `Prelude.hashWithSalt` currentVersion

instance Prelude.NFData ServiceSoftwareOptions where
  rnf ServiceSoftwareOptions' {..} =
    Prelude.rnf optionalDeployment
      `Prelude.seq` Prelude.rnf newVersion'
      `Prelude.seq` Prelude.rnf updateAvailable
      `Prelude.seq` Prelude.rnf cancellable
      `Prelude.seq` Prelude.rnf updateStatus
      `Prelude.seq` Prelude.rnf automatedUpdateDate
      `Prelude.seq` Prelude.rnf description
      `Prelude.seq` Prelude.rnf currentVersion
