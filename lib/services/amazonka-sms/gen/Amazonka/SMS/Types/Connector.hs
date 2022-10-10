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
-- Module      : Amazonka.SMS.Types.Connector
-- Copyright   : (c) 2013-2022 Brendan Hay
-- License     : Mozilla Public License, v. 2.0.
-- Maintainer  : Brendan Hay <brendan.g.hay+amazonka@gmail.com>
-- Stability   : auto-generated
-- Portability : non-portable (GHC extensions)
module Amazonka.SMS.Types.Connector where

import qualified Amazonka.Core as Core
import qualified Amazonka.Lens as Lens
import qualified Amazonka.Prelude as Prelude
import Amazonka.SMS.Types.ConnectorCapability
import Amazonka.SMS.Types.ConnectorStatus
import Amazonka.SMS.Types.VmManagerType

-- | Represents a connector.
--
-- /See:/ 'newConnector' smart constructor.
data Connector = Connector'
  { -- | The time the connector was associated.
    associatedOn :: Prelude.Maybe Core.POSIX,
    -- | The name of the VM manager.
    vmManagerName :: Prelude.Maybe Prelude.Text,
    -- | The ID of the VM manager.
    vmManagerId :: Prelude.Maybe Prelude.Text,
    -- | The ID of the connector.
    connectorId :: Prelude.Maybe Prelude.Text,
    -- | The capabilities of the connector.
    capabilityList :: Prelude.Maybe [ConnectorCapability],
    -- | The status of the connector.
    status :: Prelude.Maybe ConnectorStatus,
    -- | The MAC address of the connector.
    macAddress :: Prelude.Maybe Prelude.Text,
    -- | The VM management product.
    vmManagerType :: Prelude.Maybe VmManagerType,
    -- | The connector version.
    version :: Prelude.Maybe Prelude.Text,
    -- | The IP address of the connector.
    ipAddress :: Prelude.Maybe Prelude.Text
  }
  deriving (Prelude.Eq, Prelude.Read, Prelude.Show, Prelude.Generic)

-- |
-- Create a value of 'Connector' with all optional fields omitted.
--
-- Use <https://hackage.haskell.org/package/generic-lens generic-lens> or <https://hackage.haskell.org/package/optics optics> to modify other optional fields.
--
-- The following record fields are available, with the corresponding lenses provided
-- for backwards compatibility:
--
-- 'associatedOn', 'connector_associatedOn' - The time the connector was associated.
--
-- 'vmManagerName', 'connector_vmManagerName' - The name of the VM manager.
--
-- 'vmManagerId', 'connector_vmManagerId' - The ID of the VM manager.
--
-- 'connectorId', 'connector_connectorId' - The ID of the connector.
--
-- 'capabilityList', 'connector_capabilityList' - The capabilities of the connector.
--
-- 'status', 'connector_status' - The status of the connector.
--
-- 'macAddress', 'connector_macAddress' - The MAC address of the connector.
--
-- 'vmManagerType', 'connector_vmManagerType' - The VM management product.
--
-- 'version', 'connector_version' - The connector version.
--
-- 'ipAddress', 'connector_ipAddress' - The IP address of the connector.
newConnector ::
  Connector
newConnector =
  Connector'
    { associatedOn = Prelude.Nothing,
      vmManagerName = Prelude.Nothing,
      vmManagerId = Prelude.Nothing,
      connectorId = Prelude.Nothing,
      capabilityList = Prelude.Nothing,
      status = Prelude.Nothing,
      macAddress = Prelude.Nothing,
      vmManagerType = Prelude.Nothing,
      version = Prelude.Nothing,
      ipAddress = Prelude.Nothing
    }

-- | The time the connector was associated.
connector_associatedOn :: Lens.Lens' Connector (Prelude.Maybe Prelude.UTCTime)
connector_associatedOn = Lens.lens (\Connector' {associatedOn} -> associatedOn) (\s@Connector' {} a -> s {associatedOn = a} :: Connector) Prelude.. Lens.mapping Core._Time

-- | The name of the VM manager.
connector_vmManagerName :: Lens.Lens' Connector (Prelude.Maybe Prelude.Text)
connector_vmManagerName = Lens.lens (\Connector' {vmManagerName} -> vmManagerName) (\s@Connector' {} a -> s {vmManagerName = a} :: Connector)

-- | The ID of the VM manager.
connector_vmManagerId :: Lens.Lens' Connector (Prelude.Maybe Prelude.Text)
connector_vmManagerId = Lens.lens (\Connector' {vmManagerId} -> vmManagerId) (\s@Connector' {} a -> s {vmManagerId = a} :: Connector)

-- | The ID of the connector.
connector_connectorId :: Lens.Lens' Connector (Prelude.Maybe Prelude.Text)
connector_connectorId = Lens.lens (\Connector' {connectorId} -> connectorId) (\s@Connector' {} a -> s {connectorId = a} :: Connector)

-- | The capabilities of the connector.
connector_capabilityList :: Lens.Lens' Connector (Prelude.Maybe [ConnectorCapability])
connector_capabilityList = Lens.lens (\Connector' {capabilityList} -> capabilityList) (\s@Connector' {} a -> s {capabilityList = a} :: Connector) Prelude.. Lens.mapping Lens.coerced

-- | The status of the connector.
connector_status :: Lens.Lens' Connector (Prelude.Maybe ConnectorStatus)
connector_status = Lens.lens (\Connector' {status} -> status) (\s@Connector' {} a -> s {status = a} :: Connector)

-- | The MAC address of the connector.
connector_macAddress :: Lens.Lens' Connector (Prelude.Maybe Prelude.Text)
connector_macAddress = Lens.lens (\Connector' {macAddress} -> macAddress) (\s@Connector' {} a -> s {macAddress = a} :: Connector)

-- | The VM management product.
connector_vmManagerType :: Lens.Lens' Connector (Prelude.Maybe VmManagerType)
connector_vmManagerType = Lens.lens (\Connector' {vmManagerType} -> vmManagerType) (\s@Connector' {} a -> s {vmManagerType = a} :: Connector)

-- | The connector version.
connector_version :: Lens.Lens' Connector (Prelude.Maybe Prelude.Text)
connector_version = Lens.lens (\Connector' {version} -> version) (\s@Connector' {} a -> s {version = a} :: Connector)

-- | The IP address of the connector.
connector_ipAddress :: Lens.Lens' Connector (Prelude.Maybe Prelude.Text)
connector_ipAddress = Lens.lens (\Connector' {ipAddress} -> ipAddress) (\s@Connector' {} a -> s {ipAddress = a} :: Connector)

instance Core.FromJSON Connector where
  parseJSON =
    Core.withObject
      "Connector"
      ( \x ->
          Connector'
            Prelude.<$> (x Core..:? "associatedOn")
            Prelude.<*> (x Core..:? "vmManagerName")
            Prelude.<*> (x Core..:? "vmManagerId")
            Prelude.<*> (x Core..:? "connectorId")
            Prelude.<*> (x Core..:? "capabilityList" Core..!= Prelude.mempty)
            Prelude.<*> (x Core..:? "status")
            Prelude.<*> (x Core..:? "macAddress")
            Prelude.<*> (x Core..:? "vmManagerType")
            Prelude.<*> (x Core..:? "version")
            Prelude.<*> (x Core..:? "ipAddress")
      )

instance Prelude.Hashable Connector where
  hashWithSalt _salt Connector' {..} =
    _salt `Prelude.hashWithSalt` associatedOn
      `Prelude.hashWithSalt` vmManagerName
      `Prelude.hashWithSalt` vmManagerId
      `Prelude.hashWithSalt` connectorId
      `Prelude.hashWithSalt` capabilityList
      `Prelude.hashWithSalt` status
      `Prelude.hashWithSalt` macAddress
      `Prelude.hashWithSalt` vmManagerType
      `Prelude.hashWithSalt` version
      `Prelude.hashWithSalt` ipAddress

instance Prelude.NFData Connector where
  rnf Connector' {..} =
    Prelude.rnf associatedOn
      `Prelude.seq` Prelude.rnf vmManagerName
      `Prelude.seq` Prelude.rnf vmManagerId
      `Prelude.seq` Prelude.rnf connectorId
      `Prelude.seq` Prelude.rnf capabilityList
      `Prelude.seq` Prelude.rnf status
      `Prelude.seq` Prelude.rnf macAddress
      `Prelude.seq` Prelude.rnf vmManagerType
      `Prelude.seq` Prelude.rnf version
      `Prelude.seq` Prelude.rnf ipAddress
