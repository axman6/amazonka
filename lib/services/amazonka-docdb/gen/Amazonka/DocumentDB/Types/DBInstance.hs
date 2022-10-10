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
-- Module      : Amazonka.DocumentDB.Types.DBInstance
-- Copyright   : (c) 2013-2022 Brendan Hay
-- License     : Mozilla Public License, v. 2.0.
-- Maintainer  : Brendan Hay <brendan.g.hay+amazonka@gmail.com>
-- Stability   : auto-generated
-- Portability : non-portable (GHC extensions)
module Amazonka.DocumentDB.Types.DBInstance where

import qualified Amazonka.Core as Core
import Amazonka.DocumentDB.Types.DBInstanceStatusInfo
import Amazonka.DocumentDB.Types.DBSubnetGroup
import Amazonka.DocumentDB.Types.Endpoint
import Amazonka.DocumentDB.Types.PendingModifiedValues
import Amazonka.DocumentDB.Types.VpcSecurityGroupMembership
import qualified Amazonka.Lens as Lens
import qualified Amazonka.Prelude as Prelude

-- | Detailed information about an instance.
--
-- /See:/ 'newDBInstance' smart constructor.
data DBInstance = DBInstance'
  { -- | Specifies the current state of this database.
    dbInstanceStatus :: Prelude.Maybe Prelude.Text,
    -- | Specifies the daily time range during which automated backups are
    -- created if automated backups are enabled, as determined by the
    -- @BackupRetentionPeriod@.
    preferredBackupWindow :: Prelude.Maybe Prelude.Text,
    -- | Specifies the number of days for which automatic snapshots are retained.
    backupRetentionPeriod :: Prelude.Maybe Prelude.Int,
    -- | Contains the name of the compute and memory capacity class of the
    -- instance.
    dbInstanceClass :: Prelude.Maybe Prelude.Text,
    -- | A value that indicates whether to copy tags from the DB instance to
    -- snapshots of the DB instance. By default, tags are not copied.
    copyTagsToSnapshot :: Prelude.Maybe Prelude.Bool,
    -- | A value that specifies the order in which an Amazon DocumentDB replica
    -- is promoted to the primary instance after a failure of the existing
    -- primary instance.
    promotionTier :: Prelude.Maybe Prelude.Int,
    -- | Does not apply. This parameter does not apply to Amazon DocumentDB.
    -- Amazon DocumentDB does not perform minor version upgrades regardless of
    -- the value set.
    autoMinorVersionUpgrade :: Prelude.Maybe Prelude.Bool,
    -- | Contains a user-provided database identifier. This identifier is the
    -- unique key that identifies an instance.
    dbInstanceIdentifier :: Prelude.Maybe Prelude.Text,
    -- | Specifies the latest time to which a database can be restored with
    -- point-in-time restore.
    latestRestorableTime :: Prelude.Maybe Core.ISO8601,
    -- | Contains the name of the cluster that the instance is a member of if the
    -- instance is a member of a cluster.
    dbClusterIdentifier :: Prelude.Maybe Prelude.Text,
    -- | Specifies information on the subnet group that is associated with the
    -- instance, including the name, description, and subnets in the subnet
    -- group.
    dbSubnetGroup :: Prelude.Maybe DBSubnetGroup,
    -- | Provides the date and time that the instance was created.
    instanceCreateTime :: Prelude.Maybe Core.ISO8601,
    -- | Specifies the name of the Availability Zone that the instance is located
    -- in.
    availabilityZone :: Prelude.Maybe Prelude.Text,
    -- | Not supported. Amazon DocumentDB does not currently support public
    -- endpoints. The value of @PubliclyAccessible@ is always @false@.
    publiclyAccessible :: Prelude.Maybe Prelude.Bool,
    -- | The Amazon Resource Name (ARN) for the instance.
    dbInstanceArn :: Prelude.Maybe Prelude.Text,
    -- | The identifier of the CA certificate for this DB instance.
    cACertificateIdentifier :: Prelude.Maybe Prelude.Text,
    -- | Specifies whether or not the instance is encrypted.
    storageEncrypted :: Prelude.Maybe Prelude.Bool,
    -- | If @StorageEncrypted@ is @true@, the KMS key identifier for the
    -- encrypted instance.
    kmsKeyId :: Prelude.Maybe Prelude.Text,
    -- | Provides the name of the database engine to be used for this instance.
    engine :: Prelude.Maybe Prelude.Text,
    -- | Specifies that changes to the instance are pending. This element is
    -- included only when changes are pending. Specific changes are identified
    -- by subelements.
    pendingModifiedValues :: Prelude.Maybe PendingModifiedValues,
    -- | Specifies the weekly time range during which system maintenance can
    -- occur, in Universal Coordinated Time (UTC).
    preferredMaintenanceWindow :: Prelude.Maybe Prelude.Text,
    -- | Specifies the connection endpoint.
    endpoint :: Prelude.Maybe Endpoint,
    -- | The Amazon Web Services Region-unique, immutable identifier for the
    -- instance. This identifier is found in CloudTrail log entries whenever
    -- the KMS key for the instance is accessed.
    dbiResourceId :: Prelude.Maybe Prelude.Text,
    -- | A list of log types that this instance is configured to export to
    -- CloudWatch Logs.
    enabledCloudwatchLogsExports :: Prelude.Maybe [Prelude.Text],
    -- | Indicates the database engine version.
    engineVersion :: Prelude.Maybe Prelude.Text,
    -- | The status of a read replica. If the instance is not a read replica,
    -- this is blank.
    statusInfos :: Prelude.Maybe [DBInstanceStatusInfo],
    -- | Provides a list of VPC security group elements that the instance belongs
    -- to.
    vpcSecurityGroups :: Prelude.Maybe [VpcSecurityGroupMembership]
  }
  deriving (Prelude.Eq, Prelude.Read, Prelude.Show, Prelude.Generic)

-- |
-- Create a value of 'DBInstance' with all optional fields omitted.
--
-- Use <https://hackage.haskell.org/package/generic-lens generic-lens> or <https://hackage.haskell.org/package/optics optics> to modify other optional fields.
--
-- The following record fields are available, with the corresponding lenses provided
-- for backwards compatibility:
--
-- 'dbInstanceStatus', 'dbInstance_dbInstanceStatus' - Specifies the current state of this database.
--
-- 'preferredBackupWindow', 'dbInstance_preferredBackupWindow' - Specifies the daily time range during which automated backups are
-- created if automated backups are enabled, as determined by the
-- @BackupRetentionPeriod@.
--
-- 'backupRetentionPeriod', 'dbInstance_backupRetentionPeriod' - Specifies the number of days for which automatic snapshots are retained.
--
-- 'dbInstanceClass', 'dbInstance_dbInstanceClass' - Contains the name of the compute and memory capacity class of the
-- instance.
--
-- 'copyTagsToSnapshot', 'dbInstance_copyTagsToSnapshot' - A value that indicates whether to copy tags from the DB instance to
-- snapshots of the DB instance. By default, tags are not copied.
--
-- 'promotionTier', 'dbInstance_promotionTier' - A value that specifies the order in which an Amazon DocumentDB replica
-- is promoted to the primary instance after a failure of the existing
-- primary instance.
--
-- 'autoMinorVersionUpgrade', 'dbInstance_autoMinorVersionUpgrade' - Does not apply. This parameter does not apply to Amazon DocumentDB.
-- Amazon DocumentDB does not perform minor version upgrades regardless of
-- the value set.
--
-- 'dbInstanceIdentifier', 'dbInstance_dbInstanceIdentifier' - Contains a user-provided database identifier. This identifier is the
-- unique key that identifies an instance.
--
-- 'latestRestorableTime', 'dbInstance_latestRestorableTime' - Specifies the latest time to which a database can be restored with
-- point-in-time restore.
--
-- 'dbClusterIdentifier', 'dbInstance_dbClusterIdentifier' - Contains the name of the cluster that the instance is a member of if the
-- instance is a member of a cluster.
--
-- 'dbSubnetGroup', 'dbInstance_dbSubnetGroup' - Specifies information on the subnet group that is associated with the
-- instance, including the name, description, and subnets in the subnet
-- group.
--
-- 'instanceCreateTime', 'dbInstance_instanceCreateTime' - Provides the date and time that the instance was created.
--
-- 'availabilityZone', 'dbInstance_availabilityZone' - Specifies the name of the Availability Zone that the instance is located
-- in.
--
-- 'publiclyAccessible', 'dbInstance_publiclyAccessible' - Not supported. Amazon DocumentDB does not currently support public
-- endpoints. The value of @PubliclyAccessible@ is always @false@.
--
-- 'dbInstanceArn', 'dbInstance_dbInstanceArn' - The Amazon Resource Name (ARN) for the instance.
--
-- 'cACertificateIdentifier', 'dbInstance_cACertificateIdentifier' - The identifier of the CA certificate for this DB instance.
--
-- 'storageEncrypted', 'dbInstance_storageEncrypted' - Specifies whether or not the instance is encrypted.
--
-- 'kmsKeyId', 'dbInstance_kmsKeyId' - If @StorageEncrypted@ is @true@, the KMS key identifier for the
-- encrypted instance.
--
-- 'engine', 'dbInstance_engine' - Provides the name of the database engine to be used for this instance.
--
-- 'pendingModifiedValues', 'dbInstance_pendingModifiedValues' - Specifies that changes to the instance are pending. This element is
-- included only when changes are pending. Specific changes are identified
-- by subelements.
--
-- 'preferredMaintenanceWindow', 'dbInstance_preferredMaintenanceWindow' - Specifies the weekly time range during which system maintenance can
-- occur, in Universal Coordinated Time (UTC).
--
-- 'endpoint', 'dbInstance_endpoint' - Specifies the connection endpoint.
--
-- 'dbiResourceId', 'dbInstance_dbiResourceId' - The Amazon Web Services Region-unique, immutable identifier for the
-- instance. This identifier is found in CloudTrail log entries whenever
-- the KMS key for the instance is accessed.
--
-- 'enabledCloudwatchLogsExports', 'dbInstance_enabledCloudwatchLogsExports' - A list of log types that this instance is configured to export to
-- CloudWatch Logs.
--
-- 'engineVersion', 'dbInstance_engineVersion' - Indicates the database engine version.
--
-- 'statusInfos', 'dbInstance_statusInfos' - The status of a read replica. If the instance is not a read replica,
-- this is blank.
--
-- 'vpcSecurityGroups', 'dbInstance_vpcSecurityGroups' - Provides a list of VPC security group elements that the instance belongs
-- to.
newDBInstance ::
  DBInstance
newDBInstance =
  DBInstance'
    { dbInstanceStatus = Prelude.Nothing,
      preferredBackupWindow = Prelude.Nothing,
      backupRetentionPeriod = Prelude.Nothing,
      dbInstanceClass = Prelude.Nothing,
      copyTagsToSnapshot = Prelude.Nothing,
      promotionTier = Prelude.Nothing,
      autoMinorVersionUpgrade = Prelude.Nothing,
      dbInstanceIdentifier = Prelude.Nothing,
      latestRestorableTime = Prelude.Nothing,
      dbClusterIdentifier = Prelude.Nothing,
      dbSubnetGroup = Prelude.Nothing,
      instanceCreateTime = Prelude.Nothing,
      availabilityZone = Prelude.Nothing,
      publiclyAccessible = Prelude.Nothing,
      dbInstanceArn = Prelude.Nothing,
      cACertificateIdentifier = Prelude.Nothing,
      storageEncrypted = Prelude.Nothing,
      kmsKeyId = Prelude.Nothing,
      engine = Prelude.Nothing,
      pendingModifiedValues = Prelude.Nothing,
      preferredMaintenanceWindow = Prelude.Nothing,
      endpoint = Prelude.Nothing,
      dbiResourceId = Prelude.Nothing,
      enabledCloudwatchLogsExports = Prelude.Nothing,
      engineVersion = Prelude.Nothing,
      statusInfos = Prelude.Nothing,
      vpcSecurityGroups = Prelude.Nothing
    }

-- | Specifies the current state of this database.
dbInstance_dbInstanceStatus :: Lens.Lens' DBInstance (Prelude.Maybe Prelude.Text)
dbInstance_dbInstanceStatus = Lens.lens (\DBInstance' {dbInstanceStatus} -> dbInstanceStatus) (\s@DBInstance' {} a -> s {dbInstanceStatus = a} :: DBInstance)

-- | Specifies the daily time range during which automated backups are
-- created if automated backups are enabled, as determined by the
-- @BackupRetentionPeriod@.
dbInstance_preferredBackupWindow :: Lens.Lens' DBInstance (Prelude.Maybe Prelude.Text)
dbInstance_preferredBackupWindow = Lens.lens (\DBInstance' {preferredBackupWindow} -> preferredBackupWindow) (\s@DBInstance' {} a -> s {preferredBackupWindow = a} :: DBInstance)

-- | Specifies the number of days for which automatic snapshots are retained.
dbInstance_backupRetentionPeriod :: Lens.Lens' DBInstance (Prelude.Maybe Prelude.Int)
dbInstance_backupRetentionPeriod = Lens.lens (\DBInstance' {backupRetentionPeriod} -> backupRetentionPeriod) (\s@DBInstance' {} a -> s {backupRetentionPeriod = a} :: DBInstance)

-- | Contains the name of the compute and memory capacity class of the
-- instance.
dbInstance_dbInstanceClass :: Lens.Lens' DBInstance (Prelude.Maybe Prelude.Text)
dbInstance_dbInstanceClass = Lens.lens (\DBInstance' {dbInstanceClass} -> dbInstanceClass) (\s@DBInstance' {} a -> s {dbInstanceClass = a} :: DBInstance)

-- | A value that indicates whether to copy tags from the DB instance to
-- snapshots of the DB instance. By default, tags are not copied.
dbInstance_copyTagsToSnapshot :: Lens.Lens' DBInstance (Prelude.Maybe Prelude.Bool)
dbInstance_copyTagsToSnapshot = Lens.lens (\DBInstance' {copyTagsToSnapshot} -> copyTagsToSnapshot) (\s@DBInstance' {} a -> s {copyTagsToSnapshot = a} :: DBInstance)

-- | A value that specifies the order in which an Amazon DocumentDB replica
-- is promoted to the primary instance after a failure of the existing
-- primary instance.
dbInstance_promotionTier :: Lens.Lens' DBInstance (Prelude.Maybe Prelude.Int)
dbInstance_promotionTier = Lens.lens (\DBInstance' {promotionTier} -> promotionTier) (\s@DBInstance' {} a -> s {promotionTier = a} :: DBInstance)

-- | Does not apply. This parameter does not apply to Amazon DocumentDB.
-- Amazon DocumentDB does not perform minor version upgrades regardless of
-- the value set.
dbInstance_autoMinorVersionUpgrade :: Lens.Lens' DBInstance (Prelude.Maybe Prelude.Bool)
dbInstance_autoMinorVersionUpgrade = Lens.lens (\DBInstance' {autoMinorVersionUpgrade} -> autoMinorVersionUpgrade) (\s@DBInstance' {} a -> s {autoMinorVersionUpgrade = a} :: DBInstance)

-- | Contains a user-provided database identifier. This identifier is the
-- unique key that identifies an instance.
dbInstance_dbInstanceIdentifier :: Lens.Lens' DBInstance (Prelude.Maybe Prelude.Text)
dbInstance_dbInstanceIdentifier = Lens.lens (\DBInstance' {dbInstanceIdentifier} -> dbInstanceIdentifier) (\s@DBInstance' {} a -> s {dbInstanceIdentifier = a} :: DBInstance)

-- | Specifies the latest time to which a database can be restored with
-- point-in-time restore.
dbInstance_latestRestorableTime :: Lens.Lens' DBInstance (Prelude.Maybe Prelude.UTCTime)
dbInstance_latestRestorableTime = Lens.lens (\DBInstance' {latestRestorableTime} -> latestRestorableTime) (\s@DBInstance' {} a -> s {latestRestorableTime = a} :: DBInstance) Prelude.. Lens.mapping Core._Time

-- | Contains the name of the cluster that the instance is a member of if the
-- instance is a member of a cluster.
dbInstance_dbClusterIdentifier :: Lens.Lens' DBInstance (Prelude.Maybe Prelude.Text)
dbInstance_dbClusterIdentifier = Lens.lens (\DBInstance' {dbClusterIdentifier} -> dbClusterIdentifier) (\s@DBInstance' {} a -> s {dbClusterIdentifier = a} :: DBInstance)

-- | Specifies information on the subnet group that is associated with the
-- instance, including the name, description, and subnets in the subnet
-- group.
dbInstance_dbSubnetGroup :: Lens.Lens' DBInstance (Prelude.Maybe DBSubnetGroup)
dbInstance_dbSubnetGroup = Lens.lens (\DBInstance' {dbSubnetGroup} -> dbSubnetGroup) (\s@DBInstance' {} a -> s {dbSubnetGroup = a} :: DBInstance)

-- | Provides the date and time that the instance was created.
dbInstance_instanceCreateTime :: Lens.Lens' DBInstance (Prelude.Maybe Prelude.UTCTime)
dbInstance_instanceCreateTime = Lens.lens (\DBInstance' {instanceCreateTime} -> instanceCreateTime) (\s@DBInstance' {} a -> s {instanceCreateTime = a} :: DBInstance) Prelude.. Lens.mapping Core._Time

-- | Specifies the name of the Availability Zone that the instance is located
-- in.
dbInstance_availabilityZone :: Lens.Lens' DBInstance (Prelude.Maybe Prelude.Text)
dbInstance_availabilityZone = Lens.lens (\DBInstance' {availabilityZone} -> availabilityZone) (\s@DBInstance' {} a -> s {availabilityZone = a} :: DBInstance)

-- | Not supported. Amazon DocumentDB does not currently support public
-- endpoints. The value of @PubliclyAccessible@ is always @false@.
dbInstance_publiclyAccessible :: Lens.Lens' DBInstance (Prelude.Maybe Prelude.Bool)
dbInstance_publiclyAccessible = Lens.lens (\DBInstance' {publiclyAccessible} -> publiclyAccessible) (\s@DBInstance' {} a -> s {publiclyAccessible = a} :: DBInstance)

-- | The Amazon Resource Name (ARN) for the instance.
dbInstance_dbInstanceArn :: Lens.Lens' DBInstance (Prelude.Maybe Prelude.Text)
dbInstance_dbInstanceArn = Lens.lens (\DBInstance' {dbInstanceArn} -> dbInstanceArn) (\s@DBInstance' {} a -> s {dbInstanceArn = a} :: DBInstance)

-- | The identifier of the CA certificate for this DB instance.
dbInstance_cACertificateIdentifier :: Lens.Lens' DBInstance (Prelude.Maybe Prelude.Text)
dbInstance_cACertificateIdentifier = Lens.lens (\DBInstance' {cACertificateIdentifier} -> cACertificateIdentifier) (\s@DBInstance' {} a -> s {cACertificateIdentifier = a} :: DBInstance)

-- | Specifies whether or not the instance is encrypted.
dbInstance_storageEncrypted :: Lens.Lens' DBInstance (Prelude.Maybe Prelude.Bool)
dbInstance_storageEncrypted = Lens.lens (\DBInstance' {storageEncrypted} -> storageEncrypted) (\s@DBInstance' {} a -> s {storageEncrypted = a} :: DBInstance)

-- | If @StorageEncrypted@ is @true@, the KMS key identifier for the
-- encrypted instance.
dbInstance_kmsKeyId :: Lens.Lens' DBInstance (Prelude.Maybe Prelude.Text)
dbInstance_kmsKeyId = Lens.lens (\DBInstance' {kmsKeyId} -> kmsKeyId) (\s@DBInstance' {} a -> s {kmsKeyId = a} :: DBInstance)

-- | Provides the name of the database engine to be used for this instance.
dbInstance_engine :: Lens.Lens' DBInstance (Prelude.Maybe Prelude.Text)
dbInstance_engine = Lens.lens (\DBInstance' {engine} -> engine) (\s@DBInstance' {} a -> s {engine = a} :: DBInstance)

-- | Specifies that changes to the instance are pending. This element is
-- included only when changes are pending. Specific changes are identified
-- by subelements.
dbInstance_pendingModifiedValues :: Lens.Lens' DBInstance (Prelude.Maybe PendingModifiedValues)
dbInstance_pendingModifiedValues = Lens.lens (\DBInstance' {pendingModifiedValues} -> pendingModifiedValues) (\s@DBInstance' {} a -> s {pendingModifiedValues = a} :: DBInstance)

-- | Specifies the weekly time range during which system maintenance can
-- occur, in Universal Coordinated Time (UTC).
dbInstance_preferredMaintenanceWindow :: Lens.Lens' DBInstance (Prelude.Maybe Prelude.Text)
dbInstance_preferredMaintenanceWindow = Lens.lens (\DBInstance' {preferredMaintenanceWindow} -> preferredMaintenanceWindow) (\s@DBInstance' {} a -> s {preferredMaintenanceWindow = a} :: DBInstance)

-- | Specifies the connection endpoint.
dbInstance_endpoint :: Lens.Lens' DBInstance (Prelude.Maybe Endpoint)
dbInstance_endpoint = Lens.lens (\DBInstance' {endpoint} -> endpoint) (\s@DBInstance' {} a -> s {endpoint = a} :: DBInstance)

-- | The Amazon Web Services Region-unique, immutable identifier for the
-- instance. This identifier is found in CloudTrail log entries whenever
-- the KMS key for the instance is accessed.
dbInstance_dbiResourceId :: Lens.Lens' DBInstance (Prelude.Maybe Prelude.Text)
dbInstance_dbiResourceId = Lens.lens (\DBInstance' {dbiResourceId} -> dbiResourceId) (\s@DBInstance' {} a -> s {dbiResourceId = a} :: DBInstance)

-- | A list of log types that this instance is configured to export to
-- CloudWatch Logs.
dbInstance_enabledCloudwatchLogsExports :: Lens.Lens' DBInstance (Prelude.Maybe [Prelude.Text])
dbInstance_enabledCloudwatchLogsExports = Lens.lens (\DBInstance' {enabledCloudwatchLogsExports} -> enabledCloudwatchLogsExports) (\s@DBInstance' {} a -> s {enabledCloudwatchLogsExports = a} :: DBInstance) Prelude.. Lens.mapping Lens.coerced

-- | Indicates the database engine version.
dbInstance_engineVersion :: Lens.Lens' DBInstance (Prelude.Maybe Prelude.Text)
dbInstance_engineVersion = Lens.lens (\DBInstance' {engineVersion} -> engineVersion) (\s@DBInstance' {} a -> s {engineVersion = a} :: DBInstance)

-- | The status of a read replica. If the instance is not a read replica,
-- this is blank.
dbInstance_statusInfos :: Lens.Lens' DBInstance (Prelude.Maybe [DBInstanceStatusInfo])
dbInstance_statusInfos = Lens.lens (\DBInstance' {statusInfos} -> statusInfos) (\s@DBInstance' {} a -> s {statusInfos = a} :: DBInstance) Prelude.. Lens.mapping Lens.coerced

-- | Provides a list of VPC security group elements that the instance belongs
-- to.
dbInstance_vpcSecurityGroups :: Lens.Lens' DBInstance (Prelude.Maybe [VpcSecurityGroupMembership])
dbInstance_vpcSecurityGroups = Lens.lens (\DBInstance' {vpcSecurityGroups} -> vpcSecurityGroups) (\s@DBInstance' {} a -> s {vpcSecurityGroups = a} :: DBInstance) Prelude.. Lens.mapping Lens.coerced

instance Core.FromXML DBInstance where
  parseXML x =
    DBInstance'
      Prelude.<$> (x Core..@? "DBInstanceStatus")
      Prelude.<*> (x Core..@? "PreferredBackupWindow")
      Prelude.<*> (x Core..@? "BackupRetentionPeriod")
      Prelude.<*> (x Core..@? "DBInstanceClass")
      Prelude.<*> (x Core..@? "CopyTagsToSnapshot")
      Prelude.<*> (x Core..@? "PromotionTier")
      Prelude.<*> (x Core..@? "AutoMinorVersionUpgrade")
      Prelude.<*> (x Core..@? "DBInstanceIdentifier")
      Prelude.<*> (x Core..@? "LatestRestorableTime")
      Prelude.<*> (x Core..@? "DBClusterIdentifier")
      Prelude.<*> (x Core..@? "DBSubnetGroup")
      Prelude.<*> (x Core..@? "InstanceCreateTime")
      Prelude.<*> (x Core..@? "AvailabilityZone")
      Prelude.<*> (x Core..@? "PubliclyAccessible")
      Prelude.<*> (x Core..@? "DBInstanceArn")
      Prelude.<*> (x Core..@? "CACertificateIdentifier")
      Prelude.<*> (x Core..@? "StorageEncrypted")
      Prelude.<*> (x Core..@? "KmsKeyId")
      Prelude.<*> (x Core..@? "Engine")
      Prelude.<*> (x Core..@? "PendingModifiedValues")
      Prelude.<*> (x Core..@? "PreferredMaintenanceWindow")
      Prelude.<*> (x Core..@? "Endpoint")
      Prelude.<*> (x Core..@? "DbiResourceId")
      Prelude.<*> ( x Core..@? "EnabledCloudwatchLogsExports"
                      Core..!@ Prelude.mempty
                      Prelude.>>= Core.may (Core.parseXMLList "member")
                  )
      Prelude.<*> (x Core..@? "EngineVersion")
      Prelude.<*> ( x Core..@? "StatusInfos" Core..!@ Prelude.mempty
                      Prelude.>>= Core.may (Core.parseXMLList "DBInstanceStatusInfo")
                  )
      Prelude.<*> ( x Core..@? "VpcSecurityGroups"
                      Core..!@ Prelude.mempty
                      Prelude.>>= Core.may
                        (Core.parseXMLList "VpcSecurityGroupMembership")
                  )

instance Prelude.Hashable DBInstance where
  hashWithSalt _salt DBInstance' {..} =
    _salt `Prelude.hashWithSalt` dbInstanceStatus
      `Prelude.hashWithSalt` preferredBackupWindow
      `Prelude.hashWithSalt` backupRetentionPeriod
      `Prelude.hashWithSalt` dbInstanceClass
      `Prelude.hashWithSalt` copyTagsToSnapshot
      `Prelude.hashWithSalt` promotionTier
      `Prelude.hashWithSalt` autoMinorVersionUpgrade
      `Prelude.hashWithSalt` dbInstanceIdentifier
      `Prelude.hashWithSalt` latestRestorableTime
      `Prelude.hashWithSalt` dbClusterIdentifier
      `Prelude.hashWithSalt` dbSubnetGroup
      `Prelude.hashWithSalt` instanceCreateTime
      `Prelude.hashWithSalt` availabilityZone
      `Prelude.hashWithSalt` publiclyAccessible
      `Prelude.hashWithSalt` dbInstanceArn
      `Prelude.hashWithSalt` cACertificateIdentifier
      `Prelude.hashWithSalt` storageEncrypted
      `Prelude.hashWithSalt` kmsKeyId
      `Prelude.hashWithSalt` engine
      `Prelude.hashWithSalt` pendingModifiedValues
      `Prelude.hashWithSalt` preferredMaintenanceWindow
      `Prelude.hashWithSalt` endpoint
      `Prelude.hashWithSalt` dbiResourceId
      `Prelude.hashWithSalt` enabledCloudwatchLogsExports
      `Prelude.hashWithSalt` engineVersion
      `Prelude.hashWithSalt` statusInfos
      `Prelude.hashWithSalt` vpcSecurityGroups

instance Prelude.NFData DBInstance where
  rnf DBInstance' {..} =
    Prelude.rnf dbInstanceStatus
      `Prelude.seq` Prelude.rnf preferredBackupWindow
      `Prelude.seq` Prelude.rnf backupRetentionPeriod
      `Prelude.seq` Prelude.rnf dbInstanceClass
      `Prelude.seq` Prelude.rnf copyTagsToSnapshot
      `Prelude.seq` Prelude.rnf promotionTier
      `Prelude.seq` Prelude.rnf autoMinorVersionUpgrade
      `Prelude.seq` Prelude.rnf dbInstanceIdentifier
      `Prelude.seq` Prelude.rnf latestRestorableTime
      `Prelude.seq` Prelude.rnf dbClusterIdentifier
      `Prelude.seq` Prelude.rnf dbSubnetGroup
      `Prelude.seq` Prelude.rnf instanceCreateTime
      `Prelude.seq` Prelude.rnf availabilityZone
      `Prelude.seq` Prelude.rnf publiclyAccessible
      `Prelude.seq` Prelude.rnf dbInstanceArn
      `Prelude.seq` Prelude.rnf cACertificateIdentifier
      `Prelude.seq` Prelude.rnf storageEncrypted
      `Prelude.seq` Prelude.rnf kmsKeyId
      `Prelude.seq` Prelude.rnf engine
      `Prelude.seq` Prelude.rnf
        pendingModifiedValues
      `Prelude.seq` Prelude.rnf
        preferredMaintenanceWindow
      `Prelude.seq` Prelude.rnf endpoint
      `Prelude.seq` Prelude.rnf
        dbiResourceId
      `Prelude.seq` Prelude.rnf
        enabledCloudwatchLogsExports
      `Prelude.seq` Prelude.rnf
        engineVersion
      `Prelude.seq` Prelude.rnf
        statusInfos
      `Prelude.seq` Prelude.rnf
        vpcSecurityGroups
