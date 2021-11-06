{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE StrictData #-}
{-# LANGUAGE NoImplicitPrelude #-}
{-# OPTIONS_GHC -fno-warn-unused-matches #-}

-- Derived from AWS service descriptions, licensed under Apache 2.0.

-- |
-- Module      : Amazonka.SecurityHub.Types
-- Copyright   : (c) 2013-2021 Brendan Hay
-- License     : Mozilla Public License, v. 2.0.
-- Maintainer  : Brendan Hay <brendan.g.hay+amazonka@gmail.com>
-- Stability   : auto-generated
-- Portability : non-portable (GHC extensions)
module Amazonka.SecurityHub.Types
  ( -- * Service Configuration
    defaultService,

    -- * Errors
    _AccessDeniedException,
    _InvalidAccessException,
    _InvalidInputException,
    _InternalException,
    _ResourceConflictException,
    _ResourceNotFoundException,
    _LimitExceededException,

    -- * AdminStatus
    AdminStatus (..),

    -- * AwsIamAccessKeyStatus
    AwsIamAccessKeyStatus (..),

    -- * AwsS3BucketNotificationConfigurationS3KeyFilterRuleName
    AwsS3BucketNotificationConfigurationS3KeyFilterRuleName (..),

    -- * ComplianceStatus
    ComplianceStatus (..),

    -- * ControlStatus
    ControlStatus (..),

    -- * DateRangeUnit
    DateRangeUnit (..),

    -- * IntegrationType
    IntegrationType (..),

    -- * MalwareState
    MalwareState (..),

    -- * MalwareType
    MalwareType (..),

    -- * MapFilterComparison
    MapFilterComparison (..),

    -- * NetworkDirection
    NetworkDirection (..),

    -- * Partition
    Partition (..),

    -- * RecordState
    RecordState (..),

    -- * SeverityLabel
    SeverityLabel (..),

    -- * SeverityRating
    SeverityRating (..),

    -- * SortOrder
    SortOrder (..),

    -- * StandardsStatus
    StandardsStatus (..),

    -- * StringFilterComparison
    StringFilterComparison (..),

    -- * ThreatIntelIndicatorCategory
    ThreatIntelIndicatorCategory (..),

    -- * ThreatIntelIndicatorType
    ThreatIntelIndicatorType (..),

    -- * VerificationState
    VerificationState (..),

    -- * WorkflowState
    WorkflowState (..),

    -- * WorkflowStatus
    WorkflowStatus (..),

    -- * AccountDetails
    AccountDetails (..),
    newAccountDetails,
    accountDetails_email,
    accountDetails_accountId,

    -- * Action
    Action (..),
    newAction,
    action_networkConnectionAction,
    action_portProbeAction,
    action_actionType,
    action_dnsRequestAction,
    action_awsApiCallAction,

    -- * ActionLocalIpDetails
    ActionLocalIpDetails (..),
    newActionLocalIpDetails,
    actionLocalIpDetails_ipAddressV4,

    -- * ActionLocalPortDetails
    ActionLocalPortDetails (..),
    newActionLocalPortDetails,
    actionLocalPortDetails_portName,
    actionLocalPortDetails_port,

    -- * ActionRemoteIpDetails
    ActionRemoteIpDetails (..),
    newActionRemoteIpDetails,
    actionRemoteIpDetails_country,
    actionRemoteIpDetails_city,
    actionRemoteIpDetails_ipAddressV4,
    actionRemoteIpDetails_geoLocation,
    actionRemoteIpDetails_organization,

    -- * ActionRemotePortDetails
    ActionRemotePortDetails (..),
    newActionRemotePortDetails,
    actionRemotePortDetails_portName,
    actionRemotePortDetails_port,

    -- * ActionTarget
    ActionTarget (..),
    newActionTarget,
    actionTarget_actionTargetArn,
    actionTarget_name,
    actionTarget_description,

    -- * Adjustment
    Adjustment (..),
    newAdjustment,
    adjustment_reason,
    adjustment_metric,

    -- * AdminAccount
    AdminAccount (..),
    newAdminAccount,
    adminAccount_status,
    adminAccount_accountId,

    -- * AvailabilityZone
    AvailabilityZone (..),
    newAvailabilityZone,
    availabilityZone_subnetId,
    availabilityZone_zoneName,

    -- * AwsApiCallAction
    AwsApiCallAction (..),
    newAwsApiCallAction,
    awsApiCallAction_remoteIpDetails,
    awsApiCallAction_firstSeen,
    awsApiCallAction_callerType,
    awsApiCallAction_affectedResources,
    awsApiCallAction_lastSeen,
    awsApiCallAction_domainDetails,
    awsApiCallAction_serviceName,
    awsApiCallAction_api,

    -- * AwsApiCallActionDomainDetails
    AwsApiCallActionDomainDetails (..),
    newAwsApiCallActionDomainDetails,
    awsApiCallActionDomainDetails_domain,

    -- * AwsApiGatewayAccessLogSettings
    AwsApiGatewayAccessLogSettings (..),
    newAwsApiGatewayAccessLogSettings,
    awsApiGatewayAccessLogSettings_format,
    awsApiGatewayAccessLogSettings_destinationArn,

    -- * AwsApiGatewayCanarySettings
    AwsApiGatewayCanarySettings (..),
    newAwsApiGatewayCanarySettings,
    awsApiGatewayCanarySettings_deploymentId,
    awsApiGatewayCanarySettings_stageVariableOverrides,
    awsApiGatewayCanarySettings_useStageCache,
    awsApiGatewayCanarySettings_percentTraffic,

    -- * AwsApiGatewayEndpointConfiguration
    AwsApiGatewayEndpointConfiguration (..),
    newAwsApiGatewayEndpointConfiguration,
    awsApiGatewayEndpointConfiguration_types,

    -- * AwsApiGatewayMethodSettings
    AwsApiGatewayMethodSettings (..),
    newAwsApiGatewayMethodSettings,
    awsApiGatewayMethodSettings_dataTraceEnabled,
    awsApiGatewayMethodSettings_cacheTtlInSeconds,
    awsApiGatewayMethodSettings_httpMethod,
    awsApiGatewayMethodSettings_throttlingBurstLimit,
    awsApiGatewayMethodSettings_cacheDataEncrypted,
    awsApiGatewayMethodSettings_loggingLevel,
    awsApiGatewayMethodSettings_requireAuthorizationForCacheControl,
    awsApiGatewayMethodSettings_cachingEnabled,
    awsApiGatewayMethodSettings_resourcePath,
    awsApiGatewayMethodSettings_throttlingRateLimit,
    awsApiGatewayMethodSettings_metricsEnabled,
    awsApiGatewayMethodSettings_unauthorizedCacheControlHeaderStrategy,

    -- * AwsApiGatewayRestApiDetails
    AwsApiGatewayRestApiDetails (..),
    newAwsApiGatewayRestApiDetails,
    awsApiGatewayRestApiDetails_minimumCompressionSize,
    awsApiGatewayRestApiDetails_binaryMediaTypes,
    awsApiGatewayRestApiDetails_createdDate,
    awsApiGatewayRestApiDetails_name,
    awsApiGatewayRestApiDetails_apiKeySource,
    awsApiGatewayRestApiDetails_version,
    awsApiGatewayRestApiDetails_id,
    awsApiGatewayRestApiDetails_endpointConfiguration,
    awsApiGatewayRestApiDetails_description,

    -- * AwsApiGatewayStageDetails
    AwsApiGatewayStageDetails (..),
    newAwsApiGatewayStageDetails,
    awsApiGatewayStageDetails_deploymentId,
    awsApiGatewayStageDetails_accessLogSettings,
    awsApiGatewayStageDetails_variables,
    awsApiGatewayStageDetails_documentationVersion,
    awsApiGatewayStageDetails_clientCertificateId,
    awsApiGatewayStageDetails_tracingEnabled,
    awsApiGatewayStageDetails_createdDate,
    awsApiGatewayStageDetails_methodSettings,
    awsApiGatewayStageDetails_cacheClusterStatus,
    awsApiGatewayStageDetails_webAclArn,
    awsApiGatewayStageDetails_stageName,
    awsApiGatewayStageDetails_cacheClusterEnabled,
    awsApiGatewayStageDetails_cacheClusterSize,
    awsApiGatewayStageDetails_lastUpdatedDate,
    awsApiGatewayStageDetails_canarySettings,
    awsApiGatewayStageDetails_description,

    -- * AwsApiGatewayV2ApiDetails
    AwsApiGatewayV2ApiDetails (..),
    newAwsApiGatewayV2ApiDetails,
    awsApiGatewayV2ApiDetails_apiId,
    awsApiGatewayV2ApiDetails_apiEndpoint,
    awsApiGatewayV2ApiDetails_createdDate,
    awsApiGatewayV2ApiDetails_name,
    awsApiGatewayV2ApiDetails_version,
    awsApiGatewayV2ApiDetails_apiKeySelectionExpression,
    awsApiGatewayV2ApiDetails_corsConfiguration,
    awsApiGatewayV2ApiDetails_routeSelectionExpression,
    awsApiGatewayV2ApiDetails_description,
    awsApiGatewayV2ApiDetails_protocolType,

    -- * AwsApiGatewayV2RouteSettings
    AwsApiGatewayV2RouteSettings (..),
    newAwsApiGatewayV2RouteSettings,
    awsApiGatewayV2RouteSettings_dataTraceEnabled,
    awsApiGatewayV2RouteSettings_throttlingBurstLimit,
    awsApiGatewayV2RouteSettings_loggingLevel,
    awsApiGatewayV2RouteSettings_throttlingRateLimit,
    awsApiGatewayV2RouteSettings_detailedMetricsEnabled,

    -- * AwsApiGatewayV2StageDetails
    AwsApiGatewayV2StageDetails (..),
    newAwsApiGatewayV2StageDetails,
    awsApiGatewayV2StageDetails_lastDeploymentStatusMessage,
    awsApiGatewayV2StageDetails_deploymentId,
    awsApiGatewayV2StageDetails_routeSettings,
    awsApiGatewayV2StageDetails_accessLogSettings,
    awsApiGatewayV2StageDetails_clientCertificateId,
    awsApiGatewayV2StageDetails_stageVariables,
    awsApiGatewayV2StageDetails_autoDeploy,
    awsApiGatewayV2StageDetails_createdDate,
    awsApiGatewayV2StageDetails_defaultRouteSettings,
    awsApiGatewayV2StageDetails_apiGatewayManaged,
    awsApiGatewayV2StageDetails_stageName,
    awsApiGatewayV2StageDetails_lastUpdatedDate,
    awsApiGatewayV2StageDetails_description,

    -- * AwsAutoScalingAutoScalingGroupDetails
    AwsAutoScalingAutoScalingGroupDetails (..),
    newAwsAutoScalingAutoScalingGroupDetails,
    awsAutoScalingAutoScalingGroupDetails_createdTime,
    awsAutoScalingAutoScalingGroupDetails_healthCheckGracePeriod,
    awsAutoScalingAutoScalingGroupDetails_launchConfigurationName,
    awsAutoScalingAutoScalingGroupDetails_healthCheckType,
    awsAutoScalingAutoScalingGroupDetails_loadBalancerNames,

    -- * AwsAutoScalingLaunchConfigurationBlockDeviceMappingsDetails
    AwsAutoScalingLaunchConfigurationBlockDeviceMappingsDetails (..),
    newAwsAutoScalingLaunchConfigurationBlockDeviceMappingsDetails,
    awsAutoScalingLaunchConfigurationBlockDeviceMappingsDetails_virtualName,
    awsAutoScalingLaunchConfigurationBlockDeviceMappingsDetails_noDevice,
    awsAutoScalingLaunchConfigurationBlockDeviceMappingsDetails_ebs,
    awsAutoScalingLaunchConfigurationBlockDeviceMappingsDetails_deviceName,

    -- * AwsAutoScalingLaunchConfigurationBlockDeviceMappingsEbsDetails
    AwsAutoScalingLaunchConfigurationBlockDeviceMappingsEbsDetails (..),
    newAwsAutoScalingLaunchConfigurationBlockDeviceMappingsEbsDetails,
    awsAutoScalingLaunchConfigurationBlockDeviceMappingsEbsDetails_deleteOnTermination,
    awsAutoScalingLaunchConfigurationBlockDeviceMappingsEbsDetails_volumeSize,
    awsAutoScalingLaunchConfigurationBlockDeviceMappingsEbsDetails_iops,
    awsAutoScalingLaunchConfigurationBlockDeviceMappingsEbsDetails_encrypted,
    awsAutoScalingLaunchConfigurationBlockDeviceMappingsEbsDetails_volumeType,
    awsAutoScalingLaunchConfigurationBlockDeviceMappingsEbsDetails_snapshotId,

    -- * AwsAutoScalingLaunchConfigurationDetails
    AwsAutoScalingLaunchConfigurationDetails (..),
    newAwsAutoScalingLaunchConfigurationDetails,
    awsAutoScalingLaunchConfigurationDetails_associatePublicIpAddress,
    awsAutoScalingLaunchConfigurationDetails_securityGroups,
    awsAutoScalingLaunchConfigurationDetails_spotPrice,
    awsAutoScalingLaunchConfigurationDetails_createdTime,
    awsAutoScalingLaunchConfigurationDetails_instanceMonitoring,
    awsAutoScalingLaunchConfigurationDetails_keyName,
    awsAutoScalingLaunchConfigurationDetails_classicLinkVpcSecurityGroups,
    awsAutoScalingLaunchConfigurationDetails_ramdiskId,
    awsAutoScalingLaunchConfigurationDetails_kernelId,
    awsAutoScalingLaunchConfigurationDetails_instanceType,
    awsAutoScalingLaunchConfigurationDetails_ebsOptimized,
    awsAutoScalingLaunchConfigurationDetails_userData,
    awsAutoScalingLaunchConfigurationDetails_classicLinkVpcId,
    awsAutoScalingLaunchConfigurationDetails_iamInstanceProfile,
    awsAutoScalingLaunchConfigurationDetails_imageId,
    awsAutoScalingLaunchConfigurationDetails_launchConfigurationName,
    awsAutoScalingLaunchConfigurationDetails_placementTenancy,
    awsAutoScalingLaunchConfigurationDetails_blockDeviceMappings,

    -- * AwsAutoScalingLaunchConfigurationInstanceMonitoringDetails
    AwsAutoScalingLaunchConfigurationInstanceMonitoringDetails (..),
    newAwsAutoScalingLaunchConfigurationInstanceMonitoringDetails,
    awsAutoScalingLaunchConfigurationInstanceMonitoringDetails_enabled,

    -- * AwsCertificateManagerCertificateDetails
    AwsCertificateManagerCertificateDetails (..),
    newAwsCertificateManagerCertificateDetails,
    awsCertificateManagerCertificateDetails_subject,
    awsCertificateManagerCertificateDetails_status,
    awsCertificateManagerCertificateDetails_failureReason,
    awsCertificateManagerCertificateDetails_subjectAlternativeNames,
    awsCertificateManagerCertificateDetails_inUseBy,
    awsCertificateManagerCertificateDetails_createdAt,
    awsCertificateManagerCertificateDetails_serial,
    awsCertificateManagerCertificateDetails_renewalEligibility,
    awsCertificateManagerCertificateDetails_extendedKeyUsages,
    awsCertificateManagerCertificateDetails_importedAt,
    awsCertificateManagerCertificateDetails_keyUsages,
    awsCertificateManagerCertificateDetails_notBefore,
    awsCertificateManagerCertificateDetails_domainName,
    awsCertificateManagerCertificateDetails_renewalSummary,
    awsCertificateManagerCertificateDetails_keyAlgorithm,
    awsCertificateManagerCertificateDetails_type,
    awsCertificateManagerCertificateDetails_options,
    awsCertificateManagerCertificateDetails_issuedAt,
    awsCertificateManagerCertificateDetails_signatureAlgorithm,
    awsCertificateManagerCertificateDetails_domainValidationOptions,
    awsCertificateManagerCertificateDetails_issuer,
    awsCertificateManagerCertificateDetails_notAfter,
    awsCertificateManagerCertificateDetails_certificateAuthorityArn,

    -- * AwsCertificateManagerCertificateDomainValidationOption
    AwsCertificateManagerCertificateDomainValidationOption (..),
    newAwsCertificateManagerCertificateDomainValidationOption,
    awsCertificateManagerCertificateDomainValidationOption_validationEmails,
    awsCertificateManagerCertificateDomainValidationOption_validationMethod,
    awsCertificateManagerCertificateDomainValidationOption_resourceRecord,
    awsCertificateManagerCertificateDomainValidationOption_validationStatus,
    awsCertificateManagerCertificateDomainValidationOption_domainName,
    awsCertificateManagerCertificateDomainValidationOption_validationDomain,

    -- * AwsCertificateManagerCertificateExtendedKeyUsage
    AwsCertificateManagerCertificateExtendedKeyUsage (..),
    newAwsCertificateManagerCertificateExtendedKeyUsage,
    awsCertificateManagerCertificateExtendedKeyUsage_oId,
    awsCertificateManagerCertificateExtendedKeyUsage_name,

    -- * AwsCertificateManagerCertificateKeyUsage
    AwsCertificateManagerCertificateKeyUsage (..),
    newAwsCertificateManagerCertificateKeyUsage,
    awsCertificateManagerCertificateKeyUsage_name,

    -- * AwsCertificateManagerCertificateOptions
    AwsCertificateManagerCertificateOptions (..),
    newAwsCertificateManagerCertificateOptions,
    awsCertificateManagerCertificateOptions_certificateTransparencyLoggingPreference,

    -- * AwsCertificateManagerCertificateRenewalSummary
    AwsCertificateManagerCertificateRenewalSummary (..),
    newAwsCertificateManagerCertificateRenewalSummary,
    awsCertificateManagerCertificateRenewalSummary_renewalStatus,
    awsCertificateManagerCertificateRenewalSummary_updatedAt,
    awsCertificateManagerCertificateRenewalSummary_domainValidationOptions,
    awsCertificateManagerCertificateRenewalSummary_renewalStatusReason,

    -- * AwsCertificateManagerCertificateResourceRecord
    AwsCertificateManagerCertificateResourceRecord (..),
    newAwsCertificateManagerCertificateResourceRecord,
    awsCertificateManagerCertificateResourceRecord_value,
    awsCertificateManagerCertificateResourceRecord_name,
    awsCertificateManagerCertificateResourceRecord_type,

    -- * AwsCloudFrontDistributionCacheBehavior
    AwsCloudFrontDistributionCacheBehavior (..),
    newAwsCloudFrontDistributionCacheBehavior,
    awsCloudFrontDistributionCacheBehavior_viewerProtocolPolicy,

    -- * AwsCloudFrontDistributionCacheBehaviors
    AwsCloudFrontDistributionCacheBehaviors (..),
    newAwsCloudFrontDistributionCacheBehaviors,
    awsCloudFrontDistributionCacheBehaviors_items,

    -- * AwsCloudFrontDistributionDefaultCacheBehavior
    AwsCloudFrontDistributionDefaultCacheBehavior (..),
    newAwsCloudFrontDistributionDefaultCacheBehavior,
    awsCloudFrontDistributionDefaultCacheBehavior_viewerProtocolPolicy,

    -- * AwsCloudFrontDistributionDetails
    AwsCloudFrontDistributionDetails (..),
    newAwsCloudFrontDistributionDetails,
    awsCloudFrontDistributionDetails_status,
    awsCloudFrontDistributionDetails_eTag,
    awsCloudFrontDistributionDetails_originGroups,
    awsCloudFrontDistributionDetails_defaultRootObject,
    awsCloudFrontDistributionDetails_webAclId,
    awsCloudFrontDistributionDetails_lastModifiedTime,
    awsCloudFrontDistributionDetails_viewerCertificate,
    awsCloudFrontDistributionDetails_domainName,
    awsCloudFrontDistributionDetails_origins,
    awsCloudFrontDistributionDetails_logging,
    awsCloudFrontDistributionDetails_cacheBehaviors,
    awsCloudFrontDistributionDetails_defaultCacheBehavior,

    -- * AwsCloudFrontDistributionLogging
    AwsCloudFrontDistributionLogging (..),
    newAwsCloudFrontDistributionLogging,
    awsCloudFrontDistributionLogging_enabled,
    awsCloudFrontDistributionLogging_prefix,
    awsCloudFrontDistributionLogging_bucket,
    awsCloudFrontDistributionLogging_includeCookies,

    -- * AwsCloudFrontDistributionOriginGroup
    AwsCloudFrontDistributionOriginGroup (..),
    newAwsCloudFrontDistributionOriginGroup,
    awsCloudFrontDistributionOriginGroup_failoverCriteria,

    -- * AwsCloudFrontDistributionOriginGroupFailover
    AwsCloudFrontDistributionOriginGroupFailover (..),
    newAwsCloudFrontDistributionOriginGroupFailover,
    awsCloudFrontDistributionOriginGroupFailover_statusCodes,

    -- * AwsCloudFrontDistributionOriginGroupFailoverStatusCodes
    AwsCloudFrontDistributionOriginGroupFailoverStatusCodes (..),
    newAwsCloudFrontDistributionOriginGroupFailoverStatusCodes,
    awsCloudFrontDistributionOriginGroupFailoverStatusCodes_quantity,
    awsCloudFrontDistributionOriginGroupFailoverStatusCodes_items,

    -- * AwsCloudFrontDistributionOriginGroups
    AwsCloudFrontDistributionOriginGroups (..),
    newAwsCloudFrontDistributionOriginGroups,
    awsCloudFrontDistributionOriginGroups_items,

    -- * AwsCloudFrontDistributionOriginItem
    AwsCloudFrontDistributionOriginItem (..),
    newAwsCloudFrontDistributionOriginItem,
    awsCloudFrontDistributionOriginItem_s3OriginConfig,
    awsCloudFrontDistributionOriginItem_originPath,
    awsCloudFrontDistributionOriginItem_domainName,
    awsCloudFrontDistributionOriginItem_id,

    -- * AwsCloudFrontDistributionOriginS3OriginConfig
    AwsCloudFrontDistributionOriginS3OriginConfig (..),
    newAwsCloudFrontDistributionOriginS3OriginConfig,
    awsCloudFrontDistributionOriginS3OriginConfig_originAccessIdentity,

    -- * AwsCloudFrontDistributionOrigins
    AwsCloudFrontDistributionOrigins (..),
    newAwsCloudFrontDistributionOrigins,
    awsCloudFrontDistributionOrigins_items,

    -- * AwsCloudFrontDistributionViewerCertificate
    AwsCloudFrontDistributionViewerCertificate (..),
    newAwsCloudFrontDistributionViewerCertificate,
    awsCloudFrontDistributionViewerCertificate_sslSupportMethod,
    awsCloudFrontDistributionViewerCertificate_acmCertificateArn,
    awsCloudFrontDistributionViewerCertificate_certificateSource,
    awsCloudFrontDistributionViewerCertificate_minimumProtocolVersion,
    awsCloudFrontDistributionViewerCertificate_certificate,
    awsCloudFrontDistributionViewerCertificate_iamCertificateId,
    awsCloudFrontDistributionViewerCertificate_cloudFrontDefaultCertificate,

    -- * AwsCloudTrailTrailDetails
    AwsCloudTrailTrailDetails (..),
    newAwsCloudTrailTrailDetails,
    awsCloudTrailTrailDetails_logFileValidationEnabled,
    awsCloudTrailTrailDetails_trailArn,
    awsCloudTrailTrailDetails_s3KeyPrefix,
    awsCloudTrailTrailDetails_snsTopicArn,
    awsCloudTrailTrailDetails_snsTopicName,
    awsCloudTrailTrailDetails_cloudWatchLogsLogGroupArn,
    awsCloudTrailTrailDetails_kmsKeyId,
    awsCloudTrailTrailDetails_homeRegion,
    awsCloudTrailTrailDetails_name,
    awsCloudTrailTrailDetails_includeGlobalServiceEvents,
    awsCloudTrailTrailDetails_hasCustomEventSelectors,
    awsCloudTrailTrailDetails_isOrganizationTrail,
    awsCloudTrailTrailDetails_cloudWatchLogsRoleArn,
    awsCloudTrailTrailDetails_s3BucketName,
    awsCloudTrailTrailDetails_isMultiRegionTrail,

    -- * AwsCodeBuildProjectArtifactsDetails
    AwsCodeBuildProjectArtifactsDetails (..),
    newAwsCodeBuildProjectArtifactsDetails,
    awsCodeBuildProjectArtifactsDetails_packaging,
    awsCodeBuildProjectArtifactsDetails_location,
    awsCodeBuildProjectArtifactsDetails_path,
    awsCodeBuildProjectArtifactsDetails_encryptionDisabled,
    awsCodeBuildProjectArtifactsDetails_name,
    awsCodeBuildProjectArtifactsDetails_overrideArtifactName,
    awsCodeBuildProjectArtifactsDetails_artifactIdentifier,
    awsCodeBuildProjectArtifactsDetails_type,
    awsCodeBuildProjectArtifactsDetails_namespaceType,

    -- * AwsCodeBuildProjectDetails
    AwsCodeBuildProjectDetails (..),
    newAwsCodeBuildProjectDetails,
    awsCodeBuildProjectDetails_artifacts,
    awsCodeBuildProjectDetails_environment,
    awsCodeBuildProjectDetails_vpcConfig,
    awsCodeBuildProjectDetails_name,
    awsCodeBuildProjectDetails_source,
    awsCodeBuildProjectDetails_logsConfig,
    awsCodeBuildProjectDetails_encryptionKey,
    awsCodeBuildProjectDetails_serviceRole,

    -- * AwsCodeBuildProjectEnvironment
    AwsCodeBuildProjectEnvironment (..),
    newAwsCodeBuildProjectEnvironment,
    awsCodeBuildProjectEnvironment_imagePullCredentialsType,
    awsCodeBuildProjectEnvironment_privilegedMode,
    awsCodeBuildProjectEnvironment_registryCredential,
    awsCodeBuildProjectEnvironment_certificate,
    awsCodeBuildProjectEnvironment_environmentVariables,
    awsCodeBuildProjectEnvironment_type,

    -- * AwsCodeBuildProjectEnvironmentEnvironmentVariablesDetails
    AwsCodeBuildProjectEnvironmentEnvironmentVariablesDetails (..),
    newAwsCodeBuildProjectEnvironmentEnvironmentVariablesDetails,
    awsCodeBuildProjectEnvironmentEnvironmentVariablesDetails_value,
    awsCodeBuildProjectEnvironmentEnvironmentVariablesDetails_name,
    awsCodeBuildProjectEnvironmentEnvironmentVariablesDetails_type,

    -- * AwsCodeBuildProjectEnvironmentRegistryCredential
    AwsCodeBuildProjectEnvironmentRegistryCredential (..),
    newAwsCodeBuildProjectEnvironmentRegistryCredential,
    awsCodeBuildProjectEnvironmentRegistryCredential_credential,
    awsCodeBuildProjectEnvironmentRegistryCredential_credentialProvider,

    -- * AwsCodeBuildProjectLogsConfigCloudWatchLogsDetails
    AwsCodeBuildProjectLogsConfigCloudWatchLogsDetails (..),
    newAwsCodeBuildProjectLogsConfigCloudWatchLogsDetails,
    awsCodeBuildProjectLogsConfigCloudWatchLogsDetails_status,
    awsCodeBuildProjectLogsConfigCloudWatchLogsDetails_groupName,
    awsCodeBuildProjectLogsConfigCloudWatchLogsDetails_streamName,

    -- * AwsCodeBuildProjectLogsConfigDetails
    AwsCodeBuildProjectLogsConfigDetails (..),
    newAwsCodeBuildProjectLogsConfigDetails,
    awsCodeBuildProjectLogsConfigDetails_s3Logs,
    awsCodeBuildProjectLogsConfigDetails_cloudWatchLogs,

    -- * AwsCodeBuildProjectLogsConfigS3LogsDetails
    AwsCodeBuildProjectLogsConfigS3LogsDetails (..),
    newAwsCodeBuildProjectLogsConfigS3LogsDetails,
    awsCodeBuildProjectLogsConfigS3LogsDetails_status,
    awsCodeBuildProjectLogsConfigS3LogsDetails_location,
    awsCodeBuildProjectLogsConfigS3LogsDetails_encryptionDisabled,

    -- * AwsCodeBuildProjectSource
    AwsCodeBuildProjectSource (..),
    newAwsCodeBuildProjectSource,
    awsCodeBuildProjectSource_insecureSsl,
    awsCodeBuildProjectSource_location,
    awsCodeBuildProjectSource_gitCloneDepth,
    awsCodeBuildProjectSource_type,

    -- * AwsCodeBuildProjectVpcConfig
    AwsCodeBuildProjectVpcConfig (..),
    newAwsCodeBuildProjectVpcConfig,
    awsCodeBuildProjectVpcConfig_securityGroupIds,
    awsCodeBuildProjectVpcConfig_vpcId,
    awsCodeBuildProjectVpcConfig_subnets,

    -- * AwsCorsConfiguration
    AwsCorsConfiguration (..),
    newAwsCorsConfiguration,
    awsCorsConfiguration_maxAge,
    awsCorsConfiguration_allowMethods,
    awsCorsConfiguration_allowHeaders,
    awsCorsConfiguration_exposeHeaders,
    awsCorsConfiguration_allowOrigins,
    awsCorsConfiguration_allowCredentials,

    -- * AwsDynamoDbTableAttributeDefinition
    AwsDynamoDbTableAttributeDefinition (..),
    newAwsDynamoDbTableAttributeDefinition,
    awsDynamoDbTableAttributeDefinition_attributeType,
    awsDynamoDbTableAttributeDefinition_attributeName,

    -- * AwsDynamoDbTableBillingModeSummary
    AwsDynamoDbTableBillingModeSummary (..),
    newAwsDynamoDbTableBillingModeSummary,
    awsDynamoDbTableBillingModeSummary_lastUpdateToPayPerRequestDateTime,
    awsDynamoDbTableBillingModeSummary_billingMode,

    -- * AwsDynamoDbTableDetails
    AwsDynamoDbTableDetails (..),
    newAwsDynamoDbTableDetails,
    awsDynamoDbTableDetails_restoreSummary,
    awsDynamoDbTableDetails_globalTableVersion,
    awsDynamoDbTableDetails_tableSizeBytes,
    awsDynamoDbTableDetails_attributeDefinitions,
    awsDynamoDbTableDetails_latestStreamArn,
    awsDynamoDbTableDetails_provisionedThroughput,
    awsDynamoDbTableDetails_tableStatus,
    awsDynamoDbTableDetails_keySchema,
    awsDynamoDbTableDetails_globalSecondaryIndexes,
    awsDynamoDbTableDetails_latestStreamLabel,
    awsDynamoDbTableDetails_billingModeSummary,
    awsDynamoDbTableDetails_localSecondaryIndexes,
    awsDynamoDbTableDetails_creationDateTime,
    awsDynamoDbTableDetails_sseDescription,
    awsDynamoDbTableDetails_tableId,
    awsDynamoDbTableDetails_replicas,
    awsDynamoDbTableDetails_itemCount,
    awsDynamoDbTableDetails_tableName,
    awsDynamoDbTableDetails_streamSpecification,

    -- * AwsDynamoDbTableGlobalSecondaryIndex
    AwsDynamoDbTableGlobalSecondaryIndex (..),
    newAwsDynamoDbTableGlobalSecondaryIndex,
    awsDynamoDbTableGlobalSecondaryIndex_backfilling,
    awsDynamoDbTableGlobalSecondaryIndex_indexSizeBytes,
    awsDynamoDbTableGlobalSecondaryIndex_indexStatus,
    awsDynamoDbTableGlobalSecondaryIndex_provisionedThroughput,
    awsDynamoDbTableGlobalSecondaryIndex_indexArn,
    awsDynamoDbTableGlobalSecondaryIndex_keySchema,
    awsDynamoDbTableGlobalSecondaryIndex_projection,
    awsDynamoDbTableGlobalSecondaryIndex_itemCount,
    awsDynamoDbTableGlobalSecondaryIndex_indexName,

    -- * AwsDynamoDbTableKeySchema
    AwsDynamoDbTableKeySchema (..),
    newAwsDynamoDbTableKeySchema,
    awsDynamoDbTableKeySchema_keyType,
    awsDynamoDbTableKeySchema_attributeName,

    -- * AwsDynamoDbTableLocalSecondaryIndex
    AwsDynamoDbTableLocalSecondaryIndex (..),
    newAwsDynamoDbTableLocalSecondaryIndex,
    awsDynamoDbTableLocalSecondaryIndex_indexArn,
    awsDynamoDbTableLocalSecondaryIndex_keySchema,
    awsDynamoDbTableLocalSecondaryIndex_projection,
    awsDynamoDbTableLocalSecondaryIndex_indexName,

    -- * AwsDynamoDbTableProjection
    AwsDynamoDbTableProjection (..),
    newAwsDynamoDbTableProjection,
    awsDynamoDbTableProjection_projectionType,
    awsDynamoDbTableProjection_nonKeyAttributes,

    -- * AwsDynamoDbTableProvisionedThroughput
    AwsDynamoDbTableProvisionedThroughput (..),
    newAwsDynamoDbTableProvisionedThroughput,
    awsDynamoDbTableProvisionedThroughput_readCapacityUnits,
    awsDynamoDbTableProvisionedThroughput_lastDecreaseDateTime,
    awsDynamoDbTableProvisionedThroughput_writeCapacityUnits,
    awsDynamoDbTableProvisionedThroughput_numberOfDecreasesToday,
    awsDynamoDbTableProvisionedThroughput_lastIncreaseDateTime,

    -- * AwsDynamoDbTableProvisionedThroughputOverride
    AwsDynamoDbTableProvisionedThroughputOverride (..),
    newAwsDynamoDbTableProvisionedThroughputOverride,
    awsDynamoDbTableProvisionedThroughputOverride_readCapacityUnits,

    -- * AwsDynamoDbTableReplica
    AwsDynamoDbTableReplica (..),
    newAwsDynamoDbTableReplica,
    awsDynamoDbTableReplica_replicaStatus,
    awsDynamoDbTableReplica_regionName,
    awsDynamoDbTableReplica_replicaStatusDescription,
    awsDynamoDbTableReplica_kmsMasterKeyId,
    awsDynamoDbTableReplica_provisionedThroughputOverride,
    awsDynamoDbTableReplica_globalSecondaryIndexes,

    -- * AwsDynamoDbTableReplicaGlobalSecondaryIndex
    AwsDynamoDbTableReplicaGlobalSecondaryIndex (..),
    newAwsDynamoDbTableReplicaGlobalSecondaryIndex,
    awsDynamoDbTableReplicaGlobalSecondaryIndex_provisionedThroughputOverride,
    awsDynamoDbTableReplicaGlobalSecondaryIndex_indexName,

    -- * AwsDynamoDbTableRestoreSummary
    AwsDynamoDbTableRestoreSummary (..),
    newAwsDynamoDbTableRestoreSummary,
    awsDynamoDbTableRestoreSummary_sourceTableArn,
    awsDynamoDbTableRestoreSummary_sourceBackupArn,
    awsDynamoDbTableRestoreSummary_restoreInProgress,
    awsDynamoDbTableRestoreSummary_restoreDateTime,

    -- * AwsDynamoDbTableSseDescription
    AwsDynamoDbTableSseDescription (..),
    newAwsDynamoDbTableSseDescription,
    awsDynamoDbTableSseDescription_status,
    awsDynamoDbTableSseDescription_inaccessibleEncryptionDateTime,
    awsDynamoDbTableSseDescription_sseType,
    awsDynamoDbTableSseDescription_kmsMasterKeyArn,

    -- * AwsDynamoDbTableStreamSpecification
    AwsDynamoDbTableStreamSpecification (..),
    newAwsDynamoDbTableStreamSpecification,
    awsDynamoDbTableStreamSpecification_streamViewType,
    awsDynamoDbTableStreamSpecification_streamEnabled,

    -- * AwsEc2EipDetails
    AwsEc2EipDetails (..),
    newAwsEc2EipDetails,
    awsEc2EipDetails_associationId,
    awsEc2EipDetails_instanceId,
    awsEc2EipDetails_networkInterfaceOwnerId,
    awsEc2EipDetails_allocationId,
    awsEc2EipDetails_networkBorderGroup,
    awsEc2EipDetails_domain,
    awsEc2EipDetails_networkInterfaceId,
    awsEc2EipDetails_publicIpv4Pool,
    awsEc2EipDetails_privateIpAddress,
    awsEc2EipDetails_publicIp,

    -- * AwsEc2InstanceDetails
    AwsEc2InstanceDetails (..),
    newAwsEc2InstanceDetails,
    awsEc2InstanceDetails_iamInstanceProfileArn,
    awsEc2InstanceDetails_vpcId,
    awsEc2InstanceDetails_keyName,
    awsEc2InstanceDetails_networkInterfaces,
    awsEc2InstanceDetails_ipV4Addresses,
    awsEc2InstanceDetails_subnetId,
    awsEc2InstanceDetails_imageId,
    awsEc2InstanceDetails_type,
    awsEc2InstanceDetails_ipV6Addresses,
    awsEc2InstanceDetails_launchedAt,

    -- * AwsEc2InstanceNetworkInterfacesDetails
    AwsEc2InstanceNetworkInterfacesDetails (..),
    newAwsEc2InstanceNetworkInterfacesDetails,
    awsEc2InstanceNetworkInterfacesDetails_networkInterfaceId,

    -- * AwsEc2NetworkAclAssociation
    AwsEc2NetworkAclAssociation (..),
    newAwsEc2NetworkAclAssociation,
    awsEc2NetworkAclAssociation_networkAclId,
    awsEc2NetworkAclAssociation_subnetId,
    awsEc2NetworkAclAssociation_networkAclAssociationId,

    -- * AwsEc2NetworkAclDetails
    AwsEc2NetworkAclDetails (..),
    newAwsEc2NetworkAclDetails,
    awsEc2NetworkAclDetails_entries,
    awsEc2NetworkAclDetails_networkAclId,
    awsEc2NetworkAclDetails_vpcId,
    awsEc2NetworkAclDetails_ownerId,
    awsEc2NetworkAclDetails_associations,
    awsEc2NetworkAclDetails_isDefault,

    -- * AwsEc2NetworkAclEntry
    AwsEc2NetworkAclEntry (..),
    newAwsEc2NetworkAclEntry,
    awsEc2NetworkAclEntry_ipv6CidrBlock,
    awsEc2NetworkAclEntry_icmpTypeCode,
    awsEc2NetworkAclEntry_ruleNumber,
    awsEc2NetworkAclEntry_ruleAction,
    awsEc2NetworkAclEntry_protocol,
    awsEc2NetworkAclEntry_portRange,
    awsEc2NetworkAclEntry_cidrBlock,
    awsEc2NetworkAclEntry_egress,

    -- * AwsEc2NetworkInterfaceAttachment
    AwsEc2NetworkInterfaceAttachment (..),
    newAwsEc2NetworkInterfaceAttachment,
    awsEc2NetworkInterfaceAttachment_instanceId,
    awsEc2NetworkInterfaceAttachment_status,
    awsEc2NetworkInterfaceAttachment_deleteOnTermination,
    awsEc2NetworkInterfaceAttachment_attachmentId,
    awsEc2NetworkInterfaceAttachment_instanceOwnerId,
    awsEc2NetworkInterfaceAttachment_attachTime,
    awsEc2NetworkInterfaceAttachment_deviceIndex,

    -- * AwsEc2NetworkInterfaceDetails
    AwsEc2NetworkInterfaceDetails (..),
    newAwsEc2NetworkInterfaceDetails,
    awsEc2NetworkInterfaceDetails_privateIpAddresses,
    awsEc2NetworkInterfaceDetails_publicDnsName,
    awsEc2NetworkInterfaceDetails_securityGroups,
    awsEc2NetworkInterfaceDetails_sourceDestCheck,
    awsEc2NetworkInterfaceDetails_networkInterfaceId,
    awsEc2NetworkInterfaceDetails_attachment,
    awsEc2NetworkInterfaceDetails_publicIp,
    awsEc2NetworkInterfaceDetails_ipV6Addresses,

    -- * AwsEc2NetworkInterfaceIpV6AddressDetail
    AwsEc2NetworkInterfaceIpV6AddressDetail (..),
    newAwsEc2NetworkInterfaceIpV6AddressDetail,
    awsEc2NetworkInterfaceIpV6AddressDetail_ipV6Address,

    -- * AwsEc2NetworkInterfacePrivateIpAddressDetail
    AwsEc2NetworkInterfacePrivateIpAddressDetail (..),
    newAwsEc2NetworkInterfacePrivateIpAddressDetail,
    awsEc2NetworkInterfacePrivateIpAddressDetail_privateIpAddress,
    awsEc2NetworkInterfacePrivateIpAddressDetail_privateDnsName,

    -- * AwsEc2NetworkInterfaceSecurityGroup
    AwsEc2NetworkInterfaceSecurityGroup (..),
    newAwsEc2NetworkInterfaceSecurityGroup,
    awsEc2NetworkInterfaceSecurityGroup_groupId,
    awsEc2NetworkInterfaceSecurityGroup_groupName,

    -- * AwsEc2SecurityGroupDetails
    AwsEc2SecurityGroupDetails (..),
    newAwsEc2SecurityGroupDetails,
    awsEc2SecurityGroupDetails_vpcId,
    awsEc2SecurityGroupDetails_ipPermissions,
    awsEc2SecurityGroupDetails_ownerId,
    awsEc2SecurityGroupDetails_ipPermissionsEgress,
    awsEc2SecurityGroupDetails_groupId,
    awsEc2SecurityGroupDetails_groupName,

    -- * AwsEc2SecurityGroupIpPermission
    AwsEc2SecurityGroupIpPermission (..),
    newAwsEc2SecurityGroupIpPermission,
    awsEc2SecurityGroupIpPermission_fromPort,
    awsEc2SecurityGroupIpPermission_userIdGroupPairs,
    awsEc2SecurityGroupIpPermission_prefixListIds,
    awsEc2SecurityGroupIpPermission_ipProtocol,
    awsEc2SecurityGroupIpPermission_toPort,
    awsEc2SecurityGroupIpPermission_ipv6Ranges,
    awsEc2SecurityGroupIpPermission_ipRanges,

    -- * AwsEc2SecurityGroupIpRange
    AwsEc2SecurityGroupIpRange (..),
    newAwsEc2SecurityGroupIpRange,
    awsEc2SecurityGroupIpRange_cidrIp,

    -- * AwsEc2SecurityGroupIpv6Range
    AwsEc2SecurityGroupIpv6Range (..),
    newAwsEc2SecurityGroupIpv6Range,
    awsEc2SecurityGroupIpv6Range_cidrIpv6,

    -- * AwsEc2SecurityGroupPrefixListId
    AwsEc2SecurityGroupPrefixListId (..),
    newAwsEc2SecurityGroupPrefixListId,
    awsEc2SecurityGroupPrefixListId_prefixListId,

    -- * AwsEc2SecurityGroupUserIdGroupPair
    AwsEc2SecurityGroupUserIdGroupPair (..),
    newAwsEc2SecurityGroupUserIdGroupPair,
    awsEc2SecurityGroupUserIdGroupPair_vpcPeeringConnectionId,
    awsEc2SecurityGroupUserIdGroupPair_vpcId,
    awsEc2SecurityGroupUserIdGroupPair_userId,
    awsEc2SecurityGroupUserIdGroupPair_groupId,
    awsEc2SecurityGroupUserIdGroupPair_groupName,
    awsEc2SecurityGroupUserIdGroupPair_peeringStatus,

    -- * AwsEc2SubnetDetails
    AwsEc2SubnetDetails (..),
    newAwsEc2SubnetDetails,
    awsEc2SubnetDetails_state,
    awsEc2SubnetDetails_ipv6CidrBlockAssociationSet,
    awsEc2SubnetDetails_availabilityZoneId,
    awsEc2SubnetDetails_availableIpAddressCount,
    awsEc2SubnetDetails_vpcId,
    awsEc2SubnetDetails_assignIpv6AddressOnCreation,
    awsEc2SubnetDetails_subnetId,
    awsEc2SubnetDetails_subnetArn,
    awsEc2SubnetDetails_ownerId,
    awsEc2SubnetDetails_availabilityZone,
    awsEc2SubnetDetails_cidrBlock,
    awsEc2SubnetDetails_mapPublicIpOnLaunch,
    awsEc2SubnetDetails_defaultForAz,

    -- * AwsEc2VolumeAttachment
    AwsEc2VolumeAttachment (..),
    newAwsEc2VolumeAttachment,
    awsEc2VolumeAttachment_instanceId,
    awsEc2VolumeAttachment_status,
    awsEc2VolumeAttachment_deleteOnTermination,
    awsEc2VolumeAttachment_attachTime,

    -- * AwsEc2VolumeDetails
    AwsEc2VolumeDetails (..),
    newAwsEc2VolumeDetails,
    awsEc2VolumeDetails_status,
    awsEc2VolumeDetails_attachments,
    awsEc2VolumeDetails_size,
    awsEc2VolumeDetails_encrypted,
    awsEc2VolumeDetails_kmsKeyId,
    awsEc2VolumeDetails_createTime,
    awsEc2VolumeDetails_snapshotId,

    -- * AwsEc2VpcDetails
    AwsEc2VpcDetails (..),
    newAwsEc2VpcDetails,
    awsEc2VpcDetails_state,
    awsEc2VpcDetails_ipv6CidrBlockAssociationSet,
    awsEc2VpcDetails_cidrBlockAssociationSet,
    awsEc2VpcDetails_dhcpOptionsId,

    -- * AwsEc2VpcEndpointServiceDetails
    AwsEc2VpcEndpointServiceDetails (..),
    newAwsEc2VpcEndpointServiceDetails,
    awsEc2VpcEndpointServiceDetails_networkLoadBalancerArns,
    awsEc2VpcEndpointServiceDetails_baseEndpointDnsNames,
    awsEc2VpcEndpointServiceDetails_availabilityZones,
    awsEc2VpcEndpointServiceDetails_gatewayLoadBalancerArns,
    awsEc2VpcEndpointServiceDetails_managesVpcEndpoints,
    awsEc2VpcEndpointServiceDetails_serviceName,
    awsEc2VpcEndpointServiceDetails_serviceState,
    awsEc2VpcEndpointServiceDetails_serviceType,
    awsEc2VpcEndpointServiceDetails_acceptanceRequired,
    awsEc2VpcEndpointServiceDetails_serviceId,
    awsEc2VpcEndpointServiceDetails_privateDnsName,

    -- * AwsEc2VpcEndpointServiceServiceTypeDetails
    AwsEc2VpcEndpointServiceServiceTypeDetails (..),
    newAwsEc2VpcEndpointServiceServiceTypeDetails,
    awsEc2VpcEndpointServiceServiceTypeDetails_serviceType,

    -- * AwsEc2VpnConnectionDetails
    AwsEc2VpnConnectionDetails (..),
    newAwsEc2VpnConnectionDetails,
    awsEc2VpnConnectionDetails_customerGatewayConfiguration,
    awsEc2VpnConnectionDetails_state,
    awsEc2VpnConnectionDetails_routes,
    awsEc2VpnConnectionDetails_vpnGatewayId,
    awsEc2VpnConnectionDetails_category,
    awsEc2VpnConnectionDetails_customerGatewayId,
    awsEc2VpnConnectionDetails_transitGatewayId,
    awsEc2VpnConnectionDetails_type,
    awsEc2VpnConnectionDetails_options,
    awsEc2VpnConnectionDetails_vpnConnectionId,
    awsEc2VpnConnectionDetails_vgwTelemetry,

    -- * AwsEc2VpnConnectionOptionsDetails
    AwsEc2VpnConnectionOptionsDetails (..),
    newAwsEc2VpnConnectionOptionsDetails,
    awsEc2VpnConnectionOptionsDetails_tunnelOptions,
    awsEc2VpnConnectionOptionsDetails_staticRoutesOnly,

    -- * AwsEc2VpnConnectionOptionsTunnelOptionsDetails
    AwsEc2VpnConnectionOptionsTunnelOptionsDetails (..),
    newAwsEc2VpnConnectionOptionsTunnelOptionsDetails,
    awsEc2VpnConnectionOptionsTunnelOptionsDetails_outsideIpAddress,
    awsEc2VpnConnectionOptionsTunnelOptionsDetails_replayWindowSize,
    awsEc2VpnConnectionOptionsTunnelOptionsDetails_rekeyFuzzPercentage,
    awsEc2VpnConnectionOptionsTunnelOptionsDetails_phase1LifetimeSeconds,
    awsEc2VpnConnectionOptionsTunnelOptionsDetails_ikeVersions,
    awsEc2VpnConnectionOptionsTunnelOptionsDetails_phase2IntegrityAlgorithms,
    awsEc2VpnConnectionOptionsTunnelOptionsDetails_phase2LifetimeSeconds,
    awsEc2VpnConnectionOptionsTunnelOptionsDetails_phase1EncryptionAlgorithms,
    awsEc2VpnConnectionOptionsTunnelOptionsDetails_phase1DhGroupNumbers,
    awsEc2VpnConnectionOptionsTunnelOptionsDetails_phase1IntegrityAlgorithms,
    awsEc2VpnConnectionOptionsTunnelOptionsDetails_rekeyMarginTimeSeconds,
    awsEc2VpnConnectionOptionsTunnelOptionsDetails_dpdTimeoutSeconds,
    awsEc2VpnConnectionOptionsTunnelOptionsDetails_tunnelInsideCidr,
    awsEc2VpnConnectionOptionsTunnelOptionsDetails_phase2EncryptionAlgorithms,
    awsEc2VpnConnectionOptionsTunnelOptionsDetails_phase2DhGroupNumbers,
    awsEc2VpnConnectionOptionsTunnelOptionsDetails_preSharedKey,

    -- * AwsEc2VpnConnectionRoutesDetails
    AwsEc2VpnConnectionRoutesDetails (..),
    newAwsEc2VpnConnectionRoutesDetails,
    awsEc2VpnConnectionRoutesDetails_state,
    awsEc2VpnConnectionRoutesDetails_destinationCidrBlock,

    -- * AwsEc2VpnConnectionVgwTelemetryDetails
    AwsEc2VpnConnectionVgwTelemetryDetails (..),
    newAwsEc2VpnConnectionVgwTelemetryDetails,
    awsEc2VpnConnectionVgwTelemetryDetails_status,
    awsEc2VpnConnectionVgwTelemetryDetails_outsideIpAddress,
    awsEc2VpnConnectionVgwTelemetryDetails_certificateArn,
    awsEc2VpnConnectionVgwTelemetryDetails_lastStatusChange,
    awsEc2VpnConnectionVgwTelemetryDetails_acceptedRouteCount,
    awsEc2VpnConnectionVgwTelemetryDetails_statusMessage,

    -- * AwsEcrContainerImageDetails
    AwsEcrContainerImageDetails (..),
    newAwsEcrContainerImageDetails,
    awsEcrContainerImageDetails_registryId,
    awsEcrContainerImageDetails_imageTags,
    awsEcrContainerImageDetails_imageDigest,
    awsEcrContainerImageDetails_imagePublishedAt,
    awsEcrContainerImageDetails_architecture,
    awsEcrContainerImageDetails_repositoryName,

    -- * AwsEcrRepositoryDetails
    AwsEcrRepositoryDetails (..),
    newAwsEcrRepositoryDetails,
    awsEcrRepositoryDetails_arn,
    awsEcrRepositoryDetails_imageScanningConfiguration,
    awsEcrRepositoryDetails_repositoryPolicyText,
    awsEcrRepositoryDetails_repositoryName,
    awsEcrRepositoryDetails_imageTagMutability,
    awsEcrRepositoryDetails_lifecyclePolicy,

    -- * AwsEcrRepositoryImageScanningConfigurationDetails
    AwsEcrRepositoryImageScanningConfigurationDetails (..),
    newAwsEcrRepositoryImageScanningConfigurationDetails,
    awsEcrRepositoryImageScanningConfigurationDetails_scanOnPush,

    -- * AwsEcrRepositoryLifecyclePolicyDetails
    AwsEcrRepositoryLifecyclePolicyDetails (..),
    newAwsEcrRepositoryLifecyclePolicyDetails,
    awsEcrRepositoryLifecyclePolicyDetails_registryId,
    awsEcrRepositoryLifecyclePolicyDetails_lifecyclePolicyText,

    -- * AwsEcsClusterClusterSettingsDetails
    AwsEcsClusterClusterSettingsDetails (..),
    newAwsEcsClusterClusterSettingsDetails,
    awsEcsClusterClusterSettingsDetails_value,
    awsEcsClusterClusterSettingsDetails_name,

    -- * AwsEcsClusterConfigurationDetails
    AwsEcsClusterConfigurationDetails (..),
    newAwsEcsClusterConfigurationDetails,
    awsEcsClusterConfigurationDetails_executeCommandConfiguration,

    -- * AwsEcsClusterConfigurationExecuteCommandConfigurationDetails
    AwsEcsClusterConfigurationExecuteCommandConfigurationDetails (..),
    newAwsEcsClusterConfigurationExecuteCommandConfigurationDetails,
    awsEcsClusterConfigurationExecuteCommandConfigurationDetails_logConfiguration,
    awsEcsClusterConfigurationExecuteCommandConfigurationDetails_kmsKeyId,
    awsEcsClusterConfigurationExecuteCommandConfigurationDetails_logging,

    -- * AwsEcsClusterConfigurationExecuteCommandConfigurationLogConfigurationDetails
    AwsEcsClusterConfigurationExecuteCommandConfigurationLogConfigurationDetails (..),
    newAwsEcsClusterConfigurationExecuteCommandConfigurationLogConfigurationDetails,
    awsEcsClusterConfigurationExecuteCommandConfigurationLogConfigurationDetails_cloudWatchLogGroupName,
    awsEcsClusterConfigurationExecuteCommandConfigurationLogConfigurationDetails_s3KeyPrefix,
    awsEcsClusterConfigurationExecuteCommandConfigurationLogConfigurationDetails_cloudWatchEncryptionEnabled,
    awsEcsClusterConfigurationExecuteCommandConfigurationLogConfigurationDetails_s3EncryptionEnabled,
    awsEcsClusterConfigurationExecuteCommandConfigurationLogConfigurationDetails_s3BucketName,

    -- * AwsEcsClusterDefaultCapacityProviderStrategyDetails
    AwsEcsClusterDefaultCapacityProviderStrategyDetails (..),
    newAwsEcsClusterDefaultCapacityProviderStrategyDetails,
    awsEcsClusterDefaultCapacityProviderStrategyDetails_base,
    awsEcsClusterDefaultCapacityProviderStrategyDetails_capacityProvider,
    awsEcsClusterDefaultCapacityProviderStrategyDetails_weight,

    -- * AwsEcsClusterDetails
    AwsEcsClusterDetails (..),
    newAwsEcsClusterDetails,
    awsEcsClusterDetails_clusterSettings,
    awsEcsClusterDetails_defaultCapacityProviderStrategy,
    awsEcsClusterDetails_configuration,
    awsEcsClusterDetails_capacityProviders,

    -- * AwsEcsServiceCapacityProviderStrategyDetails
    AwsEcsServiceCapacityProviderStrategyDetails (..),
    newAwsEcsServiceCapacityProviderStrategyDetails,
    awsEcsServiceCapacityProviderStrategyDetails_base,
    awsEcsServiceCapacityProviderStrategyDetails_capacityProvider,
    awsEcsServiceCapacityProviderStrategyDetails_weight,

    -- * AwsEcsServiceDeploymentConfigurationDeploymentCircuitBreakerDetails
    AwsEcsServiceDeploymentConfigurationDeploymentCircuitBreakerDetails (..),
    newAwsEcsServiceDeploymentConfigurationDeploymentCircuitBreakerDetails,
    awsEcsServiceDeploymentConfigurationDeploymentCircuitBreakerDetails_rollback,
    awsEcsServiceDeploymentConfigurationDeploymentCircuitBreakerDetails_enable,

    -- * AwsEcsServiceDeploymentConfigurationDetails
    AwsEcsServiceDeploymentConfigurationDetails (..),
    newAwsEcsServiceDeploymentConfigurationDetails,
    awsEcsServiceDeploymentConfigurationDetails_minimumHealthyPercent,
    awsEcsServiceDeploymentConfigurationDetails_maximumPercent,
    awsEcsServiceDeploymentConfigurationDetails_deploymentCircuitBreaker,

    -- * AwsEcsServiceDeploymentControllerDetails
    AwsEcsServiceDeploymentControllerDetails (..),
    newAwsEcsServiceDeploymentControllerDetails,
    awsEcsServiceDeploymentControllerDetails_type,

    -- * AwsEcsServiceDetails
    AwsEcsServiceDetails (..),
    newAwsEcsServiceDetails,
    awsEcsServiceDetails_placementStrategies,
    awsEcsServiceDetails_cluster,
    awsEcsServiceDetails_propagateTags,
    awsEcsServiceDetails_platformVersion,
    awsEcsServiceDetails_enableEcsManagedTags,
    awsEcsServiceDetails_desiredCount,
    awsEcsServiceDetails_loadBalancers,
    awsEcsServiceDetails_role,
    awsEcsServiceDetails_name,
    awsEcsServiceDetails_placementConstraints,
    awsEcsServiceDetails_serviceName,
    awsEcsServiceDetails_deploymentController,
    awsEcsServiceDetails_launchType,
    awsEcsServiceDetails_taskDefinition,
    awsEcsServiceDetails_serviceArn,
    awsEcsServiceDetails_schedulingStrategy,
    awsEcsServiceDetails_capacityProviderStrategy,
    awsEcsServiceDetails_serviceRegistries,
    awsEcsServiceDetails_healthCheckGracePeriodSeconds,
    awsEcsServiceDetails_networkConfiguration,
    awsEcsServiceDetails_deploymentConfiguration,
    awsEcsServiceDetails_enableExecuteCommand,

    -- * AwsEcsServiceLoadBalancersDetails
    AwsEcsServiceLoadBalancersDetails (..),
    newAwsEcsServiceLoadBalancersDetails,
    awsEcsServiceLoadBalancersDetails_loadBalancerName,
    awsEcsServiceLoadBalancersDetails_containerName,
    awsEcsServiceLoadBalancersDetails_targetGroupArn,
    awsEcsServiceLoadBalancersDetails_containerPort,

    -- * AwsEcsServiceNetworkConfigurationAwsVpcConfigurationDetails
    AwsEcsServiceNetworkConfigurationAwsVpcConfigurationDetails (..),
    newAwsEcsServiceNetworkConfigurationAwsVpcConfigurationDetails,
    awsEcsServiceNetworkConfigurationAwsVpcConfigurationDetails_securityGroups,
    awsEcsServiceNetworkConfigurationAwsVpcConfigurationDetails_subnets,
    awsEcsServiceNetworkConfigurationAwsVpcConfigurationDetails_assignPublicIp,

    -- * AwsEcsServiceNetworkConfigurationDetails
    AwsEcsServiceNetworkConfigurationDetails (..),
    newAwsEcsServiceNetworkConfigurationDetails,
    awsEcsServiceNetworkConfigurationDetails_awsVpcConfiguration,

    -- * AwsEcsServicePlacementConstraintsDetails
    AwsEcsServicePlacementConstraintsDetails (..),
    newAwsEcsServicePlacementConstraintsDetails,
    awsEcsServicePlacementConstraintsDetails_expression,
    awsEcsServicePlacementConstraintsDetails_type,

    -- * AwsEcsServicePlacementStrategiesDetails
    AwsEcsServicePlacementStrategiesDetails (..),
    newAwsEcsServicePlacementStrategiesDetails,
    awsEcsServicePlacementStrategiesDetails_field,
    awsEcsServicePlacementStrategiesDetails_type,

    -- * AwsEcsServiceServiceRegistriesDetails
    AwsEcsServiceServiceRegistriesDetails (..),
    newAwsEcsServiceServiceRegistriesDetails,
    awsEcsServiceServiceRegistriesDetails_containerName,
    awsEcsServiceServiceRegistriesDetails_registryArn,
    awsEcsServiceServiceRegistriesDetails_containerPort,
    awsEcsServiceServiceRegistriesDetails_port,

    -- * AwsEcsTaskDefinitionContainerDefinitionsDependsOnDetails
    AwsEcsTaskDefinitionContainerDefinitionsDependsOnDetails (..),
    newAwsEcsTaskDefinitionContainerDefinitionsDependsOnDetails,
    awsEcsTaskDefinitionContainerDefinitionsDependsOnDetails_containerName,
    awsEcsTaskDefinitionContainerDefinitionsDependsOnDetails_condition,

    -- * AwsEcsTaskDefinitionContainerDefinitionsDetails
    AwsEcsTaskDefinitionContainerDefinitionsDetails (..),
    newAwsEcsTaskDefinitionContainerDefinitionsDetails,
    awsEcsTaskDefinitionContainerDefinitionsDetails_command,
    awsEcsTaskDefinitionContainerDefinitionsDetails_hostname,
    awsEcsTaskDefinitionContainerDefinitionsDetails_image,
    awsEcsTaskDefinitionContainerDefinitionsDetails_repositoryCredentials,
    awsEcsTaskDefinitionContainerDefinitionsDetails_dockerSecurityOptions,
    awsEcsTaskDefinitionContainerDefinitionsDetails_healthCheck,
    awsEcsTaskDefinitionContainerDefinitionsDetails_disableNetworking,
    awsEcsTaskDefinitionContainerDefinitionsDetails_volumesFrom,
    awsEcsTaskDefinitionContainerDefinitionsDetails_environment,
    awsEcsTaskDefinitionContainerDefinitionsDetails_secrets,
    awsEcsTaskDefinitionContainerDefinitionsDetails_entryPoint,
    awsEcsTaskDefinitionContainerDefinitionsDetails_workingDirectory,
    awsEcsTaskDefinitionContainerDefinitionsDetails_environmentFiles,
    awsEcsTaskDefinitionContainerDefinitionsDetails_stopTimeout,
    awsEcsTaskDefinitionContainerDefinitionsDetails_privileged,
    awsEcsTaskDefinitionContainerDefinitionsDetails_ulimits,
    awsEcsTaskDefinitionContainerDefinitionsDetails_portMappings,
    awsEcsTaskDefinitionContainerDefinitionsDetails_resourceRequirements,
    awsEcsTaskDefinitionContainerDefinitionsDetails_memory,
    awsEcsTaskDefinitionContainerDefinitionsDetails_extraHosts,
    awsEcsTaskDefinitionContainerDefinitionsDetails_dockerLabels,
    awsEcsTaskDefinitionContainerDefinitionsDetails_user,
    awsEcsTaskDefinitionContainerDefinitionsDetails_systemControls,
    awsEcsTaskDefinitionContainerDefinitionsDetails_linuxParameters,
    awsEcsTaskDefinitionContainerDefinitionsDetails_logConfiguration,
    awsEcsTaskDefinitionContainerDefinitionsDetails_firelensConfiguration,
    awsEcsTaskDefinitionContainerDefinitionsDetails_dnsSearchDomains,
    awsEcsTaskDefinitionContainerDefinitionsDetails_pseudoTerminal,
    awsEcsTaskDefinitionContainerDefinitionsDetails_dependsOn,
    awsEcsTaskDefinitionContainerDefinitionsDetails_dnsServers,
    awsEcsTaskDefinitionContainerDefinitionsDetails_name,
    awsEcsTaskDefinitionContainerDefinitionsDetails_mountPoints,
    awsEcsTaskDefinitionContainerDefinitionsDetails_interactive,
    awsEcsTaskDefinitionContainerDefinitionsDetails_startTimeout,
    awsEcsTaskDefinitionContainerDefinitionsDetails_readonlyRootFilesystem,
    awsEcsTaskDefinitionContainerDefinitionsDetails_links,
    awsEcsTaskDefinitionContainerDefinitionsDetails_cpu,
    awsEcsTaskDefinitionContainerDefinitionsDetails_essential,
    awsEcsTaskDefinitionContainerDefinitionsDetails_memoryReservation,

    -- * AwsEcsTaskDefinitionContainerDefinitionsEnvironmentDetails
    AwsEcsTaskDefinitionContainerDefinitionsEnvironmentDetails (..),
    newAwsEcsTaskDefinitionContainerDefinitionsEnvironmentDetails,
    awsEcsTaskDefinitionContainerDefinitionsEnvironmentDetails_value,
    awsEcsTaskDefinitionContainerDefinitionsEnvironmentDetails_name,

    -- * AwsEcsTaskDefinitionContainerDefinitionsEnvironmentFilesDetails
    AwsEcsTaskDefinitionContainerDefinitionsEnvironmentFilesDetails (..),
    newAwsEcsTaskDefinitionContainerDefinitionsEnvironmentFilesDetails,
    awsEcsTaskDefinitionContainerDefinitionsEnvironmentFilesDetails_value,
    awsEcsTaskDefinitionContainerDefinitionsEnvironmentFilesDetails_type,

    -- * AwsEcsTaskDefinitionContainerDefinitionsExtraHostsDetails
    AwsEcsTaskDefinitionContainerDefinitionsExtraHostsDetails (..),
    newAwsEcsTaskDefinitionContainerDefinitionsExtraHostsDetails,
    awsEcsTaskDefinitionContainerDefinitionsExtraHostsDetails_hostname,
    awsEcsTaskDefinitionContainerDefinitionsExtraHostsDetails_ipAddress,

    -- * AwsEcsTaskDefinitionContainerDefinitionsFirelensConfigurationDetails
    AwsEcsTaskDefinitionContainerDefinitionsFirelensConfigurationDetails (..),
    newAwsEcsTaskDefinitionContainerDefinitionsFirelensConfigurationDetails,
    awsEcsTaskDefinitionContainerDefinitionsFirelensConfigurationDetails_type,
    awsEcsTaskDefinitionContainerDefinitionsFirelensConfigurationDetails_options,

    -- * AwsEcsTaskDefinitionContainerDefinitionsHealthCheckDetails
    AwsEcsTaskDefinitionContainerDefinitionsHealthCheckDetails (..),
    newAwsEcsTaskDefinitionContainerDefinitionsHealthCheckDetails,
    awsEcsTaskDefinitionContainerDefinitionsHealthCheckDetails_command,
    awsEcsTaskDefinitionContainerDefinitionsHealthCheckDetails_startPeriod,
    awsEcsTaskDefinitionContainerDefinitionsHealthCheckDetails_retries,
    awsEcsTaskDefinitionContainerDefinitionsHealthCheckDetails_interval,
    awsEcsTaskDefinitionContainerDefinitionsHealthCheckDetails_timeout,

    -- * AwsEcsTaskDefinitionContainerDefinitionsLinuxParametersCapabilitiesDetails
    AwsEcsTaskDefinitionContainerDefinitionsLinuxParametersCapabilitiesDetails (..),
    newAwsEcsTaskDefinitionContainerDefinitionsLinuxParametersCapabilitiesDetails,
    awsEcsTaskDefinitionContainerDefinitionsLinuxParametersCapabilitiesDetails_drop,
    awsEcsTaskDefinitionContainerDefinitionsLinuxParametersCapabilitiesDetails_add,

    -- * AwsEcsTaskDefinitionContainerDefinitionsLinuxParametersDetails
    AwsEcsTaskDefinitionContainerDefinitionsLinuxParametersDetails (..),
    newAwsEcsTaskDefinitionContainerDefinitionsLinuxParametersDetails,
    awsEcsTaskDefinitionContainerDefinitionsLinuxParametersDetails_sharedMemorySize,
    awsEcsTaskDefinitionContainerDefinitionsLinuxParametersDetails_tmpfs,
    awsEcsTaskDefinitionContainerDefinitionsLinuxParametersDetails_initProcessEnabled,
    awsEcsTaskDefinitionContainerDefinitionsLinuxParametersDetails_swappiness,
    awsEcsTaskDefinitionContainerDefinitionsLinuxParametersDetails_devices,
    awsEcsTaskDefinitionContainerDefinitionsLinuxParametersDetails_capabilities,
    awsEcsTaskDefinitionContainerDefinitionsLinuxParametersDetails_maxSwap,

    -- * AwsEcsTaskDefinitionContainerDefinitionsLinuxParametersDevicesDetails
    AwsEcsTaskDefinitionContainerDefinitionsLinuxParametersDevicesDetails (..),
    newAwsEcsTaskDefinitionContainerDefinitionsLinuxParametersDevicesDetails,
    awsEcsTaskDefinitionContainerDefinitionsLinuxParametersDevicesDetails_containerPath,
    awsEcsTaskDefinitionContainerDefinitionsLinuxParametersDevicesDetails_hostPath,
    awsEcsTaskDefinitionContainerDefinitionsLinuxParametersDevicesDetails_permissions,

    -- * AwsEcsTaskDefinitionContainerDefinitionsLinuxParametersTmpfsDetails
    AwsEcsTaskDefinitionContainerDefinitionsLinuxParametersTmpfsDetails (..),
    newAwsEcsTaskDefinitionContainerDefinitionsLinuxParametersTmpfsDetails,
    awsEcsTaskDefinitionContainerDefinitionsLinuxParametersTmpfsDetails_size,
    awsEcsTaskDefinitionContainerDefinitionsLinuxParametersTmpfsDetails_containerPath,
    awsEcsTaskDefinitionContainerDefinitionsLinuxParametersTmpfsDetails_mountOptions,

    -- * AwsEcsTaskDefinitionContainerDefinitionsLogConfigurationDetails
    AwsEcsTaskDefinitionContainerDefinitionsLogConfigurationDetails (..),
    newAwsEcsTaskDefinitionContainerDefinitionsLogConfigurationDetails,
    awsEcsTaskDefinitionContainerDefinitionsLogConfigurationDetails_logDriver,
    awsEcsTaskDefinitionContainerDefinitionsLogConfigurationDetails_options,
    awsEcsTaskDefinitionContainerDefinitionsLogConfigurationDetails_secretOptions,

    -- * AwsEcsTaskDefinitionContainerDefinitionsLogConfigurationSecretOptionsDetails
    AwsEcsTaskDefinitionContainerDefinitionsLogConfigurationSecretOptionsDetails (..),
    newAwsEcsTaskDefinitionContainerDefinitionsLogConfigurationSecretOptionsDetails,
    awsEcsTaskDefinitionContainerDefinitionsLogConfigurationSecretOptionsDetails_name,
    awsEcsTaskDefinitionContainerDefinitionsLogConfigurationSecretOptionsDetails_valueFrom,

    -- * AwsEcsTaskDefinitionContainerDefinitionsMountPointsDetails
    AwsEcsTaskDefinitionContainerDefinitionsMountPointsDetails (..),
    newAwsEcsTaskDefinitionContainerDefinitionsMountPointsDetails,
    awsEcsTaskDefinitionContainerDefinitionsMountPointsDetails_containerPath,
    awsEcsTaskDefinitionContainerDefinitionsMountPointsDetails_sourceVolume,
    awsEcsTaskDefinitionContainerDefinitionsMountPointsDetails_readOnly,

    -- * AwsEcsTaskDefinitionContainerDefinitionsPortMappingsDetails
    AwsEcsTaskDefinitionContainerDefinitionsPortMappingsDetails (..),
    newAwsEcsTaskDefinitionContainerDefinitionsPortMappingsDetails,
    awsEcsTaskDefinitionContainerDefinitionsPortMappingsDetails_protocol,
    awsEcsTaskDefinitionContainerDefinitionsPortMappingsDetails_hostPort,
    awsEcsTaskDefinitionContainerDefinitionsPortMappingsDetails_containerPort,

    -- * AwsEcsTaskDefinitionContainerDefinitionsRepositoryCredentialsDetails
    AwsEcsTaskDefinitionContainerDefinitionsRepositoryCredentialsDetails (..),
    newAwsEcsTaskDefinitionContainerDefinitionsRepositoryCredentialsDetails,
    awsEcsTaskDefinitionContainerDefinitionsRepositoryCredentialsDetails_credentialsParameter,

    -- * AwsEcsTaskDefinitionContainerDefinitionsResourceRequirementsDetails
    AwsEcsTaskDefinitionContainerDefinitionsResourceRequirementsDetails (..),
    newAwsEcsTaskDefinitionContainerDefinitionsResourceRequirementsDetails,
    awsEcsTaskDefinitionContainerDefinitionsResourceRequirementsDetails_value,
    awsEcsTaskDefinitionContainerDefinitionsResourceRequirementsDetails_type,

    -- * AwsEcsTaskDefinitionContainerDefinitionsSecretsDetails
    AwsEcsTaskDefinitionContainerDefinitionsSecretsDetails (..),
    newAwsEcsTaskDefinitionContainerDefinitionsSecretsDetails,
    awsEcsTaskDefinitionContainerDefinitionsSecretsDetails_name,
    awsEcsTaskDefinitionContainerDefinitionsSecretsDetails_valueFrom,

    -- * AwsEcsTaskDefinitionContainerDefinitionsSystemControlsDetails
    AwsEcsTaskDefinitionContainerDefinitionsSystemControlsDetails (..),
    newAwsEcsTaskDefinitionContainerDefinitionsSystemControlsDetails,
    awsEcsTaskDefinitionContainerDefinitionsSystemControlsDetails_namespace,
    awsEcsTaskDefinitionContainerDefinitionsSystemControlsDetails_value,

    -- * AwsEcsTaskDefinitionContainerDefinitionsUlimitsDetails
    AwsEcsTaskDefinitionContainerDefinitionsUlimitsDetails (..),
    newAwsEcsTaskDefinitionContainerDefinitionsUlimitsDetails,
    awsEcsTaskDefinitionContainerDefinitionsUlimitsDetails_name,
    awsEcsTaskDefinitionContainerDefinitionsUlimitsDetails_hardLimit,
    awsEcsTaskDefinitionContainerDefinitionsUlimitsDetails_softLimit,

    -- * AwsEcsTaskDefinitionContainerDefinitionsVolumesFromDetails
    AwsEcsTaskDefinitionContainerDefinitionsVolumesFromDetails (..),
    newAwsEcsTaskDefinitionContainerDefinitionsVolumesFromDetails,
    awsEcsTaskDefinitionContainerDefinitionsVolumesFromDetails_sourceContainer,
    awsEcsTaskDefinitionContainerDefinitionsVolumesFromDetails_readOnly,

    -- * AwsEcsTaskDefinitionDetails
    AwsEcsTaskDefinitionDetails (..),
    newAwsEcsTaskDefinitionDetails,
    awsEcsTaskDefinitionDetails_inferenceAccelerators,
    awsEcsTaskDefinitionDetails_executionRoleArn,
    awsEcsTaskDefinitionDetails_pidMode,
    awsEcsTaskDefinitionDetails_family,
    awsEcsTaskDefinitionDetails_requiresCompatibilities,
    awsEcsTaskDefinitionDetails_containerDefinitions,
    awsEcsTaskDefinitionDetails_memory,
    awsEcsTaskDefinitionDetails_ipcMode,
    awsEcsTaskDefinitionDetails_taskRoleArn,
    awsEcsTaskDefinitionDetails_proxyConfiguration,
    awsEcsTaskDefinitionDetails_placementConstraints,
    awsEcsTaskDefinitionDetails_networkMode,
    awsEcsTaskDefinitionDetails_volumes,
    awsEcsTaskDefinitionDetails_cpu,

    -- * AwsEcsTaskDefinitionInferenceAcceleratorsDetails
    AwsEcsTaskDefinitionInferenceAcceleratorsDetails (..),
    newAwsEcsTaskDefinitionInferenceAcceleratorsDetails,
    awsEcsTaskDefinitionInferenceAcceleratorsDetails_deviceName,
    awsEcsTaskDefinitionInferenceAcceleratorsDetails_deviceType,

    -- * AwsEcsTaskDefinitionPlacementConstraintsDetails
    AwsEcsTaskDefinitionPlacementConstraintsDetails (..),
    newAwsEcsTaskDefinitionPlacementConstraintsDetails,
    awsEcsTaskDefinitionPlacementConstraintsDetails_expression,
    awsEcsTaskDefinitionPlacementConstraintsDetails_type,

    -- * AwsEcsTaskDefinitionProxyConfigurationDetails
    AwsEcsTaskDefinitionProxyConfigurationDetails (..),
    newAwsEcsTaskDefinitionProxyConfigurationDetails,
    awsEcsTaskDefinitionProxyConfigurationDetails_proxyConfigurationProperties,
    awsEcsTaskDefinitionProxyConfigurationDetails_containerName,
    awsEcsTaskDefinitionProxyConfigurationDetails_type,

    -- * AwsEcsTaskDefinitionProxyConfigurationProxyConfigurationPropertiesDetails
    AwsEcsTaskDefinitionProxyConfigurationProxyConfigurationPropertiesDetails (..),
    newAwsEcsTaskDefinitionProxyConfigurationProxyConfigurationPropertiesDetails,
    awsEcsTaskDefinitionProxyConfigurationProxyConfigurationPropertiesDetails_value,
    awsEcsTaskDefinitionProxyConfigurationProxyConfigurationPropertiesDetails_name,

    -- * AwsEcsTaskDefinitionVolumesDetails
    AwsEcsTaskDefinitionVolumesDetails (..),
    newAwsEcsTaskDefinitionVolumesDetails,
    awsEcsTaskDefinitionVolumesDetails_dockerVolumeConfiguration,
    awsEcsTaskDefinitionVolumesDetails_name,
    awsEcsTaskDefinitionVolumesDetails_efsVolumeConfiguration,
    awsEcsTaskDefinitionVolumesDetails_host,

    -- * AwsEcsTaskDefinitionVolumesDockerVolumeConfigurationDetails
    AwsEcsTaskDefinitionVolumesDockerVolumeConfigurationDetails (..),
    newAwsEcsTaskDefinitionVolumesDockerVolumeConfigurationDetails,
    awsEcsTaskDefinitionVolumesDockerVolumeConfigurationDetails_driver,
    awsEcsTaskDefinitionVolumesDockerVolumeConfigurationDetails_driverOpts,
    awsEcsTaskDefinitionVolumesDockerVolumeConfigurationDetails_scope,
    awsEcsTaskDefinitionVolumesDockerVolumeConfigurationDetails_labels,
    awsEcsTaskDefinitionVolumesDockerVolumeConfigurationDetails_autoprovision,

    -- * AwsEcsTaskDefinitionVolumesEfsVolumeConfigurationAuthorizationConfigDetails
    AwsEcsTaskDefinitionVolumesEfsVolumeConfigurationAuthorizationConfigDetails (..),
    newAwsEcsTaskDefinitionVolumesEfsVolumeConfigurationAuthorizationConfigDetails,
    awsEcsTaskDefinitionVolumesEfsVolumeConfigurationAuthorizationConfigDetails_iam,
    awsEcsTaskDefinitionVolumesEfsVolumeConfigurationAuthorizationConfigDetails_accessPointId,

    -- * AwsEcsTaskDefinitionVolumesEfsVolumeConfigurationDetails
    AwsEcsTaskDefinitionVolumesEfsVolumeConfigurationDetails (..),
    newAwsEcsTaskDefinitionVolumesEfsVolumeConfigurationDetails,
    awsEcsTaskDefinitionVolumesEfsVolumeConfigurationDetails_rootDirectory,
    awsEcsTaskDefinitionVolumesEfsVolumeConfigurationDetails_transitEncryption,
    awsEcsTaskDefinitionVolumesEfsVolumeConfigurationDetails_filesystemId,
    awsEcsTaskDefinitionVolumesEfsVolumeConfigurationDetails_authorizationConfig,
    awsEcsTaskDefinitionVolumesEfsVolumeConfigurationDetails_transitEncryptionPort,

    -- * AwsEcsTaskDefinitionVolumesHostDetails
    AwsEcsTaskDefinitionVolumesHostDetails (..),
    newAwsEcsTaskDefinitionVolumesHostDetails,
    awsEcsTaskDefinitionVolumesHostDetails_sourcePath,

    -- * AwsEksClusterDetails
    AwsEksClusterDetails (..),
    newAwsEksClusterDetails,
    awsEksClusterDetails_arn,
    awsEksClusterDetails_certificateAuthorityData,
    awsEksClusterDetails_name,
    awsEksClusterDetails_version,
    awsEksClusterDetails_logging,
    awsEksClusterDetails_endpoint,
    awsEksClusterDetails_resourcesVpcConfig,
    awsEksClusterDetails_clusterStatus,
    awsEksClusterDetails_roleArn,

    -- * AwsEksClusterLoggingClusterLoggingDetails
    AwsEksClusterLoggingClusterLoggingDetails (..),
    newAwsEksClusterLoggingClusterLoggingDetails,
    awsEksClusterLoggingClusterLoggingDetails_enabled,
    awsEksClusterLoggingClusterLoggingDetails_types,

    -- * AwsEksClusterLoggingDetails
    AwsEksClusterLoggingDetails (..),
    newAwsEksClusterLoggingDetails,
    awsEksClusterLoggingDetails_clusterLogging,

    -- * AwsEksClusterResourcesVpcConfigDetails
    AwsEksClusterResourcesVpcConfigDetails (..),
    newAwsEksClusterResourcesVpcConfigDetails,
    awsEksClusterResourcesVpcConfigDetails_securityGroupIds,
    awsEksClusterResourcesVpcConfigDetails_subnetIds,

    -- * AwsElasticBeanstalkEnvironmentDetails
    AwsElasticBeanstalkEnvironmentDetails (..),
    newAwsElasticBeanstalkEnvironmentDetails,
    awsElasticBeanstalkEnvironmentDetails_status,
    awsElasticBeanstalkEnvironmentDetails_cname,
    awsElasticBeanstalkEnvironmentDetails_endpointUrl,
    awsElasticBeanstalkEnvironmentDetails_optionSettings,
    awsElasticBeanstalkEnvironmentDetails_dateUpdated,
    awsElasticBeanstalkEnvironmentDetails_dateCreated,
    awsElasticBeanstalkEnvironmentDetails_versionLabel,
    awsElasticBeanstalkEnvironmentDetails_platformArn,
    awsElasticBeanstalkEnvironmentDetails_tier,
    awsElasticBeanstalkEnvironmentDetails_environmentName,
    awsElasticBeanstalkEnvironmentDetails_applicationName,
    awsElasticBeanstalkEnvironmentDetails_environmentArn,
    awsElasticBeanstalkEnvironmentDetails_solutionStackName,
    awsElasticBeanstalkEnvironmentDetails_environmentId,
    awsElasticBeanstalkEnvironmentDetails_environmentLinks,
    awsElasticBeanstalkEnvironmentDetails_description,

    -- * AwsElasticBeanstalkEnvironmentEnvironmentLink
    AwsElasticBeanstalkEnvironmentEnvironmentLink (..),
    newAwsElasticBeanstalkEnvironmentEnvironmentLink,
    awsElasticBeanstalkEnvironmentEnvironmentLink_linkName,
    awsElasticBeanstalkEnvironmentEnvironmentLink_environmentName,

    -- * AwsElasticBeanstalkEnvironmentOptionSetting
    AwsElasticBeanstalkEnvironmentOptionSetting (..),
    newAwsElasticBeanstalkEnvironmentOptionSetting,
    awsElasticBeanstalkEnvironmentOptionSetting_optionName,
    awsElasticBeanstalkEnvironmentOptionSetting_resourceName,
    awsElasticBeanstalkEnvironmentOptionSetting_namespace,
    awsElasticBeanstalkEnvironmentOptionSetting_value,

    -- * AwsElasticBeanstalkEnvironmentTier
    AwsElasticBeanstalkEnvironmentTier (..),
    newAwsElasticBeanstalkEnvironmentTier,
    awsElasticBeanstalkEnvironmentTier_name,
    awsElasticBeanstalkEnvironmentTier_version,
    awsElasticBeanstalkEnvironmentTier_type,

    -- * AwsElasticsearchDomainDetails
    AwsElasticsearchDomainDetails (..),
    newAwsElasticsearchDomainDetails,
    awsElasticsearchDomainDetails_nodeToNodeEncryptionOptions,
    awsElasticsearchDomainDetails_accessPolicies,
    awsElasticsearchDomainDetails_serviceSoftwareOptions,
    awsElasticsearchDomainDetails_logPublishingOptions,
    awsElasticsearchDomainDetails_elasticsearchClusterConfig,
    awsElasticsearchDomainDetails_domainName,
    awsElasticsearchDomainDetails_encryptionAtRestOptions,
    awsElasticsearchDomainDetails_vPCOptions,
    awsElasticsearchDomainDetails_domainId,
    awsElasticsearchDomainDetails_endpoints,
    awsElasticsearchDomainDetails_domainEndpointOptions,
    awsElasticsearchDomainDetails_endpoint,
    awsElasticsearchDomainDetails_elasticsearchVersion,

    -- * AwsElasticsearchDomainDomainEndpointOptions
    AwsElasticsearchDomainDomainEndpointOptions (..),
    newAwsElasticsearchDomainDomainEndpointOptions,
    awsElasticsearchDomainDomainEndpointOptions_enforceHTTPS,
    awsElasticsearchDomainDomainEndpointOptions_tLSSecurityPolicy,

    -- * AwsElasticsearchDomainElasticsearchClusterConfigDetails
    AwsElasticsearchDomainElasticsearchClusterConfigDetails (..),
    newAwsElasticsearchDomainElasticsearchClusterConfigDetails,
    awsElasticsearchDomainElasticsearchClusterConfigDetails_dedicatedMasterCount,
    awsElasticsearchDomainElasticsearchClusterConfigDetails_dedicatedMasterType,
    awsElasticsearchDomainElasticsearchClusterConfigDetails_dedicatedMasterEnabled,
    awsElasticsearchDomainElasticsearchClusterConfigDetails_instanceCount,
    awsElasticsearchDomainElasticsearchClusterConfigDetails_zoneAwarenessEnabled,
    awsElasticsearchDomainElasticsearchClusterConfigDetails_instanceType,
    awsElasticsearchDomainElasticsearchClusterConfigDetails_zoneAwarenessConfig,

    -- * AwsElasticsearchDomainElasticsearchClusterConfigZoneAwarenessConfigDetails
    AwsElasticsearchDomainElasticsearchClusterConfigZoneAwarenessConfigDetails (..),
    newAwsElasticsearchDomainElasticsearchClusterConfigZoneAwarenessConfigDetails,
    awsElasticsearchDomainElasticsearchClusterConfigZoneAwarenessConfigDetails_availabilityZoneCount,

    -- * AwsElasticsearchDomainEncryptionAtRestOptions
    AwsElasticsearchDomainEncryptionAtRestOptions (..),
    newAwsElasticsearchDomainEncryptionAtRestOptions,
    awsElasticsearchDomainEncryptionAtRestOptions_enabled,
    awsElasticsearchDomainEncryptionAtRestOptions_kmsKeyId,

    -- * AwsElasticsearchDomainLogPublishingOptions
    AwsElasticsearchDomainLogPublishingOptions (..),
    newAwsElasticsearchDomainLogPublishingOptions,
    awsElasticsearchDomainLogPublishingOptions_indexSlowLogs,
    awsElasticsearchDomainLogPublishingOptions_searchSlowLogs,
    awsElasticsearchDomainLogPublishingOptions_auditLogs,

    -- * AwsElasticsearchDomainLogPublishingOptionsLogConfig
    AwsElasticsearchDomainLogPublishingOptionsLogConfig (..),
    newAwsElasticsearchDomainLogPublishingOptionsLogConfig,
    awsElasticsearchDomainLogPublishingOptionsLogConfig_enabled,
    awsElasticsearchDomainLogPublishingOptionsLogConfig_cloudWatchLogsLogGroupArn,

    -- * AwsElasticsearchDomainNodeToNodeEncryptionOptions
    AwsElasticsearchDomainNodeToNodeEncryptionOptions (..),
    newAwsElasticsearchDomainNodeToNodeEncryptionOptions,
    awsElasticsearchDomainNodeToNodeEncryptionOptions_enabled,

    -- * AwsElasticsearchDomainServiceSoftwareOptions
    AwsElasticsearchDomainServiceSoftwareOptions (..),
    newAwsElasticsearchDomainServiceSoftwareOptions,
    awsElasticsearchDomainServiceSoftwareOptions_automatedUpdateDate,
    awsElasticsearchDomainServiceSoftwareOptions_currentVersion,
    awsElasticsearchDomainServiceSoftwareOptions_updateStatus,
    awsElasticsearchDomainServiceSoftwareOptions_cancellable,
    awsElasticsearchDomainServiceSoftwareOptions_updateAvailable,
    awsElasticsearchDomainServiceSoftwareOptions_description,
    awsElasticsearchDomainServiceSoftwareOptions_newVersion,

    -- * AwsElasticsearchDomainVPCOptions
    AwsElasticsearchDomainVPCOptions (..),
    newAwsElasticsearchDomainVPCOptions,
    awsElasticsearchDomainVPCOptions_securityGroupIds,
    awsElasticsearchDomainVPCOptions_subnetIds,
    awsElasticsearchDomainVPCOptions_vPCId,
    awsElasticsearchDomainVPCOptions_availabilityZones,

    -- * AwsElbAppCookieStickinessPolicy
    AwsElbAppCookieStickinessPolicy (..),
    newAwsElbAppCookieStickinessPolicy,
    awsElbAppCookieStickinessPolicy_policyName,
    awsElbAppCookieStickinessPolicy_cookieName,

    -- * AwsElbLbCookieStickinessPolicy
    AwsElbLbCookieStickinessPolicy (..),
    newAwsElbLbCookieStickinessPolicy,
    awsElbLbCookieStickinessPolicy_policyName,
    awsElbLbCookieStickinessPolicy_cookieExpirationPeriod,

    -- * AwsElbLoadBalancerAccessLog
    AwsElbLoadBalancerAccessLog (..),
    newAwsElbLoadBalancerAccessLog,
    awsElbLoadBalancerAccessLog_emitInterval,
    awsElbLoadBalancerAccessLog_enabled,
    awsElbLoadBalancerAccessLog_s3BucketPrefix,
    awsElbLoadBalancerAccessLog_s3BucketName,

    -- * AwsElbLoadBalancerAttributes
    AwsElbLoadBalancerAttributes (..),
    newAwsElbLoadBalancerAttributes,
    awsElbLoadBalancerAttributes_crossZoneLoadBalancing,
    awsElbLoadBalancerAttributes_accessLog,
    awsElbLoadBalancerAttributes_connectionSettings,
    awsElbLoadBalancerAttributes_connectionDraining,

    -- * AwsElbLoadBalancerBackendServerDescription
    AwsElbLoadBalancerBackendServerDescription (..),
    newAwsElbLoadBalancerBackendServerDescription,
    awsElbLoadBalancerBackendServerDescription_policyNames,
    awsElbLoadBalancerBackendServerDescription_instancePort,

    -- * AwsElbLoadBalancerConnectionDraining
    AwsElbLoadBalancerConnectionDraining (..),
    newAwsElbLoadBalancerConnectionDraining,
    awsElbLoadBalancerConnectionDraining_enabled,
    awsElbLoadBalancerConnectionDraining_timeout,

    -- * AwsElbLoadBalancerConnectionSettings
    AwsElbLoadBalancerConnectionSettings (..),
    newAwsElbLoadBalancerConnectionSettings,
    awsElbLoadBalancerConnectionSettings_idleTimeout,

    -- * AwsElbLoadBalancerCrossZoneLoadBalancing
    AwsElbLoadBalancerCrossZoneLoadBalancing (..),
    newAwsElbLoadBalancerCrossZoneLoadBalancing,
    awsElbLoadBalancerCrossZoneLoadBalancing_enabled,

    -- * AwsElbLoadBalancerDetails
    AwsElbLoadBalancerDetails (..),
    newAwsElbLoadBalancerDetails,
    awsElbLoadBalancerDetails_sourceSecurityGroup,
    awsElbLoadBalancerDetails_canonicalHostedZoneName,
    awsElbLoadBalancerDetails_securityGroups,
    awsElbLoadBalancerDetails_healthCheck,
    awsElbLoadBalancerDetails_loadBalancerName,
    awsElbLoadBalancerDetails_loadBalancerAttributes,
    awsElbLoadBalancerDetails_createdTime,
    awsElbLoadBalancerDetails_vpcId,
    awsElbLoadBalancerDetails_subnets,
    awsElbLoadBalancerDetails_availabilityZones,
    awsElbLoadBalancerDetails_backendServerDescriptions,
    awsElbLoadBalancerDetails_canonicalHostedZoneNameID,
    awsElbLoadBalancerDetails_instances,
    awsElbLoadBalancerDetails_scheme,
    awsElbLoadBalancerDetails_listenerDescriptions,
    awsElbLoadBalancerDetails_dnsName,
    awsElbLoadBalancerDetails_policies,

    -- * AwsElbLoadBalancerHealthCheck
    AwsElbLoadBalancerHealthCheck (..),
    newAwsElbLoadBalancerHealthCheck,
    awsElbLoadBalancerHealthCheck_healthyThreshold,
    awsElbLoadBalancerHealthCheck_interval,
    awsElbLoadBalancerHealthCheck_timeout,
    awsElbLoadBalancerHealthCheck_unhealthyThreshold,
    awsElbLoadBalancerHealthCheck_target,

    -- * AwsElbLoadBalancerInstance
    AwsElbLoadBalancerInstance (..),
    newAwsElbLoadBalancerInstance,
    awsElbLoadBalancerInstance_instanceId,

    -- * AwsElbLoadBalancerListener
    AwsElbLoadBalancerListener (..),
    newAwsElbLoadBalancerListener,
    awsElbLoadBalancerListener_instanceProtocol,
    awsElbLoadBalancerListener_instancePort,
    awsElbLoadBalancerListener_loadBalancerPort,
    awsElbLoadBalancerListener_protocol,
    awsElbLoadBalancerListener_sslCertificateId,

    -- * AwsElbLoadBalancerListenerDescription
    AwsElbLoadBalancerListenerDescription (..),
    newAwsElbLoadBalancerListenerDescription,
    awsElbLoadBalancerListenerDescription_policyNames,
    awsElbLoadBalancerListenerDescription_listener,

    -- * AwsElbLoadBalancerPolicies
    AwsElbLoadBalancerPolicies (..),
    newAwsElbLoadBalancerPolicies,
    awsElbLoadBalancerPolicies_otherPolicies,
    awsElbLoadBalancerPolicies_lbCookieStickinessPolicies,
    awsElbLoadBalancerPolicies_appCookieStickinessPolicies,

    -- * AwsElbLoadBalancerSourceSecurityGroup
    AwsElbLoadBalancerSourceSecurityGroup (..),
    newAwsElbLoadBalancerSourceSecurityGroup,
    awsElbLoadBalancerSourceSecurityGroup_ownerAlias,
    awsElbLoadBalancerSourceSecurityGroup_groupName,

    -- * AwsElbv2LoadBalancerAttribute
    AwsElbv2LoadBalancerAttribute (..),
    newAwsElbv2LoadBalancerAttribute,
    awsElbv2LoadBalancerAttribute_value,
    awsElbv2LoadBalancerAttribute_key,

    -- * AwsElbv2LoadBalancerDetails
    AwsElbv2LoadBalancerDetails (..),
    newAwsElbv2LoadBalancerDetails,
    awsElbv2LoadBalancerDetails_state,
    awsElbv2LoadBalancerDetails_securityGroups,
    awsElbv2LoadBalancerDetails_loadBalancerAttributes,
    awsElbv2LoadBalancerDetails_createdTime,
    awsElbv2LoadBalancerDetails_vpcId,
    awsElbv2LoadBalancerDetails_canonicalHostedZoneId,
    awsElbv2LoadBalancerDetails_availabilityZones,
    awsElbv2LoadBalancerDetails_ipAddressType,
    awsElbv2LoadBalancerDetails_scheme,
    awsElbv2LoadBalancerDetails_type,
    awsElbv2LoadBalancerDetails_dNSName,

    -- * AwsIamAccessKeyDetails
    AwsIamAccessKeyDetails (..),
    newAwsIamAccessKeyDetails,
    awsIamAccessKeyDetails_status,
    awsIamAccessKeyDetails_principalId,
    awsIamAccessKeyDetails_principalType,
    awsIamAccessKeyDetails_principalName,
    awsIamAccessKeyDetails_createdAt,
    awsIamAccessKeyDetails_userName,
    awsIamAccessKeyDetails_sessionContext,
    awsIamAccessKeyDetails_accountId,
    awsIamAccessKeyDetails_accessKeyId,

    -- * AwsIamAccessKeySessionContext
    AwsIamAccessKeySessionContext (..),
    newAwsIamAccessKeySessionContext,
    awsIamAccessKeySessionContext_attributes,
    awsIamAccessKeySessionContext_sessionIssuer,

    -- * AwsIamAccessKeySessionContextAttributes
    AwsIamAccessKeySessionContextAttributes (..),
    newAwsIamAccessKeySessionContextAttributes,
    awsIamAccessKeySessionContextAttributes_creationDate,
    awsIamAccessKeySessionContextAttributes_mfaAuthenticated,

    -- * AwsIamAccessKeySessionContextSessionIssuer
    AwsIamAccessKeySessionContextSessionIssuer (..),
    newAwsIamAccessKeySessionContextSessionIssuer,
    awsIamAccessKeySessionContextSessionIssuer_principalId,
    awsIamAccessKeySessionContextSessionIssuer_arn,
    awsIamAccessKeySessionContextSessionIssuer_userName,
    awsIamAccessKeySessionContextSessionIssuer_accountId,
    awsIamAccessKeySessionContextSessionIssuer_type,

    -- * AwsIamAttachedManagedPolicy
    AwsIamAttachedManagedPolicy (..),
    newAwsIamAttachedManagedPolicy,
    awsIamAttachedManagedPolicy_policyName,
    awsIamAttachedManagedPolicy_policyArn,

    -- * AwsIamGroupDetails
    AwsIamGroupDetails (..),
    newAwsIamGroupDetails,
    awsIamGroupDetails_path,
    awsIamGroupDetails_createDate,
    awsIamGroupDetails_groupId,
    awsIamGroupDetails_groupPolicyList,
    awsIamGroupDetails_groupName,
    awsIamGroupDetails_attachedManagedPolicies,

    -- * AwsIamGroupPolicy
    AwsIamGroupPolicy (..),
    newAwsIamGroupPolicy,
    awsIamGroupPolicy_policyName,

    -- * AwsIamInstanceProfile
    AwsIamInstanceProfile (..),
    newAwsIamInstanceProfile,
    awsIamInstanceProfile_roles,
    awsIamInstanceProfile_arn,
    awsIamInstanceProfile_path,
    awsIamInstanceProfile_createDate,
    awsIamInstanceProfile_instanceProfileId,
    awsIamInstanceProfile_instanceProfileName,

    -- * AwsIamInstanceProfileRole
    AwsIamInstanceProfileRole (..),
    newAwsIamInstanceProfileRole,
    awsIamInstanceProfileRole_assumeRolePolicyDocument,
    awsIamInstanceProfileRole_arn,
    awsIamInstanceProfileRole_path,
    awsIamInstanceProfileRole_createDate,
    awsIamInstanceProfileRole_roleName,
    awsIamInstanceProfileRole_roleId,

    -- * AwsIamPermissionsBoundary
    AwsIamPermissionsBoundary (..),
    newAwsIamPermissionsBoundary,
    awsIamPermissionsBoundary_permissionsBoundaryType,
    awsIamPermissionsBoundary_permissionsBoundaryArn,

    -- * AwsIamPolicyDetails
    AwsIamPolicyDetails (..),
    newAwsIamPolicyDetails,
    awsIamPolicyDetails_policyName,
    awsIamPolicyDetails_updateDate,
    awsIamPolicyDetails_policyId,
    awsIamPolicyDetails_path,
    awsIamPolicyDetails_policyVersionList,
    awsIamPolicyDetails_createDate,
    awsIamPolicyDetails_isAttachable,
    awsIamPolicyDetails_permissionsBoundaryUsageCount,
    awsIamPolicyDetails_defaultVersionId,
    awsIamPolicyDetails_attachmentCount,
    awsIamPolicyDetails_description,

    -- * AwsIamPolicyVersion
    AwsIamPolicyVersion (..),
    newAwsIamPolicyVersion,
    awsIamPolicyVersion_versionId,
    awsIamPolicyVersion_createDate,
    awsIamPolicyVersion_isDefaultVersion,

    -- * AwsIamRoleDetails
    AwsIamRoleDetails (..),
    newAwsIamRoleDetails,
    awsIamRoleDetails_maxSessionDuration,
    awsIamRoleDetails_assumeRolePolicyDocument,
    awsIamRoleDetails_path,
    awsIamRoleDetails_instanceProfileList,
    awsIamRoleDetails_createDate,
    awsIamRoleDetails_roleName,
    awsIamRoleDetails_roleId,
    awsIamRoleDetails_permissionsBoundary,
    awsIamRoleDetails_rolePolicyList,
    awsIamRoleDetails_attachedManagedPolicies,

    -- * AwsIamRolePolicy
    AwsIamRolePolicy (..),
    newAwsIamRolePolicy,
    awsIamRolePolicy_policyName,

    -- * AwsIamUserDetails
    AwsIamUserDetails (..),
    newAwsIamUserDetails,
    awsIamUserDetails_groupList,
    awsIamUserDetails_path,
    awsIamUserDetails_createDate,
    awsIamUserDetails_userName,
    awsIamUserDetails_userId,
    awsIamUserDetails_permissionsBoundary,
    awsIamUserDetails_userPolicyList,
    awsIamUserDetails_attachedManagedPolicies,

    -- * AwsIamUserPolicy
    AwsIamUserPolicy (..),
    newAwsIamUserPolicy,
    awsIamUserPolicy_policyName,

    -- * AwsKmsKeyDetails
    AwsKmsKeyDetails (..),
    newAwsKmsKeyDetails,
    awsKmsKeyDetails_origin,
    awsKmsKeyDetails_keyManager,
    awsKmsKeyDetails_keyId,
    awsKmsKeyDetails_keyState,
    awsKmsKeyDetails_aWSAccountId,
    awsKmsKeyDetails_keyRotationStatus,
    awsKmsKeyDetails_creationDate,
    awsKmsKeyDetails_description,

    -- * AwsLambdaFunctionCode
    AwsLambdaFunctionCode (..),
    newAwsLambdaFunctionCode,
    awsLambdaFunctionCode_s3ObjectVersion,
    awsLambdaFunctionCode_s3Key,
    awsLambdaFunctionCode_zipFile,
    awsLambdaFunctionCode_s3Bucket,

    -- * AwsLambdaFunctionDeadLetterConfig
    AwsLambdaFunctionDeadLetterConfig (..),
    newAwsLambdaFunctionDeadLetterConfig,
    awsLambdaFunctionDeadLetterConfig_targetArn,

    -- * AwsLambdaFunctionDetails
    AwsLambdaFunctionDetails (..),
    newAwsLambdaFunctionDetails,
    awsLambdaFunctionDetails_memorySize,
    awsLambdaFunctionDetails_runtime,
    awsLambdaFunctionDetails_kmsKeyArn,
    awsLambdaFunctionDetails_environment,
    awsLambdaFunctionDetails_deadLetterConfig,
    awsLambdaFunctionDetails_role,
    awsLambdaFunctionDetails_vpcConfig,
    awsLambdaFunctionDetails_version,
    awsLambdaFunctionDetails_functionName,
    awsLambdaFunctionDetails_code,
    awsLambdaFunctionDetails_layers,
    awsLambdaFunctionDetails_handler,
    awsLambdaFunctionDetails_timeout,
    awsLambdaFunctionDetails_lastModified,
    awsLambdaFunctionDetails_codeSha256,
    awsLambdaFunctionDetails_tracingConfig,
    awsLambdaFunctionDetails_revisionId,
    awsLambdaFunctionDetails_masterArn,

    -- * AwsLambdaFunctionEnvironment
    AwsLambdaFunctionEnvironment (..),
    newAwsLambdaFunctionEnvironment,
    awsLambdaFunctionEnvironment_variables,
    awsLambdaFunctionEnvironment_error,

    -- * AwsLambdaFunctionEnvironmentError
    AwsLambdaFunctionEnvironmentError (..),
    newAwsLambdaFunctionEnvironmentError,
    awsLambdaFunctionEnvironmentError_errorCode,
    awsLambdaFunctionEnvironmentError_message,

    -- * AwsLambdaFunctionLayer
    AwsLambdaFunctionLayer (..),
    newAwsLambdaFunctionLayer,
    awsLambdaFunctionLayer_arn,
    awsLambdaFunctionLayer_codeSize,

    -- * AwsLambdaFunctionTracingConfig
    AwsLambdaFunctionTracingConfig (..),
    newAwsLambdaFunctionTracingConfig,
    awsLambdaFunctionTracingConfig_mode,

    -- * AwsLambdaFunctionVpcConfig
    AwsLambdaFunctionVpcConfig (..),
    newAwsLambdaFunctionVpcConfig,
    awsLambdaFunctionVpcConfig_securityGroupIds,
    awsLambdaFunctionVpcConfig_subnetIds,
    awsLambdaFunctionVpcConfig_vpcId,

    -- * AwsLambdaLayerVersionDetails
    AwsLambdaLayerVersionDetails (..),
    newAwsLambdaLayerVersionDetails,
    awsLambdaLayerVersionDetails_createdDate,
    awsLambdaLayerVersionDetails_version,
    awsLambdaLayerVersionDetails_compatibleRuntimes,

    -- * AwsOpenSearchServiceDomainClusterConfigDetails
    AwsOpenSearchServiceDomainClusterConfigDetails (..),
    newAwsOpenSearchServiceDomainClusterConfigDetails,
    awsOpenSearchServiceDomainClusterConfigDetails_dedicatedMasterCount,
    awsOpenSearchServiceDomainClusterConfigDetails_dedicatedMasterType,
    awsOpenSearchServiceDomainClusterConfigDetails_dedicatedMasterEnabled,
    awsOpenSearchServiceDomainClusterConfigDetails_instanceCount,
    awsOpenSearchServiceDomainClusterConfigDetails_zoneAwarenessEnabled,
    awsOpenSearchServiceDomainClusterConfigDetails_instanceType,
    awsOpenSearchServiceDomainClusterConfigDetails_warmEnabled,
    awsOpenSearchServiceDomainClusterConfigDetails_zoneAwarenessConfig,
    awsOpenSearchServiceDomainClusterConfigDetails_warmCount,
    awsOpenSearchServiceDomainClusterConfigDetails_warmType,

    -- * AwsOpenSearchServiceDomainClusterConfigZoneAwarenessConfigDetails
    AwsOpenSearchServiceDomainClusterConfigZoneAwarenessConfigDetails (..),
    newAwsOpenSearchServiceDomainClusterConfigZoneAwarenessConfigDetails,
    awsOpenSearchServiceDomainClusterConfigZoneAwarenessConfigDetails_availabilityZoneCount,

    -- * AwsOpenSearchServiceDomainDetails
    AwsOpenSearchServiceDomainDetails (..),
    newAwsOpenSearchServiceDomainDetails,
    awsOpenSearchServiceDomainDetails_engineVersion,
    awsOpenSearchServiceDomainDetails_nodeToNodeEncryptionOptions,
    awsOpenSearchServiceDomainDetails_accessPolicies,
    awsOpenSearchServiceDomainDetails_serviceSoftwareOptions,
    awsOpenSearchServiceDomainDetails_arn,
    awsOpenSearchServiceDomainDetails_logPublishingOptions,
    awsOpenSearchServiceDomainDetails_clusterConfig,
    awsOpenSearchServiceDomainDetails_domainName,
    awsOpenSearchServiceDomainDetails_encryptionAtRestOptions,
    awsOpenSearchServiceDomainDetails_vpcOptions,
    awsOpenSearchServiceDomainDetails_id,
    awsOpenSearchServiceDomainDetails_domainEndpoints,
    awsOpenSearchServiceDomainDetails_domainEndpoint,
    awsOpenSearchServiceDomainDetails_domainEndpointOptions,

    -- * AwsOpenSearchServiceDomainDomainEndpointOptionsDetails
    AwsOpenSearchServiceDomainDomainEndpointOptionsDetails (..),
    newAwsOpenSearchServiceDomainDomainEndpointOptionsDetails,
    awsOpenSearchServiceDomainDomainEndpointOptionsDetails_enforceHTTPS,
    awsOpenSearchServiceDomainDomainEndpointOptionsDetails_tLSSecurityPolicy,
    awsOpenSearchServiceDomainDomainEndpointOptionsDetails_customEndpointEnabled,
    awsOpenSearchServiceDomainDomainEndpointOptionsDetails_customEndpoint,
    awsOpenSearchServiceDomainDomainEndpointOptionsDetails_customEndpointCertificateArn,

    -- * AwsOpenSearchServiceDomainEncryptionAtRestOptionsDetails
    AwsOpenSearchServiceDomainEncryptionAtRestOptionsDetails (..),
    newAwsOpenSearchServiceDomainEncryptionAtRestOptionsDetails,
    awsOpenSearchServiceDomainEncryptionAtRestOptionsDetails_enabled,
    awsOpenSearchServiceDomainEncryptionAtRestOptionsDetails_kmsKeyId,

    -- * AwsOpenSearchServiceDomainLogPublishingOption
    AwsOpenSearchServiceDomainLogPublishingOption (..),
    newAwsOpenSearchServiceDomainLogPublishingOption,
    awsOpenSearchServiceDomainLogPublishingOption_enabled,
    awsOpenSearchServiceDomainLogPublishingOption_cloudWatchLogsLogGroupArn,

    -- * AwsOpenSearchServiceDomainLogPublishingOptionsDetails
    AwsOpenSearchServiceDomainLogPublishingOptionsDetails (..),
    newAwsOpenSearchServiceDomainLogPublishingOptionsDetails,
    awsOpenSearchServiceDomainLogPublishingOptionsDetails_indexSlowLogs,
    awsOpenSearchServiceDomainLogPublishingOptionsDetails_searchSlowLogs,
    awsOpenSearchServiceDomainLogPublishingOptionsDetails_auditLogs,

    -- * AwsOpenSearchServiceDomainNodeToNodeEncryptionOptionsDetails
    AwsOpenSearchServiceDomainNodeToNodeEncryptionOptionsDetails (..),
    newAwsOpenSearchServiceDomainNodeToNodeEncryptionOptionsDetails,
    awsOpenSearchServiceDomainNodeToNodeEncryptionOptionsDetails_enabled,

    -- * AwsOpenSearchServiceDomainServiceSoftwareOptionsDetails
    AwsOpenSearchServiceDomainServiceSoftwareOptionsDetails (..),
    newAwsOpenSearchServiceDomainServiceSoftwareOptionsDetails,
    awsOpenSearchServiceDomainServiceSoftwareOptionsDetails_automatedUpdateDate,
    awsOpenSearchServiceDomainServiceSoftwareOptionsDetails_currentVersion,
    awsOpenSearchServiceDomainServiceSoftwareOptionsDetails_optionalDeployment,
    awsOpenSearchServiceDomainServiceSoftwareOptionsDetails_updateStatus,
    awsOpenSearchServiceDomainServiceSoftwareOptionsDetails_cancellable,
    awsOpenSearchServiceDomainServiceSoftwareOptionsDetails_updateAvailable,
    awsOpenSearchServiceDomainServiceSoftwareOptionsDetails_description,
    awsOpenSearchServiceDomainServiceSoftwareOptionsDetails_newVersion,

    -- * AwsOpenSearchServiceDomainVpcOptionsDetails
    AwsOpenSearchServiceDomainVpcOptionsDetails (..),
    newAwsOpenSearchServiceDomainVpcOptionsDetails,
    awsOpenSearchServiceDomainVpcOptionsDetails_securityGroupIds,
    awsOpenSearchServiceDomainVpcOptionsDetails_subnetIds,

    -- * AwsRdsDbClusterAssociatedRole
    AwsRdsDbClusterAssociatedRole (..),
    newAwsRdsDbClusterAssociatedRole,
    awsRdsDbClusterAssociatedRole_status,
    awsRdsDbClusterAssociatedRole_roleArn,

    -- * AwsRdsDbClusterDetails
    AwsRdsDbClusterDetails (..),
    newAwsRdsDbClusterDetails,
    awsRdsDbClusterDetails_engineVersion,
    awsRdsDbClusterDetails_status,
    awsRdsDbClusterDetails_dbClusterMembers,
    awsRdsDbClusterDetails_deletionProtection,
    awsRdsDbClusterDetails_storageEncrypted,
    awsRdsDbClusterDetails_dbClusterIdentifier,
    awsRdsDbClusterDetails_readReplicaIdentifiers,
    awsRdsDbClusterDetails_dbClusterParameterGroup,
    awsRdsDbClusterDetails_hostedZoneId,
    awsRdsDbClusterDetails_masterUsername,
    awsRdsDbClusterDetails_iamDatabaseAuthenticationEnabled,
    awsRdsDbClusterDetails_dbClusterResourceId,
    awsRdsDbClusterDetails_customEndpoints,
    awsRdsDbClusterDetails_engine,
    awsRdsDbClusterDetails_httpEndpointEnabled,
    awsRdsDbClusterDetails_crossAccountClone,
    awsRdsDbClusterDetails_preferredMaintenanceWindow,
    awsRdsDbClusterDetails_availabilityZones,
    awsRdsDbClusterDetails_kmsKeyId,
    awsRdsDbClusterDetails_preferredBackupWindow,
    awsRdsDbClusterDetails_associatedRoles,
    awsRdsDbClusterDetails_vpcSecurityGroups,
    awsRdsDbClusterDetails_backupRetentionPeriod,
    awsRdsDbClusterDetails_dbSubnetGroup,
    awsRdsDbClusterDetails_multiAz,
    awsRdsDbClusterDetails_databaseName,
    awsRdsDbClusterDetails_engineMode,
    awsRdsDbClusterDetails_enabledCloudWatchLogsExports,
    awsRdsDbClusterDetails_activityStreamStatus,
    awsRdsDbClusterDetails_allocatedStorage,
    awsRdsDbClusterDetails_copyTagsToSnapshot,
    awsRdsDbClusterDetails_clusterCreateTime,
    awsRdsDbClusterDetails_endpoint,
    awsRdsDbClusterDetails_readerEndpoint,
    awsRdsDbClusterDetails_dbClusterOptionGroupMemberships,
    awsRdsDbClusterDetails_port,
    awsRdsDbClusterDetails_domainMemberships,

    -- * AwsRdsDbClusterMember
    AwsRdsDbClusterMember (..),
    newAwsRdsDbClusterMember,
    awsRdsDbClusterMember_promotionTier,
    awsRdsDbClusterMember_dbInstanceIdentifier,
    awsRdsDbClusterMember_isClusterWriter,
    awsRdsDbClusterMember_dbClusterParameterGroupStatus,

    -- * AwsRdsDbClusterOptionGroupMembership
    AwsRdsDbClusterOptionGroupMembership (..),
    newAwsRdsDbClusterOptionGroupMembership,
    awsRdsDbClusterOptionGroupMembership_status,
    awsRdsDbClusterOptionGroupMembership_dbClusterOptionGroupName,

    -- * AwsRdsDbClusterSnapshotDetails
    AwsRdsDbClusterSnapshotDetails (..),
    newAwsRdsDbClusterSnapshotDetails,
    awsRdsDbClusterSnapshotDetails_engineVersion,
    awsRdsDbClusterSnapshotDetails_status,
    awsRdsDbClusterSnapshotDetails_storageEncrypted,
    awsRdsDbClusterSnapshotDetails_dbClusterIdentifier,
    awsRdsDbClusterSnapshotDetails_masterUsername,
    awsRdsDbClusterSnapshotDetails_iamDatabaseAuthenticationEnabled,
    awsRdsDbClusterSnapshotDetails_vpcId,
    awsRdsDbClusterSnapshotDetails_dbClusterSnapshotIdentifier,
    awsRdsDbClusterSnapshotDetails_engine,
    awsRdsDbClusterSnapshotDetails_licenseModel,
    awsRdsDbClusterSnapshotDetails_availabilityZones,
    awsRdsDbClusterSnapshotDetails_snapshotType,
    awsRdsDbClusterSnapshotDetails_kmsKeyId,
    awsRdsDbClusterSnapshotDetails_snapshotCreateTime,
    awsRdsDbClusterSnapshotDetails_allocatedStorage,
    awsRdsDbClusterSnapshotDetails_clusterCreateTime,
    awsRdsDbClusterSnapshotDetails_percentProgress,
    awsRdsDbClusterSnapshotDetails_port,

    -- * AwsRdsDbDomainMembership
    AwsRdsDbDomainMembership (..),
    newAwsRdsDbDomainMembership,
    awsRdsDbDomainMembership_status,
    awsRdsDbDomainMembership_fqdn,
    awsRdsDbDomainMembership_domain,
    awsRdsDbDomainMembership_iamRoleName,

    -- * AwsRdsDbInstanceAssociatedRole
    AwsRdsDbInstanceAssociatedRole (..),
    newAwsRdsDbInstanceAssociatedRole,
    awsRdsDbInstanceAssociatedRole_status,
    awsRdsDbInstanceAssociatedRole_featureName,
    awsRdsDbInstanceAssociatedRole_roleArn,

    -- * AwsRdsDbInstanceDetails
    AwsRdsDbInstanceDetails (..),
    newAwsRdsDbInstanceDetails,
    awsRdsDbInstanceDetails_dbSecurityGroups,
    awsRdsDbInstanceDetails_engineVersion,
    awsRdsDbInstanceDetails_deletionProtection,
    awsRdsDbInstanceDetails_storageEncrypted,
    awsRdsDbInstanceDetails_dbClusterIdentifier,
    awsRdsDbInstanceDetails_publiclyAccessible,
    awsRdsDbInstanceDetails_autoMinorVersionUpgrade,
    awsRdsDbInstanceDetails_masterUsername,
    awsRdsDbInstanceDetails_readReplicaDBInstanceIdentifiers,
    awsRdsDbInstanceDetails_iAMDatabaseAuthenticationEnabled,
    awsRdsDbInstanceDetails_monitoringRoleArn,
    awsRdsDbInstanceDetails_iops,
    awsRdsDbInstanceDetails_instanceCreateTime,
    awsRdsDbInstanceDetails_readReplicaSourceDBInstanceIdentifier,
    awsRdsDbInstanceDetails_monitoringInterval,
    awsRdsDbInstanceDetails_engine,
    awsRdsDbInstanceDetails_processorFeatures,
    awsRdsDbInstanceDetails_latestRestorableTime,
    awsRdsDbInstanceDetails_dbInstanceClass,
    awsRdsDbInstanceDetails_promotionTier,
    awsRdsDbInstanceDetails_licenseModel,
    awsRdsDbInstanceDetails_preferredMaintenanceWindow,
    awsRdsDbInstanceDetails_performanceInsightsRetentionPeriod,
    awsRdsDbInstanceDetails_cACertificateIdentifier,
    awsRdsDbInstanceDetails_dbInstanceIdentifier,
    awsRdsDbInstanceDetails_characterSetName,
    awsRdsDbInstanceDetails_maxAllocatedStorage,
    awsRdsDbInstanceDetails_kmsKeyId,
    awsRdsDbInstanceDetails_preferredBackupWindow,
    awsRdsDbInstanceDetails_associatedRoles,
    awsRdsDbInstanceDetails_availabilityZone,
    awsRdsDbInstanceDetails_vpcSecurityGroups,
    awsRdsDbInstanceDetails_backupRetentionPeriod,
    awsRdsDbInstanceDetails_performanceInsightsKmsKeyId,
    awsRdsDbInstanceDetails_dbSubnetGroup,
    awsRdsDbInstanceDetails_multiAz,
    awsRdsDbInstanceDetails_listenerEndpoint,
    awsRdsDbInstanceDetails_optionGroupMemberships,
    awsRdsDbInstanceDetails_enhancedMonitoringResourceArn,
    awsRdsDbInstanceDetails_secondaryAvailabilityZone,
    awsRdsDbInstanceDetails_enabledCloudWatchLogsExports,
    awsRdsDbInstanceDetails_performanceInsightsEnabled,
    awsRdsDbInstanceDetails_allocatedStorage,
    awsRdsDbInstanceDetails_dbiResourceId,
    awsRdsDbInstanceDetails_dbInstanceStatus,
    awsRdsDbInstanceDetails_copyTagsToSnapshot,
    awsRdsDbInstanceDetails_timezone,
    awsRdsDbInstanceDetails_tdeCredentialArn,
    awsRdsDbInstanceDetails_dbParameterGroups,
    awsRdsDbInstanceDetails_endpoint,
    awsRdsDbInstanceDetails_dbInstancePort,
    awsRdsDbInstanceDetails_pendingModifiedValues,
    awsRdsDbInstanceDetails_readReplicaDBClusterIdentifiers,
    awsRdsDbInstanceDetails_storageType,
    awsRdsDbInstanceDetails_statusInfos,
    awsRdsDbInstanceDetails_domainMemberships,
    awsRdsDbInstanceDetails_dbName,

    -- * AwsRdsDbInstanceEndpoint
    AwsRdsDbInstanceEndpoint (..),
    newAwsRdsDbInstanceEndpoint,
    awsRdsDbInstanceEndpoint_hostedZoneId,
    awsRdsDbInstanceEndpoint_address,
    awsRdsDbInstanceEndpoint_port,

    -- * AwsRdsDbInstanceVpcSecurityGroup
    AwsRdsDbInstanceVpcSecurityGroup (..),
    newAwsRdsDbInstanceVpcSecurityGroup,
    awsRdsDbInstanceVpcSecurityGroup_status,
    awsRdsDbInstanceVpcSecurityGroup_vpcSecurityGroupId,

    -- * AwsRdsDbOptionGroupMembership
    AwsRdsDbOptionGroupMembership (..),
    newAwsRdsDbOptionGroupMembership,
    awsRdsDbOptionGroupMembership_status,
    awsRdsDbOptionGroupMembership_optionGroupName,

    -- * AwsRdsDbParameterGroup
    AwsRdsDbParameterGroup (..),
    newAwsRdsDbParameterGroup,
    awsRdsDbParameterGroup_dbParameterGroupName,
    awsRdsDbParameterGroup_parameterApplyStatus,

    -- * AwsRdsDbPendingModifiedValues
    AwsRdsDbPendingModifiedValues (..),
    newAwsRdsDbPendingModifiedValues,
    awsRdsDbPendingModifiedValues_engineVersion,
    awsRdsDbPendingModifiedValues_masterUserPassword,
    awsRdsDbPendingModifiedValues_dbSubnetGroupName,
    awsRdsDbPendingModifiedValues_iops,
    awsRdsDbPendingModifiedValues_dbInstanceClass,
    awsRdsDbPendingModifiedValues_processorFeatures,
    awsRdsDbPendingModifiedValues_licenseModel,
    awsRdsDbPendingModifiedValues_dbInstanceIdentifier,
    awsRdsDbPendingModifiedValues_caCertificateIdentifier,
    awsRdsDbPendingModifiedValues_pendingCloudWatchLogsExports,
    awsRdsDbPendingModifiedValues_backupRetentionPeriod,
    awsRdsDbPendingModifiedValues_multiAZ,
    awsRdsDbPendingModifiedValues_allocatedStorage,
    awsRdsDbPendingModifiedValues_port,
    awsRdsDbPendingModifiedValues_storageType,

    -- * AwsRdsDbProcessorFeature
    AwsRdsDbProcessorFeature (..),
    newAwsRdsDbProcessorFeature,
    awsRdsDbProcessorFeature_value,
    awsRdsDbProcessorFeature_name,

    -- * AwsRdsDbSnapshotDetails
    AwsRdsDbSnapshotDetails (..),
    newAwsRdsDbSnapshotDetails,
    awsRdsDbSnapshotDetails_engineVersion,
    awsRdsDbSnapshotDetails_status,
    awsRdsDbSnapshotDetails_masterUsername,
    awsRdsDbSnapshotDetails_sourceRegion,
    awsRdsDbSnapshotDetails_iops,
    awsRdsDbSnapshotDetails_iamDatabaseAuthenticationEnabled,
    awsRdsDbSnapshotDetails_vpcId,
    awsRdsDbSnapshotDetails_instanceCreateTime,
    awsRdsDbSnapshotDetails_engine,
    awsRdsDbSnapshotDetails_encrypted,
    awsRdsDbSnapshotDetails_dbSnapshotIdentifier,
    awsRdsDbSnapshotDetails_processorFeatures,
    awsRdsDbSnapshotDetails_licenseModel,
    awsRdsDbSnapshotDetails_dbInstanceIdentifier,
    awsRdsDbSnapshotDetails_snapshotType,
    awsRdsDbSnapshotDetails_sourceDbSnapshotIdentifier,
    awsRdsDbSnapshotDetails_kmsKeyId,
    awsRdsDbSnapshotDetails_availabilityZone,
    awsRdsDbSnapshotDetails_snapshotCreateTime,
    awsRdsDbSnapshotDetails_allocatedStorage,
    awsRdsDbSnapshotDetails_dbiResourceId,
    awsRdsDbSnapshotDetails_optionGroupName,
    awsRdsDbSnapshotDetails_timezone,
    awsRdsDbSnapshotDetails_tdeCredentialArn,
    awsRdsDbSnapshotDetails_percentProgress,
    awsRdsDbSnapshotDetails_port,
    awsRdsDbSnapshotDetails_storageType,

    -- * AwsRdsDbStatusInfo
    AwsRdsDbStatusInfo (..),
    newAwsRdsDbStatusInfo,
    awsRdsDbStatusInfo_status,
    awsRdsDbStatusInfo_normal,
    awsRdsDbStatusInfo_statusType,
    awsRdsDbStatusInfo_message,

    -- * AwsRdsDbSubnetGroup
    AwsRdsDbSubnetGroup (..),
    newAwsRdsDbSubnetGroup,
    awsRdsDbSubnetGroup_dbSubnetGroupName,
    awsRdsDbSubnetGroup_vpcId,
    awsRdsDbSubnetGroup_subnets,
    awsRdsDbSubnetGroup_dbSubnetGroupDescription,
    awsRdsDbSubnetGroup_dbSubnetGroupArn,
    awsRdsDbSubnetGroup_subnetGroupStatus,

    -- * AwsRdsDbSubnetGroupSubnet
    AwsRdsDbSubnetGroupSubnet (..),
    newAwsRdsDbSubnetGroupSubnet,
    awsRdsDbSubnetGroupSubnet_subnetStatus,
    awsRdsDbSubnetGroupSubnet_subnetIdentifier,
    awsRdsDbSubnetGroupSubnet_subnetAvailabilityZone,

    -- * AwsRdsDbSubnetGroupSubnetAvailabilityZone
    AwsRdsDbSubnetGroupSubnetAvailabilityZone (..),
    newAwsRdsDbSubnetGroupSubnetAvailabilityZone,
    awsRdsDbSubnetGroupSubnetAvailabilityZone_name,

    -- * AwsRdsEventSubscriptionDetails
    AwsRdsEventSubscriptionDetails (..),
    newAwsRdsEventSubscriptionDetails,
    awsRdsEventSubscriptionDetails_status,
    awsRdsEventSubscriptionDetails_customerAwsId,
    awsRdsEventSubscriptionDetails_custSubscriptionId,
    awsRdsEventSubscriptionDetails_snsTopicArn,
    awsRdsEventSubscriptionDetails_eventSubscriptionArn,
    awsRdsEventSubscriptionDetails_enabled,
    awsRdsEventSubscriptionDetails_sourceType,
    awsRdsEventSubscriptionDetails_subscriptionCreationTime,
    awsRdsEventSubscriptionDetails_eventCategoriesList,
    awsRdsEventSubscriptionDetails_sourceIdsList,

    -- * AwsRdsPendingCloudWatchLogsExports
    AwsRdsPendingCloudWatchLogsExports (..),
    newAwsRdsPendingCloudWatchLogsExports,
    awsRdsPendingCloudWatchLogsExports_logTypesToEnable,
    awsRdsPendingCloudWatchLogsExports_logTypesToDisable,

    -- * AwsRedshiftClusterClusterNode
    AwsRedshiftClusterClusterNode (..),
    newAwsRedshiftClusterClusterNode,
    awsRedshiftClusterClusterNode_nodeRole,
    awsRedshiftClusterClusterNode_privateIpAddress,
    awsRedshiftClusterClusterNode_publicIpAddress,

    -- * AwsRedshiftClusterClusterParameterGroup
    AwsRedshiftClusterClusterParameterGroup (..),
    newAwsRedshiftClusterClusterParameterGroup,
    awsRedshiftClusterClusterParameterGroup_clusterParameterStatusList,
    awsRedshiftClusterClusterParameterGroup_parameterApplyStatus,
    awsRedshiftClusterClusterParameterGroup_parameterGroupName,

    -- * AwsRedshiftClusterClusterParameterStatus
    AwsRedshiftClusterClusterParameterStatus (..),
    newAwsRedshiftClusterClusterParameterStatus,
    awsRedshiftClusterClusterParameterStatus_parameterApplyErrorDescription,
    awsRedshiftClusterClusterParameterStatus_parameterName,
    awsRedshiftClusterClusterParameterStatus_parameterApplyStatus,

    -- * AwsRedshiftClusterClusterSecurityGroup
    AwsRedshiftClusterClusterSecurityGroup (..),
    newAwsRedshiftClusterClusterSecurityGroup,
    awsRedshiftClusterClusterSecurityGroup_status,
    awsRedshiftClusterClusterSecurityGroup_clusterSecurityGroupName,

    -- * AwsRedshiftClusterClusterSnapshotCopyStatus
    AwsRedshiftClusterClusterSnapshotCopyStatus (..),
    newAwsRedshiftClusterClusterSnapshotCopyStatus,
    awsRedshiftClusterClusterSnapshotCopyStatus_manualSnapshotRetentionPeriod,
    awsRedshiftClusterClusterSnapshotCopyStatus_retentionPeriod,
    awsRedshiftClusterClusterSnapshotCopyStatus_destinationRegion,
    awsRedshiftClusterClusterSnapshotCopyStatus_snapshotCopyGrantName,

    -- * AwsRedshiftClusterDeferredMaintenanceWindow
    AwsRedshiftClusterDeferredMaintenanceWindow (..),
    newAwsRedshiftClusterDeferredMaintenanceWindow,
    awsRedshiftClusterDeferredMaintenanceWindow_deferMaintenanceEndTime,
    awsRedshiftClusterDeferredMaintenanceWindow_deferMaintenanceStartTime,
    awsRedshiftClusterDeferredMaintenanceWindow_deferMaintenanceIdentifier,

    -- * AwsRedshiftClusterDetails
    AwsRedshiftClusterDetails (..),
    newAwsRedshiftClusterDetails,
    awsRedshiftClusterDetails_resizeInfo,
    awsRedshiftClusterDetails_restoreStatus,
    awsRedshiftClusterDetails_manualSnapshotRetentionPeriod,
    awsRedshiftClusterDetails_enhancedVpcRouting,
    awsRedshiftClusterDetails_clusterSnapshotCopyStatus,
    awsRedshiftClusterDetails_clusterAvailabilityStatus,
    awsRedshiftClusterDetails_clusterRevisionNumber,
    awsRedshiftClusterDetails_snapshotScheduleIdentifier,
    awsRedshiftClusterDetails_publiclyAccessible,
    awsRedshiftClusterDetails_masterUsername,
    awsRedshiftClusterDetails_maintenanceTrackName,
    awsRedshiftClusterDetails_expectedNextSnapshotScheduleTime,
    awsRedshiftClusterDetails_elasticResizeNumberOfNodeOptions,
    awsRedshiftClusterDetails_vpcId,
    awsRedshiftClusterDetails_clusterSecurityGroups,
    awsRedshiftClusterDetails_automatedSnapshotRetentionPeriod,
    awsRedshiftClusterDetails_snapshotScheduleState,
    awsRedshiftClusterDetails_encrypted,
    awsRedshiftClusterDetails_clusterSubnetGroupName,
    awsRedshiftClusterDetails_expectedNextSnapshotScheduleTimeStatus,
    awsRedshiftClusterDetails_clusterIdentifier,
    awsRedshiftClusterDetails_deferredMaintenanceWindows,
    awsRedshiftClusterDetails_numberOfNodes,
    awsRedshiftClusterDetails_clusterPublicKey,
    awsRedshiftClusterDetails_preferredMaintenanceWindow,
    awsRedshiftClusterDetails_kmsKeyId,
    awsRedshiftClusterDetails_clusterParameterGroups,
    awsRedshiftClusterDetails_availabilityZone,
    awsRedshiftClusterDetails_vpcSecurityGroups,
    awsRedshiftClusterDetails_hsmStatus,
    awsRedshiftClusterDetails_iamRoles,
    awsRedshiftClusterDetails_pendingActions,
    awsRedshiftClusterDetails_elasticIpStatus,
    awsRedshiftClusterDetails_clusterVersion,
    awsRedshiftClusterDetails_nodeType,
    awsRedshiftClusterDetails_nextMaintenanceWindowStartTime,
    awsRedshiftClusterDetails_clusterCreateTime,
    awsRedshiftClusterDetails_endpoint,
    awsRedshiftClusterDetails_allowVersionUpgrade,
    awsRedshiftClusterDetails_clusterStatus,
    awsRedshiftClusterDetails_pendingModifiedValues,
    awsRedshiftClusterDetails_clusterNodes,
    awsRedshiftClusterDetails_dbName,

    -- * AwsRedshiftClusterElasticIpStatus
    AwsRedshiftClusterElasticIpStatus (..),
    newAwsRedshiftClusterElasticIpStatus,
    awsRedshiftClusterElasticIpStatus_status,
    awsRedshiftClusterElasticIpStatus_elasticIp,

    -- * AwsRedshiftClusterEndpoint
    AwsRedshiftClusterEndpoint (..),
    newAwsRedshiftClusterEndpoint,
    awsRedshiftClusterEndpoint_address,
    awsRedshiftClusterEndpoint_port,

    -- * AwsRedshiftClusterHsmStatus
    AwsRedshiftClusterHsmStatus (..),
    newAwsRedshiftClusterHsmStatus,
    awsRedshiftClusterHsmStatus_status,
    awsRedshiftClusterHsmStatus_hsmConfigurationIdentifier,
    awsRedshiftClusterHsmStatus_hsmClientCertificateIdentifier,

    -- * AwsRedshiftClusterIamRole
    AwsRedshiftClusterIamRole (..),
    newAwsRedshiftClusterIamRole,
    awsRedshiftClusterIamRole_iamRoleArn,
    awsRedshiftClusterIamRole_applyStatus,

    -- * AwsRedshiftClusterPendingModifiedValues
    AwsRedshiftClusterPendingModifiedValues (..),
    newAwsRedshiftClusterPendingModifiedValues,
    awsRedshiftClusterPendingModifiedValues_encryptionType,
    awsRedshiftClusterPendingModifiedValues_enhancedVpcRouting,
    awsRedshiftClusterPendingModifiedValues_masterUserPassword,
    awsRedshiftClusterPendingModifiedValues_publiclyAccessible,
    awsRedshiftClusterPendingModifiedValues_maintenanceTrackName,
    awsRedshiftClusterPendingModifiedValues_automatedSnapshotRetentionPeriod,
    awsRedshiftClusterPendingModifiedValues_clusterIdentifier,
    awsRedshiftClusterPendingModifiedValues_numberOfNodes,
    awsRedshiftClusterPendingModifiedValues_clusterType,
    awsRedshiftClusterPendingModifiedValues_clusterVersion,
    awsRedshiftClusterPendingModifiedValues_nodeType,

    -- * AwsRedshiftClusterResizeInfo
    AwsRedshiftClusterResizeInfo (..),
    newAwsRedshiftClusterResizeInfo,
    awsRedshiftClusterResizeInfo_allowCancelResize,
    awsRedshiftClusterResizeInfo_resizeType,

    -- * AwsRedshiftClusterRestoreStatus
    AwsRedshiftClusterRestoreStatus (..),
    newAwsRedshiftClusterRestoreStatus,
    awsRedshiftClusterRestoreStatus_status,
    awsRedshiftClusterRestoreStatus_estimatedTimeToCompletionInSeconds,
    awsRedshiftClusterRestoreStatus_currentRestoreRateInMegaBytesPerSecond,
    awsRedshiftClusterRestoreStatus_progressInMegaBytes,
    awsRedshiftClusterRestoreStatus_elapsedTimeInSeconds,
    awsRedshiftClusterRestoreStatus_snapshotSizeInMegaBytes,

    -- * AwsRedshiftClusterVpcSecurityGroup
    AwsRedshiftClusterVpcSecurityGroup (..),
    newAwsRedshiftClusterVpcSecurityGroup,
    awsRedshiftClusterVpcSecurityGroup_status,
    awsRedshiftClusterVpcSecurityGroup_vpcSecurityGroupId,

    -- * AwsS3AccountPublicAccessBlockDetails
    AwsS3AccountPublicAccessBlockDetails (..),
    newAwsS3AccountPublicAccessBlockDetails,
    awsS3AccountPublicAccessBlockDetails_ignorePublicAcls,
    awsS3AccountPublicAccessBlockDetails_blockPublicAcls,
    awsS3AccountPublicAccessBlockDetails_restrictPublicBuckets,
    awsS3AccountPublicAccessBlockDetails_blockPublicPolicy,

    -- * AwsS3BucketBucketLifecycleConfigurationDetails
    AwsS3BucketBucketLifecycleConfigurationDetails (..),
    newAwsS3BucketBucketLifecycleConfigurationDetails,
    awsS3BucketBucketLifecycleConfigurationDetails_rules,

    -- * AwsS3BucketBucketLifecycleConfigurationRulesAbortIncompleteMultipartUploadDetails
    AwsS3BucketBucketLifecycleConfigurationRulesAbortIncompleteMultipartUploadDetails (..),
    newAwsS3BucketBucketLifecycleConfigurationRulesAbortIncompleteMultipartUploadDetails,
    awsS3BucketBucketLifecycleConfigurationRulesAbortIncompleteMultipartUploadDetails_daysAfterInitiation,

    -- * AwsS3BucketBucketLifecycleConfigurationRulesDetails
    AwsS3BucketBucketLifecycleConfigurationRulesDetails (..),
    newAwsS3BucketBucketLifecycleConfigurationRulesDetails,
    awsS3BucketBucketLifecycleConfigurationRulesDetails_status,
    awsS3BucketBucketLifecycleConfigurationRulesDetails_transitions,
    awsS3BucketBucketLifecycleConfigurationRulesDetails_prefix,
    awsS3BucketBucketLifecycleConfigurationRulesDetails_noncurrentVersionTransitions,
    awsS3BucketBucketLifecycleConfigurationRulesDetails_noncurrentVersionExpirationInDays,
    awsS3BucketBucketLifecycleConfigurationRulesDetails_expirationDate,
    awsS3BucketBucketLifecycleConfigurationRulesDetails_id,
    awsS3BucketBucketLifecycleConfigurationRulesDetails_filter,
    awsS3BucketBucketLifecycleConfigurationRulesDetails_expirationInDays,
    awsS3BucketBucketLifecycleConfigurationRulesDetails_abortIncompleteMultipartUpload,
    awsS3BucketBucketLifecycleConfigurationRulesDetails_expiredObjectDeleteMarker,

    -- * AwsS3BucketBucketLifecycleConfigurationRulesFilterDetails
    AwsS3BucketBucketLifecycleConfigurationRulesFilterDetails (..),
    newAwsS3BucketBucketLifecycleConfigurationRulesFilterDetails,
    awsS3BucketBucketLifecycleConfigurationRulesFilterDetails_predicate,

    -- * AwsS3BucketBucketLifecycleConfigurationRulesFilterPredicateDetails
    AwsS3BucketBucketLifecycleConfigurationRulesFilterPredicateDetails (..),
    newAwsS3BucketBucketLifecycleConfigurationRulesFilterPredicateDetails,
    awsS3BucketBucketLifecycleConfigurationRulesFilterPredicateDetails_tag,
    awsS3BucketBucketLifecycleConfigurationRulesFilterPredicateDetails_prefix,
    awsS3BucketBucketLifecycleConfigurationRulesFilterPredicateDetails_type,
    awsS3BucketBucketLifecycleConfigurationRulesFilterPredicateDetails_operands,

    -- * AwsS3BucketBucketLifecycleConfigurationRulesFilterPredicateOperandsDetails
    AwsS3BucketBucketLifecycleConfigurationRulesFilterPredicateOperandsDetails (..),
    newAwsS3BucketBucketLifecycleConfigurationRulesFilterPredicateOperandsDetails,
    awsS3BucketBucketLifecycleConfigurationRulesFilterPredicateOperandsDetails_tag,
    awsS3BucketBucketLifecycleConfigurationRulesFilterPredicateOperandsDetails_prefix,
    awsS3BucketBucketLifecycleConfigurationRulesFilterPredicateOperandsDetails_type,

    -- * AwsS3BucketBucketLifecycleConfigurationRulesFilterPredicateOperandsTagDetails
    AwsS3BucketBucketLifecycleConfigurationRulesFilterPredicateOperandsTagDetails (..),
    newAwsS3BucketBucketLifecycleConfigurationRulesFilterPredicateOperandsTagDetails,
    awsS3BucketBucketLifecycleConfigurationRulesFilterPredicateOperandsTagDetails_value,
    awsS3BucketBucketLifecycleConfigurationRulesFilterPredicateOperandsTagDetails_key,

    -- * AwsS3BucketBucketLifecycleConfigurationRulesFilterPredicateTagDetails
    AwsS3BucketBucketLifecycleConfigurationRulesFilterPredicateTagDetails (..),
    newAwsS3BucketBucketLifecycleConfigurationRulesFilterPredicateTagDetails,
    awsS3BucketBucketLifecycleConfigurationRulesFilterPredicateTagDetails_value,
    awsS3BucketBucketLifecycleConfigurationRulesFilterPredicateTagDetails_key,

    -- * AwsS3BucketBucketLifecycleConfigurationRulesNoncurrentVersionTransitionsDetails
    AwsS3BucketBucketLifecycleConfigurationRulesNoncurrentVersionTransitionsDetails (..),
    newAwsS3BucketBucketLifecycleConfigurationRulesNoncurrentVersionTransitionsDetails,
    awsS3BucketBucketLifecycleConfigurationRulesNoncurrentVersionTransitionsDetails_days,
    awsS3BucketBucketLifecycleConfigurationRulesNoncurrentVersionTransitionsDetails_storageClass,

    -- * AwsS3BucketBucketLifecycleConfigurationRulesTransitionsDetails
    AwsS3BucketBucketLifecycleConfigurationRulesTransitionsDetails (..),
    newAwsS3BucketBucketLifecycleConfigurationRulesTransitionsDetails,
    awsS3BucketBucketLifecycleConfigurationRulesTransitionsDetails_days,
    awsS3BucketBucketLifecycleConfigurationRulesTransitionsDetails_date,
    awsS3BucketBucketLifecycleConfigurationRulesTransitionsDetails_storageClass,

    -- * AwsS3BucketDetails
    AwsS3BucketDetails (..),
    newAwsS3BucketDetails,
    awsS3BucketDetails_createdAt,
    awsS3BucketDetails_ownerAccountId,
    awsS3BucketDetails_bucketLoggingConfiguration,
    awsS3BucketDetails_ownerName,
    awsS3BucketDetails_accessControlList,
    awsS3BucketDetails_ownerId,
    awsS3BucketDetails_publicAccessBlockConfiguration,
    awsS3BucketDetails_bucketWebsiteConfiguration,
    awsS3BucketDetails_bucketLifecycleConfiguration,
    awsS3BucketDetails_bucketNotificationConfiguration,
    awsS3BucketDetails_serverSideEncryptionConfiguration,

    -- * AwsS3BucketLoggingConfiguration
    AwsS3BucketLoggingConfiguration (..),
    newAwsS3BucketLoggingConfiguration,
    awsS3BucketLoggingConfiguration_logFilePrefix,
    awsS3BucketLoggingConfiguration_destinationBucketName,

    -- * AwsS3BucketNotificationConfiguration
    AwsS3BucketNotificationConfiguration (..),
    newAwsS3BucketNotificationConfiguration,
    awsS3BucketNotificationConfiguration_configurations,

    -- * AwsS3BucketNotificationConfigurationDetail
    AwsS3BucketNotificationConfigurationDetail (..),
    newAwsS3BucketNotificationConfigurationDetail,
    awsS3BucketNotificationConfigurationDetail_destination,
    awsS3BucketNotificationConfigurationDetail_events,
    awsS3BucketNotificationConfigurationDetail_type,
    awsS3BucketNotificationConfigurationDetail_filter,

    -- * AwsS3BucketNotificationConfigurationFilter
    AwsS3BucketNotificationConfigurationFilter (..),
    newAwsS3BucketNotificationConfigurationFilter,
    awsS3BucketNotificationConfigurationFilter_s3KeyFilter,

    -- * AwsS3BucketNotificationConfigurationS3KeyFilter
    AwsS3BucketNotificationConfigurationS3KeyFilter (..),
    newAwsS3BucketNotificationConfigurationS3KeyFilter,
    awsS3BucketNotificationConfigurationS3KeyFilter_filterRules,

    -- * AwsS3BucketNotificationConfigurationS3KeyFilterRule
    AwsS3BucketNotificationConfigurationS3KeyFilterRule (..),
    newAwsS3BucketNotificationConfigurationS3KeyFilterRule,
    awsS3BucketNotificationConfigurationS3KeyFilterRule_value,
    awsS3BucketNotificationConfigurationS3KeyFilterRule_name,

    -- * AwsS3BucketServerSideEncryptionByDefault
    AwsS3BucketServerSideEncryptionByDefault (..),
    newAwsS3BucketServerSideEncryptionByDefault,
    awsS3BucketServerSideEncryptionByDefault_sSEAlgorithm,
    awsS3BucketServerSideEncryptionByDefault_kmsMasterKeyID,

    -- * AwsS3BucketServerSideEncryptionConfiguration
    AwsS3BucketServerSideEncryptionConfiguration (..),
    newAwsS3BucketServerSideEncryptionConfiguration,
    awsS3BucketServerSideEncryptionConfiguration_rules,

    -- * AwsS3BucketServerSideEncryptionRule
    AwsS3BucketServerSideEncryptionRule (..),
    newAwsS3BucketServerSideEncryptionRule,
    awsS3BucketServerSideEncryptionRule_applyServerSideEncryptionByDefault,

    -- * AwsS3BucketWebsiteConfiguration
    AwsS3BucketWebsiteConfiguration (..),
    newAwsS3BucketWebsiteConfiguration,
    awsS3BucketWebsiteConfiguration_redirectAllRequestsTo,
    awsS3BucketWebsiteConfiguration_indexDocumentSuffix,
    awsS3BucketWebsiteConfiguration_errorDocument,
    awsS3BucketWebsiteConfiguration_routingRules,

    -- * AwsS3BucketWebsiteConfigurationRedirectTo
    AwsS3BucketWebsiteConfigurationRedirectTo (..),
    newAwsS3BucketWebsiteConfigurationRedirectTo,
    awsS3BucketWebsiteConfigurationRedirectTo_hostname,
    awsS3BucketWebsiteConfigurationRedirectTo_protocol,

    -- * AwsS3BucketWebsiteConfigurationRoutingRule
    AwsS3BucketWebsiteConfigurationRoutingRule (..),
    newAwsS3BucketWebsiteConfigurationRoutingRule,
    awsS3BucketWebsiteConfigurationRoutingRule_redirect,
    awsS3BucketWebsiteConfigurationRoutingRule_condition,

    -- * AwsS3BucketWebsiteConfigurationRoutingRuleCondition
    AwsS3BucketWebsiteConfigurationRoutingRuleCondition (..),
    newAwsS3BucketWebsiteConfigurationRoutingRuleCondition,
    awsS3BucketWebsiteConfigurationRoutingRuleCondition_keyPrefixEquals,
    awsS3BucketWebsiteConfigurationRoutingRuleCondition_httpErrorCodeReturnedEquals,

    -- * AwsS3BucketWebsiteConfigurationRoutingRuleRedirect
    AwsS3BucketWebsiteConfigurationRoutingRuleRedirect (..),
    newAwsS3BucketWebsiteConfigurationRoutingRuleRedirect,
    awsS3BucketWebsiteConfigurationRoutingRuleRedirect_hostname,
    awsS3BucketWebsiteConfigurationRoutingRuleRedirect_protocol,
    awsS3BucketWebsiteConfigurationRoutingRuleRedirect_httpRedirectCode,
    awsS3BucketWebsiteConfigurationRoutingRuleRedirect_replaceKeyWith,
    awsS3BucketWebsiteConfigurationRoutingRuleRedirect_replaceKeyPrefixWith,

    -- * AwsS3ObjectDetails
    AwsS3ObjectDetails (..),
    newAwsS3ObjectDetails,
    awsS3ObjectDetails_eTag,
    awsS3ObjectDetails_versionId,
    awsS3ObjectDetails_sSEKMSKeyId,
    awsS3ObjectDetails_lastModified,
    awsS3ObjectDetails_serverSideEncryption,
    awsS3ObjectDetails_contentType,

    -- * AwsSecretsManagerSecretDetails
    AwsSecretsManagerSecretDetails (..),
    newAwsSecretsManagerSecretDetails,
    awsSecretsManagerSecretDetails_rotationRules,
    awsSecretsManagerSecretDetails_rotationEnabled,
    awsSecretsManagerSecretDetails_kmsKeyId,
    awsSecretsManagerSecretDetails_name,
    awsSecretsManagerSecretDetails_deleted,
    awsSecretsManagerSecretDetails_description,
    awsSecretsManagerSecretDetails_rotationOccurredWithinFrequency,
    awsSecretsManagerSecretDetails_rotationLambdaArn,

    -- * AwsSecretsManagerSecretRotationRules
    AwsSecretsManagerSecretRotationRules (..),
    newAwsSecretsManagerSecretRotationRules,
    awsSecretsManagerSecretRotationRules_automaticallyAfterDays,

    -- * AwsSecurityFinding
    AwsSecurityFinding (..),
    newAwsSecurityFinding,
    awsSecurityFinding_productName,
    awsSecurityFinding_workflowState,
    awsSecurityFinding_criticality,
    awsSecurityFinding_recordState,
    awsSecurityFinding_productFields,
    awsSecurityFinding_compliance,
    awsSecurityFinding_findingProviderFields,
    awsSecurityFinding_companyName,
    awsSecurityFinding_note,
    awsSecurityFinding_process,
    awsSecurityFinding_severity,
    awsSecurityFinding_types,
    awsSecurityFinding_action,
    awsSecurityFinding_network,
    awsSecurityFinding_relatedFindings,
    awsSecurityFinding_firstObservedAt,
    awsSecurityFinding_malware,
    awsSecurityFinding_confidence,
    awsSecurityFinding_remediation,
    awsSecurityFinding_patchSummary,
    awsSecurityFinding_vulnerabilities,
    awsSecurityFinding_region,
    awsSecurityFinding_networkPath,
    awsSecurityFinding_workflow,
    awsSecurityFinding_verificationState,
    awsSecurityFinding_threatIntelIndicators,
    awsSecurityFinding_sourceUrl,
    awsSecurityFinding_lastObservedAt,
    awsSecurityFinding_userDefinedFields,
    awsSecurityFinding_schemaVersion,
    awsSecurityFinding_id,
    awsSecurityFinding_productArn,
    awsSecurityFinding_generatorId,
    awsSecurityFinding_awsAccountId,
    awsSecurityFinding_createdAt,
    awsSecurityFinding_updatedAt,
    awsSecurityFinding_title,
    awsSecurityFinding_description,
    awsSecurityFinding_resources,

    -- * AwsSecurityFindingFilters
    AwsSecurityFindingFilters (..),
    newAwsSecurityFindingFilters,
    awsSecurityFindingFilters_resourceAwsIamAccessKeyPrincipalName,
    awsSecurityFindingFilters_resourceAwsIamAccessKeyCreatedAt,
    awsSecurityFindingFilters_malwarePath,
    awsSecurityFindingFilters_resourceDetailsOther,
    awsSecurityFindingFilters_productName,
    awsSecurityFindingFilters_resourceAwsEc2InstanceSubnetId,
    awsSecurityFindingFilters_workflowState,
    awsSecurityFindingFilters_resourceContainerImageId,
    awsSecurityFindingFilters_relatedFindingsProductArn,
    awsSecurityFindingFilters_criticality,
    awsSecurityFindingFilters_resourceId,
    awsSecurityFindingFilters_resourceAwsIamAccessKeyUserName,
    awsSecurityFindingFilters_processParentPid,
    awsSecurityFindingFilters_resourceAwsEc2InstanceType,
    awsSecurityFindingFilters_resourceRegion,
    awsSecurityFindingFilters_recordState,
    awsSecurityFindingFilters_networkSourceIpV6,
    awsSecurityFindingFilters_resourceType,
    awsSecurityFindingFilters_productFields,
    awsSecurityFindingFilters_noteText,
    awsSecurityFindingFilters_resourceContainerImageName,
    awsSecurityFindingFilters_createdAt,
    awsSecurityFindingFilters_threatIntelIndicatorCategory,
    awsSecurityFindingFilters_severityProduct,
    awsSecurityFindingFilters_companyName,
    awsSecurityFindingFilters_findingProviderFieldsSeverityLabel,
    awsSecurityFindingFilters_networkProtocol,
    awsSecurityFindingFilters_resourceAwsEc2InstanceImageId,
    awsSecurityFindingFilters_resourcePartition,
    awsSecurityFindingFilters_resourceAwsEc2InstanceIpV6Addresses,
    awsSecurityFindingFilters_resourceTags,
    awsSecurityFindingFilters_resourceAwsEc2InstanceLaunchedAt,
    awsSecurityFindingFilters_networkSourceDomain,
    awsSecurityFindingFilters_networkDestinationPort,
    awsSecurityFindingFilters_noteUpdatedBy,
    awsSecurityFindingFilters_malwareName,
    awsSecurityFindingFilters_findingProviderFieldsTypes,
    awsSecurityFindingFilters_threatIntelIndicatorValue,
    awsSecurityFindingFilters_malwareState,
    awsSecurityFindingFilters_awsAccountId,
    awsSecurityFindingFilters_complianceStatus,
    awsSecurityFindingFilters_networkDestinationIpV4,
    awsSecurityFindingFilters_findingProviderFieldsRelatedFindingsId,
    awsSecurityFindingFilters_firstObservedAt,
    awsSecurityFindingFilters_threatIntelIndicatorLastObservedAt,
    awsSecurityFindingFilters_recommendationText,
    awsSecurityFindingFilters_resourceContainerLaunchedAt,
    awsSecurityFindingFilters_networkSourceMac,
    awsSecurityFindingFilters_confidence,
    awsSecurityFindingFilters_relatedFindingsId,
    awsSecurityFindingFilters_processName,
    awsSecurityFindingFilters_findingProviderFieldsSeverityOriginal,
    awsSecurityFindingFilters_workflowStatus,
    awsSecurityFindingFilters_resourceAwsS3BucketOwnerName,
    awsSecurityFindingFilters_findingProviderFieldsCriticality,
    awsSecurityFindingFilters_findingProviderFieldsRelatedFindingsProductArn,
    awsSecurityFindingFilters_resourceAwsEc2InstanceVpcId,
    awsSecurityFindingFilters_networkSourcePort,
    awsSecurityFindingFilters_resourceContainerName,
    awsSecurityFindingFilters_severityNormalized,
    awsSecurityFindingFilters_resourceAwsEc2InstanceKeyName,
    awsSecurityFindingFilters_networkDestinationDomain,
    awsSecurityFindingFilters_processLaunchedAt,
    awsSecurityFindingFilters_id,
    awsSecurityFindingFilters_severityLabel,
    awsSecurityFindingFilters_resourceAwsIamAccessKeyStatus,
    awsSecurityFindingFilters_resourceAwsS3BucketOwnerId,
    awsSecurityFindingFilters_threatIntelIndicatorType,
    awsSecurityFindingFilters_resourceAwsIamUserUserName,
    awsSecurityFindingFilters_noteUpdatedAt,
    awsSecurityFindingFilters_title,
    awsSecurityFindingFilters_region,
    awsSecurityFindingFilters_threatIntelIndicatorSource,
    awsSecurityFindingFilters_type,
    awsSecurityFindingFilters_networkSourceIpV4,
    awsSecurityFindingFilters_resourceAwsEc2InstanceIamInstanceProfileArn,
    awsSecurityFindingFilters_updatedAt,
    awsSecurityFindingFilters_processTerminatedAt,
    awsSecurityFindingFilters_networkDestinationIpV6,
    awsSecurityFindingFilters_threatIntelIndicatorSourceUrl,
    awsSecurityFindingFilters_networkDirection,
    awsSecurityFindingFilters_description,
    awsSecurityFindingFilters_verificationState,
    awsSecurityFindingFilters_sourceUrl,
    awsSecurityFindingFilters_processPath,
    awsSecurityFindingFilters_processPid,
    awsSecurityFindingFilters_generatorId,
    awsSecurityFindingFilters_productArn,
    awsSecurityFindingFilters_lastObservedAt,
    awsSecurityFindingFilters_findingProviderFieldsConfidence,
    awsSecurityFindingFilters_userDefinedFields,
    awsSecurityFindingFilters_resourceAwsEc2InstanceIpV4Addresses,
    awsSecurityFindingFilters_malwareType,
    awsSecurityFindingFilters_keyword,

    -- * AwsSecurityFindingIdentifier
    AwsSecurityFindingIdentifier (..),
    newAwsSecurityFindingIdentifier,
    awsSecurityFindingIdentifier_id,
    awsSecurityFindingIdentifier_productArn,

    -- * AwsSnsTopicDetails
    AwsSnsTopicDetails (..),
    newAwsSnsTopicDetails,
    awsSnsTopicDetails_kmsMasterKeyId,
    awsSnsTopicDetails_topicName,
    awsSnsTopicDetails_owner,
    awsSnsTopicDetails_subscription,

    -- * AwsSnsTopicSubscription
    AwsSnsTopicSubscription (..),
    newAwsSnsTopicSubscription,
    awsSnsTopicSubscription_protocol,
    awsSnsTopicSubscription_endpoint,

    -- * AwsSqsQueueDetails
    AwsSqsQueueDetails (..),
    newAwsSqsQueueDetails,
    awsSqsQueueDetails_kmsMasterKeyId,
    awsSqsQueueDetails_queueName,
    awsSqsQueueDetails_kmsDataKeyReusePeriodSeconds,
    awsSqsQueueDetails_deadLetterTargetArn,

    -- * AwsSsmComplianceSummary
    AwsSsmComplianceSummary (..),
    newAwsSsmComplianceSummary,
    awsSsmComplianceSummary_status,
    awsSsmComplianceSummary_nonCompliantLowCount,
    awsSsmComplianceSummary_compliantHighCount,
    awsSsmComplianceSummary_nonCompliantUnspecifiedCount,
    awsSsmComplianceSummary_executionType,
    awsSsmComplianceSummary_compliantInformationalCount,
    awsSsmComplianceSummary_nonCompliantHighCount,
    awsSsmComplianceSummary_nonCompliantMediumCount,
    awsSsmComplianceSummary_overallSeverity,
    awsSsmComplianceSummary_compliantCriticalCount,
    awsSsmComplianceSummary_nonCompliantInformationalCount,
    awsSsmComplianceSummary_complianceType,
    awsSsmComplianceSummary_compliantUnspecifiedCount,
    awsSsmComplianceSummary_nonCompliantCriticalCount,
    awsSsmComplianceSummary_patchBaselineId,
    awsSsmComplianceSummary_compliantLowCount,
    awsSsmComplianceSummary_patchGroup,
    awsSsmComplianceSummary_compliantMediumCount,

    -- * AwsSsmPatch
    AwsSsmPatch (..),
    newAwsSsmPatch,
    awsSsmPatch_complianceSummary,

    -- * AwsSsmPatchComplianceDetails
    AwsSsmPatchComplianceDetails (..),
    newAwsSsmPatchComplianceDetails,
    awsSsmPatchComplianceDetails_patch,

    -- * AwsWafRateBasedRuleDetails
    AwsWafRateBasedRuleDetails (..),
    newAwsWafRateBasedRuleDetails,
    awsWafRateBasedRuleDetails_rateLimit,
    awsWafRateBasedRuleDetails_rateKey,
    awsWafRateBasedRuleDetails_metricName,
    awsWafRateBasedRuleDetails_ruleId,
    awsWafRateBasedRuleDetails_name,
    awsWafRateBasedRuleDetails_matchPredicates,

    -- * AwsWafRateBasedRuleMatchPredicate
    AwsWafRateBasedRuleMatchPredicate (..),
    newAwsWafRateBasedRuleMatchPredicate,
    awsWafRateBasedRuleMatchPredicate_negated,
    awsWafRateBasedRuleMatchPredicate_dataId,
    awsWafRateBasedRuleMatchPredicate_type,

    -- * AwsWafRegionalRateBasedRuleDetails
    AwsWafRegionalRateBasedRuleDetails (..),
    newAwsWafRegionalRateBasedRuleDetails,
    awsWafRegionalRateBasedRuleDetails_rateLimit,
    awsWafRegionalRateBasedRuleDetails_rateKey,
    awsWafRegionalRateBasedRuleDetails_metricName,
    awsWafRegionalRateBasedRuleDetails_ruleId,
    awsWafRegionalRateBasedRuleDetails_name,
    awsWafRegionalRateBasedRuleDetails_matchPredicates,

    -- * AwsWafRegionalRateBasedRuleMatchPredicate
    AwsWafRegionalRateBasedRuleMatchPredicate (..),
    newAwsWafRegionalRateBasedRuleMatchPredicate,
    awsWafRegionalRateBasedRuleMatchPredicate_negated,
    awsWafRegionalRateBasedRuleMatchPredicate_dataId,
    awsWafRegionalRateBasedRuleMatchPredicate_type,

    -- * AwsWafWebAclDetails
    AwsWafWebAclDetails (..),
    newAwsWafWebAclDetails,
    awsWafWebAclDetails_rules,
    awsWafWebAclDetails_webAclId,
    awsWafWebAclDetails_name,
    awsWafWebAclDetails_defaultAction,

    -- * AwsWafWebAclRule
    AwsWafWebAclRule (..),
    newAwsWafWebAclRule,
    awsWafWebAclRule_priority,
    awsWafWebAclRule_overrideAction,
    awsWafWebAclRule_ruleId,
    awsWafWebAclRule_action,
    awsWafWebAclRule_excludedRules,
    awsWafWebAclRule_type,

    -- * AwsXrayEncryptionConfigDetails
    AwsXrayEncryptionConfigDetails (..),
    newAwsXrayEncryptionConfigDetails,
    awsXrayEncryptionConfigDetails_status,
    awsXrayEncryptionConfigDetails_keyId,
    awsXrayEncryptionConfigDetails_type,

    -- * BatchUpdateFindingsUnprocessedFinding
    BatchUpdateFindingsUnprocessedFinding (..),
    newBatchUpdateFindingsUnprocessedFinding,
    batchUpdateFindingsUnprocessedFinding_findingIdentifier,
    batchUpdateFindingsUnprocessedFinding_errorCode,
    batchUpdateFindingsUnprocessedFinding_errorMessage,

    -- * Cell
    Cell (..),
    newCell,
    cell_row,
    cell_cellReference,
    cell_column,
    cell_columnName,

    -- * CidrBlockAssociation
    CidrBlockAssociation (..),
    newCidrBlockAssociation,
    cidrBlockAssociation_associationId,
    cidrBlockAssociation_cidrBlockState,
    cidrBlockAssociation_cidrBlock,

    -- * City
    City (..),
    newCity,
    city_cityName,

    -- * ClassificationResult
    ClassificationResult (..),
    newClassificationResult,
    classificationResult_status,
    classificationResult_sensitiveData,
    classificationResult_mimeType,
    classificationResult_sizeClassified,
    classificationResult_additionalOccurrences,
    classificationResult_customDataIdentifiers,

    -- * ClassificationStatus
    ClassificationStatus (..),
    newClassificationStatus,
    classificationStatus_reason,
    classificationStatus_code,

    -- * Compliance
    Compliance (..),
    newCompliance,
    compliance_status,
    compliance_relatedRequirements,
    compliance_statusReasons,

    -- * ContainerDetails
    ContainerDetails (..),
    newContainerDetails,
    containerDetails_name,
    containerDetails_imageId,
    containerDetails_imageName,
    containerDetails_launchedAt,

    -- * Country
    Country (..),
    newCountry,
    country_countryName,
    country_countryCode,

    -- * CustomDataIdentifiersDetections
    CustomDataIdentifiersDetections (..),
    newCustomDataIdentifiersDetections,
    customDataIdentifiersDetections_occurrences,
    customDataIdentifiersDetections_arn,
    customDataIdentifiersDetections_count,
    customDataIdentifiersDetections_name,

    -- * CustomDataIdentifiersResult
    CustomDataIdentifiersResult (..),
    newCustomDataIdentifiersResult,
    customDataIdentifiersResult_detections,
    customDataIdentifiersResult_totalCount,

    -- * Cvss
    Cvss (..),
    newCvss,
    cvss_adjustments,
    cvss_baseVector,
    cvss_version,
    cvss_source,
    cvss_baseScore,

    -- * DataClassificationDetails
    DataClassificationDetails (..),
    newDataClassificationDetails,
    dataClassificationDetails_detailedResultsLocation,
    dataClassificationDetails_result,

    -- * DateFilter
    DateFilter (..),
    newDateFilter,
    dateFilter_start,
    dateFilter_dateRange,
    dateFilter_end,

    -- * DateRange
    DateRange (..),
    newDateRange,
    dateRange_value,
    dateRange_unit,

    -- * DnsRequestAction
    DnsRequestAction (..),
    newDnsRequestAction,
    dnsRequestAction_domain,
    dnsRequestAction_protocol,
    dnsRequestAction_blocked,

    -- * FindingAggregator
    FindingAggregator (..),
    newFindingAggregator,
    findingAggregator_findingAggregatorArn,

    -- * FindingProviderFields
    FindingProviderFields (..),
    newFindingProviderFields,
    findingProviderFields_criticality,
    findingProviderFields_severity,
    findingProviderFields_types,
    findingProviderFields_relatedFindings,
    findingProviderFields_confidence,

    -- * FindingProviderSeverity
    FindingProviderSeverity (..),
    newFindingProviderSeverity,
    findingProviderSeverity_label,
    findingProviderSeverity_original,

    -- * GeoLocation
    GeoLocation (..),
    newGeoLocation,
    geoLocation_lat,
    geoLocation_lon,

    -- * IcmpTypeCode
    IcmpTypeCode (..),
    newIcmpTypeCode,
    icmpTypeCode_code,
    icmpTypeCode_type,

    -- * ImportFindingsError
    ImportFindingsError (..),
    newImportFindingsError,
    importFindingsError_id,
    importFindingsError_errorCode,
    importFindingsError_errorMessage,

    -- * Insight
    Insight (..),
    newInsight,
    insight_insightArn,
    insight_name,
    insight_filters,
    insight_groupByAttribute,

    -- * InsightResultValue
    InsightResultValue (..),
    newInsightResultValue,
    insightResultValue_groupByAttributeValue,
    insightResultValue_count,

    -- * InsightResults
    InsightResults (..),
    newInsightResults,
    insightResults_insightArn,
    insightResults_groupByAttribute,
    insightResults_resultValues,

    -- * Invitation
    Invitation (..),
    newInvitation,
    invitation_invitedAt,
    invitation_invitationId,
    invitation_accountId,
    invitation_memberStatus,

    -- * IpFilter
    IpFilter (..),
    newIpFilter,
    ipFilter_cidr,

    -- * IpOrganizationDetails
    IpOrganizationDetails (..),
    newIpOrganizationDetails,
    ipOrganizationDetails_org,
    ipOrganizationDetails_asnOrg,
    ipOrganizationDetails_asn,
    ipOrganizationDetails_isp,

    -- * Ipv6CidrBlockAssociation
    Ipv6CidrBlockAssociation (..),
    newIpv6CidrBlockAssociation,
    ipv6CidrBlockAssociation_associationId,
    ipv6CidrBlockAssociation_ipv6CidrBlock,
    ipv6CidrBlockAssociation_cidrBlockState,

    -- * KeywordFilter
    KeywordFilter (..),
    newKeywordFilter,
    keywordFilter_value,

    -- * LoadBalancerState
    LoadBalancerState (..),
    newLoadBalancerState,
    loadBalancerState_reason,
    loadBalancerState_code,

    -- * Malware
    Malware (..),
    newMalware,
    malware_state,
    malware_path,
    malware_type,
    malware_name,

    -- * MapFilter
    MapFilter (..),
    newMapFilter,
    mapFilter_value,
    mapFilter_comparison,
    mapFilter_key,

    -- * Member
    Member (..),
    newMember,
    member_email,
    member_invitedAt,
    member_administratorId,
    member_masterId,
    member_accountId,
    member_memberStatus,
    member_updatedAt,

    -- * Network
    Network (..),
    newNetwork,
    network_destinationDomain,
    network_sourcePort,
    network_openPortRange,
    network_sourceMac,
    network_direction,
    network_destinationIpV6,
    network_protocol,
    network_sourceIpV6,
    network_destinationIpV4,
    network_sourceDomain,
    network_destinationPort,
    network_sourceIpV4,

    -- * NetworkConnectionAction
    NetworkConnectionAction (..),
    newNetworkConnectionAction,
    networkConnectionAction_remoteIpDetails,
    networkConnectionAction_protocol,
    networkConnectionAction_remotePortDetails,
    networkConnectionAction_blocked,
    networkConnectionAction_connectionDirection,
    networkConnectionAction_localPortDetails,

    -- * NetworkHeader
    NetworkHeader (..),
    newNetworkHeader,
    networkHeader_destination,
    networkHeader_protocol,
    networkHeader_source,

    -- * NetworkPathComponent
    NetworkPathComponent (..),
    newNetworkPathComponent,
    networkPathComponent_componentType,
    networkPathComponent_ingress,
    networkPathComponent_componentId,
    networkPathComponent_egress,

    -- * NetworkPathComponentDetails
    NetworkPathComponentDetails (..),
    newNetworkPathComponentDetails,
    networkPathComponentDetails_portRanges,
    networkPathComponentDetails_address,

    -- * Note
    Note (..),
    newNote,
    note_text,
    note_updatedBy,
    note_updatedAt,

    -- * NoteUpdate
    NoteUpdate (..),
    newNoteUpdate,
    noteUpdate_text,
    noteUpdate_updatedBy,

    -- * NumberFilter
    NumberFilter (..),
    newNumberFilter,
    numberFilter_eq,
    numberFilter_lte,
    numberFilter_gte,

    -- * Occurrences
    Occurrences (..),
    newOccurrences,
    occurrences_lineRanges,
    occurrences_cells,
    occurrences_pages,
    occurrences_records,
    occurrences_offsetRanges,

    -- * Page
    Page (..),
    newPage,
    page_offsetRange,
    page_lineRange,
    page_pageNumber,

    -- * PatchSummary
    PatchSummary (..),
    newPatchSummary,
    patchSummary_operationEndTime,
    patchSummary_rebootOption,
    patchSummary_operation,
    patchSummary_installedRejectedCount,
    patchSummary_failedCount,
    patchSummary_installedOtherCount,
    patchSummary_missingCount,
    patchSummary_operationStartTime,
    patchSummary_installedCount,
    patchSummary_installedPendingReboot,
    patchSummary_id,

    -- * PortProbeAction
    PortProbeAction (..),
    newPortProbeAction,
    portProbeAction_portProbeDetails,
    portProbeAction_blocked,

    -- * PortProbeDetail
    PortProbeDetail (..),
    newPortProbeDetail,
    portProbeDetail_remoteIpDetails,
    portProbeDetail_localIpDetails,
    portProbeDetail_localPortDetails,

    -- * PortRange
    PortRange (..),
    newPortRange,
    portRange_begin,
    portRange_end,

    -- * PortRangeFromTo
    PortRangeFromTo (..),
    newPortRangeFromTo,
    portRangeFromTo_to,
    portRangeFromTo_from,

    -- * ProcessDetails
    ProcessDetails (..),
    newProcessDetails,
    processDetails_path,
    processDetails_name,
    processDetails_pid,
    processDetails_terminatedAt,
    processDetails_parentPid,
    processDetails_launchedAt,

    -- * Product
    Product (..),
    newProduct,
    product_productName,
    product_productSubscriptionResourcePolicy,
    product_companyName,
    product_categories,
    product_marketplaceUrl,
    product_activationUrl,
    product_integrationTypes,
    product_description,
    product_productArn,

    -- * Range
    Range (..),
    newRange,
    range_start,
    range_end,
    range_startColumn,

    -- * Recommendation
    Recommendation (..),
    newRecommendation,
    recommendation_text,
    recommendation_url,

    -- * Record
    Record (..),
    newRecord,
    record_jsonPath,
    record_recordIndex,

    -- * RelatedFinding
    RelatedFinding (..),
    newRelatedFinding,
    relatedFinding_productArn,
    relatedFinding_id,

    -- * Remediation
    Remediation (..),
    newRemediation,
    remediation_recommendation,

    -- * Resource
    Resource (..),
    newResource,
    resource_dataClassification,
    resource_partition,
    resource_details,
    resource_region,
    resource_resourceRole,
    resource_tags,
    resource_type,
    resource_id,

    -- * ResourceDetails
    ResourceDetails (..),
    newResourceDetails,
    resourceDetails_awsCloudTrailTrail,
    resourceDetails_awsRdsDbCluster,
    resourceDetails_other,
    resourceDetails_awsIamRole,
    resourceDetails_awsElbLoadBalancer,
    resourceDetails_awsEc2VpnConnection,
    resourceDetails_awsCloudFrontDistribution,
    resourceDetails_awsKmsKey,
    resourceDetails_awsEksCluster,
    resourceDetails_awsAutoScalingLaunchConfiguration,
    resourceDetails_awsOpenSearchServiceDomain,
    resourceDetails_awsRdsDbSnapshot,
    resourceDetails_awsWafRegionalRateBasedRule,
    resourceDetails_awsApiGatewayRestApi,
    resourceDetails_awsSqsQueue,
    resourceDetails_awsSecretsManagerSecret,
    resourceDetails_awsDynamoDbTable,
    resourceDetails_awsS3AccountPublicAccessBlock,
    resourceDetails_awsRdsDbClusterSnapshot,
    resourceDetails_awsEc2SecurityGroup,
    resourceDetails_awsEc2Instance,
    resourceDetails_awsIamPolicy,
    resourceDetails_awsS3Object,
    resourceDetails_awsEcsTaskDefinition,
    resourceDetails_awsLambdaLayerVersion,
    resourceDetails_awsS3Bucket,
    resourceDetails_awsIamAccessKey,
    resourceDetails_awsCodeBuildProject,
    resourceDetails_awsApiGatewayStage,
    resourceDetails_awsEc2NetworkAcl,
    resourceDetails_awsApiGatewayV2Api,
    resourceDetails_awsElasticBeanstalkEnvironment,
    resourceDetails_awsEc2Vpc,
    resourceDetails_awsRedshiftCluster,
    resourceDetails_awsRdsDbInstance,
    resourceDetails_awsRdsEventSubscription,
    resourceDetails_container,
    resourceDetails_awsIamGroup,
    resourceDetails_awsXrayEncryptionConfig,
    resourceDetails_awsEc2Subnet,
    resourceDetails_awsEcsCluster,
    resourceDetails_awsEc2VpcEndpointService,
    resourceDetails_awsAutoScalingAutoScalingGroup,
    resourceDetails_awsSnsTopic,
    resourceDetails_awsEc2NetworkInterface,
    resourceDetails_awsEcsService,
    resourceDetails_awsEc2Eip,
    resourceDetails_awsApiGatewayV2Stage,
    resourceDetails_awsLambdaFunction,
    resourceDetails_awsElbv2LoadBalancer,
    resourceDetails_awsWafRateBasedRule,
    resourceDetails_awsEcrRepository,
    resourceDetails_awsWafWebAcl,
    resourceDetails_awsSsmPatchCompliance,
    resourceDetails_awsElasticsearchDomain,
    resourceDetails_awsCertificateManagerCertificate,
    resourceDetails_awsEcrContainerImage,
    resourceDetails_awsIamUser,
    resourceDetails_awsEc2Volume,

    -- * Result
    Result (..),
    newResult,
    result_accountId,
    result_processingResult,

    -- * SensitiveDataDetections
    SensitiveDataDetections (..),
    newSensitiveDataDetections,
    sensitiveDataDetections_occurrences,
    sensitiveDataDetections_count,
    sensitiveDataDetections_type,

    -- * SensitiveDataResult
    SensitiveDataResult (..),
    newSensitiveDataResult,
    sensitiveDataResult_detections,
    sensitiveDataResult_category,
    sensitiveDataResult_totalCount,

    -- * Severity
    Severity (..),
    newSeverity,
    severity_product,
    severity_label,
    severity_original,
    severity_normalized,

    -- * SeverityUpdate
    SeverityUpdate (..),
    newSeverityUpdate,
    severityUpdate_product,
    severityUpdate_label,
    severityUpdate_normalized,

    -- * SoftwarePackage
    SoftwarePackage (..),
    newSoftwarePackage,
    softwarePackage_filePath,
    softwarePackage_release,
    softwarePackage_name,
    softwarePackage_version,
    softwarePackage_architecture,
    softwarePackage_packageManager,
    softwarePackage_epoch,

    -- * SortCriterion
    SortCriterion (..),
    newSortCriterion,
    sortCriterion_field,
    sortCriterion_sortOrder,

    -- * Standard
    Standard (..),
    newStandard,
    standard_standardsArn,
    standard_enabledByDefault,
    standard_name,
    standard_description,

    -- * StandardsControl
    StandardsControl (..),
    newStandardsControl,
    standardsControl_remediationUrl,
    standardsControl_severityRating,
    standardsControl_controlStatusUpdatedAt,
    standardsControl_relatedRequirements,
    standardsControl_controlStatus,
    standardsControl_disabledReason,
    standardsControl_controlId,
    standardsControl_standardsControlArn,
    standardsControl_title,
    standardsControl_description,

    -- * StandardsSubscription
    StandardsSubscription (..),
    newStandardsSubscription,
    standardsSubscription_standardsSubscriptionArn,
    standardsSubscription_standardsArn,
    standardsSubscription_standardsInput,
    standardsSubscription_standardsStatus,

    -- * StandardsSubscriptionRequest
    StandardsSubscriptionRequest (..),
    newStandardsSubscriptionRequest,
    standardsSubscriptionRequest_standardsInput,
    standardsSubscriptionRequest_standardsArn,

    -- * StatusReason
    StatusReason (..),
    newStatusReason,
    statusReason_description,
    statusReason_reasonCode,

    -- * StringFilter
    StringFilter (..),
    newStringFilter,
    stringFilter_value,
    stringFilter_comparison,

    -- * ThreatIntelIndicator
    ThreatIntelIndicator (..),
    newThreatIntelIndicator,
    threatIntelIndicator_category,
    threatIntelIndicator_value,
    threatIntelIndicator_source,
    threatIntelIndicator_type,
    threatIntelIndicator_sourceUrl,
    threatIntelIndicator_lastObservedAt,

    -- * Vulnerability
    Vulnerability (..),
    newVulnerability,
    vulnerability_vendor,
    vulnerability_relatedVulnerabilities,
    vulnerability_vulnerablePackages,
    vulnerability_referenceUrls,
    vulnerability_cvss,
    vulnerability_id,

    -- * VulnerabilityVendor
    VulnerabilityVendor (..),
    newVulnerabilityVendor,
    vulnerabilityVendor_vendorSeverity,
    vulnerabilityVendor_url,
    vulnerabilityVendor_vendorCreatedAt,
    vulnerabilityVendor_vendorUpdatedAt,
    vulnerabilityVendor_name,

    -- * WafAction
    WafAction (..),
    newWafAction,
    wafAction_type,

    -- * WafExcludedRule
    WafExcludedRule (..),
    newWafExcludedRule,
    wafExcludedRule_ruleId,

    -- * WafOverrideAction
    WafOverrideAction (..),
    newWafOverrideAction,
    wafOverrideAction_type,

    -- * Workflow
    Workflow (..),
    newWorkflow,
    workflow_status,

    -- * WorkflowUpdate
    WorkflowUpdate (..),
    newWorkflowUpdate,
    workflowUpdate_status,
  )
where

import qualified Amazonka.Core as Core
import qualified Amazonka.Lens as Lens
import qualified Amazonka.Prelude as Prelude
import Amazonka.SecurityHub.Types.AccountDetails
import Amazonka.SecurityHub.Types.Action
import Amazonka.SecurityHub.Types.ActionLocalIpDetails
import Amazonka.SecurityHub.Types.ActionLocalPortDetails
import Amazonka.SecurityHub.Types.ActionRemoteIpDetails
import Amazonka.SecurityHub.Types.ActionRemotePortDetails
import Amazonka.SecurityHub.Types.ActionTarget
import Amazonka.SecurityHub.Types.Adjustment
import Amazonka.SecurityHub.Types.AdminAccount
import Amazonka.SecurityHub.Types.AdminStatus
import Amazonka.SecurityHub.Types.AvailabilityZone
import Amazonka.SecurityHub.Types.AwsApiCallAction
import Amazonka.SecurityHub.Types.AwsApiCallActionDomainDetails
import Amazonka.SecurityHub.Types.AwsApiGatewayAccessLogSettings
import Amazonka.SecurityHub.Types.AwsApiGatewayCanarySettings
import Amazonka.SecurityHub.Types.AwsApiGatewayEndpointConfiguration
import Amazonka.SecurityHub.Types.AwsApiGatewayMethodSettings
import Amazonka.SecurityHub.Types.AwsApiGatewayRestApiDetails
import Amazonka.SecurityHub.Types.AwsApiGatewayStageDetails
import Amazonka.SecurityHub.Types.AwsApiGatewayV2ApiDetails
import Amazonka.SecurityHub.Types.AwsApiGatewayV2RouteSettings
import Amazonka.SecurityHub.Types.AwsApiGatewayV2StageDetails
import Amazonka.SecurityHub.Types.AwsAutoScalingAutoScalingGroupDetails
import Amazonka.SecurityHub.Types.AwsAutoScalingLaunchConfigurationBlockDeviceMappingsDetails
import Amazonka.SecurityHub.Types.AwsAutoScalingLaunchConfigurationBlockDeviceMappingsEbsDetails
import Amazonka.SecurityHub.Types.AwsAutoScalingLaunchConfigurationDetails
import Amazonka.SecurityHub.Types.AwsAutoScalingLaunchConfigurationInstanceMonitoringDetails
import Amazonka.SecurityHub.Types.AwsCertificateManagerCertificateDetails
import Amazonka.SecurityHub.Types.AwsCertificateManagerCertificateDomainValidationOption
import Amazonka.SecurityHub.Types.AwsCertificateManagerCertificateExtendedKeyUsage
import Amazonka.SecurityHub.Types.AwsCertificateManagerCertificateKeyUsage
import Amazonka.SecurityHub.Types.AwsCertificateManagerCertificateOptions
import Amazonka.SecurityHub.Types.AwsCertificateManagerCertificateRenewalSummary
import Amazonka.SecurityHub.Types.AwsCertificateManagerCertificateResourceRecord
import Amazonka.SecurityHub.Types.AwsCloudFrontDistributionCacheBehavior
import Amazonka.SecurityHub.Types.AwsCloudFrontDistributionCacheBehaviors
import Amazonka.SecurityHub.Types.AwsCloudFrontDistributionDefaultCacheBehavior
import Amazonka.SecurityHub.Types.AwsCloudFrontDistributionDetails
import Amazonka.SecurityHub.Types.AwsCloudFrontDistributionLogging
import Amazonka.SecurityHub.Types.AwsCloudFrontDistributionOriginGroup
import Amazonka.SecurityHub.Types.AwsCloudFrontDistributionOriginGroupFailover
import Amazonka.SecurityHub.Types.AwsCloudFrontDistributionOriginGroupFailoverStatusCodes
import Amazonka.SecurityHub.Types.AwsCloudFrontDistributionOriginGroups
import Amazonka.SecurityHub.Types.AwsCloudFrontDistributionOriginItem
import Amazonka.SecurityHub.Types.AwsCloudFrontDistributionOriginS3OriginConfig
import Amazonka.SecurityHub.Types.AwsCloudFrontDistributionOrigins
import Amazonka.SecurityHub.Types.AwsCloudFrontDistributionViewerCertificate
import Amazonka.SecurityHub.Types.AwsCloudTrailTrailDetails
import Amazonka.SecurityHub.Types.AwsCodeBuildProjectArtifactsDetails
import Amazonka.SecurityHub.Types.AwsCodeBuildProjectDetails
import Amazonka.SecurityHub.Types.AwsCodeBuildProjectEnvironment
import Amazonka.SecurityHub.Types.AwsCodeBuildProjectEnvironmentEnvironmentVariablesDetails
import Amazonka.SecurityHub.Types.AwsCodeBuildProjectEnvironmentRegistryCredential
import Amazonka.SecurityHub.Types.AwsCodeBuildProjectLogsConfigCloudWatchLogsDetails
import Amazonka.SecurityHub.Types.AwsCodeBuildProjectLogsConfigDetails
import Amazonka.SecurityHub.Types.AwsCodeBuildProjectLogsConfigS3LogsDetails
import Amazonka.SecurityHub.Types.AwsCodeBuildProjectSource
import Amazonka.SecurityHub.Types.AwsCodeBuildProjectVpcConfig
import Amazonka.SecurityHub.Types.AwsCorsConfiguration
import Amazonka.SecurityHub.Types.AwsDynamoDbTableAttributeDefinition
import Amazonka.SecurityHub.Types.AwsDynamoDbTableBillingModeSummary
import Amazonka.SecurityHub.Types.AwsDynamoDbTableDetails
import Amazonka.SecurityHub.Types.AwsDynamoDbTableGlobalSecondaryIndex
import Amazonka.SecurityHub.Types.AwsDynamoDbTableKeySchema
import Amazonka.SecurityHub.Types.AwsDynamoDbTableLocalSecondaryIndex
import Amazonka.SecurityHub.Types.AwsDynamoDbTableProjection
import Amazonka.SecurityHub.Types.AwsDynamoDbTableProvisionedThroughput
import Amazonka.SecurityHub.Types.AwsDynamoDbTableProvisionedThroughputOverride
import Amazonka.SecurityHub.Types.AwsDynamoDbTableReplica
import Amazonka.SecurityHub.Types.AwsDynamoDbTableReplicaGlobalSecondaryIndex
import Amazonka.SecurityHub.Types.AwsDynamoDbTableRestoreSummary
import Amazonka.SecurityHub.Types.AwsDynamoDbTableSseDescription
import Amazonka.SecurityHub.Types.AwsDynamoDbTableStreamSpecification
import Amazonka.SecurityHub.Types.AwsEc2EipDetails
import Amazonka.SecurityHub.Types.AwsEc2InstanceDetails
import Amazonka.SecurityHub.Types.AwsEc2InstanceNetworkInterfacesDetails
import Amazonka.SecurityHub.Types.AwsEc2NetworkAclAssociation
import Amazonka.SecurityHub.Types.AwsEc2NetworkAclDetails
import Amazonka.SecurityHub.Types.AwsEc2NetworkAclEntry
import Amazonka.SecurityHub.Types.AwsEc2NetworkInterfaceAttachment
import Amazonka.SecurityHub.Types.AwsEc2NetworkInterfaceDetails
import Amazonka.SecurityHub.Types.AwsEc2NetworkInterfaceIpV6AddressDetail
import Amazonka.SecurityHub.Types.AwsEc2NetworkInterfacePrivateIpAddressDetail
import Amazonka.SecurityHub.Types.AwsEc2NetworkInterfaceSecurityGroup
import Amazonka.SecurityHub.Types.AwsEc2SecurityGroupDetails
import Amazonka.SecurityHub.Types.AwsEc2SecurityGroupIpPermission
import Amazonka.SecurityHub.Types.AwsEc2SecurityGroupIpRange
import Amazonka.SecurityHub.Types.AwsEc2SecurityGroupIpv6Range
import Amazonka.SecurityHub.Types.AwsEc2SecurityGroupPrefixListId
import Amazonka.SecurityHub.Types.AwsEc2SecurityGroupUserIdGroupPair
import Amazonka.SecurityHub.Types.AwsEc2SubnetDetails
import Amazonka.SecurityHub.Types.AwsEc2VolumeAttachment
import Amazonka.SecurityHub.Types.AwsEc2VolumeDetails
import Amazonka.SecurityHub.Types.AwsEc2VpcDetails
import Amazonka.SecurityHub.Types.AwsEc2VpcEndpointServiceDetails
import Amazonka.SecurityHub.Types.AwsEc2VpcEndpointServiceServiceTypeDetails
import Amazonka.SecurityHub.Types.AwsEc2VpnConnectionDetails
import Amazonka.SecurityHub.Types.AwsEc2VpnConnectionOptionsDetails
import Amazonka.SecurityHub.Types.AwsEc2VpnConnectionOptionsTunnelOptionsDetails
import Amazonka.SecurityHub.Types.AwsEc2VpnConnectionRoutesDetails
import Amazonka.SecurityHub.Types.AwsEc2VpnConnectionVgwTelemetryDetails
import Amazonka.SecurityHub.Types.AwsEcrContainerImageDetails
import Amazonka.SecurityHub.Types.AwsEcrRepositoryDetails
import Amazonka.SecurityHub.Types.AwsEcrRepositoryImageScanningConfigurationDetails
import Amazonka.SecurityHub.Types.AwsEcrRepositoryLifecyclePolicyDetails
import Amazonka.SecurityHub.Types.AwsEcsClusterClusterSettingsDetails
import Amazonka.SecurityHub.Types.AwsEcsClusterConfigurationDetails
import Amazonka.SecurityHub.Types.AwsEcsClusterConfigurationExecuteCommandConfigurationDetails
import Amazonka.SecurityHub.Types.AwsEcsClusterConfigurationExecuteCommandConfigurationLogConfigurationDetails
import Amazonka.SecurityHub.Types.AwsEcsClusterDefaultCapacityProviderStrategyDetails
import Amazonka.SecurityHub.Types.AwsEcsClusterDetails
import Amazonka.SecurityHub.Types.AwsEcsServiceCapacityProviderStrategyDetails
import Amazonka.SecurityHub.Types.AwsEcsServiceDeploymentConfigurationDeploymentCircuitBreakerDetails
import Amazonka.SecurityHub.Types.AwsEcsServiceDeploymentConfigurationDetails
import Amazonka.SecurityHub.Types.AwsEcsServiceDeploymentControllerDetails
import Amazonka.SecurityHub.Types.AwsEcsServiceDetails
import Amazonka.SecurityHub.Types.AwsEcsServiceLoadBalancersDetails
import Amazonka.SecurityHub.Types.AwsEcsServiceNetworkConfigurationAwsVpcConfigurationDetails
import Amazonka.SecurityHub.Types.AwsEcsServiceNetworkConfigurationDetails
import Amazonka.SecurityHub.Types.AwsEcsServicePlacementConstraintsDetails
import Amazonka.SecurityHub.Types.AwsEcsServicePlacementStrategiesDetails
import Amazonka.SecurityHub.Types.AwsEcsServiceServiceRegistriesDetails
import Amazonka.SecurityHub.Types.AwsEcsTaskDefinitionContainerDefinitionsDependsOnDetails
import Amazonka.SecurityHub.Types.AwsEcsTaskDefinitionContainerDefinitionsDetails
import Amazonka.SecurityHub.Types.AwsEcsTaskDefinitionContainerDefinitionsEnvironmentDetails
import Amazonka.SecurityHub.Types.AwsEcsTaskDefinitionContainerDefinitionsEnvironmentFilesDetails
import Amazonka.SecurityHub.Types.AwsEcsTaskDefinitionContainerDefinitionsExtraHostsDetails
import Amazonka.SecurityHub.Types.AwsEcsTaskDefinitionContainerDefinitionsFirelensConfigurationDetails
import Amazonka.SecurityHub.Types.AwsEcsTaskDefinitionContainerDefinitionsHealthCheckDetails
import Amazonka.SecurityHub.Types.AwsEcsTaskDefinitionContainerDefinitionsLinuxParametersCapabilitiesDetails
import Amazonka.SecurityHub.Types.AwsEcsTaskDefinitionContainerDefinitionsLinuxParametersDetails
import Amazonka.SecurityHub.Types.AwsEcsTaskDefinitionContainerDefinitionsLinuxParametersDevicesDetails
import Amazonka.SecurityHub.Types.AwsEcsTaskDefinitionContainerDefinitionsLinuxParametersTmpfsDetails
import Amazonka.SecurityHub.Types.AwsEcsTaskDefinitionContainerDefinitionsLogConfigurationDetails
import Amazonka.SecurityHub.Types.AwsEcsTaskDefinitionContainerDefinitionsLogConfigurationSecretOptionsDetails
import Amazonka.SecurityHub.Types.AwsEcsTaskDefinitionContainerDefinitionsMountPointsDetails
import Amazonka.SecurityHub.Types.AwsEcsTaskDefinitionContainerDefinitionsPortMappingsDetails
import Amazonka.SecurityHub.Types.AwsEcsTaskDefinitionContainerDefinitionsRepositoryCredentialsDetails
import Amazonka.SecurityHub.Types.AwsEcsTaskDefinitionContainerDefinitionsResourceRequirementsDetails
import Amazonka.SecurityHub.Types.AwsEcsTaskDefinitionContainerDefinitionsSecretsDetails
import Amazonka.SecurityHub.Types.AwsEcsTaskDefinitionContainerDefinitionsSystemControlsDetails
import Amazonka.SecurityHub.Types.AwsEcsTaskDefinitionContainerDefinitionsUlimitsDetails
import Amazonka.SecurityHub.Types.AwsEcsTaskDefinitionContainerDefinitionsVolumesFromDetails
import Amazonka.SecurityHub.Types.AwsEcsTaskDefinitionDetails
import Amazonka.SecurityHub.Types.AwsEcsTaskDefinitionInferenceAcceleratorsDetails
import Amazonka.SecurityHub.Types.AwsEcsTaskDefinitionPlacementConstraintsDetails
import Amazonka.SecurityHub.Types.AwsEcsTaskDefinitionProxyConfigurationDetails
import Amazonka.SecurityHub.Types.AwsEcsTaskDefinitionProxyConfigurationProxyConfigurationPropertiesDetails
import Amazonka.SecurityHub.Types.AwsEcsTaskDefinitionVolumesDetails
import Amazonka.SecurityHub.Types.AwsEcsTaskDefinitionVolumesDockerVolumeConfigurationDetails
import Amazonka.SecurityHub.Types.AwsEcsTaskDefinitionVolumesEfsVolumeConfigurationAuthorizationConfigDetails
import Amazonka.SecurityHub.Types.AwsEcsTaskDefinitionVolumesEfsVolumeConfigurationDetails
import Amazonka.SecurityHub.Types.AwsEcsTaskDefinitionVolumesHostDetails
import Amazonka.SecurityHub.Types.AwsEksClusterDetails
import Amazonka.SecurityHub.Types.AwsEksClusterLoggingClusterLoggingDetails
import Amazonka.SecurityHub.Types.AwsEksClusterLoggingDetails
import Amazonka.SecurityHub.Types.AwsEksClusterResourcesVpcConfigDetails
import Amazonka.SecurityHub.Types.AwsElasticBeanstalkEnvironmentDetails
import Amazonka.SecurityHub.Types.AwsElasticBeanstalkEnvironmentEnvironmentLink
import Amazonka.SecurityHub.Types.AwsElasticBeanstalkEnvironmentOptionSetting
import Amazonka.SecurityHub.Types.AwsElasticBeanstalkEnvironmentTier
import Amazonka.SecurityHub.Types.AwsElasticsearchDomainDetails
import Amazonka.SecurityHub.Types.AwsElasticsearchDomainDomainEndpointOptions
import Amazonka.SecurityHub.Types.AwsElasticsearchDomainElasticsearchClusterConfigDetails
import Amazonka.SecurityHub.Types.AwsElasticsearchDomainElasticsearchClusterConfigZoneAwarenessConfigDetails
import Amazonka.SecurityHub.Types.AwsElasticsearchDomainEncryptionAtRestOptions
import Amazonka.SecurityHub.Types.AwsElasticsearchDomainLogPublishingOptions
import Amazonka.SecurityHub.Types.AwsElasticsearchDomainLogPublishingOptionsLogConfig
import Amazonka.SecurityHub.Types.AwsElasticsearchDomainNodeToNodeEncryptionOptions
import Amazonka.SecurityHub.Types.AwsElasticsearchDomainServiceSoftwareOptions
import Amazonka.SecurityHub.Types.AwsElasticsearchDomainVPCOptions
import Amazonka.SecurityHub.Types.AwsElbAppCookieStickinessPolicy
import Amazonka.SecurityHub.Types.AwsElbLbCookieStickinessPolicy
import Amazonka.SecurityHub.Types.AwsElbLoadBalancerAccessLog
import Amazonka.SecurityHub.Types.AwsElbLoadBalancerAttributes
import Amazonka.SecurityHub.Types.AwsElbLoadBalancerBackendServerDescription
import Amazonka.SecurityHub.Types.AwsElbLoadBalancerConnectionDraining
import Amazonka.SecurityHub.Types.AwsElbLoadBalancerConnectionSettings
import Amazonka.SecurityHub.Types.AwsElbLoadBalancerCrossZoneLoadBalancing
import Amazonka.SecurityHub.Types.AwsElbLoadBalancerDetails
import Amazonka.SecurityHub.Types.AwsElbLoadBalancerHealthCheck
import Amazonka.SecurityHub.Types.AwsElbLoadBalancerInstance
import Amazonka.SecurityHub.Types.AwsElbLoadBalancerListener
import Amazonka.SecurityHub.Types.AwsElbLoadBalancerListenerDescription
import Amazonka.SecurityHub.Types.AwsElbLoadBalancerPolicies
import Amazonka.SecurityHub.Types.AwsElbLoadBalancerSourceSecurityGroup
import Amazonka.SecurityHub.Types.AwsElbv2LoadBalancerAttribute
import Amazonka.SecurityHub.Types.AwsElbv2LoadBalancerDetails
import Amazonka.SecurityHub.Types.AwsIamAccessKeyDetails
import Amazonka.SecurityHub.Types.AwsIamAccessKeySessionContext
import Amazonka.SecurityHub.Types.AwsIamAccessKeySessionContextAttributes
import Amazonka.SecurityHub.Types.AwsIamAccessKeySessionContextSessionIssuer
import Amazonka.SecurityHub.Types.AwsIamAccessKeyStatus
import Amazonka.SecurityHub.Types.AwsIamAttachedManagedPolicy
import Amazonka.SecurityHub.Types.AwsIamGroupDetails
import Amazonka.SecurityHub.Types.AwsIamGroupPolicy
import Amazonka.SecurityHub.Types.AwsIamInstanceProfile
import Amazonka.SecurityHub.Types.AwsIamInstanceProfileRole
import Amazonka.SecurityHub.Types.AwsIamPermissionsBoundary
import Amazonka.SecurityHub.Types.AwsIamPolicyDetails
import Amazonka.SecurityHub.Types.AwsIamPolicyVersion
import Amazonka.SecurityHub.Types.AwsIamRoleDetails
import Amazonka.SecurityHub.Types.AwsIamRolePolicy
import Amazonka.SecurityHub.Types.AwsIamUserDetails
import Amazonka.SecurityHub.Types.AwsIamUserPolicy
import Amazonka.SecurityHub.Types.AwsKmsKeyDetails
import Amazonka.SecurityHub.Types.AwsLambdaFunctionCode
import Amazonka.SecurityHub.Types.AwsLambdaFunctionDeadLetterConfig
import Amazonka.SecurityHub.Types.AwsLambdaFunctionDetails
import Amazonka.SecurityHub.Types.AwsLambdaFunctionEnvironment
import Amazonka.SecurityHub.Types.AwsLambdaFunctionEnvironmentError
import Amazonka.SecurityHub.Types.AwsLambdaFunctionLayer
import Amazonka.SecurityHub.Types.AwsLambdaFunctionTracingConfig
import Amazonka.SecurityHub.Types.AwsLambdaFunctionVpcConfig
import Amazonka.SecurityHub.Types.AwsLambdaLayerVersionDetails
import Amazonka.SecurityHub.Types.AwsOpenSearchServiceDomainClusterConfigDetails
import Amazonka.SecurityHub.Types.AwsOpenSearchServiceDomainClusterConfigZoneAwarenessConfigDetails
import Amazonka.SecurityHub.Types.AwsOpenSearchServiceDomainDetails
import Amazonka.SecurityHub.Types.AwsOpenSearchServiceDomainDomainEndpointOptionsDetails
import Amazonka.SecurityHub.Types.AwsOpenSearchServiceDomainEncryptionAtRestOptionsDetails
import Amazonka.SecurityHub.Types.AwsOpenSearchServiceDomainLogPublishingOption
import Amazonka.SecurityHub.Types.AwsOpenSearchServiceDomainLogPublishingOptionsDetails
import Amazonka.SecurityHub.Types.AwsOpenSearchServiceDomainNodeToNodeEncryptionOptionsDetails
import Amazonka.SecurityHub.Types.AwsOpenSearchServiceDomainServiceSoftwareOptionsDetails
import Amazonka.SecurityHub.Types.AwsOpenSearchServiceDomainVpcOptionsDetails
import Amazonka.SecurityHub.Types.AwsRdsDbClusterAssociatedRole
import Amazonka.SecurityHub.Types.AwsRdsDbClusterDetails
import Amazonka.SecurityHub.Types.AwsRdsDbClusterMember
import Amazonka.SecurityHub.Types.AwsRdsDbClusterOptionGroupMembership
import Amazonka.SecurityHub.Types.AwsRdsDbClusterSnapshotDetails
import Amazonka.SecurityHub.Types.AwsRdsDbDomainMembership
import Amazonka.SecurityHub.Types.AwsRdsDbInstanceAssociatedRole
import Amazonka.SecurityHub.Types.AwsRdsDbInstanceDetails
import Amazonka.SecurityHub.Types.AwsRdsDbInstanceEndpoint
import Amazonka.SecurityHub.Types.AwsRdsDbInstanceVpcSecurityGroup
import Amazonka.SecurityHub.Types.AwsRdsDbOptionGroupMembership
import Amazonka.SecurityHub.Types.AwsRdsDbParameterGroup
import Amazonka.SecurityHub.Types.AwsRdsDbPendingModifiedValues
import Amazonka.SecurityHub.Types.AwsRdsDbProcessorFeature
import Amazonka.SecurityHub.Types.AwsRdsDbSnapshotDetails
import Amazonka.SecurityHub.Types.AwsRdsDbStatusInfo
import Amazonka.SecurityHub.Types.AwsRdsDbSubnetGroup
import Amazonka.SecurityHub.Types.AwsRdsDbSubnetGroupSubnet
import Amazonka.SecurityHub.Types.AwsRdsDbSubnetGroupSubnetAvailabilityZone
import Amazonka.SecurityHub.Types.AwsRdsEventSubscriptionDetails
import Amazonka.SecurityHub.Types.AwsRdsPendingCloudWatchLogsExports
import Amazonka.SecurityHub.Types.AwsRedshiftClusterClusterNode
import Amazonka.SecurityHub.Types.AwsRedshiftClusterClusterParameterGroup
import Amazonka.SecurityHub.Types.AwsRedshiftClusterClusterParameterStatus
import Amazonka.SecurityHub.Types.AwsRedshiftClusterClusterSecurityGroup
import Amazonka.SecurityHub.Types.AwsRedshiftClusterClusterSnapshotCopyStatus
import Amazonka.SecurityHub.Types.AwsRedshiftClusterDeferredMaintenanceWindow
import Amazonka.SecurityHub.Types.AwsRedshiftClusterDetails
import Amazonka.SecurityHub.Types.AwsRedshiftClusterElasticIpStatus
import Amazonka.SecurityHub.Types.AwsRedshiftClusterEndpoint
import Amazonka.SecurityHub.Types.AwsRedshiftClusterHsmStatus
import Amazonka.SecurityHub.Types.AwsRedshiftClusterIamRole
import Amazonka.SecurityHub.Types.AwsRedshiftClusterPendingModifiedValues
import Amazonka.SecurityHub.Types.AwsRedshiftClusterResizeInfo
import Amazonka.SecurityHub.Types.AwsRedshiftClusterRestoreStatus
import Amazonka.SecurityHub.Types.AwsRedshiftClusterVpcSecurityGroup
import Amazonka.SecurityHub.Types.AwsS3AccountPublicAccessBlockDetails
import Amazonka.SecurityHub.Types.AwsS3BucketBucketLifecycleConfigurationDetails
import Amazonka.SecurityHub.Types.AwsS3BucketBucketLifecycleConfigurationRulesAbortIncompleteMultipartUploadDetails
import Amazonka.SecurityHub.Types.AwsS3BucketBucketLifecycleConfigurationRulesDetails
import Amazonka.SecurityHub.Types.AwsS3BucketBucketLifecycleConfigurationRulesFilterDetails
import Amazonka.SecurityHub.Types.AwsS3BucketBucketLifecycleConfigurationRulesFilterPredicateDetails
import Amazonka.SecurityHub.Types.AwsS3BucketBucketLifecycleConfigurationRulesFilterPredicateOperandsDetails
import Amazonka.SecurityHub.Types.AwsS3BucketBucketLifecycleConfigurationRulesFilterPredicateOperandsTagDetails
import Amazonka.SecurityHub.Types.AwsS3BucketBucketLifecycleConfigurationRulesFilterPredicateTagDetails
import Amazonka.SecurityHub.Types.AwsS3BucketBucketLifecycleConfigurationRulesNoncurrentVersionTransitionsDetails
import Amazonka.SecurityHub.Types.AwsS3BucketBucketLifecycleConfigurationRulesTransitionsDetails
import Amazonka.SecurityHub.Types.AwsS3BucketDetails
import Amazonka.SecurityHub.Types.AwsS3BucketLoggingConfiguration
import Amazonka.SecurityHub.Types.AwsS3BucketNotificationConfiguration
import Amazonka.SecurityHub.Types.AwsS3BucketNotificationConfigurationDetail
import Amazonka.SecurityHub.Types.AwsS3BucketNotificationConfigurationFilter
import Amazonka.SecurityHub.Types.AwsS3BucketNotificationConfigurationS3KeyFilter
import Amazonka.SecurityHub.Types.AwsS3BucketNotificationConfigurationS3KeyFilterRule
import Amazonka.SecurityHub.Types.AwsS3BucketNotificationConfigurationS3KeyFilterRuleName
import Amazonka.SecurityHub.Types.AwsS3BucketServerSideEncryptionByDefault
import Amazonka.SecurityHub.Types.AwsS3BucketServerSideEncryptionConfiguration
import Amazonka.SecurityHub.Types.AwsS3BucketServerSideEncryptionRule
import Amazonka.SecurityHub.Types.AwsS3BucketWebsiteConfiguration
import Amazonka.SecurityHub.Types.AwsS3BucketWebsiteConfigurationRedirectTo
import Amazonka.SecurityHub.Types.AwsS3BucketWebsiteConfigurationRoutingRule
import Amazonka.SecurityHub.Types.AwsS3BucketWebsiteConfigurationRoutingRuleCondition
import Amazonka.SecurityHub.Types.AwsS3BucketWebsiteConfigurationRoutingRuleRedirect
import Amazonka.SecurityHub.Types.AwsS3ObjectDetails
import Amazonka.SecurityHub.Types.AwsSecretsManagerSecretDetails
import Amazonka.SecurityHub.Types.AwsSecretsManagerSecretRotationRules
import Amazonka.SecurityHub.Types.AwsSecurityFinding
import Amazonka.SecurityHub.Types.AwsSecurityFindingFilters
import Amazonka.SecurityHub.Types.AwsSecurityFindingIdentifier
import Amazonka.SecurityHub.Types.AwsSnsTopicDetails
import Amazonka.SecurityHub.Types.AwsSnsTopicSubscription
import Amazonka.SecurityHub.Types.AwsSqsQueueDetails
import Amazonka.SecurityHub.Types.AwsSsmComplianceSummary
import Amazonka.SecurityHub.Types.AwsSsmPatch
import Amazonka.SecurityHub.Types.AwsSsmPatchComplianceDetails
import Amazonka.SecurityHub.Types.AwsWafRateBasedRuleDetails
import Amazonka.SecurityHub.Types.AwsWafRateBasedRuleMatchPredicate
import Amazonka.SecurityHub.Types.AwsWafRegionalRateBasedRuleDetails
import Amazonka.SecurityHub.Types.AwsWafRegionalRateBasedRuleMatchPredicate
import Amazonka.SecurityHub.Types.AwsWafWebAclDetails
import Amazonka.SecurityHub.Types.AwsWafWebAclRule
import Amazonka.SecurityHub.Types.AwsXrayEncryptionConfigDetails
import Amazonka.SecurityHub.Types.BatchUpdateFindingsUnprocessedFinding
import Amazonka.SecurityHub.Types.Cell
import Amazonka.SecurityHub.Types.CidrBlockAssociation
import Amazonka.SecurityHub.Types.City
import Amazonka.SecurityHub.Types.ClassificationResult
import Amazonka.SecurityHub.Types.ClassificationStatus
import Amazonka.SecurityHub.Types.Compliance
import Amazonka.SecurityHub.Types.ComplianceStatus
import Amazonka.SecurityHub.Types.ContainerDetails
import Amazonka.SecurityHub.Types.ControlStatus
import Amazonka.SecurityHub.Types.Country
import Amazonka.SecurityHub.Types.CustomDataIdentifiersDetections
import Amazonka.SecurityHub.Types.CustomDataIdentifiersResult
import Amazonka.SecurityHub.Types.Cvss
import Amazonka.SecurityHub.Types.DataClassificationDetails
import Amazonka.SecurityHub.Types.DateFilter
import Amazonka.SecurityHub.Types.DateRange
import Amazonka.SecurityHub.Types.DateRangeUnit
import Amazonka.SecurityHub.Types.DnsRequestAction
import Amazonka.SecurityHub.Types.FindingAggregator
import Amazonka.SecurityHub.Types.FindingProviderFields
import Amazonka.SecurityHub.Types.FindingProviderSeverity
import Amazonka.SecurityHub.Types.GeoLocation
import Amazonka.SecurityHub.Types.IcmpTypeCode
import Amazonka.SecurityHub.Types.ImportFindingsError
import Amazonka.SecurityHub.Types.Insight
import Amazonka.SecurityHub.Types.InsightResultValue
import Amazonka.SecurityHub.Types.InsightResults
import Amazonka.SecurityHub.Types.IntegrationType
import Amazonka.SecurityHub.Types.Invitation
import Amazonka.SecurityHub.Types.IpFilter
import Amazonka.SecurityHub.Types.IpOrganizationDetails
import Amazonka.SecurityHub.Types.Ipv6CidrBlockAssociation
import Amazonka.SecurityHub.Types.KeywordFilter
import Amazonka.SecurityHub.Types.LoadBalancerState
import Amazonka.SecurityHub.Types.Malware
import Amazonka.SecurityHub.Types.MalwareState
import Amazonka.SecurityHub.Types.MalwareType
import Amazonka.SecurityHub.Types.MapFilter
import Amazonka.SecurityHub.Types.MapFilterComparison
import Amazonka.SecurityHub.Types.Member
import Amazonka.SecurityHub.Types.Network
import Amazonka.SecurityHub.Types.NetworkConnectionAction
import Amazonka.SecurityHub.Types.NetworkDirection
import Amazonka.SecurityHub.Types.NetworkHeader
import Amazonka.SecurityHub.Types.NetworkPathComponent
import Amazonka.SecurityHub.Types.NetworkPathComponentDetails
import Amazonka.SecurityHub.Types.Note
import Amazonka.SecurityHub.Types.NoteUpdate
import Amazonka.SecurityHub.Types.NumberFilter
import Amazonka.SecurityHub.Types.Occurrences
import Amazonka.SecurityHub.Types.Page
import Amazonka.SecurityHub.Types.Partition
import Amazonka.SecurityHub.Types.PatchSummary
import Amazonka.SecurityHub.Types.PortProbeAction
import Amazonka.SecurityHub.Types.PortProbeDetail
import Amazonka.SecurityHub.Types.PortRange
import Amazonka.SecurityHub.Types.PortRangeFromTo
import Amazonka.SecurityHub.Types.ProcessDetails
import Amazonka.SecurityHub.Types.Product
import Amazonka.SecurityHub.Types.Range
import Amazonka.SecurityHub.Types.Recommendation
import Amazonka.SecurityHub.Types.Record
import Amazonka.SecurityHub.Types.RecordState
import Amazonka.SecurityHub.Types.RelatedFinding
import Amazonka.SecurityHub.Types.Remediation
import Amazonka.SecurityHub.Types.Resource
import Amazonka.SecurityHub.Types.ResourceDetails
import Amazonka.SecurityHub.Types.Result
import Amazonka.SecurityHub.Types.SensitiveDataDetections
import Amazonka.SecurityHub.Types.SensitiveDataResult
import Amazonka.SecurityHub.Types.Severity
import Amazonka.SecurityHub.Types.SeverityLabel
import Amazonka.SecurityHub.Types.SeverityRating
import Amazonka.SecurityHub.Types.SeverityUpdate
import Amazonka.SecurityHub.Types.SoftwarePackage
import Amazonka.SecurityHub.Types.SortCriterion
import Amazonka.SecurityHub.Types.SortOrder
import Amazonka.SecurityHub.Types.Standard
import Amazonka.SecurityHub.Types.StandardsControl
import Amazonka.SecurityHub.Types.StandardsStatus
import Amazonka.SecurityHub.Types.StandardsSubscription
import Amazonka.SecurityHub.Types.StandardsSubscriptionRequest
import Amazonka.SecurityHub.Types.StatusReason
import Amazonka.SecurityHub.Types.StringFilter
import Amazonka.SecurityHub.Types.StringFilterComparison
import Amazonka.SecurityHub.Types.ThreatIntelIndicator
import Amazonka.SecurityHub.Types.ThreatIntelIndicatorCategory
import Amazonka.SecurityHub.Types.ThreatIntelIndicatorType
import Amazonka.SecurityHub.Types.VerificationState
import Amazonka.SecurityHub.Types.Vulnerability
import Amazonka.SecurityHub.Types.VulnerabilityVendor
import Amazonka.SecurityHub.Types.WafAction
import Amazonka.SecurityHub.Types.WafExcludedRule
import Amazonka.SecurityHub.Types.WafOverrideAction
import Amazonka.SecurityHub.Types.Workflow
import Amazonka.SecurityHub.Types.WorkflowState
import Amazonka.SecurityHub.Types.WorkflowStatus
import Amazonka.SecurityHub.Types.WorkflowUpdate
import qualified Amazonka.Sign.V4 as Sign

-- | API version @2018-10-26@ of the Amazon SecurityHub SDK configuration.
defaultService :: Core.Service
defaultService =
  Core.Service
    { Core._serviceAbbrev = "SecurityHub",
      Core._serviceSigner = Sign.v4,
      Core._serviceEndpointPrefix = "securityhub",
      Core._serviceSigningName = "securityhub",
      Core._serviceVersion = "2018-10-26",
      Core._serviceEndpoint =
        Core.defaultEndpoint defaultService,
      Core._serviceTimeout = Prelude.Just 70,
      Core._serviceCheck = Core.statusSuccess,
      Core._serviceError =
        Core.parseJSONError "SecurityHub",
      Core._serviceRetry = retry
    }
  where
    retry =
      Core.Exponential
        { Core._retryBase = 5.0e-2,
          Core._retryGrowth = 2,
          Core._retryAttempts = 5,
          Core._retryCheck = check
        }
    check e
      | Lens.has
          ( Core.hasCode "ThrottledException"
              Prelude.. Core.hasStatus 400
          )
          e =
        Prelude.Just "throttled_exception"
      | Lens.has (Core.hasStatus 429) e =
        Prelude.Just "too_many_requests"
      | Lens.has
          ( Core.hasCode "ThrottlingException"
              Prelude.. Core.hasStatus 400
          )
          e =
        Prelude.Just "throttling_exception"
      | Lens.has
          ( Core.hasCode "Throttling"
              Prelude.. Core.hasStatus 400
          )
          e =
        Prelude.Just "throttling"
      | Lens.has
          ( Core.hasCode
              "ProvisionedThroughputExceededException"
              Prelude.. Core.hasStatus 400
          )
          e =
        Prelude.Just "throughput_exceeded"
      | Lens.has (Core.hasStatus 504) e =
        Prelude.Just "gateway_timeout"
      | Lens.has
          ( Core.hasCode "RequestThrottledException"
              Prelude.. Core.hasStatus 400
          )
          e =
        Prelude.Just "request_throttled_exception"
      | Lens.has (Core.hasStatus 502) e =
        Prelude.Just "bad_gateway"
      | Lens.has (Core.hasStatus 503) e =
        Prelude.Just "service_unavailable"
      | Lens.has (Core.hasStatus 500) e =
        Prelude.Just "general_server_error"
      | Lens.has (Core.hasStatus 509) e =
        Prelude.Just "limit_exceeded"
      | Prelude.otherwise = Prelude.Nothing

-- | You don\'t have permission to perform the action specified in the
-- request.
_AccessDeniedException :: Core.AsError a => Lens.Getting (Prelude.First Core.ServiceError) a Core.ServiceError
_AccessDeniedException =
  Core._MatchServiceError
    defaultService
    "AccessDeniedException"
    Prelude.. Core.hasStatus 403

-- | There is an issue with the account used to make the request. Either
-- Security Hub is not enabled for the account, or the account does not
-- have permission to perform this action.
_InvalidAccessException :: Core.AsError a => Lens.Getting (Prelude.First Core.ServiceError) a Core.ServiceError
_InvalidAccessException =
  Core._MatchServiceError
    defaultService
    "InvalidAccessException"
    Prelude.. Core.hasStatus 401

-- | The request was rejected because you supplied an invalid or out-of-range
-- value for an input parameter.
_InvalidInputException :: Core.AsError a => Lens.Getting (Prelude.First Core.ServiceError) a Core.ServiceError
_InvalidInputException =
  Core._MatchServiceError
    defaultService
    "InvalidInputException"
    Prelude.. Core.hasStatus 400

-- | Internal server error.
_InternalException :: Core.AsError a => Lens.Getting (Prelude.First Core.ServiceError) a Core.ServiceError
_InternalException =
  Core._MatchServiceError
    defaultService
    "InternalException"
    Prelude.. Core.hasStatus 500

-- | The resource specified in the request conflicts with an existing
-- resource.
_ResourceConflictException :: Core.AsError a => Lens.Getting (Prelude.First Core.ServiceError) a Core.ServiceError
_ResourceConflictException =
  Core._MatchServiceError
    defaultService
    "ResourceConflictException"
    Prelude.. Core.hasStatus 409

-- | The request was rejected because we can\'t find the specified resource.
_ResourceNotFoundException :: Core.AsError a => Lens.Getting (Prelude.First Core.ServiceError) a Core.ServiceError
_ResourceNotFoundException =
  Core._MatchServiceError
    defaultService
    "ResourceNotFoundException"
    Prelude.. Core.hasStatus 404

-- | The request was rejected because it attempted to create resources beyond
-- the current Amazon Web Services account or throttling limits. The error
-- code describes the limit exceeded.
_LimitExceededException :: Core.AsError a => Lens.Getting (Prelude.First Core.ServiceError) a Core.ServiceError
_LimitExceededException =
  Core._MatchServiceError
    defaultService
    "LimitExceededException"
    Prelude.. Core.hasStatus 429
