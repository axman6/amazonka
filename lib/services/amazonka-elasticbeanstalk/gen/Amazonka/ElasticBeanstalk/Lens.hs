{-# LANGUAGE NoImplicitPrelude #-}
{-# OPTIONS_GHC -fno-warn-duplicate-exports #-}
{-# OPTIONS_GHC -fno-warn-unused-imports #-}

-- Derived from AWS service descriptions, licensed under Apache 2.0.

-- |
-- Module      : Amazonka.ElasticBeanstalk.Lens
-- Copyright   : (c) 2013-2021 Brendan Hay
-- License     : Mozilla Public License, v. 2.0.
-- Maintainer  : Brendan Hay <brendan.g.hay+amazonka@gmail.com>
-- Stability   : auto-generated
-- Portability : non-portable (GHC extensions)
module Amazonka.ElasticBeanstalk.Lens
  ( -- * Operations

    -- ** DescribeApplications
    describeApplications_applicationNames,
    describeApplicationsResponse_applications,
    describeApplicationsResponse_httpStatus,

    -- ** UpdateEnvironment
    updateEnvironment_templateName,
    updateEnvironment_optionsToRemove,
    updateEnvironment_optionSettings,
    updateEnvironment_versionLabel,
    updateEnvironment_platformArn,
    updateEnvironment_tier,
    updateEnvironment_environmentName,
    updateEnvironment_applicationName,
    updateEnvironment_solutionStackName,
    updateEnvironment_environmentId,
    updateEnvironment_groupName,
    updateEnvironment_description,
    environmentDescription_status,
    environmentDescription_cname,
    environmentDescription_templateName,
    environmentDescription_abortableOperationInProgress,
    environmentDescription_endpointURL,
    environmentDescription_resources,
    environmentDescription_dateUpdated,
    environmentDescription_dateCreated,
    environmentDescription_health,
    environmentDescription_versionLabel,
    environmentDescription_operationsRole,
    environmentDescription_platformArn,
    environmentDescription_tier,
    environmentDescription_environmentName,
    environmentDescription_applicationName,
    environmentDescription_environmentArn,
    environmentDescription_solutionStackName,
    environmentDescription_environmentId,
    environmentDescription_healthStatus,
    environmentDescription_environmentLinks,
    environmentDescription_description,

    -- ** TerminateEnvironment
    terminateEnvironment_forceTerminate,
    terminateEnvironment_terminateResources,
    terminateEnvironment_environmentName,
    terminateEnvironment_environmentId,
    environmentDescription_status,
    environmentDescription_cname,
    environmentDescription_templateName,
    environmentDescription_abortableOperationInProgress,
    environmentDescription_endpointURL,
    environmentDescription_resources,
    environmentDescription_dateUpdated,
    environmentDescription_dateCreated,
    environmentDescription_health,
    environmentDescription_versionLabel,
    environmentDescription_operationsRole,
    environmentDescription_platformArn,
    environmentDescription_tier,
    environmentDescription_environmentName,
    environmentDescription_applicationName,
    environmentDescription_environmentArn,
    environmentDescription_solutionStackName,
    environmentDescription_environmentId,
    environmentDescription_healthStatus,
    environmentDescription_environmentLinks,
    environmentDescription_description,

    -- ** ListPlatformVersions
    listPlatformVersions_filters,
    listPlatformVersions_nextToken,
    listPlatformVersions_maxRecords,
    listPlatformVersionsResponse_nextToken,
    listPlatformVersionsResponse_platformSummaryList,
    listPlatformVersionsResponse_httpStatus,

    -- ** DeletePlatformVersion
    deletePlatformVersion_platformArn,
    deletePlatformVersionResponse_platformSummary,
    deletePlatformVersionResponse_httpStatus,

    -- ** CreateApplicationVersion
    createApplicationVersion_process,
    createApplicationVersion_sourceBundle,
    createApplicationVersion_autoCreateApplication,
    createApplicationVersion_sourceBuildInformation,
    createApplicationVersion_description,
    createApplicationVersion_buildConfiguration,
    createApplicationVersion_tags,
    createApplicationVersion_applicationName,
    createApplicationVersion_versionLabel,
    applicationVersionDescriptionMessage_applicationVersion,

    -- ** ListPlatformBranches
    listPlatformBranches_filters,
    listPlatformBranches_nextToken,
    listPlatformBranches_maxRecords,
    listPlatformBranchesResponse_platformBranchSummaryList,
    listPlatformBranchesResponse_nextToken,
    listPlatformBranchesResponse_httpStatus,

    -- ** DescribeEvents
    describeEvents_requestId,
    describeEvents_templateName,
    describeEvents_startTime,
    describeEvents_severity,
    describeEvents_nextToken,
    describeEvents_versionLabel,
    describeEvents_platformArn,
    describeEvents_environmentName,
    describeEvents_maxRecords,
    describeEvents_endTime,
    describeEvents_applicationName,
    describeEvents_environmentId,
    describeEventsResponse_nextToken,
    describeEventsResponse_events,
    describeEventsResponse_httpStatus,

    -- ** RequestEnvironmentInfo
    requestEnvironmentInfo_environmentName,
    requestEnvironmentInfo_environmentId,
    requestEnvironmentInfo_infoType,

    -- ** ListTagsForResource
    listTagsForResource_resourceArn,
    listTagsForResourceResponse_resourceTags,
    listTagsForResourceResponse_resourceArn,
    listTagsForResourceResponse_httpStatus,

    -- ** RetrieveEnvironmentInfo
    retrieveEnvironmentInfo_environmentName,
    retrieveEnvironmentInfo_environmentId,
    retrieveEnvironmentInfo_infoType,
    retrieveEnvironmentInfoResponse_environmentInfo,
    retrieveEnvironmentInfoResponse_httpStatus,

    -- ** DescribePlatformVersion
    describePlatformVersion_platformArn,
    describePlatformVersionResponse_platformDescription,
    describePlatformVersionResponse_httpStatus,

    -- ** DeleteApplication
    deleteApplication_terminateEnvByForce,
    deleteApplication_applicationName,

    -- ** UpdateApplication
    updateApplication_description,
    updateApplication_applicationName,
    applicationDescriptionMessage_application,

    -- ** DescribeInstancesHealth
    describeInstancesHealth_nextToken,
    describeInstancesHealth_environmentName,
    describeInstancesHealth_attributeNames,
    describeInstancesHealth_environmentId,
    describeInstancesHealthResponse_instanceHealthList,
    describeInstancesHealthResponse_nextToken,
    describeInstancesHealthResponse_refreshedAt,
    describeInstancesHealthResponse_httpStatus,

    -- ** CreateApplication
    createApplication_resourceLifecycleConfig,
    createApplication_description,
    createApplication_tags,
    createApplication_applicationName,
    applicationDescriptionMessage_application,

    -- ** ComposeEnvironments
    composeEnvironments_versionLabels,
    composeEnvironments_applicationName,
    composeEnvironments_groupName,
    environmentDescriptionsMessage_nextToken,
    environmentDescriptionsMessage_environments,

    -- ** AbortEnvironmentUpdate
    abortEnvironmentUpdate_environmentName,
    abortEnvironmentUpdate_environmentId,

    -- ** DeleteConfigurationTemplate
    deleteConfigurationTemplate_applicationName,
    deleteConfigurationTemplate_templateName,

    -- ** UpdateConfigurationTemplate
    updateConfigurationTemplate_optionsToRemove,
    updateConfigurationTemplate_optionSettings,
    updateConfigurationTemplate_description,
    updateConfigurationTemplate_applicationName,
    updateConfigurationTemplate_templateName,
    configurationSettingsDescription_templateName,
    configurationSettingsDescription_optionSettings,
    configurationSettingsDescription_dateUpdated,
    configurationSettingsDescription_dateCreated,
    configurationSettingsDescription_platformArn,
    configurationSettingsDescription_environmentName,
    configurationSettingsDescription_applicationName,
    configurationSettingsDescription_deploymentStatus,
    configurationSettingsDescription_solutionStackName,
    configurationSettingsDescription_description,

    -- ** UpdateTagsForResource
    updateTagsForResource_tagsToRemove,
    updateTagsForResource_tagsToAdd,
    updateTagsForResource_resourceArn,

    -- ** DescribeEnvironmentResources
    describeEnvironmentResources_environmentName,
    describeEnvironmentResources_environmentId,
    describeEnvironmentResourcesResponse_environmentResources,
    describeEnvironmentResourcesResponse_httpStatus,

    -- ** DescribeEnvironmentManagedActionHistory
    describeEnvironmentManagedActionHistory_nextToken,
    describeEnvironmentManagedActionHistory_environmentName,
    describeEnvironmentManagedActionHistory_maxItems,
    describeEnvironmentManagedActionHistory_environmentId,
    describeEnvironmentManagedActionHistoryResponse_managedActionHistoryItems,
    describeEnvironmentManagedActionHistoryResponse_nextToken,
    describeEnvironmentManagedActionHistoryResponse_httpStatus,

    -- ** DeleteApplicationVersion
    deleteApplicationVersion_deleteSourceBundle,
    deleteApplicationVersion_applicationName,
    deleteApplicationVersion_versionLabel,

    -- ** UpdateApplicationVersion
    updateApplicationVersion_description,
    updateApplicationVersion_applicationName,
    updateApplicationVersion_versionLabel,
    applicationVersionDescriptionMessage_applicationVersion,

    -- ** CreateConfigurationTemplate
    createConfigurationTemplate_optionSettings,
    createConfigurationTemplate_platformArn,
    createConfigurationTemplate_sourceConfiguration,
    createConfigurationTemplate_solutionStackName,
    createConfigurationTemplate_environmentId,
    createConfigurationTemplate_description,
    createConfigurationTemplate_tags,
    createConfigurationTemplate_applicationName,
    createConfigurationTemplate_templateName,
    configurationSettingsDescription_templateName,
    configurationSettingsDescription_optionSettings,
    configurationSettingsDescription_dateUpdated,
    configurationSettingsDescription_dateCreated,
    configurationSettingsDescription_platformArn,
    configurationSettingsDescription_environmentName,
    configurationSettingsDescription_applicationName,
    configurationSettingsDescription_deploymentStatus,
    configurationSettingsDescription_solutionStackName,
    configurationSettingsDescription_description,

    -- ** DescribeEnvironmentHealth
    describeEnvironmentHealth_environmentName,
    describeEnvironmentHealth_attributeNames,
    describeEnvironmentHealth_environmentId,
    describeEnvironmentHealthResponse_status,
    describeEnvironmentHealthResponse_causes,
    describeEnvironmentHealthResponse_applicationMetrics,
    describeEnvironmentHealthResponse_color,
    describeEnvironmentHealthResponse_environmentName,
    describeEnvironmentHealthResponse_healthStatus,
    describeEnvironmentHealthResponse_instancesHealth,
    describeEnvironmentHealthResponse_refreshedAt,
    describeEnvironmentHealthResponse_httpStatus,

    -- ** RebuildEnvironment
    rebuildEnvironment_environmentName,
    rebuildEnvironment_environmentId,

    -- ** DeleteEnvironmentConfiguration
    deleteEnvironmentConfiguration_applicationName,
    deleteEnvironmentConfiguration_environmentName,

    -- ** UpdateApplicationResourceLifecycle
    updateApplicationResourceLifecycle_applicationName,
    updateApplicationResourceLifecycle_resourceLifecycleConfig,
    updateApplicationResourceLifecycleResponse_applicationName,
    updateApplicationResourceLifecycleResponse_resourceLifecycleConfig,
    updateApplicationResourceLifecycleResponse_httpStatus,

    -- ** SwapEnvironmentCNAMEs
    swapEnvironmentCNAMEs_destinationEnvironmentName,
    swapEnvironmentCNAMEs_destinationEnvironmentId,
    swapEnvironmentCNAMEs_sourceEnvironmentName,
    swapEnvironmentCNAMEs_sourceEnvironmentId,

    -- ** ListAvailableSolutionStacks
    listAvailableSolutionStacksResponse_solutionStacks,
    listAvailableSolutionStacksResponse_solutionStackDetails,
    listAvailableSolutionStacksResponse_httpStatus,

    -- ** ApplyEnvironmentManagedAction
    applyEnvironmentManagedAction_environmentName,
    applyEnvironmentManagedAction_environmentId,
    applyEnvironmentManagedAction_actionId,
    applyEnvironmentManagedActionResponse_status,
    applyEnvironmentManagedActionResponse_actionId,
    applyEnvironmentManagedActionResponse_actionDescription,
    applyEnvironmentManagedActionResponse_actionType,
    applyEnvironmentManagedActionResponse_httpStatus,

    -- ** DescribeConfigurationOptions
    describeConfigurationOptions_templateName,
    describeConfigurationOptions_platformArn,
    describeConfigurationOptions_environmentName,
    describeConfigurationOptions_applicationName,
    describeConfigurationOptions_solutionStackName,
    describeConfigurationOptions_options,
    describeConfigurationOptionsResponse_platformArn,
    describeConfigurationOptionsResponse_solutionStackName,
    describeConfigurationOptionsResponse_options,
    describeConfigurationOptionsResponse_httpStatus,

    -- ** DisassociateEnvironmentOperationsRole
    disassociateEnvironmentOperationsRole_environmentName,

    -- ** CreateStorageLocation
    createStorageLocationResponse_s3Bucket,
    createStorageLocationResponse_httpStatus,

    -- ** DescribeEnvironmentManagedActions
    describeEnvironmentManagedActions_status,
    describeEnvironmentManagedActions_environmentName,
    describeEnvironmentManagedActions_environmentId,
    describeEnvironmentManagedActionsResponse_managedActions,
    describeEnvironmentManagedActionsResponse_httpStatus,

    -- ** DescribeConfigurationSettings
    describeConfigurationSettings_templateName,
    describeConfigurationSettings_environmentName,
    describeConfigurationSettings_applicationName,
    describeConfigurationSettingsResponse_configurationSettings,
    describeConfigurationSettingsResponse_httpStatus,

    -- ** ValidateConfigurationSettings
    validateConfigurationSettings_templateName,
    validateConfigurationSettings_environmentName,
    validateConfigurationSettings_applicationName,
    validateConfigurationSettings_optionSettings,
    validateConfigurationSettingsResponse_messages,
    validateConfigurationSettingsResponse_httpStatus,

    -- ** DescribeAccountAttributes
    describeAccountAttributesResponse_resourceQuotas,
    describeAccountAttributesResponse_httpStatus,

    -- ** AssociateEnvironmentOperationsRole
    associateEnvironmentOperationsRole_environmentName,
    associateEnvironmentOperationsRole_operationsRole,

    -- ** RestartAppServer
    restartAppServer_environmentName,
    restartAppServer_environmentId,

    -- ** DescribeEnvironments
    describeEnvironments_environmentIds,
    describeEnvironments_environmentNames,
    describeEnvironments_nextToken,
    describeEnvironments_versionLabel,
    describeEnvironments_maxRecords,
    describeEnvironments_applicationName,
    describeEnvironments_includedDeletedBackTo,
    describeEnvironments_includeDeleted,
    environmentDescriptionsMessage_nextToken,
    environmentDescriptionsMessage_environments,

    -- ** CheckDNSAvailability
    checkDNSAvailability_cNAMEPrefix,
    checkDNSAvailabilityResponse_fullyQualifiedCNAME,
    checkDNSAvailabilityResponse_available,
    checkDNSAvailabilityResponse_httpStatus,

    -- ** DescribeApplicationVersions
    describeApplicationVersions_versionLabels,
    describeApplicationVersions_nextToken,
    describeApplicationVersions_maxRecords,
    describeApplicationVersions_applicationName,
    describeApplicationVersionsResponse_applicationVersions,
    describeApplicationVersionsResponse_nextToken,
    describeApplicationVersionsResponse_httpStatus,

    -- ** CreateEnvironment
    createEnvironment_cNAMEPrefix,
    createEnvironment_templateName,
    createEnvironment_optionsToRemove,
    createEnvironment_optionSettings,
    createEnvironment_versionLabel,
    createEnvironment_operationsRole,
    createEnvironment_platformArn,
    createEnvironment_tier,
    createEnvironment_environmentName,
    createEnvironment_solutionStackName,
    createEnvironment_groupName,
    createEnvironment_description,
    createEnvironment_tags,
    createEnvironment_applicationName,
    environmentDescription_status,
    environmentDescription_cname,
    environmentDescription_templateName,
    environmentDescription_abortableOperationInProgress,
    environmentDescription_endpointURL,
    environmentDescription_resources,
    environmentDescription_dateUpdated,
    environmentDescription_dateCreated,
    environmentDescription_health,
    environmentDescription_versionLabel,
    environmentDescription_operationsRole,
    environmentDescription_platformArn,
    environmentDescription_tier,
    environmentDescription_environmentName,
    environmentDescription_applicationName,
    environmentDescription_environmentArn,
    environmentDescription_solutionStackName,
    environmentDescription_environmentId,
    environmentDescription_healthStatus,
    environmentDescription_environmentLinks,
    environmentDescription_description,

    -- ** CreatePlatformVersion
    createPlatformVersion_optionSettings,
    createPlatformVersion_environmentName,
    createPlatformVersion_tags,
    createPlatformVersion_platformName,
    createPlatformVersion_platformVersion,
    createPlatformVersion_platformDefinitionBundle,
    createPlatformVersionResponse_builder,
    createPlatformVersionResponse_platformSummary,
    createPlatformVersionResponse_httpStatus,

    -- * Types

    -- ** ApplicationDescription
    applicationDescription_applicationArn,
    applicationDescription_versions,
    applicationDescription_dateUpdated,
    applicationDescription_dateCreated,
    applicationDescription_applicationName,
    applicationDescription_configurationTemplates,
    applicationDescription_resourceLifecycleConfig,
    applicationDescription_description,

    -- ** ApplicationDescriptionMessage
    applicationDescriptionMessage_application,

    -- ** ApplicationMetrics
    applicationMetrics_requestCount,
    applicationMetrics_latency,
    applicationMetrics_statusCodes,
    applicationMetrics_duration,

    -- ** ApplicationResourceLifecycleConfig
    applicationResourceLifecycleConfig_versionLifecycleConfig,
    applicationResourceLifecycleConfig_serviceRole,

    -- ** ApplicationVersionDescription
    applicationVersionDescription_status,
    applicationVersionDescription_sourceBundle,
    applicationVersionDescription_dateUpdated,
    applicationVersionDescription_dateCreated,
    applicationVersionDescription_versionLabel,
    applicationVersionDescription_sourceBuildInformation,
    applicationVersionDescription_applicationName,
    applicationVersionDescription_applicationVersionArn,
    applicationVersionDescription_buildArn,
    applicationVersionDescription_description,

    -- ** ApplicationVersionDescriptionMessage
    applicationVersionDescriptionMessage_applicationVersion,

    -- ** ApplicationVersionLifecycleConfig
    applicationVersionLifecycleConfig_maxAgeRule,
    applicationVersionLifecycleConfig_maxCountRule,

    -- ** AutoScalingGroup
    autoScalingGroup_name,

    -- ** BuildConfiguration
    buildConfiguration_artifactName,
    buildConfiguration_computeType,
    buildConfiguration_timeoutInMinutes,
    buildConfiguration_codeBuildServiceRole,
    buildConfiguration_image,

    -- ** Builder
    builder_arn,

    -- ** CPUUtilization
    cPUUtilization_softIRQ,
    cPUUtilization_idle,
    cPUUtilization_irq,
    cPUUtilization_system,
    cPUUtilization_privileged,
    cPUUtilization_user,
    cPUUtilization_iOWait,
    cPUUtilization_nice,

    -- ** ConfigurationOptionDescription
    configurationOptionDescription_maxValue,
    configurationOptionDescription_regex,
    configurationOptionDescription_maxLength,
    configurationOptionDescription_userDefined,
    configurationOptionDescription_namespace,
    configurationOptionDescription_valueOptions,
    configurationOptionDescription_name,
    configurationOptionDescription_changeSeverity,
    configurationOptionDescription_defaultValue,
    configurationOptionDescription_valueType,
    configurationOptionDescription_minValue,

    -- ** ConfigurationOptionSetting
    configurationOptionSetting_optionName,
    configurationOptionSetting_resourceName,
    configurationOptionSetting_namespace,
    configurationOptionSetting_value,

    -- ** ConfigurationSettingsDescription
    configurationSettingsDescription_templateName,
    configurationSettingsDescription_optionSettings,
    configurationSettingsDescription_dateUpdated,
    configurationSettingsDescription_dateCreated,
    configurationSettingsDescription_platformArn,
    configurationSettingsDescription_environmentName,
    configurationSettingsDescription_applicationName,
    configurationSettingsDescription_deploymentStatus,
    configurationSettingsDescription_solutionStackName,
    configurationSettingsDescription_description,

    -- ** CustomAmi
    customAmi_virtualizationType,
    customAmi_imageId,

    -- ** Deployment
    deployment_deploymentId,
    deployment_status,
    deployment_deploymentTime,
    deployment_versionLabel,

    -- ** EnvironmentDescription
    environmentDescription_status,
    environmentDescription_cname,
    environmentDescription_templateName,
    environmentDescription_abortableOperationInProgress,
    environmentDescription_endpointURL,
    environmentDescription_resources,
    environmentDescription_dateUpdated,
    environmentDescription_dateCreated,
    environmentDescription_health,
    environmentDescription_versionLabel,
    environmentDescription_operationsRole,
    environmentDescription_platformArn,
    environmentDescription_tier,
    environmentDescription_environmentName,
    environmentDescription_applicationName,
    environmentDescription_environmentArn,
    environmentDescription_solutionStackName,
    environmentDescription_environmentId,
    environmentDescription_healthStatus,
    environmentDescription_environmentLinks,
    environmentDescription_description,

    -- ** EnvironmentDescriptionsMessage
    environmentDescriptionsMessage_nextToken,
    environmentDescriptionsMessage_environments,

    -- ** EnvironmentInfoDescription
    environmentInfoDescription_sampleTimestamp,
    environmentInfoDescription_ec2InstanceId,
    environmentInfoDescription_infoType,
    environmentInfoDescription_message,

    -- ** EnvironmentLink
    environmentLink_linkName,
    environmentLink_environmentName,

    -- ** EnvironmentResourceDescription
    environmentResourceDescription_queues,
    environmentResourceDescription_triggers,
    environmentResourceDescription_launchTemplates,
    environmentResourceDescription_loadBalancers,
    environmentResourceDescription_environmentName,
    environmentResourceDescription_instances,
    environmentResourceDescription_launchConfigurations,
    environmentResourceDescription_autoScalingGroups,

    -- ** EnvironmentResourcesDescription
    environmentResourcesDescription_loadBalancer,

    -- ** EnvironmentTier
    environmentTier_name,
    environmentTier_version,
    environmentTier_type,

    -- ** EventDescription
    eventDescription_requestId,
    eventDescription_templateName,
    eventDescription_severity,
    eventDescription_versionLabel,
    eventDescription_platformArn,
    eventDescription_environmentName,
    eventDescription_applicationName,
    eventDescription_eventDate,
    eventDescription_message,

    -- ** Instance
    instance_id,

    -- ** InstanceHealthSummary
    instanceHealthSummary_ok,
    instanceHealthSummary_pending,
    instanceHealthSummary_severe,
    instanceHealthSummary_unknown,
    instanceHealthSummary_noData,
    instanceHealthSummary_warning,
    instanceHealthSummary_degraded,
    instanceHealthSummary_info,

    -- ** Latency
    latency_p75,
    latency_p50,
    latency_p85,
    latency_p999,
    latency_p90,
    latency_p95,
    latency_p99,
    latency_p10,

    -- ** LaunchConfiguration
    launchConfiguration_name,

    -- ** LaunchTemplate
    launchTemplate_id,

    -- ** Listener
    listener_protocol,
    listener_port,

    -- ** LoadBalancer
    loadBalancer_name,

    -- ** LoadBalancerDescription
    loadBalancerDescription_loadBalancerName,
    loadBalancerDescription_domain,
    loadBalancerDescription_listeners,

    -- ** ManagedAction
    managedAction_status,
    managedAction_actionId,
    managedAction_windowStartTime,
    managedAction_actionDescription,
    managedAction_actionType,

    -- ** ManagedActionHistoryItem
    managedActionHistoryItem_status,
    managedActionHistoryItem_failureType,
    managedActionHistoryItem_actionId,
    managedActionHistoryItem_failureDescription,
    managedActionHistoryItem_finishedTime,
    managedActionHistoryItem_actionDescription,
    managedActionHistoryItem_executedTime,
    managedActionHistoryItem_actionType,

    -- ** MaxAgeRule
    maxAgeRule_deleteSourceFromS3,
    maxAgeRule_maxAgeInDays,
    maxAgeRule_enabled,

    -- ** MaxCountRule
    maxCountRule_maxCount,
    maxCountRule_deleteSourceFromS3,
    maxCountRule_enabled,

    -- ** OptionRestrictionRegex
    optionRestrictionRegex_pattern,
    optionRestrictionRegex_label,

    -- ** OptionSpecification
    optionSpecification_optionName,
    optionSpecification_resourceName,
    optionSpecification_namespace,

    -- ** PlatformBranchSummary
    platformBranchSummary_branchName,
    platformBranchSummary_branchOrder,
    platformBranchSummary_platformName,
    platformBranchSummary_supportedTierList,
    platformBranchSummary_lifecycleState,

    -- ** PlatformDescription
    platformDescription_platformBranchName,
    platformDescription_supportedAddonList,
    platformDescription_platformCategory,
    platformDescription_platformBranchLifecycleState,
    platformDescription_platformVersion,
    platformDescription_platformStatus,
    platformDescription_maintainer,
    platformDescription_platformLifecycleState,
    platformDescription_platformOwner,
    platformDescription_dateUpdated,
    platformDescription_customAmiList,
    platformDescription_dateCreated,
    platformDescription_operatingSystemName,
    platformDescription_frameworks,
    platformDescription_platformArn,
    platformDescription_operatingSystemVersion,
    platformDescription_programmingLanguages,
    platformDescription_solutionStackName,
    platformDescription_platformName,
    platformDescription_description,
    platformDescription_supportedTierList,

    -- ** PlatformFilter
    platformFilter_values,
    platformFilter_operator,
    platformFilter_type,

    -- ** PlatformFramework
    platformFramework_name,
    platformFramework_version,

    -- ** PlatformProgrammingLanguage
    platformProgrammingLanguage_name,
    platformProgrammingLanguage_version,

    -- ** PlatformSummary
    platformSummary_platformBranchName,
    platformSummary_supportedAddonList,
    platformSummary_platformCategory,
    platformSummary_platformBranchLifecycleState,
    platformSummary_platformVersion,
    platformSummary_platformStatus,
    platformSummary_platformLifecycleState,
    platformSummary_platformOwner,
    platformSummary_operatingSystemName,
    platformSummary_platformArn,
    platformSummary_operatingSystemVersion,
    platformSummary_supportedTierList,

    -- ** Queue
    queue_url,
    queue_name,

    -- ** ResourceQuota
    resourceQuota_maximum,

    -- ** ResourceQuotas
    resourceQuotas_applicationQuota,
    resourceQuotas_customPlatformQuota,
    resourceQuotas_applicationVersionQuota,
    resourceQuotas_environmentQuota,
    resourceQuotas_configurationTemplateQuota,

    -- ** S3Location
    s3Location_s3Key,
    s3Location_s3Bucket,

    -- ** SearchFilter
    searchFilter_attribute,
    searchFilter_values,
    searchFilter_operator,

    -- ** SingleInstanceHealth
    singleInstanceHealth_instanceId,
    singleInstanceHealth_causes,
    singleInstanceHealth_system,
    singleInstanceHealth_applicationMetrics,
    singleInstanceHealth_color,
    singleInstanceHealth_instanceType,
    singleInstanceHealth_availabilityZone,
    singleInstanceHealth_healthStatus,
    singleInstanceHealth_deployment,
    singleInstanceHealth_launchedAt,

    -- ** SolutionStackDescription
    solutionStackDescription_permittedFileTypes,
    solutionStackDescription_solutionStackName,

    -- ** SourceBuildInformation
    sourceBuildInformation_sourceType,
    sourceBuildInformation_sourceRepository,
    sourceBuildInformation_sourceLocation,

    -- ** SourceConfiguration
    sourceConfiguration_templateName,
    sourceConfiguration_applicationName,

    -- ** StatusCodes
    statusCodes_status2xx,
    statusCodes_status3xx,
    statusCodes_status4xx,
    statusCodes_status5xx,

    -- ** SystemStatus
    systemStatus_cPUUtilization,
    systemStatus_loadAverage,

    -- ** Tag
    tag_value,
    tag_key,

    -- ** Trigger
    trigger_name,

    -- ** ValidationMessage
    validationMessage_optionName,
    validationMessage_severity,
    validationMessage_namespace,
    validationMessage_message,
  )
where

import Amazonka.ElasticBeanstalk.AbortEnvironmentUpdate
import Amazonka.ElasticBeanstalk.ApplyEnvironmentManagedAction
import Amazonka.ElasticBeanstalk.AssociateEnvironmentOperationsRole
import Amazonka.ElasticBeanstalk.CheckDNSAvailability
import Amazonka.ElasticBeanstalk.ComposeEnvironments
import Amazonka.ElasticBeanstalk.CreateApplication
import Amazonka.ElasticBeanstalk.CreateApplicationVersion
import Amazonka.ElasticBeanstalk.CreateConfigurationTemplate
import Amazonka.ElasticBeanstalk.CreateEnvironment
import Amazonka.ElasticBeanstalk.CreatePlatformVersion
import Amazonka.ElasticBeanstalk.CreateStorageLocation
import Amazonka.ElasticBeanstalk.DeleteApplication
import Amazonka.ElasticBeanstalk.DeleteApplicationVersion
import Amazonka.ElasticBeanstalk.DeleteConfigurationTemplate
import Amazonka.ElasticBeanstalk.DeleteEnvironmentConfiguration
import Amazonka.ElasticBeanstalk.DeletePlatformVersion
import Amazonka.ElasticBeanstalk.DescribeAccountAttributes
import Amazonka.ElasticBeanstalk.DescribeApplicationVersions
import Amazonka.ElasticBeanstalk.DescribeApplications
import Amazonka.ElasticBeanstalk.DescribeConfigurationOptions
import Amazonka.ElasticBeanstalk.DescribeConfigurationSettings
import Amazonka.ElasticBeanstalk.DescribeEnvironmentHealth
import Amazonka.ElasticBeanstalk.DescribeEnvironmentManagedActionHistory
import Amazonka.ElasticBeanstalk.DescribeEnvironmentManagedActions
import Amazonka.ElasticBeanstalk.DescribeEnvironmentResources
import Amazonka.ElasticBeanstalk.DescribeEnvironments
import Amazonka.ElasticBeanstalk.DescribeEvents
import Amazonka.ElasticBeanstalk.DescribeInstancesHealth
import Amazonka.ElasticBeanstalk.DescribePlatformVersion
import Amazonka.ElasticBeanstalk.DisassociateEnvironmentOperationsRole
import Amazonka.ElasticBeanstalk.ListAvailableSolutionStacks
import Amazonka.ElasticBeanstalk.ListPlatformBranches
import Amazonka.ElasticBeanstalk.ListPlatformVersions
import Amazonka.ElasticBeanstalk.ListTagsForResource
import Amazonka.ElasticBeanstalk.RebuildEnvironment
import Amazonka.ElasticBeanstalk.RequestEnvironmentInfo
import Amazonka.ElasticBeanstalk.RestartAppServer
import Amazonka.ElasticBeanstalk.RetrieveEnvironmentInfo
import Amazonka.ElasticBeanstalk.SwapEnvironmentCNAMEs
import Amazonka.ElasticBeanstalk.TerminateEnvironment
import Amazonka.ElasticBeanstalk.Types.ApplicationDescription
import Amazonka.ElasticBeanstalk.Types.ApplicationDescriptionMessage
import Amazonka.ElasticBeanstalk.Types.ApplicationMetrics
import Amazonka.ElasticBeanstalk.Types.ApplicationResourceLifecycleConfig
import Amazonka.ElasticBeanstalk.Types.ApplicationVersionDescription
import Amazonka.ElasticBeanstalk.Types.ApplicationVersionDescriptionMessage
import Amazonka.ElasticBeanstalk.Types.ApplicationVersionLifecycleConfig
import Amazonka.ElasticBeanstalk.Types.AutoScalingGroup
import Amazonka.ElasticBeanstalk.Types.BuildConfiguration
import Amazonka.ElasticBeanstalk.Types.Builder
import Amazonka.ElasticBeanstalk.Types.CPUUtilization
import Amazonka.ElasticBeanstalk.Types.ConfigurationOptionDescription
import Amazonka.ElasticBeanstalk.Types.ConfigurationOptionSetting
import Amazonka.ElasticBeanstalk.Types.ConfigurationSettingsDescription
import Amazonka.ElasticBeanstalk.Types.CustomAmi
import Amazonka.ElasticBeanstalk.Types.Deployment
import Amazonka.ElasticBeanstalk.Types.EnvironmentDescription
import Amazonka.ElasticBeanstalk.Types.EnvironmentDescriptionsMessage
import Amazonka.ElasticBeanstalk.Types.EnvironmentInfoDescription
import Amazonka.ElasticBeanstalk.Types.EnvironmentLink
import Amazonka.ElasticBeanstalk.Types.EnvironmentResourceDescription
import Amazonka.ElasticBeanstalk.Types.EnvironmentResourcesDescription
import Amazonka.ElasticBeanstalk.Types.EnvironmentTier
import Amazonka.ElasticBeanstalk.Types.EventDescription
import Amazonka.ElasticBeanstalk.Types.Instance
import Amazonka.ElasticBeanstalk.Types.InstanceHealthSummary
import Amazonka.ElasticBeanstalk.Types.Latency
import Amazonka.ElasticBeanstalk.Types.LaunchConfiguration
import Amazonka.ElasticBeanstalk.Types.LaunchTemplate
import Amazonka.ElasticBeanstalk.Types.Listener
import Amazonka.ElasticBeanstalk.Types.LoadBalancer
import Amazonka.ElasticBeanstalk.Types.LoadBalancerDescription
import Amazonka.ElasticBeanstalk.Types.ManagedAction
import Amazonka.ElasticBeanstalk.Types.ManagedActionHistoryItem
import Amazonka.ElasticBeanstalk.Types.MaxAgeRule
import Amazonka.ElasticBeanstalk.Types.MaxCountRule
import Amazonka.ElasticBeanstalk.Types.OptionRestrictionRegex
import Amazonka.ElasticBeanstalk.Types.OptionSpecification
import Amazonka.ElasticBeanstalk.Types.PlatformBranchSummary
import Amazonka.ElasticBeanstalk.Types.PlatformDescription
import Amazonka.ElasticBeanstalk.Types.PlatformFilter
import Amazonka.ElasticBeanstalk.Types.PlatformFramework
import Amazonka.ElasticBeanstalk.Types.PlatformProgrammingLanguage
import Amazonka.ElasticBeanstalk.Types.PlatformSummary
import Amazonka.ElasticBeanstalk.Types.Queue
import Amazonka.ElasticBeanstalk.Types.ResourceQuota
import Amazonka.ElasticBeanstalk.Types.ResourceQuotas
import Amazonka.ElasticBeanstalk.Types.S3Location
import Amazonka.ElasticBeanstalk.Types.SearchFilter
import Amazonka.ElasticBeanstalk.Types.SingleInstanceHealth
import Amazonka.ElasticBeanstalk.Types.SolutionStackDescription
import Amazonka.ElasticBeanstalk.Types.SourceBuildInformation
import Amazonka.ElasticBeanstalk.Types.SourceConfiguration
import Amazonka.ElasticBeanstalk.Types.StatusCodes
import Amazonka.ElasticBeanstalk.Types.SystemStatus
import Amazonka.ElasticBeanstalk.Types.Tag
import Amazonka.ElasticBeanstalk.Types.Trigger
import Amazonka.ElasticBeanstalk.Types.ValidationMessage
import Amazonka.ElasticBeanstalk.UpdateApplication
import Amazonka.ElasticBeanstalk.UpdateApplicationResourceLifecycle
import Amazonka.ElasticBeanstalk.UpdateApplicationVersion
import Amazonka.ElasticBeanstalk.UpdateConfigurationTemplate
import Amazonka.ElasticBeanstalk.UpdateEnvironment
import Amazonka.ElasticBeanstalk.UpdateTagsForResource
import Amazonka.ElasticBeanstalk.ValidateConfigurationSettings
