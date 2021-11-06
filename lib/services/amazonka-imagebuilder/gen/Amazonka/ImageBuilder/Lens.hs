{-# LANGUAGE NoImplicitPrelude #-}
{-# OPTIONS_GHC -fno-warn-duplicate-exports #-}
{-# OPTIONS_GHC -fno-warn-unused-imports #-}

-- Derived from AWS service descriptions, licensed under Apache 2.0.

-- |
-- Module      : Amazonka.ImageBuilder.Lens
-- Copyright   : (c) 2013-2021 Brendan Hay
-- License     : Mozilla Public License, v. 2.0.
-- Maintainer  : Brendan Hay <brendan.g.hay+amazonka@gmail.com>
-- Stability   : auto-generated
-- Portability : non-portable (GHC extensions)
module Amazonka.ImageBuilder.Lens
  ( -- * Operations

    -- ** ListImagePackages
    listImagePackages_nextToken,
    listImagePackages_maxResults,
    listImagePackages_imageBuildVersionArn,
    listImagePackagesResponse_requestId,
    listImagePackagesResponse_imagePackageList,
    listImagePackagesResponse_nextToken,
    listImagePackagesResponse_httpStatus,

    -- ** GetDistributionConfiguration
    getDistributionConfiguration_distributionConfigurationArn,
    getDistributionConfigurationResponse_requestId,
    getDistributionConfigurationResponse_distributionConfiguration,
    getDistributionConfigurationResponse_httpStatus,

    -- ** ImportComponent
    importComponent_data,
    importComponent_uri,
    importComponent_kmsKeyId,
    importComponent_changeDescription,
    importComponent_description,
    importComponent_tags,
    importComponent_name,
    importComponent_semanticVersion,
    importComponent_type,
    importComponent_format,
    importComponent_platform,
    importComponent_clientToken,
    importComponentResponse_requestId,
    importComponentResponse_clientToken,
    importComponentResponse_componentBuildVersionArn,
    importComponentResponse_httpStatus,

    -- ** ListComponentBuildVersions
    listComponentBuildVersions_nextToken,
    listComponentBuildVersions_maxResults,
    listComponentBuildVersions_componentVersionArn,
    listComponentBuildVersionsResponse_requestId,
    listComponentBuildVersionsResponse_nextToken,
    listComponentBuildVersionsResponse_componentSummaryList,
    listComponentBuildVersionsResponse_httpStatus,

    -- ** ListTagsForResource
    listTagsForResource_resourceArn,
    listTagsForResourceResponse_tags,
    listTagsForResourceResponse_httpStatus,

    -- ** ListImageBuildVersions
    listImageBuildVersions_filters,
    listImageBuildVersions_nextToken,
    listImageBuildVersions_maxResults,
    listImageBuildVersions_imageVersionArn,
    listImageBuildVersionsResponse_requestId,
    listImageBuildVersionsResponse_nextToken,
    listImageBuildVersionsResponse_imageSummaryList,
    listImageBuildVersionsResponse_httpStatus,

    -- ** CancelImageCreation
    cancelImageCreation_imageBuildVersionArn,
    cancelImageCreation_clientToken,
    cancelImageCreationResponse_requestId,
    cancelImageCreationResponse_clientToken,
    cancelImageCreationResponse_imageBuildVersionArn,
    cancelImageCreationResponse_httpStatus,

    -- ** GetImagePipeline
    getImagePipeline_imagePipelineArn,
    getImagePipelineResponse_requestId,
    getImagePipelineResponse_imagePipeline,
    getImagePipelineResponse_httpStatus,

    -- ** CreateInfrastructureConfiguration
    createInfrastructureConfiguration_securityGroupIds,
    createInfrastructureConfiguration_snsTopicArn,
    createInfrastructureConfiguration_instanceTypes,
    createInfrastructureConfiguration_keyPair,
    createInfrastructureConfiguration_resourceTags,
    createInfrastructureConfiguration_subnetId,
    createInfrastructureConfiguration_instanceMetadataOptions,
    createInfrastructureConfiguration_logging,
    createInfrastructureConfiguration_description,
    createInfrastructureConfiguration_tags,
    createInfrastructureConfiguration_terminateInstanceOnFailure,
    createInfrastructureConfiguration_name,
    createInfrastructureConfiguration_instanceProfileName,
    createInfrastructureConfiguration_clientToken,
    createInfrastructureConfigurationResponse_requestId,
    createInfrastructureConfigurationResponse_infrastructureConfigurationArn,
    createInfrastructureConfigurationResponse_clientToken,
    createInfrastructureConfigurationResponse_httpStatus,

    -- ** ListDistributionConfigurations
    listDistributionConfigurations_filters,
    listDistributionConfigurations_nextToken,
    listDistributionConfigurations_maxResults,
    listDistributionConfigurationsResponse_requestId,
    listDistributionConfigurationsResponse_distributionConfigurationSummaryList,
    listDistributionConfigurationsResponse_nextToken,
    listDistributionConfigurationsResponse_httpStatus,

    -- ** CreateContainerRecipe
    createContainerRecipe_dockerfileTemplateData,
    createContainerRecipe_imageOsVersionOverride,
    createContainerRecipe_workingDirectory,
    createContainerRecipe_dockerfileTemplateUri,
    createContainerRecipe_kmsKeyId,
    createContainerRecipe_platformOverride,
    createContainerRecipe_description,
    createContainerRecipe_tags,
    createContainerRecipe_instanceConfiguration,
    createContainerRecipe_containerType,
    createContainerRecipe_name,
    createContainerRecipe_semanticVersion,
    createContainerRecipe_components,
    createContainerRecipe_parentImage,
    createContainerRecipe_targetRepository,
    createContainerRecipe_clientToken,
    createContainerRecipeResponse_requestId,
    createContainerRecipeResponse_clientToken,
    createContainerRecipeResponse_containerRecipeArn,
    createContainerRecipeResponse_httpStatus,

    -- ** ListInfrastructureConfigurations
    listInfrastructureConfigurations_filters,
    listInfrastructureConfigurations_nextToken,
    listInfrastructureConfigurations_maxResults,
    listInfrastructureConfigurationsResponse_requestId,
    listInfrastructureConfigurationsResponse_infrastructureConfigurationSummaryList,
    listInfrastructureConfigurationsResponse_nextToken,
    listInfrastructureConfigurationsResponse_httpStatus,

    -- ** PutImageRecipePolicy
    putImageRecipePolicy_imageRecipeArn,
    putImageRecipePolicy_policy,
    putImageRecipePolicyResponse_requestId,
    putImageRecipePolicyResponse_imageRecipeArn,
    putImageRecipePolicyResponse_httpStatus,

    -- ** ListContainerRecipes
    listContainerRecipes_filters,
    listContainerRecipes_owner,
    listContainerRecipes_nextToken,
    listContainerRecipes_maxResults,
    listContainerRecipesResponse_requestId,
    listContainerRecipesResponse_containerRecipeSummaryList,
    listContainerRecipesResponse_nextToken,
    listContainerRecipesResponse_httpStatus,

    -- ** PutImagePolicy
    putImagePolicy_imageArn,
    putImagePolicy_policy,
    putImagePolicyResponse_requestId,
    putImagePolicyResponse_imageArn,
    putImagePolicyResponse_httpStatus,

    -- ** DeleteContainerRecipe
    deleteContainerRecipe_containerRecipeArn,
    deleteContainerRecipeResponse_requestId,
    deleteContainerRecipeResponse_containerRecipeArn,
    deleteContainerRecipeResponse_httpStatus,

    -- ** PutComponentPolicy
    putComponentPolicy_componentArn,
    putComponentPolicy_policy,
    putComponentPolicyResponse_requestId,
    putComponentPolicyResponse_componentArn,
    putComponentPolicyResponse_httpStatus,

    -- ** DeleteInfrastructureConfiguration
    deleteInfrastructureConfiguration_infrastructureConfigurationArn,
    deleteInfrastructureConfigurationResponse_requestId,
    deleteInfrastructureConfigurationResponse_infrastructureConfigurationArn,
    deleteInfrastructureConfigurationResponse_httpStatus,

    -- ** UpdateInfrastructureConfiguration
    updateInfrastructureConfiguration_securityGroupIds,
    updateInfrastructureConfiguration_snsTopicArn,
    updateInfrastructureConfiguration_instanceTypes,
    updateInfrastructureConfiguration_keyPair,
    updateInfrastructureConfiguration_resourceTags,
    updateInfrastructureConfiguration_subnetId,
    updateInfrastructureConfiguration_instanceMetadataOptions,
    updateInfrastructureConfiguration_logging,
    updateInfrastructureConfiguration_description,
    updateInfrastructureConfiguration_terminateInstanceOnFailure,
    updateInfrastructureConfiguration_infrastructureConfigurationArn,
    updateInfrastructureConfiguration_instanceProfileName,
    updateInfrastructureConfiguration_clientToken,
    updateInfrastructureConfigurationResponse_requestId,
    updateInfrastructureConfigurationResponse_infrastructureConfigurationArn,
    updateInfrastructureConfigurationResponse_clientToken,
    updateInfrastructureConfigurationResponse_httpStatus,

    -- ** CreateImagePipeline
    createImagePipeline_status,
    createImagePipeline_containerRecipeArn,
    createImagePipeline_imageTestsConfiguration,
    createImagePipeline_schedule,
    createImagePipeline_enhancedImageMetadataEnabled,
    createImagePipeline_distributionConfigurationArn,
    createImagePipeline_imageRecipeArn,
    createImagePipeline_description,
    createImagePipeline_tags,
    createImagePipeline_name,
    createImagePipeline_infrastructureConfigurationArn,
    createImagePipeline_clientToken,
    createImagePipelineResponse_requestId,
    createImagePipelineResponse_clientToken,
    createImagePipelineResponse_imagePipelineArn,
    createImagePipelineResponse_httpStatus,

    -- ** GetContainerRecipe
    getContainerRecipe_containerRecipeArn,
    getContainerRecipeResponse_requestId,
    getContainerRecipeResponse_containerRecipe,
    getContainerRecipeResponse_httpStatus,

    -- ** GetInfrastructureConfiguration
    getInfrastructureConfiguration_infrastructureConfigurationArn,
    getInfrastructureConfigurationResponse_requestId,
    getInfrastructureConfigurationResponse_infrastructureConfiguration,
    getInfrastructureConfigurationResponse_httpStatus,

    -- ** GetImagePolicy
    getImagePolicy_imageArn,
    getImagePolicyResponse_requestId,
    getImagePolicyResponse_policy,
    getImagePolicyResponse_httpStatus,

    -- ** GetImageRecipePolicy
    getImageRecipePolicy_imageRecipeArn,
    getImageRecipePolicyResponse_requestId,
    getImageRecipePolicyResponse_policy,
    getImageRecipePolicyResponse_httpStatus,

    -- ** GetComponentPolicy
    getComponentPolicy_componentArn,
    getComponentPolicyResponse_requestId,
    getComponentPolicyResponse_policy,
    getComponentPolicyResponse_httpStatus,

    -- ** DeleteImagePipeline
    deleteImagePipeline_imagePipelineArn,
    deleteImagePipelineResponse_requestId,
    deleteImagePipelineResponse_imagePipelineArn,
    deleteImagePipelineResponse_httpStatus,

    -- ** UpdateImagePipeline
    updateImagePipeline_status,
    updateImagePipeline_containerRecipeArn,
    updateImagePipeline_imageTestsConfiguration,
    updateImagePipeline_schedule,
    updateImagePipeline_enhancedImageMetadataEnabled,
    updateImagePipeline_distributionConfigurationArn,
    updateImagePipeline_imageRecipeArn,
    updateImagePipeline_description,
    updateImagePipeline_imagePipelineArn,
    updateImagePipeline_infrastructureConfigurationArn,
    updateImagePipeline_clientToken,
    updateImagePipelineResponse_requestId,
    updateImagePipelineResponse_clientToken,
    updateImagePipelineResponse_imagePipelineArn,
    updateImagePipelineResponse_httpStatus,

    -- ** ListImagePipelines
    listImagePipelines_filters,
    listImagePipelines_nextToken,
    listImagePipelines_maxResults,
    listImagePipelinesResponse_requestId,
    listImagePipelinesResponse_nextToken,
    listImagePipelinesResponse_imagePipelineList,
    listImagePipelinesResponse_httpStatus,

    -- ** StartImagePipelineExecution
    startImagePipelineExecution_imagePipelineArn,
    startImagePipelineExecution_clientToken,
    startImagePipelineExecutionResponse_requestId,
    startImagePipelineExecutionResponse_clientToken,
    startImagePipelineExecutionResponse_imageBuildVersionArn,
    startImagePipelineExecutionResponse_httpStatus,

    -- ** TagResource
    tagResource_resourceArn,
    tagResource_tags,
    tagResourceResponse_httpStatus,

    -- ** CreateImageRecipe
    createImageRecipe_additionalInstanceConfiguration,
    createImageRecipe_workingDirectory,
    createImageRecipe_blockDeviceMappings,
    createImageRecipe_description,
    createImageRecipe_tags,
    createImageRecipe_name,
    createImageRecipe_semanticVersion,
    createImageRecipe_components,
    createImageRecipe_parentImage,
    createImageRecipe_clientToken,
    createImageRecipeResponse_requestId,
    createImageRecipeResponse_clientToken,
    createImageRecipeResponse_imageRecipeArn,
    createImageRecipeResponse_httpStatus,

    -- ** CreateImage
    createImage_containerRecipeArn,
    createImage_imageTestsConfiguration,
    createImage_enhancedImageMetadataEnabled,
    createImage_distributionConfigurationArn,
    createImage_imageRecipeArn,
    createImage_tags,
    createImage_infrastructureConfigurationArn,
    createImage_clientToken,
    createImageResponse_requestId,
    createImageResponse_clientToken,
    createImageResponse_imageBuildVersionArn,
    createImageResponse_httpStatus,

    -- ** UntagResource
    untagResource_resourceArn,
    untagResource_tagKeys,
    untagResourceResponse_httpStatus,

    -- ** CreateComponent
    createComponent_data,
    createComponent_supportedOsVersions,
    createComponent_uri,
    createComponent_kmsKeyId,
    createComponent_changeDescription,
    createComponent_description,
    createComponent_tags,
    createComponent_name,
    createComponent_semanticVersion,
    createComponent_platform,
    createComponent_clientToken,
    createComponentResponse_requestId,
    createComponentResponse_clientToken,
    createComponentResponse_componentBuildVersionArn,
    createComponentResponse_httpStatus,

    -- ** DeleteDistributionConfiguration
    deleteDistributionConfiguration_distributionConfigurationArn,
    deleteDistributionConfigurationResponse_requestId,
    deleteDistributionConfigurationResponse_distributionConfigurationArn,
    deleteDistributionConfigurationResponse_httpStatus,

    -- ** UpdateDistributionConfiguration
    updateDistributionConfiguration_description,
    updateDistributionConfiguration_distributionConfigurationArn,
    updateDistributionConfiguration_distributions,
    updateDistributionConfiguration_clientToken,
    updateDistributionConfigurationResponse_requestId,
    updateDistributionConfigurationResponse_clientToken,
    updateDistributionConfigurationResponse_distributionConfigurationArn,
    updateDistributionConfigurationResponse_httpStatus,

    -- ** ListImagePipelineImages
    listImagePipelineImages_filters,
    listImagePipelineImages_nextToken,
    listImagePipelineImages_maxResults,
    listImagePipelineImages_imagePipelineArn,
    listImagePipelineImagesResponse_requestId,
    listImagePipelineImagesResponse_nextToken,
    listImagePipelineImagesResponse_imageSummaryList,
    listImagePipelineImagesResponse_httpStatus,

    -- ** DeleteImageRecipe
    deleteImageRecipe_imageRecipeArn,
    deleteImageRecipeResponse_requestId,
    deleteImageRecipeResponse_imageRecipeArn,
    deleteImageRecipeResponse_httpStatus,

    -- ** ListComponents
    listComponents_filters,
    listComponents_owner,
    listComponents_byName,
    listComponents_nextToken,
    listComponents_maxResults,
    listComponentsResponse_requestId,
    listComponentsResponse_componentVersionList,
    listComponentsResponse_nextToken,
    listComponentsResponse_httpStatus,

    -- ** PutContainerRecipePolicy
    putContainerRecipePolicy_containerRecipeArn,
    putContainerRecipePolicy_policy,
    putContainerRecipePolicyResponse_requestId,
    putContainerRecipePolicyResponse_containerRecipeArn,
    putContainerRecipePolicyResponse_httpStatus,

    -- ** ListImages
    listImages_filters,
    listImages_owner,
    listImages_byName,
    listImages_nextToken,
    listImages_includeDeprecated,
    listImages_maxResults,
    listImagesResponse_requestId,
    listImagesResponse_imageVersionList,
    listImagesResponse_nextToken,
    listImagesResponse_httpStatus,

    -- ** CreateDistributionConfiguration
    createDistributionConfiguration_description,
    createDistributionConfiguration_tags,
    createDistributionConfiguration_name,
    createDistributionConfiguration_distributions,
    createDistributionConfiguration_clientToken,
    createDistributionConfigurationResponse_requestId,
    createDistributionConfigurationResponse_clientToken,
    createDistributionConfigurationResponse_distributionConfigurationArn,
    createDistributionConfigurationResponse_httpStatus,

    -- ** ListImageRecipes
    listImageRecipes_filters,
    listImageRecipes_owner,
    listImageRecipes_nextToken,
    listImageRecipes_maxResults,
    listImageRecipesResponse_requestId,
    listImageRecipesResponse_nextToken,
    listImageRecipesResponse_imageRecipeSummaryList,
    listImageRecipesResponse_httpStatus,

    -- ** DeleteImage
    deleteImage_imageBuildVersionArn,
    deleteImageResponse_requestId,
    deleteImageResponse_imageBuildVersionArn,
    deleteImageResponse_httpStatus,

    -- ** DeleteComponent
    deleteComponent_componentBuildVersionArn,
    deleteComponentResponse_requestId,
    deleteComponentResponse_componentBuildVersionArn,
    deleteComponentResponse_httpStatus,

    -- ** GetImage
    getImage_imageBuildVersionArn,
    getImageResponse_requestId,
    getImageResponse_image,
    getImageResponse_httpStatus,

    -- ** GetContainerRecipePolicy
    getContainerRecipePolicy_containerRecipeArn,
    getContainerRecipePolicyResponse_requestId,
    getContainerRecipePolicyResponse_policy,
    getContainerRecipePolicyResponse_httpStatus,

    -- ** GetImageRecipe
    getImageRecipe_imageRecipeArn,
    getImageRecipeResponse_requestId,
    getImageRecipeResponse_imageRecipe,
    getImageRecipeResponse_httpStatus,

    -- ** GetComponent
    getComponent_componentBuildVersionArn,
    getComponentResponse_requestId,
    getComponentResponse_component,
    getComponentResponse_httpStatus,

    -- * Types

    -- ** AdditionalInstanceConfiguration
    additionalInstanceConfiguration_systemsManagerAgent,
    additionalInstanceConfiguration_userDataOverride,

    -- ** Ami
    ami_image,
    ami_state,
    ami_accountId,
    ami_name,
    ami_region,
    ami_description,

    -- ** AmiDistributionConfiguration
    amiDistributionConfiguration_launchPermission,
    amiDistributionConfiguration_targetAccountIds,
    amiDistributionConfiguration_amiTags,
    amiDistributionConfiguration_name,
    amiDistributionConfiguration_kmsKeyId,
    amiDistributionConfiguration_description,

    -- ** Component
    component_state,
    component_platform,
    component_arn,
    component_data,
    component_supportedOsVersions,
    component_encrypted,
    component_owner,
    component_dateCreated,
    component_name,
    component_kmsKeyId,
    component_version,
    component_parameters,
    component_changeDescription,
    component_type,
    component_description,
    component_tags,

    -- ** ComponentConfiguration
    componentConfiguration_parameters,
    componentConfiguration_componentArn,

    -- ** ComponentParameter
    componentParameter_name,
    componentParameter_value,

    -- ** ComponentParameterDetail
    componentParameterDetail_defaultValue,
    componentParameterDetail_description,
    componentParameterDetail_name,
    componentParameterDetail_type,

    -- ** ComponentState
    componentState_status,
    componentState_reason,

    -- ** ComponentSummary
    componentSummary_state,
    componentSummary_platform,
    componentSummary_arn,
    componentSummary_supportedOsVersions,
    componentSummary_owner,
    componentSummary_dateCreated,
    componentSummary_name,
    componentSummary_version,
    componentSummary_changeDescription,
    componentSummary_type,
    componentSummary_description,
    componentSummary_tags,

    -- ** ComponentVersion
    componentVersion_platform,
    componentVersion_arn,
    componentVersion_supportedOsVersions,
    componentVersion_owner,
    componentVersion_dateCreated,
    componentVersion_name,
    componentVersion_version,
    componentVersion_type,
    componentVersion_description,

    -- ** Container
    container_imageUris,
    container_region,

    -- ** ContainerDistributionConfiguration
    containerDistributionConfiguration_containerTags,
    containerDistributionConfiguration_description,
    containerDistributionConfiguration_targetRepository,

    -- ** ContainerRecipe
    containerRecipe_components,
    containerRecipe_containerType,
    containerRecipe_platform,
    containerRecipe_dockerfileTemplateData,
    containerRecipe_arn,
    containerRecipe_workingDirectory,
    containerRecipe_parentImage,
    containerRecipe_encrypted,
    containerRecipe_owner,
    containerRecipe_dateCreated,
    containerRecipe_name,
    containerRecipe_kmsKeyId,
    containerRecipe_version,
    containerRecipe_targetRepository,
    containerRecipe_description,
    containerRecipe_tags,
    containerRecipe_instanceConfiguration,

    -- ** ContainerRecipeSummary
    containerRecipeSummary_containerType,
    containerRecipeSummary_platform,
    containerRecipeSummary_arn,
    containerRecipeSummary_parentImage,
    containerRecipeSummary_owner,
    containerRecipeSummary_dateCreated,
    containerRecipeSummary_name,
    containerRecipeSummary_tags,

    -- ** Distribution
    distribution_amiDistributionConfiguration,
    distribution_launchTemplateConfigurations,
    distribution_licenseConfigurationArns,
    distribution_containerDistributionConfiguration,
    distribution_region,

    -- ** DistributionConfiguration
    distributionConfiguration_arn,
    distributionConfiguration_dateUpdated,
    distributionConfiguration_dateCreated,
    distributionConfiguration_name,
    distributionConfiguration_description,
    distributionConfiguration_distributions,
    distributionConfiguration_tags,
    distributionConfiguration_timeoutMinutes,

    -- ** DistributionConfigurationSummary
    distributionConfigurationSummary_arn,
    distributionConfigurationSummary_regions,
    distributionConfigurationSummary_dateUpdated,
    distributionConfigurationSummary_dateCreated,
    distributionConfigurationSummary_name,
    distributionConfigurationSummary_description,
    distributionConfigurationSummary_tags,

    -- ** EbsInstanceBlockDeviceSpecification
    ebsInstanceBlockDeviceSpecification_deleteOnTermination,
    ebsInstanceBlockDeviceSpecification_throughput,
    ebsInstanceBlockDeviceSpecification_volumeSize,
    ebsInstanceBlockDeviceSpecification_iops,
    ebsInstanceBlockDeviceSpecification_encrypted,
    ebsInstanceBlockDeviceSpecification_kmsKeyId,
    ebsInstanceBlockDeviceSpecification_volumeType,
    ebsInstanceBlockDeviceSpecification_snapshotId,

    -- ** Filter
    filter_values,
    filter_name,

    -- ** Image
    image_imageRecipe,
    image_state,
    image_platform,
    image_imageTestsConfiguration,
    image_arn,
    image_enhancedImageMetadataEnabled,
    image_dateCreated,
    image_containerRecipe,
    image_name,
    image_infrastructureConfiguration,
    image_version,
    image_distributionConfiguration,
    image_sourcePipelineArn,
    image_type,
    image_sourcePipelineName,
    image_outputResources,
    image_osVersion,
    image_tags,

    -- ** ImagePackage
    imagePackage_packageName,
    imagePackage_packageVersion,

    -- ** ImagePipeline
    imagePipeline_status,
    imagePipeline_dateLastRun,
    imagePipeline_platform,
    imagePipeline_infrastructureConfigurationArn,
    imagePipeline_containerRecipeArn,
    imagePipeline_imageTestsConfiguration,
    imagePipeline_dateNextRun,
    imagePipeline_arn,
    imagePipeline_schedule,
    imagePipeline_enhancedImageMetadataEnabled,
    imagePipeline_dateUpdated,
    imagePipeline_dateCreated,
    imagePipeline_name,
    imagePipeline_distributionConfigurationArn,
    imagePipeline_imageRecipeArn,
    imagePipeline_description,
    imagePipeline_tags,

    -- ** ImageRecipe
    imageRecipe_components,
    imageRecipe_platform,
    imageRecipe_arn,
    imageRecipe_additionalInstanceConfiguration,
    imageRecipe_workingDirectory,
    imageRecipe_parentImage,
    imageRecipe_owner,
    imageRecipe_dateCreated,
    imageRecipe_name,
    imageRecipe_version,
    imageRecipe_type,
    imageRecipe_blockDeviceMappings,
    imageRecipe_description,
    imageRecipe_tags,

    -- ** ImageRecipeSummary
    imageRecipeSummary_platform,
    imageRecipeSummary_arn,
    imageRecipeSummary_parentImage,
    imageRecipeSummary_owner,
    imageRecipeSummary_dateCreated,
    imageRecipeSummary_name,
    imageRecipeSummary_tags,

    -- ** ImageState
    imageState_status,
    imageState_reason,

    -- ** ImageSummary
    imageSummary_state,
    imageSummary_platform,
    imageSummary_arn,
    imageSummary_owner,
    imageSummary_dateCreated,
    imageSummary_name,
    imageSummary_version,
    imageSummary_type,
    imageSummary_outputResources,
    imageSummary_osVersion,
    imageSummary_tags,

    -- ** ImageTestsConfiguration
    imageTestsConfiguration_timeoutMinutes,
    imageTestsConfiguration_imageTestsEnabled,

    -- ** ImageVersion
    imageVersion_platform,
    imageVersion_arn,
    imageVersion_owner,
    imageVersion_dateCreated,
    imageVersion_name,
    imageVersion_version,
    imageVersion_type,
    imageVersion_osVersion,

    -- ** InfrastructureConfiguration
    infrastructureConfiguration_securityGroupIds,
    infrastructureConfiguration_snsTopicArn,
    infrastructureConfiguration_instanceTypes,
    infrastructureConfiguration_arn,
    infrastructureConfiguration_keyPair,
    infrastructureConfiguration_resourceTags,
    infrastructureConfiguration_subnetId,
    infrastructureConfiguration_dateUpdated,
    infrastructureConfiguration_dateCreated,
    infrastructureConfiguration_instanceMetadataOptions,
    infrastructureConfiguration_name,
    infrastructureConfiguration_instanceProfileName,
    infrastructureConfiguration_logging,
    infrastructureConfiguration_description,
    infrastructureConfiguration_tags,
    infrastructureConfiguration_terminateInstanceOnFailure,

    -- ** InfrastructureConfigurationSummary
    infrastructureConfigurationSummary_instanceTypes,
    infrastructureConfigurationSummary_arn,
    infrastructureConfigurationSummary_resourceTags,
    infrastructureConfigurationSummary_dateUpdated,
    infrastructureConfigurationSummary_dateCreated,
    infrastructureConfigurationSummary_name,
    infrastructureConfigurationSummary_instanceProfileName,
    infrastructureConfigurationSummary_description,
    infrastructureConfigurationSummary_tags,

    -- ** InstanceBlockDeviceMapping
    instanceBlockDeviceMapping_virtualName,
    instanceBlockDeviceMapping_noDevice,
    instanceBlockDeviceMapping_ebs,
    instanceBlockDeviceMapping_deviceName,

    -- ** InstanceConfiguration
    instanceConfiguration_image,
    instanceConfiguration_blockDeviceMappings,

    -- ** InstanceMetadataOptions
    instanceMetadataOptions_httpPutResponseHopLimit,
    instanceMetadataOptions_httpTokens,

    -- ** LaunchPermissionConfiguration
    launchPermissionConfiguration_userIds,
    launchPermissionConfiguration_userGroups,

    -- ** LaunchTemplateConfiguration
    launchTemplateConfiguration_setDefaultVersion,
    launchTemplateConfiguration_accountId,
    launchTemplateConfiguration_launchTemplateId,

    -- ** Logging
    logging_s3Logs,

    -- ** OutputResources
    outputResources_containers,
    outputResources_amis,

    -- ** S3Logs
    s3Logs_s3KeyPrefix,
    s3Logs_s3BucketName,

    -- ** Schedule
    schedule_scheduleExpression,
    schedule_pipelineExecutionStartCondition,
    schedule_timezone,

    -- ** SystemsManagerAgent
    systemsManagerAgent_uninstallAfterBuild,

    -- ** TargetContainerRepository
    targetContainerRepository_service,
    targetContainerRepository_repositoryName,
  )
where

import Amazonka.ImageBuilder.CancelImageCreation
import Amazonka.ImageBuilder.CreateComponent
import Amazonka.ImageBuilder.CreateContainerRecipe
import Amazonka.ImageBuilder.CreateDistributionConfiguration
import Amazonka.ImageBuilder.CreateImage
import Amazonka.ImageBuilder.CreateImagePipeline
import Amazonka.ImageBuilder.CreateImageRecipe
import Amazonka.ImageBuilder.CreateInfrastructureConfiguration
import Amazonka.ImageBuilder.DeleteComponent
import Amazonka.ImageBuilder.DeleteContainerRecipe
import Amazonka.ImageBuilder.DeleteDistributionConfiguration
import Amazonka.ImageBuilder.DeleteImage
import Amazonka.ImageBuilder.DeleteImagePipeline
import Amazonka.ImageBuilder.DeleteImageRecipe
import Amazonka.ImageBuilder.DeleteInfrastructureConfiguration
import Amazonka.ImageBuilder.GetComponent
import Amazonka.ImageBuilder.GetComponentPolicy
import Amazonka.ImageBuilder.GetContainerRecipe
import Amazonka.ImageBuilder.GetContainerRecipePolicy
import Amazonka.ImageBuilder.GetDistributionConfiguration
import Amazonka.ImageBuilder.GetImage
import Amazonka.ImageBuilder.GetImagePipeline
import Amazonka.ImageBuilder.GetImagePolicy
import Amazonka.ImageBuilder.GetImageRecipe
import Amazonka.ImageBuilder.GetImageRecipePolicy
import Amazonka.ImageBuilder.GetInfrastructureConfiguration
import Amazonka.ImageBuilder.ImportComponent
import Amazonka.ImageBuilder.ListComponentBuildVersions
import Amazonka.ImageBuilder.ListComponents
import Amazonka.ImageBuilder.ListContainerRecipes
import Amazonka.ImageBuilder.ListDistributionConfigurations
import Amazonka.ImageBuilder.ListImageBuildVersions
import Amazonka.ImageBuilder.ListImagePackages
import Amazonka.ImageBuilder.ListImagePipelineImages
import Amazonka.ImageBuilder.ListImagePipelines
import Amazonka.ImageBuilder.ListImageRecipes
import Amazonka.ImageBuilder.ListImages
import Amazonka.ImageBuilder.ListInfrastructureConfigurations
import Amazonka.ImageBuilder.ListTagsForResource
import Amazonka.ImageBuilder.PutComponentPolicy
import Amazonka.ImageBuilder.PutContainerRecipePolicy
import Amazonka.ImageBuilder.PutImagePolicy
import Amazonka.ImageBuilder.PutImageRecipePolicy
import Amazonka.ImageBuilder.StartImagePipelineExecution
import Amazonka.ImageBuilder.TagResource
import Amazonka.ImageBuilder.Types.AdditionalInstanceConfiguration
import Amazonka.ImageBuilder.Types.Ami
import Amazonka.ImageBuilder.Types.AmiDistributionConfiguration
import Amazonka.ImageBuilder.Types.Component
import Amazonka.ImageBuilder.Types.ComponentConfiguration
import Amazonka.ImageBuilder.Types.ComponentParameter
import Amazonka.ImageBuilder.Types.ComponentParameterDetail
import Amazonka.ImageBuilder.Types.ComponentState
import Amazonka.ImageBuilder.Types.ComponentSummary
import Amazonka.ImageBuilder.Types.ComponentVersion
import Amazonka.ImageBuilder.Types.Container
import Amazonka.ImageBuilder.Types.ContainerDistributionConfiguration
import Amazonka.ImageBuilder.Types.ContainerRecipe
import Amazonka.ImageBuilder.Types.ContainerRecipeSummary
import Amazonka.ImageBuilder.Types.Distribution
import Amazonka.ImageBuilder.Types.DistributionConfiguration
import Amazonka.ImageBuilder.Types.DistributionConfigurationSummary
import Amazonka.ImageBuilder.Types.EbsInstanceBlockDeviceSpecification
import Amazonka.ImageBuilder.Types.Filter
import Amazonka.ImageBuilder.Types.Image
import Amazonka.ImageBuilder.Types.ImagePackage
import Amazonka.ImageBuilder.Types.ImagePipeline
import Amazonka.ImageBuilder.Types.ImageRecipe
import Amazonka.ImageBuilder.Types.ImageRecipeSummary
import Amazonka.ImageBuilder.Types.ImageState
import Amazonka.ImageBuilder.Types.ImageSummary
import Amazonka.ImageBuilder.Types.ImageTestsConfiguration
import Amazonka.ImageBuilder.Types.ImageVersion
import Amazonka.ImageBuilder.Types.InfrastructureConfiguration
import Amazonka.ImageBuilder.Types.InfrastructureConfigurationSummary
import Amazonka.ImageBuilder.Types.InstanceBlockDeviceMapping
import Amazonka.ImageBuilder.Types.InstanceConfiguration
import Amazonka.ImageBuilder.Types.InstanceMetadataOptions
import Amazonka.ImageBuilder.Types.LaunchPermissionConfiguration
import Amazonka.ImageBuilder.Types.LaunchTemplateConfiguration
import Amazonka.ImageBuilder.Types.Logging
import Amazonka.ImageBuilder.Types.OutputResources
import Amazonka.ImageBuilder.Types.S3Logs
import Amazonka.ImageBuilder.Types.Schedule
import Amazonka.ImageBuilder.Types.SystemsManagerAgent
import Amazonka.ImageBuilder.Types.TargetContainerRepository
import Amazonka.ImageBuilder.UntagResource
import Amazonka.ImageBuilder.UpdateDistributionConfiguration
import Amazonka.ImageBuilder.UpdateImagePipeline
import Amazonka.ImageBuilder.UpdateInfrastructureConfiguration
