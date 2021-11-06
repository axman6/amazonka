{-# LANGUAGE NoImplicitPrelude #-}
{-# OPTIONS_GHC -fno-warn-duplicate-exports #-}
{-# OPTIONS_GHC -fno-warn-unused-imports #-}

-- Derived from AWS service descriptions, licensed under Apache 2.0.

-- |
-- Module      : Amazonka.CodeGuruProfiler.Lens
-- Copyright   : (c) 2013-2021 Brendan Hay
-- License     : Mozilla Public License, v. 2.0.
-- Maintainer  : Brendan Hay <brendan.g.hay+amazonka@gmail.com>
-- Stability   : auto-generated
-- Portability : non-portable (GHC extensions)
module Amazonka.CodeGuruProfiler.Lens
  ( -- * Operations

    -- ** GetRecommendations
    getRecommendations_locale,
    getRecommendations_endTime,
    getRecommendations_profilingGroupName,
    getRecommendations_startTime,
    getRecommendationsResponse_httpStatus,
    getRecommendationsResponse_anomalies,
    getRecommendationsResponse_profileEndTime,
    getRecommendationsResponse_profileStartTime,
    getRecommendationsResponse_profilingGroupName,
    getRecommendationsResponse_recommendations,

    -- ** AddNotificationChannels
    addNotificationChannels_channels,
    addNotificationChannels_profilingGroupName,
    addNotificationChannelsResponse_notificationConfiguration,
    addNotificationChannelsResponse_httpStatus,

    -- ** DescribeProfilingGroup
    describeProfilingGroup_profilingGroupName,
    describeProfilingGroupResponse_httpStatus,
    describeProfilingGroupResponse_profilingGroup,

    -- ** PutPermission
    putPermission_revisionId,
    putPermission_actionGroup,
    putPermission_principals,
    putPermission_profilingGroupName,
    putPermissionResponse_httpStatus,
    putPermissionResponse_policy,
    putPermissionResponse_revisionId,

    -- ** ListTagsForResource
    listTagsForResource_resourceArn,
    listTagsForResourceResponse_tags,
    listTagsForResourceResponse_httpStatus,

    -- ** RemovePermission
    removePermission_actionGroup,
    removePermission_profilingGroupName,
    removePermission_revisionId,
    removePermissionResponse_httpStatus,
    removePermissionResponse_policy,
    removePermissionResponse_revisionId,

    -- ** SubmitFeedback
    submitFeedback_comment,
    submitFeedback_anomalyInstanceId,
    submitFeedback_profilingGroupName,
    submitFeedback_type,
    submitFeedbackResponse_httpStatus,

    -- ** CreateProfilingGroup
    createProfilingGroup_computePlatform,
    createProfilingGroup_agentOrchestrationConfig,
    createProfilingGroup_tags,
    createProfilingGroup_clientToken,
    createProfilingGroup_profilingGroupName,
    createProfilingGroupResponse_httpStatus,
    createProfilingGroupResponse_profilingGroup,

    -- ** RemoveNotificationChannel
    removeNotificationChannel_channelId,
    removeNotificationChannel_profilingGroupName,
    removeNotificationChannelResponse_notificationConfiguration,
    removeNotificationChannelResponse_httpStatus,

    -- ** UpdateProfilingGroup
    updateProfilingGroup_agentOrchestrationConfig,
    updateProfilingGroup_profilingGroupName,
    updateProfilingGroupResponse_httpStatus,
    updateProfilingGroupResponse_profilingGroup,

    -- ** DeleteProfilingGroup
    deleteProfilingGroup_profilingGroupName,
    deleteProfilingGroupResponse_httpStatus,

    -- ** ListFindingsReports
    listFindingsReports_nextToken,
    listFindingsReports_dailyReportsOnly,
    listFindingsReports_maxResults,
    listFindingsReports_endTime,
    listFindingsReports_profilingGroupName,
    listFindingsReports_startTime,
    listFindingsReportsResponse_nextToken,
    listFindingsReportsResponse_httpStatus,
    listFindingsReportsResponse_findingsReportSummaries,

    -- ** ListProfileTimes
    listProfileTimes_orderBy,
    listProfileTimes_nextToken,
    listProfileTimes_maxResults,
    listProfileTimes_endTime,
    listProfileTimes_period,
    listProfileTimes_profilingGroupName,
    listProfileTimes_startTime,
    listProfileTimesResponse_nextToken,
    listProfileTimesResponse_httpStatus,
    listProfileTimesResponse_profileTimes,

    -- ** PostAgentProfile
    postAgentProfile_profileToken,
    postAgentProfile_agentProfile,
    postAgentProfile_contentType,
    postAgentProfile_profilingGroupName,
    postAgentProfileResponse_httpStatus,

    -- ** GetProfile
    getProfile_startTime,
    getProfile_period,
    getProfile_accept,
    getProfile_endTime,
    getProfile_maxDepth,
    getProfile_profilingGroupName,
    getProfileResponse_contentEncoding,
    getProfileResponse_httpStatus,
    getProfileResponse_contentType,
    getProfileResponse_profile,

    -- ** ListProfilingGroups
    listProfilingGroups_includeDescription,
    listProfilingGroups_nextToken,
    listProfilingGroups_maxResults,
    listProfilingGroupsResponse_nextToken,
    listProfilingGroupsResponse_profilingGroups,
    listProfilingGroupsResponse_httpStatus,
    listProfilingGroupsResponse_profilingGroupNames,

    -- ** TagResource
    tagResource_resourceArn,
    tagResource_tags,
    tagResourceResponse_httpStatus,

    -- ** GetNotificationConfiguration
    getNotificationConfiguration_profilingGroupName,
    getNotificationConfigurationResponse_httpStatus,
    getNotificationConfigurationResponse_notificationConfiguration,

    -- ** BatchGetFrameMetricData
    batchGetFrameMetricData_targetResolution,
    batchGetFrameMetricData_frameMetrics,
    batchGetFrameMetricData_startTime,
    batchGetFrameMetricData_period,
    batchGetFrameMetricData_endTime,
    batchGetFrameMetricData_profilingGroupName,
    batchGetFrameMetricDataResponse_httpStatus,
    batchGetFrameMetricDataResponse_endTime,
    batchGetFrameMetricDataResponse_endTimes,
    batchGetFrameMetricDataResponse_frameMetricData,
    batchGetFrameMetricDataResponse_resolution,
    batchGetFrameMetricDataResponse_startTime,
    batchGetFrameMetricDataResponse_unprocessedEndTimes,

    -- ** UntagResource
    untagResource_resourceArn,
    untagResource_tagKeys,
    untagResourceResponse_httpStatus,

    -- ** GetFindingsReportAccountSummary
    getFindingsReportAccountSummary_nextToken,
    getFindingsReportAccountSummary_dailyReportsOnly,
    getFindingsReportAccountSummary_maxResults,
    getFindingsReportAccountSummaryResponse_nextToken,
    getFindingsReportAccountSummaryResponse_httpStatus,
    getFindingsReportAccountSummaryResponse_reportSummaries,

    -- ** GetPolicy
    getPolicy_profilingGroupName,
    getPolicyResponse_httpStatus,
    getPolicyResponse_policy,
    getPolicyResponse_revisionId,

    -- ** ConfigureAgent
    configureAgent_fleetInstanceId,
    configureAgent_metadata,
    configureAgent_profilingGroupName,
    configureAgentResponse_httpStatus,
    configureAgentResponse_configuration,

    -- * Types

    -- ** AgentConfiguration
    agentConfiguration_agentParameters,
    agentConfiguration_periodInSeconds,
    agentConfiguration_shouldProfile,

    -- ** AgentOrchestrationConfig
    agentOrchestrationConfig_profilingEnabled,

    -- ** AggregatedProfileTime
    aggregatedProfileTime_period,
    aggregatedProfileTime_start,

    -- ** Anomaly
    anomaly_instances,
    anomaly_metric,
    anomaly_reason,

    -- ** AnomalyInstance
    anomalyInstance_endTime,
    anomalyInstance_userFeedback,
    anomalyInstance_id,
    anomalyInstance_startTime,

    -- ** Channel
    channel_id,
    channel_eventPublishers,
    channel_uri,

    -- ** FindingsReportSummary
    findingsReportSummary_profileStartTime,
    findingsReportSummary_profileEndTime,
    findingsReportSummary_id,
    findingsReportSummary_profilingGroupName,
    findingsReportSummary_totalNumberOfFindings,

    -- ** FrameMetric
    frameMetric_frameName,
    frameMetric_threadStates,
    frameMetric_type,

    -- ** FrameMetricDatum
    frameMetricDatum_frameMetric,
    frameMetricDatum_values,

    -- ** Match
    match_thresholdBreachValue,
    match_frameAddress,
    match_targetFramesIndex,

    -- ** Metric
    metric_frameName,
    metric_threadStates,
    metric_type,

    -- ** NotificationConfiguration
    notificationConfiguration_channels,

    -- ** Pattern
    pattern_thresholdPercent,
    pattern_targetFrames,
    pattern_countersToAggregate,
    pattern_name,
    pattern_resolutionSteps,
    pattern_id,
    pattern_description,

    -- ** ProfileTime
    profileTime_start,

    -- ** ProfilingGroupDescription
    profilingGroupDescription_computePlatform,
    profilingGroupDescription_arn,
    profilingGroupDescription_createdAt,
    profilingGroupDescription_name,
    profilingGroupDescription_profilingStatus,
    profilingGroupDescription_updatedAt,
    profilingGroupDescription_agentOrchestrationConfig,
    profilingGroupDescription_tags,

    -- ** ProfilingStatus
    profilingStatus_latestAgentOrchestratedAt,
    profilingStatus_latestAgentProfileReportedAt,
    profilingStatus_latestAggregatedProfile,

    -- ** Recommendation
    recommendation_allMatchesCount,
    recommendation_allMatchesSum,
    recommendation_endTime,
    recommendation_pattern,
    recommendation_startTime,
    recommendation_topMatches,

    -- ** TimestampStructure
    timestampStructure_value,

    -- ** UserFeedback
    userFeedback_type,
  )
where

import Amazonka.CodeGuruProfiler.AddNotificationChannels
import Amazonka.CodeGuruProfiler.BatchGetFrameMetricData
import Amazonka.CodeGuruProfiler.ConfigureAgent
import Amazonka.CodeGuruProfiler.CreateProfilingGroup
import Amazonka.CodeGuruProfiler.DeleteProfilingGroup
import Amazonka.CodeGuruProfiler.DescribeProfilingGroup
import Amazonka.CodeGuruProfiler.GetFindingsReportAccountSummary
import Amazonka.CodeGuruProfiler.GetNotificationConfiguration
import Amazonka.CodeGuruProfiler.GetPolicy
import Amazonka.CodeGuruProfiler.GetProfile
import Amazonka.CodeGuruProfiler.GetRecommendations
import Amazonka.CodeGuruProfiler.ListFindingsReports
import Amazonka.CodeGuruProfiler.ListProfileTimes
import Amazonka.CodeGuruProfiler.ListProfilingGroups
import Amazonka.CodeGuruProfiler.ListTagsForResource
import Amazonka.CodeGuruProfiler.PostAgentProfile
import Amazonka.CodeGuruProfiler.PutPermission
import Amazonka.CodeGuruProfiler.RemoveNotificationChannel
import Amazonka.CodeGuruProfiler.RemovePermission
import Amazonka.CodeGuruProfiler.SubmitFeedback
import Amazonka.CodeGuruProfiler.TagResource
import Amazonka.CodeGuruProfiler.Types.AgentConfiguration
import Amazonka.CodeGuruProfiler.Types.AgentOrchestrationConfig
import Amazonka.CodeGuruProfiler.Types.AggregatedProfileTime
import Amazonka.CodeGuruProfiler.Types.Anomaly
import Amazonka.CodeGuruProfiler.Types.AnomalyInstance
import Amazonka.CodeGuruProfiler.Types.Channel
import Amazonka.CodeGuruProfiler.Types.FindingsReportSummary
import Amazonka.CodeGuruProfiler.Types.FrameMetric
import Amazonka.CodeGuruProfiler.Types.FrameMetricDatum
import Amazonka.CodeGuruProfiler.Types.Match
import Amazonka.CodeGuruProfiler.Types.Metric
import Amazonka.CodeGuruProfiler.Types.NotificationConfiguration
import Amazonka.CodeGuruProfiler.Types.Pattern
import Amazonka.CodeGuruProfiler.Types.ProfileTime
import Amazonka.CodeGuruProfiler.Types.ProfilingGroupDescription
import Amazonka.CodeGuruProfiler.Types.ProfilingStatus
import Amazonka.CodeGuruProfiler.Types.Recommendation
import Amazonka.CodeGuruProfiler.Types.TimestampStructure
import Amazonka.CodeGuruProfiler.Types.UserFeedback
import Amazonka.CodeGuruProfiler.UntagResource
import Amazonka.CodeGuruProfiler.UpdateProfilingGroup
