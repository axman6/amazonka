{-# OPTIONS_GHC -fno-warn-duplicate-exports #-}
{-# OPTIONS_GHC -fno-warn-unused-imports #-}

-- |
-- Module      : Amazonka.Inspector
-- Copyright   : (c) 2013-2021 Brendan Hay
-- License     : Mozilla Public License, v. 2.0.
-- Maintainer  : Brendan Hay <brendan.g.hay+amazonka@gmail.com>
-- Stability   : auto-generated
-- Portability : non-portable (GHC extensions)
--
-- Derived from API version @2016-02-16@ of the AWS service descriptions, licensed under Apache 2.0.
--
-- Amazon Inspector
--
-- Amazon Inspector enables you to analyze the behavior of your AWS
-- resources and to identify potential security issues. For more
-- information, see
-- <https://docs.aws.amazon.com/inspector/latest/userguide/inspector_introduction.html Amazon Inspector User Guide>.
module Amazonka.Inspector
  ( -- * Service Configuration
    defaultService,

    -- * Errors
    -- $errors

    -- ** AccessDeniedException
    _AccessDeniedException,

    -- ** AssessmentRunInProgressException
    _AssessmentRunInProgressException,

    -- ** NoSuchEntityException
    _NoSuchEntityException,

    -- ** UnsupportedFeatureException
    _UnsupportedFeatureException,

    -- ** PreviewGenerationInProgressException
    _PreviewGenerationInProgressException,

    -- ** AgentsAlreadyRunningAssessmentException
    _AgentsAlreadyRunningAssessmentException,

    -- ** InvalidCrossAccountRoleException
    _InvalidCrossAccountRoleException,

    -- ** InvalidInputException
    _InvalidInputException,

    -- ** InternalException
    _InternalException,

    -- ** ServiceTemporarilyUnavailableException
    _ServiceTemporarilyUnavailableException,

    -- ** LimitExceededException
    _LimitExceededException,

    -- * Waiters
    -- $waiters

    -- * Operations
    -- $operations

    -- ** GetTelemetryMetadata
    GetTelemetryMetadata (GetTelemetryMetadata'),
    newGetTelemetryMetadata,
    GetTelemetryMetadataResponse (GetTelemetryMetadataResponse'),
    newGetTelemetryMetadataResponse,

    -- ** ListFindings (Paginated)
    ListFindings (ListFindings'),
    newListFindings,
    ListFindingsResponse (ListFindingsResponse'),
    newListFindingsResponse,

    -- ** ListAssessmentTemplates (Paginated)
    ListAssessmentTemplates (ListAssessmentTemplates'),
    newListAssessmentTemplates,
    ListAssessmentTemplatesResponse (ListAssessmentTemplatesResponse'),
    newListAssessmentTemplatesResponse,

    -- ** SubscribeToEvent
    SubscribeToEvent (SubscribeToEvent'),
    newSubscribeToEvent,
    SubscribeToEventResponse (SubscribeToEventResponse'),
    newSubscribeToEventResponse,

    -- ** ListAssessmentRunAgents (Paginated)
    ListAssessmentRunAgents (ListAssessmentRunAgents'),
    newListAssessmentRunAgents,
    ListAssessmentRunAgentsResponse (ListAssessmentRunAgentsResponse'),
    newListAssessmentRunAgentsResponse,

    -- ** StartAssessmentRun
    StartAssessmentRun (StartAssessmentRun'),
    newStartAssessmentRun,
    StartAssessmentRunResponse (StartAssessmentRunResponse'),
    newStartAssessmentRunResponse,

    -- ** DeleteAssessmentTemplate
    DeleteAssessmentTemplate (DeleteAssessmentTemplate'),
    newDeleteAssessmentTemplate,
    DeleteAssessmentTemplateResponse (DeleteAssessmentTemplateResponse'),
    newDeleteAssessmentTemplateResponse,

    -- ** CreateAssessmentTemplate
    CreateAssessmentTemplate (CreateAssessmentTemplate'),
    newCreateAssessmentTemplate,
    CreateAssessmentTemplateResponse (CreateAssessmentTemplateResponse'),
    newCreateAssessmentTemplateResponse,

    -- ** DescribeExclusions
    DescribeExclusions (DescribeExclusions'),
    newDescribeExclusions,
    DescribeExclusionsResponse (DescribeExclusionsResponse'),
    newDescribeExclusionsResponse,

    -- ** ListTagsForResource
    ListTagsForResource (ListTagsForResource'),
    newListTagsForResource,
    ListTagsForResourceResponse (ListTagsForResourceResponse'),
    newListTagsForResourceResponse,

    -- ** SetTagsForResource
    SetTagsForResource (SetTagsForResource'),
    newSetTagsForResource,
    SetTagsForResourceResponse (SetTagsForResourceResponse'),
    newSetTagsForResourceResponse,

    -- ** DescribeCrossAccountAccessRole
    DescribeCrossAccountAccessRole (DescribeCrossAccountAccessRole'),
    newDescribeCrossAccountAccessRole,
    DescribeCrossAccountAccessRoleResponse (DescribeCrossAccountAccessRoleResponse'),
    newDescribeCrossAccountAccessRoleResponse,

    -- ** DescribeAssessmentTemplates
    DescribeAssessmentTemplates (DescribeAssessmentTemplates'),
    newDescribeAssessmentTemplates,
    DescribeAssessmentTemplatesResponse (DescribeAssessmentTemplatesResponse'),
    newDescribeAssessmentTemplatesResponse,

    -- ** DescribeResourceGroups
    DescribeResourceGroups (DescribeResourceGroups'),
    newDescribeResourceGroups,
    DescribeResourceGroupsResponse (DescribeResourceGroupsResponse'),
    newDescribeResourceGroupsResponse,

    -- ** CreateAssessmentTarget
    CreateAssessmentTarget (CreateAssessmentTarget'),
    newCreateAssessmentTarget,
    CreateAssessmentTargetResponse (CreateAssessmentTargetResponse'),
    newCreateAssessmentTargetResponse,

    -- ** GetExclusionsPreview
    GetExclusionsPreview (GetExclusionsPreview'),
    newGetExclusionsPreview,
    GetExclusionsPreviewResponse (GetExclusionsPreviewResponse'),
    newGetExclusionsPreviewResponse,

    -- ** ListEventSubscriptions (Paginated)
    ListEventSubscriptions (ListEventSubscriptions'),
    newListEventSubscriptions,
    ListEventSubscriptionsResponse (ListEventSubscriptionsResponse'),
    newListEventSubscriptionsResponse,

    -- ** RegisterCrossAccountAccessRole
    RegisterCrossAccountAccessRole (RegisterCrossAccountAccessRole'),
    newRegisterCrossAccountAccessRole,
    RegisterCrossAccountAccessRoleResponse (RegisterCrossAccountAccessRoleResponse'),
    newRegisterCrossAccountAccessRoleResponse,

    -- ** ListAssessmentTargets (Paginated)
    ListAssessmentTargets (ListAssessmentTargets'),
    newListAssessmentTargets,
    ListAssessmentTargetsResponse (ListAssessmentTargetsResponse'),
    newListAssessmentTargetsResponse,

    -- ** CreateExclusionsPreview
    CreateExclusionsPreview (CreateExclusionsPreview'),
    newCreateExclusionsPreview,
    CreateExclusionsPreviewResponse (CreateExclusionsPreviewResponse'),
    newCreateExclusionsPreviewResponse,

    -- ** CreateResourceGroup
    CreateResourceGroup (CreateResourceGroup'),
    newCreateResourceGroup,
    CreateResourceGroupResponse (CreateResourceGroupResponse'),
    newCreateResourceGroupResponse,

    -- ** DescribeRulesPackages
    DescribeRulesPackages (DescribeRulesPackages'),
    newDescribeRulesPackages,
    DescribeRulesPackagesResponse (DescribeRulesPackagesResponse'),
    newDescribeRulesPackagesResponse,

    -- ** StopAssessmentRun
    StopAssessmentRun (StopAssessmentRun'),
    newStopAssessmentRun,
    StopAssessmentRunResponse (StopAssessmentRunResponse'),
    newStopAssessmentRunResponse,

    -- ** ListExclusions (Paginated)
    ListExclusions (ListExclusions'),
    newListExclusions,
    ListExclusionsResponse (ListExclusionsResponse'),
    newListExclusionsResponse,

    -- ** PreviewAgents (Paginated)
    PreviewAgents (PreviewAgents'),
    newPreviewAgents,
    PreviewAgentsResponse (PreviewAgentsResponse'),
    newPreviewAgentsResponse,

    -- ** DescribeFindings
    DescribeFindings (DescribeFindings'),
    newDescribeFindings,
    DescribeFindingsResponse (DescribeFindingsResponse'),
    newDescribeFindingsResponse,

    -- ** AddAttributesToFindings
    AddAttributesToFindings (AddAttributesToFindings'),
    newAddAttributesToFindings,
    AddAttributesToFindingsResponse (AddAttributesToFindingsResponse'),
    newAddAttributesToFindingsResponse,

    -- ** UpdateAssessmentTarget
    UpdateAssessmentTarget (UpdateAssessmentTarget'),
    newUpdateAssessmentTarget,
    UpdateAssessmentTargetResponse (UpdateAssessmentTargetResponse'),
    newUpdateAssessmentTargetResponse,

    -- ** DeleteAssessmentTarget
    DeleteAssessmentTarget (DeleteAssessmentTarget'),
    newDeleteAssessmentTarget,
    DeleteAssessmentTargetResponse (DeleteAssessmentTargetResponse'),
    newDeleteAssessmentTargetResponse,

    -- ** DeleteAssessmentRun
    DeleteAssessmentRun (DeleteAssessmentRun'),
    newDeleteAssessmentRun,
    DeleteAssessmentRunResponse (DeleteAssessmentRunResponse'),
    newDeleteAssessmentRunResponse,

    -- ** ListAssessmentRuns (Paginated)
    ListAssessmentRuns (ListAssessmentRuns'),
    newListAssessmentRuns,
    ListAssessmentRunsResponse (ListAssessmentRunsResponse'),
    newListAssessmentRunsResponse,

    -- ** GetAssessmentReport
    GetAssessmentReport (GetAssessmentReport'),
    newGetAssessmentReport,
    GetAssessmentReportResponse (GetAssessmentReportResponse'),
    newGetAssessmentReportResponse,

    -- ** ListRulesPackages (Paginated)
    ListRulesPackages (ListRulesPackages'),
    newListRulesPackages,
    ListRulesPackagesResponse (ListRulesPackagesResponse'),
    newListRulesPackagesResponse,

    -- ** DescribeAssessmentRuns
    DescribeAssessmentRuns (DescribeAssessmentRuns'),
    newDescribeAssessmentRuns,
    DescribeAssessmentRunsResponse (DescribeAssessmentRunsResponse'),
    newDescribeAssessmentRunsResponse,

    -- ** UnsubscribeFromEvent
    UnsubscribeFromEvent (UnsubscribeFromEvent'),
    newUnsubscribeFromEvent,
    UnsubscribeFromEventResponse (UnsubscribeFromEventResponse'),
    newUnsubscribeFromEventResponse,

    -- ** RemoveAttributesFromFindings
    RemoveAttributesFromFindings (RemoveAttributesFromFindings'),
    newRemoveAttributesFromFindings,
    RemoveAttributesFromFindingsResponse (RemoveAttributesFromFindingsResponse'),
    newRemoveAttributesFromFindingsResponse,

    -- ** DescribeAssessmentTargets
    DescribeAssessmentTargets (DescribeAssessmentTargets'),
    newDescribeAssessmentTargets,
    DescribeAssessmentTargetsResponse (DescribeAssessmentTargetsResponse'),
    newDescribeAssessmentTargetsResponse,

    -- * Types

    -- ** AgentHealth
    AgentHealth (..),

    -- ** AgentHealthCode
    AgentHealthCode (..),

    -- ** AssessmentRunNotificationSnsStatusCode
    AssessmentRunNotificationSnsStatusCode (..),

    -- ** AssessmentRunState
    AssessmentRunState (..),

    -- ** AssetType
    AssetType (..),

    -- ** FailedItemErrorCode
    FailedItemErrorCode (..),

    -- ** InspectorEvent
    InspectorEvent (..),

    -- ** Locale
    Locale (..),

    -- ** PreviewStatus
    PreviewStatus (..),

    -- ** ReportFileFormat
    ReportFileFormat (..),

    -- ** ReportStatus
    ReportStatus (..),

    -- ** ReportType
    ReportType (..),

    -- ** ScopeType
    ScopeType (..),

    -- ** Severity
    Severity (..),

    -- ** StopAction
    StopAction (..),

    -- ** AgentFilter
    AgentFilter (AgentFilter'),
    newAgentFilter,

    -- ** AgentPreview
    AgentPreview (AgentPreview'),
    newAgentPreview,

    -- ** AssessmentRun
    AssessmentRun (AssessmentRun'),
    newAssessmentRun,

    -- ** AssessmentRunAgent
    AssessmentRunAgent (AssessmentRunAgent'),
    newAssessmentRunAgent,

    -- ** AssessmentRunFilter
    AssessmentRunFilter (AssessmentRunFilter'),
    newAssessmentRunFilter,

    -- ** AssessmentRunNotification
    AssessmentRunNotification (AssessmentRunNotification'),
    newAssessmentRunNotification,

    -- ** AssessmentRunStateChange
    AssessmentRunStateChange (AssessmentRunStateChange'),
    newAssessmentRunStateChange,

    -- ** AssessmentTarget
    AssessmentTarget (AssessmentTarget'),
    newAssessmentTarget,

    -- ** AssessmentTargetFilter
    AssessmentTargetFilter (AssessmentTargetFilter'),
    newAssessmentTargetFilter,

    -- ** AssessmentTemplate
    AssessmentTemplate (AssessmentTemplate'),
    newAssessmentTemplate,

    -- ** AssessmentTemplateFilter
    AssessmentTemplateFilter (AssessmentTemplateFilter'),
    newAssessmentTemplateFilter,

    -- ** AssetAttributes
    AssetAttributes (AssetAttributes'),
    newAssetAttributes,

    -- ** Attribute
    Attribute (Attribute'),
    newAttribute,

    -- ** DurationRange
    DurationRange (DurationRange'),
    newDurationRange,

    -- ** EventSubscription
    EventSubscription (EventSubscription'),
    newEventSubscription,

    -- ** Exclusion
    Exclusion (Exclusion'),
    newExclusion,

    -- ** ExclusionPreview
    ExclusionPreview (ExclusionPreview'),
    newExclusionPreview,

    -- ** FailedItemDetails
    FailedItemDetails (FailedItemDetails'),
    newFailedItemDetails,

    -- ** Finding
    Finding (Finding'),
    newFinding,

    -- ** FindingFilter
    FindingFilter (FindingFilter'),
    newFindingFilter,

    -- ** InspectorServiceAttributes
    InspectorServiceAttributes (InspectorServiceAttributes'),
    newInspectorServiceAttributes,

    -- ** NetworkInterface
    NetworkInterface (NetworkInterface'),
    newNetworkInterface,

    -- ** PrivateIp
    PrivateIp (PrivateIp'),
    newPrivateIp,

    -- ** ResourceGroup
    ResourceGroup (ResourceGroup'),
    newResourceGroup,

    -- ** ResourceGroupTag
    ResourceGroupTag (ResourceGroupTag'),
    newResourceGroupTag,

    -- ** RulesPackage
    RulesPackage (RulesPackage'),
    newRulesPackage,

    -- ** Scope
    Scope (Scope'),
    newScope,

    -- ** SecurityGroup
    SecurityGroup (SecurityGroup'),
    newSecurityGroup,

    -- ** Subscription
    Subscription (Subscription'),
    newSubscription,

    -- ** Tag
    Tag (Tag'),
    newTag,

    -- ** TelemetryMetadata
    TelemetryMetadata (TelemetryMetadata'),
    newTelemetryMetadata,

    -- ** TimestampRange
    TimestampRange (TimestampRange'),
    newTimestampRange,
  )
where

import Amazonka.Inspector.AddAttributesToFindings
import Amazonka.Inspector.CreateAssessmentTarget
import Amazonka.Inspector.CreateAssessmentTemplate
import Amazonka.Inspector.CreateExclusionsPreview
import Amazonka.Inspector.CreateResourceGroup
import Amazonka.Inspector.DeleteAssessmentRun
import Amazonka.Inspector.DeleteAssessmentTarget
import Amazonka.Inspector.DeleteAssessmentTemplate
import Amazonka.Inspector.DescribeAssessmentRuns
import Amazonka.Inspector.DescribeAssessmentTargets
import Amazonka.Inspector.DescribeAssessmentTemplates
import Amazonka.Inspector.DescribeCrossAccountAccessRole
import Amazonka.Inspector.DescribeExclusions
import Amazonka.Inspector.DescribeFindings
import Amazonka.Inspector.DescribeResourceGroups
import Amazonka.Inspector.DescribeRulesPackages
import Amazonka.Inspector.GetAssessmentReport
import Amazonka.Inspector.GetExclusionsPreview
import Amazonka.Inspector.GetTelemetryMetadata
import Amazonka.Inspector.Lens
import Amazonka.Inspector.ListAssessmentRunAgents
import Amazonka.Inspector.ListAssessmentRuns
import Amazonka.Inspector.ListAssessmentTargets
import Amazonka.Inspector.ListAssessmentTemplates
import Amazonka.Inspector.ListEventSubscriptions
import Amazonka.Inspector.ListExclusions
import Amazonka.Inspector.ListFindings
import Amazonka.Inspector.ListRulesPackages
import Amazonka.Inspector.ListTagsForResource
import Amazonka.Inspector.PreviewAgents
import Amazonka.Inspector.RegisterCrossAccountAccessRole
import Amazonka.Inspector.RemoveAttributesFromFindings
import Amazonka.Inspector.SetTagsForResource
import Amazonka.Inspector.StartAssessmentRun
import Amazonka.Inspector.StopAssessmentRun
import Amazonka.Inspector.SubscribeToEvent
import Amazonka.Inspector.Types
import Amazonka.Inspector.UnsubscribeFromEvent
import Amazonka.Inspector.UpdateAssessmentTarget
import Amazonka.Inspector.Waiters

-- $errors
-- Error matchers are designed for use with the functions provided by
-- <http://hackage.haskell.org/package/lens/docs/Control-Exception-Lens.html Control.Exception.Lens>.
-- This allows catching (and rethrowing) service specific errors returned
-- by 'Inspector'.

-- $operations
-- Some AWS operations return results that are incomplete and require subsequent
-- requests in order to obtain the entire result set. The process of sending
-- subsequent requests to continue where a previous request left off is called
-- pagination. For example, the 'ListObjects' operation of Amazon S3 returns up to
-- 1000 objects at a time, and you must send subsequent requests with the
-- appropriate Marker in order to retrieve the next page of results.
--
-- Operations that have an 'AWSPager' instance can transparently perform subsequent
-- requests, correctly setting Markers and other request facets to iterate through
-- the entire result set of a truncated API operation. Operations which support
-- this have an additional note in the documentation.
--
-- Many operations have the ability to filter results on the server side. See the
-- individual operation parameters for details.

-- $waiters
-- Waiters poll by repeatedly sending a request until some remote success condition
-- configured by the 'Wait' specification is fulfilled. The 'Wait' specification
-- determines how many attempts should be made, in addition to delay and retry strategies.
