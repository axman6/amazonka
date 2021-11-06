{-# LANGUAGE NoImplicitPrelude #-}
{-# OPTIONS_GHC -fno-warn-duplicate-exports #-}
{-# OPTIONS_GHC -fno-warn-unused-imports #-}

-- Derived from AWS service descriptions, licensed under Apache 2.0.

-- |
-- Module      : Amazonka.Detective.Lens
-- Copyright   : (c) 2013-2021 Brendan Hay
-- License     : Mozilla Public License, v. 2.0.
-- Maintainer  : Brendan Hay <brendan.g.hay+amazonka@gmail.com>
-- Stability   : auto-generated
-- Portability : non-portable (GHC extensions)
module Amazonka.Detective.Lens
  ( -- * Operations

    -- ** StartMonitoringMember
    startMonitoringMember_graphArn,
    startMonitoringMember_accountId,

    -- ** DeleteMembers
    deleteMembers_graphArn,
    deleteMembers_accountIds,
    deleteMembersResponse_accountIds,
    deleteMembersResponse_unprocessedAccounts,
    deleteMembersResponse_httpStatus,

    -- ** ListTagsForResource
    listTagsForResource_resourceArn,
    listTagsForResourceResponse_tags,
    listTagsForResourceResponse_httpStatus,

    -- ** DeleteGraph
    deleteGraph_graphArn,

    -- ** ListInvitations
    listInvitations_nextToken,
    listInvitations_maxResults,
    listInvitationsResponse_invitations,
    listInvitationsResponse_nextToken,
    listInvitationsResponse_httpStatus,

    -- ** DisassociateMembership
    disassociateMembership_graphArn,

    -- ** AcceptInvitation
    acceptInvitation_graphArn,

    -- ** ListMembers
    listMembers_nextToken,
    listMembers_maxResults,
    listMembers_graphArn,
    listMembersResponse_memberDetails,
    listMembersResponse_nextToken,
    listMembersResponse_httpStatus,

    -- ** CreateMembers
    createMembers_disableEmailNotification,
    createMembers_message,
    createMembers_graphArn,
    createMembers_accounts,
    createMembersResponse_members,
    createMembersResponse_unprocessedAccounts,
    createMembersResponse_httpStatus,

    -- ** GetMembers
    getMembers_graphArn,
    getMembers_accountIds,
    getMembersResponse_memberDetails,
    getMembersResponse_unprocessedAccounts,
    getMembersResponse_httpStatus,

    -- ** ListGraphs
    listGraphs_nextToken,
    listGraphs_maxResults,
    listGraphsResponse_nextToken,
    listGraphsResponse_graphList,
    listGraphsResponse_httpStatus,

    -- ** TagResource
    tagResource_resourceArn,
    tagResource_tags,
    tagResourceResponse_httpStatus,

    -- ** CreateGraph
    createGraph_tags,
    createGraphResponse_graphArn,
    createGraphResponse_httpStatus,

    -- ** UntagResource
    untagResource_resourceArn,
    untagResource_tagKeys,
    untagResourceResponse_httpStatus,

    -- ** RejectInvitation
    rejectInvitation_graphArn,

    -- * Types

    -- ** Account
    account_accountId,
    account_emailAddress,

    -- ** Graph
    graph_arn,
    graph_createdTime,

    -- ** MemberDetail
    memberDetail_percentOfGraphUtilizationUpdatedTime,
    memberDetail_status,
    memberDetail_invitedTime,
    memberDetail_administratorId,
    memberDetail_graphArn,
    memberDetail_masterId,
    memberDetail_accountId,
    memberDetail_disabledReason,
    memberDetail_percentOfGraphUtilization,
    memberDetail_emailAddress,
    memberDetail_volumeUsageUpdatedTime,
    memberDetail_updatedTime,
    memberDetail_volumeUsageInBytes,

    -- ** UnprocessedAccount
    unprocessedAccount_accountId,
    unprocessedAccount_reason,
  )
where

import Amazonka.Detective.AcceptInvitation
import Amazonka.Detective.CreateGraph
import Amazonka.Detective.CreateMembers
import Amazonka.Detective.DeleteGraph
import Amazonka.Detective.DeleteMembers
import Amazonka.Detective.DisassociateMembership
import Amazonka.Detective.GetMembers
import Amazonka.Detective.ListGraphs
import Amazonka.Detective.ListInvitations
import Amazonka.Detective.ListMembers
import Amazonka.Detective.ListTagsForResource
import Amazonka.Detective.RejectInvitation
import Amazonka.Detective.StartMonitoringMember
import Amazonka.Detective.TagResource
import Amazonka.Detective.Types.Account
import Amazonka.Detective.Types.Graph
import Amazonka.Detective.Types.MemberDetail
import Amazonka.Detective.Types.UnprocessedAccount
import Amazonka.Detective.UntagResource
