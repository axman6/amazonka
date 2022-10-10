{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE StrictData #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE NoImplicitPrelude #-}
{-# OPTIONS_GHC -fno-warn-unused-binds #-}
{-# OPTIONS_GHC -fno-warn-unused-imports #-}
{-# OPTIONS_GHC -fno-warn-unused-matches #-}

-- Derived from AWS service descriptions, licensed under Apache 2.0.

-- |
-- Module      : Amazonka.Redshift.CreateEventSubscription
-- Copyright   : (c) 2013-2022 Brendan Hay
-- License     : Mozilla Public License, v. 2.0.
-- Maintainer  : Brendan Hay <brendan.g.hay+amazonka@gmail.com>
-- Stability   : auto-generated
-- Portability : non-portable (GHC extensions)
--
-- Creates an Amazon Redshift event notification subscription. This action
-- requires an ARN (Amazon Resource Name) of an Amazon SNS topic created by
-- either the Amazon Redshift console, the Amazon SNS console, or the
-- Amazon SNS API. To obtain an ARN with Amazon SNS, you must create a
-- topic in Amazon SNS and subscribe to the topic. The ARN is displayed in
-- the SNS console.
--
-- You can specify the source type, and lists of Amazon Redshift source
-- IDs, event categories, and event severities. Notifications will be sent
-- for all events you want that match those criteria. For example, you can
-- specify source type = cluster, source ID = my-cluster-1 and mycluster2,
-- event categories = Availability, Backup, and severity = ERROR. The
-- subscription will only send notifications for those ERROR events in the
-- Availability and Backup categories for the specified clusters.
--
-- If you specify both the source type and source IDs, such as source type
-- = cluster and source identifier = my-cluster-1, notifications will be
-- sent for all the cluster events for my-cluster-1. If you specify a
-- source type but do not specify a source identifier, you will receive
-- notice of the events for the objects of that type in your Amazon Web
-- Services account. If you do not specify either the SourceType nor the
-- SourceIdentifier, you will be notified of events generated from all
-- Amazon Redshift sources belonging to your Amazon Web Services account.
-- You must specify a source type if you specify a source ID.
module Amazonka.Redshift.CreateEventSubscription
  ( -- * Creating a Request
    CreateEventSubscription (..),
    newCreateEventSubscription,

    -- * Request Lenses
    createEventSubscription_tags,
    createEventSubscription_severity,
    createEventSubscription_sourceIds,
    createEventSubscription_sourceType,
    createEventSubscription_enabled,
    createEventSubscription_eventCategories,
    createEventSubscription_subscriptionName,
    createEventSubscription_snsTopicArn,

    -- * Destructuring the Response
    CreateEventSubscriptionResponse (..),
    newCreateEventSubscriptionResponse,

    -- * Response Lenses
    createEventSubscriptionResponse_eventSubscription,
    createEventSubscriptionResponse_httpStatus,
  )
where

import qualified Amazonka.Core as Core
import qualified Amazonka.Lens as Lens
import qualified Amazonka.Prelude as Prelude
import Amazonka.Redshift.Types
import qualified Amazonka.Request as Request
import qualified Amazonka.Response as Response

-- |
--
-- /See:/ 'newCreateEventSubscription' smart constructor.
data CreateEventSubscription = CreateEventSubscription'
  { -- | A list of tag instances.
    tags :: Prelude.Maybe [Tag],
    -- | Specifies the Amazon Redshift event severity to be published by the
    -- event notification subscription.
    --
    -- Values: ERROR, INFO
    severity :: Prelude.Maybe Prelude.Text,
    -- | A list of one or more identifiers of Amazon Redshift source objects. All
    -- of the objects must be of the same type as was specified in the source
    -- type parameter. The event subscription will return only events generated
    -- by the specified objects. If not specified, then events are returned for
    -- all objects within the source type specified.
    --
    -- Example: my-cluster-1, my-cluster-2
    --
    -- Example: my-snapshot-20131010
    sourceIds :: Prelude.Maybe [Prelude.Text],
    -- | The type of source that will be generating the events. For example, if
    -- you want to be notified of events generated by a cluster, you would set
    -- this parameter to cluster. If this value is not specified, events are
    -- returned for all Amazon Redshift objects in your Amazon Web Services
    -- account. You must specify a source type in order to specify source IDs.
    --
    -- Valid values: cluster, cluster-parameter-group, cluster-security-group,
    -- cluster-snapshot, and scheduled-action.
    sourceType :: Prelude.Maybe Prelude.Text,
    -- | A boolean value; set to @true@ to activate the subscription, and set to
    -- @false@ to create the subscription but not activate it.
    enabled :: Prelude.Maybe Prelude.Bool,
    -- | Specifies the Amazon Redshift event categories to be published by the
    -- event notification subscription.
    --
    -- Values: configuration, management, monitoring, security, pending
    eventCategories :: Prelude.Maybe [Prelude.Text],
    -- | The name of the event subscription to be created.
    --
    -- Constraints:
    --
    -- -   Cannot be null, empty, or blank.
    --
    -- -   Must contain from 1 to 255 alphanumeric characters or hyphens.
    --
    -- -   First character must be a letter.
    --
    -- -   Cannot end with a hyphen or contain two consecutive hyphens.
    subscriptionName :: Prelude.Text,
    -- | The Amazon Resource Name (ARN) of the Amazon SNS topic used to transmit
    -- the event notifications. The ARN is created by Amazon SNS when you
    -- create a topic and subscribe to it.
    snsTopicArn :: Prelude.Text
  }
  deriving (Prelude.Eq, Prelude.Read, Prelude.Show, Prelude.Generic)

-- |
-- Create a value of 'CreateEventSubscription' with all optional fields omitted.
--
-- Use <https://hackage.haskell.org/package/generic-lens generic-lens> or <https://hackage.haskell.org/package/optics optics> to modify other optional fields.
--
-- The following record fields are available, with the corresponding lenses provided
-- for backwards compatibility:
--
-- 'tags', 'createEventSubscription_tags' - A list of tag instances.
--
-- 'severity', 'createEventSubscription_severity' - Specifies the Amazon Redshift event severity to be published by the
-- event notification subscription.
--
-- Values: ERROR, INFO
--
-- 'sourceIds', 'createEventSubscription_sourceIds' - A list of one or more identifiers of Amazon Redshift source objects. All
-- of the objects must be of the same type as was specified in the source
-- type parameter. The event subscription will return only events generated
-- by the specified objects. If not specified, then events are returned for
-- all objects within the source type specified.
--
-- Example: my-cluster-1, my-cluster-2
--
-- Example: my-snapshot-20131010
--
-- 'sourceType', 'createEventSubscription_sourceType' - The type of source that will be generating the events. For example, if
-- you want to be notified of events generated by a cluster, you would set
-- this parameter to cluster. If this value is not specified, events are
-- returned for all Amazon Redshift objects in your Amazon Web Services
-- account. You must specify a source type in order to specify source IDs.
--
-- Valid values: cluster, cluster-parameter-group, cluster-security-group,
-- cluster-snapshot, and scheduled-action.
--
-- 'enabled', 'createEventSubscription_enabled' - A boolean value; set to @true@ to activate the subscription, and set to
-- @false@ to create the subscription but not activate it.
--
-- 'eventCategories', 'createEventSubscription_eventCategories' - Specifies the Amazon Redshift event categories to be published by the
-- event notification subscription.
--
-- Values: configuration, management, monitoring, security, pending
--
-- 'subscriptionName', 'createEventSubscription_subscriptionName' - The name of the event subscription to be created.
--
-- Constraints:
--
-- -   Cannot be null, empty, or blank.
--
-- -   Must contain from 1 to 255 alphanumeric characters or hyphens.
--
-- -   First character must be a letter.
--
-- -   Cannot end with a hyphen or contain two consecutive hyphens.
--
-- 'snsTopicArn', 'createEventSubscription_snsTopicArn' - The Amazon Resource Name (ARN) of the Amazon SNS topic used to transmit
-- the event notifications. The ARN is created by Amazon SNS when you
-- create a topic and subscribe to it.
newCreateEventSubscription ::
  -- | 'subscriptionName'
  Prelude.Text ->
  -- | 'snsTopicArn'
  Prelude.Text ->
  CreateEventSubscription
newCreateEventSubscription
  pSubscriptionName_
  pSnsTopicArn_ =
    CreateEventSubscription'
      { tags = Prelude.Nothing,
        severity = Prelude.Nothing,
        sourceIds = Prelude.Nothing,
        sourceType = Prelude.Nothing,
        enabled = Prelude.Nothing,
        eventCategories = Prelude.Nothing,
        subscriptionName = pSubscriptionName_,
        snsTopicArn = pSnsTopicArn_
      }

-- | A list of tag instances.
createEventSubscription_tags :: Lens.Lens' CreateEventSubscription (Prelude.Maybe [Tag])
createEventSubscription_tags = Lens.lens (\CreateEventSubscription' {tags} -> tags) (\s@CreateEventSubscription' {} a -> s {tags = a} :: CreateEventSubscription) Prelude.. Lens.mapping Lens.coerced

-- | Specifies the Amazon Redshift event severity to be published by the
-- event notification subscription.
--
-- Values: ERROR, INFO
createEventSubscription_severity :: Lens.Lens' CreateEventSubscription (Prelude.Maybe Prelude.Text)
createEventSubscription_severity = Lens.lens (\CreateEventSubscription' {severity} -> severity) (\s@CreateEventSubscription' {} a -> s {severity = a} :: CreateEventSubscription)

-- | A list of one or more identifiers of Amazon Redshift source objects. All
-- of the objects must be of the same type as was specified in the source
-- type parameter. The event subscription will return only events generated
-- by the specified objects. If not specified, then events are returned for
-- all objects within the source type specified.
--
-- Example: my-cluster-1, my-cluster-2
--
-- Example: my-snapshot-20131010
createEventSubscription_sourceIds :: Lens.Lens' CreateEventSubscription (Prelude.Maybe [Prelude.Text])
createEventSubscription_sourceIds = Lens.lens (\CreateEventSubscription' {sourceIds} -> sourceIds) (\s@CreateEventSubscription' {} a -> s {sourceIds = a} :: CreateEventSubscription) Prelude.. Lens.mapping Lens.coerced

-- | The type of source that will be generating the events. For example, if
-- you want to be notified of events generated by a cluster, you would set
-- this parameter to cluster. If this value is not specified, events are
-- returned for all Amazon Redshift objects in your Amazon Web Services
-- account. You must specify a source type in order to specify source IDs.
--
-- Valid values: cluster, cluster-parameter-group, cluster-security-group,
-- cluster-snapshot, and scheduled-action.
createEventSubscription_sourceType :: Lens.Lens' CreateEventSubscription (Prelude.Maybe Prelude.Text)
createEventSubscription_sourceType = Lens.lens (\CreateEventSubscription' {sourceType} -> sourceType) (\s@CreateEventSubscription' {} a -> s {sourceType = a} :: CreateEventSubscription)

-- | A boolean value; set to @true@ to activate the subscription, and set to
-- @false@ to create the subscription but not activate it.
createEventSubscription_enabled :: Lens.Lens' CreateEventSubscription (Prelude.Maybe Prelude.Bool)
createEventSubscription_enabled = Lens.lens (\CreateEventSubscription' {enabled} -> enabled) (\s@CreateEventSubscription' {} a -> s {enabled = a} :: CreateEventSubscription)

-- | Specifies the Amazon Redshift event categories to be published by the
-- event notification subscription.
--
-- Values: configuration, management, monitoring, security, pending
createEventSubscription_eventCategories :: Lens.Lens' CreateEventSubscription (Prelude.Maybe [Prelude.Text])
createEventSubscription_eventCategories = Lens.lens (\CreateEventSubscription' {eventCategories} -> eventCategories) (\s@CreateEventSubscription' {} a -> s {eventCategories = a} :: CreateEventSubscription) Prelude.. Lens.mapping Lens.coerced

-- | The name of the event subscription to be created.
--
-- Constraints:
--
-- -   Cannot be null, empty, or blank.
--
-- -   Must contain from 1 to 255 alphanumeric characters or hyphens.
--
-- -   First character must be a letter.
--
-- -   Cannot end with a hyphen or contain two consecutive hyphens.
createEventSubscription_subscriptionName :: Lens.Lens' CreateEventSubscription Prelude.Text
createEventSubscription_subscriptionName = Lens.lens (\CreateEventSubscription' {subscriptionName} -> subscriptionName) (\s@CreateEventSubscription' {} a -> s {subscriptionName = a} :: CreateEventSubscription)

-- | The Amazon Resource Name (ARN) of the Amazon SNS topic used to transmit
-- the event notifications. The ARN is created by Amazon SNS when you
-- create a topic and subscribe to it.
createEventSubscription_snsTopicArn :: Lens.Lens' CreateEventSubscription Prelude.Text
createEventSubscription_snsTopicArn = Lens.lens (\CreateEventSubscription' {snsTopicArn} -> snsTopicArn) (\s@CreateEventSubscription' {} a -> s {snsTopicArn = a} :: CreateEventSubscription)

instance Core.AWSRequest CreateEventSubscription where
  type
    AWSResponse CreateEventSubscription =
      CreateEventSubscriptionResponse
  request = Request.postQuery defaultService
  response =
    Response.receiveXMLWrapper
      "CreateEventSubscriptionResult"
      ( \s h x ->
          CreateEventSubscriptionResponse'
            Prelude.<$> (x Core..@? "EventSubscription")
            Prelude.<*> (Prelude.pure (Prelude.fromEnum s))
      )

instance Prelude.Hashable CreateEventSubscription where
  hashWithSalt _salt CreateEventSubscription' {..} =
    _salt `Prelude.hashWithSalt` tags
      `Prelude.hashWithSalt` severity
      `Prelude.hashWithSalt` sourceIds
      `Prelude.hashWithSalt` sourceType
      `Prelude.hashWithSalt` enabled
      `Prelude.hashWithSalt` eventCategories
      `Prelude.hashWithSalt` subscriptionName
      `Prelude.hashWithSalt` snsTopicArn

instance Prelude.NFData CreateEventSubscription where
  rnf CreateEventSubscription' {..} =
    Prelude.rnf tags
      `Prelude.seq` Prelude.rnf severity
      `Prelude.seq` Prelude.rnf sourceIds
      `Prelude.seq` Prelude.rnf sourceType
      `Prelude.seq` Prelude.rnf enabled
      `Prelude.seq` Prelude.rnf eventCategories
      `Prelude.seq` Prelude.rnf subscriptionName
      `Prelude.seq` Prelude.rnf snsTopicArn

instance Core.ToHeaders CreateEventSubscription where
  toHeaders = Prelude.const Prelude.mempty

instance Core.ToPath CreateEventSubscription where
  toPath = Prelude.const "/"

instance Core.ToQuery CreateEventSubscription where
  toQuery CreateEventSubscription' {..} =
    Prelude.mconcat
      [ "Action"
          Core.=: ("CreateEventSubscription" :: Prelude.ByteString),
        "Version"
          Core.=: ("2012-12-01" :: Prelude.ByteString),
        "Tags"
          Core.=: Core.toQuery
            (Core.toQueryList "Tag" Prelude.<$> tags),
        "Severity" Core.=: severity,
        "SourceIds"
          Core.=: Core.toQuery
            (Core.toQueryList "SourceId" Prelude.<$> sourceIds),
        "SourceType" Core.=: sourceType,
        "Enabled" Core.=: enabled,
        "EventCategories"
          Core.=: Core.toQuery
            ( Core.toQueryList "EventCategory"
                Prelude.<$> eventCategories
            ),
        "SubscriptionName" Core.=: subscriptionName,
        "SnsTopicArn" Core.=: snsTopicArn
      ]

-- | /See:/ 'newCreateEventSubscriptionResponse' smart constructor.
data CreateEventSubscriptionResponse = CreateEventSubscriptionResponse'
  { eventSubscription :: Prelude.Maybe EventSubscription,
    -- | The response's http status code.
    httpStatus :: Prelude.Int
  }
  deriving (Prelude.Eq, Prelude.Read, Prelude.Show, Prelude.Generic)

-- |
-- Create a value of 'CreateEventSubscriptionResponse' with all optional fields omitted.
--
-- Use <https://hackage.haskell.org/package/generic-lens generic-lens> or <https://hackage.haskell.org/package/optics optics> to modify other optional fields.
--
-- The following record fields are available, with the corresponding lenses provided
-- for backwards compatibility:
--
-- 'eventSubscription', 'createEventSubscriptionResponse_eventSubscription' - Undocumented member.
--
-- 'httpStatus', 'createEventSubscriptionResponse_httpStatus' - The response's http status code.
newCreateEventSubscriptionResponse ::
  -- | 'httpStatus'
  Prelude.Int ->
  CreateEventSubscriptionResponse
newCreateEventSubscriptionResponse pHttpStatus_ =
  CreateEventSubscriptionResponse'
    { eventSubscription =
        Prelude.Nothing,
      httpStatus = pHttpStatus_
    }

-- | Undocumented member.
createEventSubscriptionResponse_eventSubscription :: Lens.Lens' CreateEventSubscriptionResponse (Prelude.Maybe EventSubscription)
createEventSubscriptionResponse_eventSubscription = Lens.lens (\CreateEventSubscriptionResponse' {eventSubscription} -> eventSubscription) (\s@CreateEventSubscriptionResponse' {} a -> s {eventSubscription = a} :: CreateEventSubscriptionResponse)

-- | The response's http status code.
createEventSubscriptionResponse_httpStatus :: Lens.Lens' CreateEventSubscriptionResponse Prelude.Int
createEventSubscriptionResponse_httpStatus = Lens.lens (\CreateEventSubscriptionResponse' {httpStatus} -> httpStatus) (\s@CreateEventSubscriptionResponse' {} a -> s {httpStatus = a} :: CreateEventSubscriptionResponse)

instance
  Prelude.NFData
    CreateEventSubscriptionResponse
  where
  rnf CreateEventSubscriptionResponse' {..} =
    Prelude.rnf eventSubscription
      `Prelude.seq` Prelude.rnf httpStatus
