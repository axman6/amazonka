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
-- Module      : Amazonka.QuickSight.DescribeGroup
-- Copyright   : (c) 2013-2021 Brendan Hay
-- License     : Mozilla Public License, v. 2.0.
-- Maintainer  : Brendan Hay <brendan.g.hay+amazonka@gmail.com>
-- Stability   : auto-generated
-- Portability : non-portable (GHC extensions)
--
-- Returns an Amazon QuickSight group\'s description and Amazon Resource
-- Name (ARN).
module Amazonka.QuickSight.DescribeGroup
  ( -- * Creating a Request
    DescribeGroup (..),
    newDescribeGroup,

    -- * Request Lenses
    describeGroup_groupName,
    describeGroup_awsAccountId,
    describeGroup_namespace,

    -- * Destructuring the Response
    DescribeGroupResponse (..),
    newDescribeGroupResponse,

    -- * Response Lenses
    describeGroupResponse_requestId,
    describeGroupResponse_group,
    describeGroupResponse_status,
  )
where

import qualified Amazonka.Core as Core
import qualified Amazonka.Lens as Lens
import qualified Amazonka.Prelude as Prelude
import Amazonka.QuickSight.Types
import qualified Amazonka.Request as Request
import qualified Amazonka.Response as Response

-- | /See:/ 'newDescribeGroup' smart constructor.
data DescribeGroup = DescribeGroup'
  { -- | The name of the group that you want to describe.
    groupName :: Prelude.Text,
    -- | The ID for the Amazon Web Services account that the group is in.
    -- Currently, you use the ID for the Amazon Web Services account that
    -- contains your Amazon QuickSight account.
    awsAccountId :: Prelude.Text,
    -- | The namespace. Currently, you should set this to @default@.
    namespace :: Prelude.Text
  }
  deriving (Prelude.Eq, Prelude.Read, Prelude.Show, Prelude.Generic)

-- |
-- Create a value of 'DescribeGroup' with all optional fields omitted.
--
-- Use <https://hackage.haskell.org/package/generic-lens generic-lens> or <https://hackage.haskell.org/package/optics optics> to modify other optional fields.
--
-- The following record fields are available, with the corresponding lenses provided
-- for backwards compatibility:
--
-- 'groupName', 'describeGroup_groupName' - The name of the group that you want to describe.
--
-- 'awsAccountId', 'describeGroup_awsAccountId' - The ID for the Amazon Web Services account that the group is in.
-- Currently, you use the ID for the Amazon Web Services account that
-- contains your Amazon QuickSight account.
--
-- 'namespace', 'describeGroup_namespace' - The namespace. Currently, you should set this to @default@.
newDescribeGroup ::
  -- | 'groupName'
  Prelude.Text ->
  -- | 'awsAccountId'
  Prelude.Text ->
  -- | 'namespace'
  Prelude.Text ->
  DescribeGroup
newDescribeGroup
  pGroupName_
  pAwsAccountId_
  pNamespace_ =
    DescribeGroup'
      { groupName = pGroupName_,
        awsAccountId = pAwsAccountId_,
        namespace = pNamespace_
      }

-- | The name of the group that you want to describe.
describeGroup_groupName :: Lens.Lens' DescribeGroup Prelude.Text
describeGroup_groupName = Lens.lens (\DescribeGroup' {groupName} -> groupName) (\s@DescribeGroup' {} a -> s {groupName = a} :: DescribeGroup)

-- | The ID for the Amazon Web Services account that the group is in.
-- Currently, you use the ID for the Amazon Web Services account that
-- contains your Amazon QuickSight account.
describeGroup_awsAccountId :: Lens.Lens' DescribeGroup Prelude.Text
describeGroup_awsAccountId = Lens.lens (\DescribeGroup' {awsAccountId} -> awsAccountId) (\s@DescribeGroup' {} a -> s {awsAccountId = a} :: DescribeGroup)

-- | The namespace. Currently, you should set this to @default@.
describeGroup_namespace :: Lens.Lens' DescribeGroup Prelude.Text
describeGroup_namespace = Lens.lens (\DescribeGroup' {namespace} -> namespace) (\s@DescribeGroup' {} a -> s {namespace = a} :: DescribeGroup)

instance Core.AWSRequest DescribeGroup where
  type
    AWSResponse DescribeGroup =
      DescribeGroupResponse
  request = Request.get defaultService
  response =
    Response.receiveJSON
      ( \s h x ->
          DescribeGroupResponse'
            Prelude.<$> (x Core..?> "RequestId")
            Prelude.<*> (x Core..?> "Group")
            Prelude.<*> (Prelude.pure (Prelude.fromEnum s))
      )

instance Prelude.Hashable DescribeGroup

instance Prelude.NFData DescribeGroup

instance Core.ToHeaders DescribeGroup where
  toHeaders =
    Prelude.const
      ( Prelude.mconcat
          [ "Content-Type"
              Core.=# ( "application/x-amz-json-1.0" ::
                          Prelude.ByteString
                      )
          ]
      )

instance Core.ToPath DescribeGroup where
  toPath DescribeGroup' {..} =
    Prelude.mconcat
      [ "/accounts/",
        Core.toBS awsAccountId,
        "/namespaces/",
        Core.toBS namespace,
        "/groups/",
        Core.toBS groupName
      ]

instance Core.ToQuery DescribeGroup where
  toQuery = Prelude.const Prelude.mempty

-- | /See:/ 'newDescribeGroupResponse' smart constructor.
data DescribeGroupResponse = DescribeGroupResponse'
  { -- | The Amazon Web Services request ID for this operation.
    requestId :: Prelude.Maybe Prelude.Text,
    -- | The name of the group.
    group' :: Prelude.Maybe Group,
    -- | The HTTP status of the request.
    status :: Prelude.Int
  }
  deriving (Prelude.Eq, Prelude.Read, Prelude.Show, Prelude.Generic)

-- |
-- Create a value of 'DescribeGroupResponse' with all optional fields omitted.
--
-- Use <https://hackage.haskell.org/package/generic-lens generic-lens> or <https://hackage.haskell.org/package/optics optics> to modify other optional fields.
--
-- The following record fields are available, with the corresponding lenses provided
-- for backwards compatibility:
--
-- 'requestId', 'describeGroupResponse_requestId' - The Amazon Web Services request ID for this operation.
--
-- 'group'', 'describeGroupResponse_group' - The name of the group.
--
-- 'status', 'describeGroupResponse_status' - The HTTP status of the request.
newDescribeGroupResponse ::
  -- | 'status'
  Prelude.Int ->
  DescribeGroupResponse
newDescribeGroupResponse pStatus_ =
  DescribeGroupResponse'
    { requestId = Prelude.Nothing,
      group' = Prelude.Nothing,
      status = pStatus_
    }

-- | The Amazon Web Services request ID for this operation.
describeGroupResponse_requestId :: Lens.Lens' DescribeGroupResponse (Prelude.Maybe Prelude.Text)
describeGroupResponse_requestId = Lens.lens (\DescribeGroupResponse' {requestId} -> requestId) (\s@DescribeGroupResponse' {} a -> s {requestId = a} :: DescribeGroupResponse)

-- | The name of the group.
describeGroupResponse_group :: Lens.Lens' DescribeGroupResponse (Prelude.Maybe Group)
describeGroupResponse_group = Lens.lens (\DescribeGroupResponse' {group'} -> group') (\s@DescribeGroupResponse' {} a -> s {group' = a} :: DescribeGroupResponse)

-- | The HTTP status of the request.
describeGroupResponse_status :: Lens.Lens' DescribeGroupResponse Prelude.Int
describeGroupResponse_status = Lens.lens (\DescribeGroupResponse' {status} -> status) (\s@DescribeGroupResponse' {} a -> s {status = a} :: DescribeGroupResponse)

instance Prelude.NFData DescribeGroupResponse
