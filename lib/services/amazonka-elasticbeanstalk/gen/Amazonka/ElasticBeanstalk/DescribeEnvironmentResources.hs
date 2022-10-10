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
-- Module      : Amazonka.ElasticBeanstalk.DescribeEnvironmentResources
-- Copyright   : (c) 2013-2022 Brendan Hay
-- License     : Mozilla Public License, v. 2.0.
-- Maintainer  : Brendan Hay <brendan.g.hay+amazonka@gmail.com>
-- Stability   : auto-generated
-- Portability : non-portable (GHC extensions)
--
-- Returns AWS resources for this environment.
module Amazonka.ElasticBeanstalk.DescribeEnvironmentResources
  ( -- * Creating a Request
    DescribeEnvironmentResources (..),
    newDescribeEnvironmentResources,

    -- * Request Lenses
    describeEnvironmentResources_environmentName,
    describeEnvironmentResources_environmentId,

    -- * Destructuring the Response
    DescribeEnvironmentResourcesResponse (..),
    newDescribeEnvironmentResourcesResponse,

    -- * Response Lenses
    describeEnvironmentResourcesResponse_environmentResources,
    describeEnvironmentResourcesResponse_httpStatus,
  )
where

import qualified Amazonka.Core as Core
import Amazonka.ElasticBeanstalk.Types
import qualified Amazonka.Lens as Lens
import qualified Amazonka.Prelude as Prelude
import qualified Amazonka.Request as Request
import qualified Amazonka.Response as Response

-- | Request to describe the resources in an environment.
--
-- /See:/ 'newDescribeEnvironmentResources' smart constructor.
data DescribeEnvironmentResources = DescribeEnvironmentResources'
  { -- | The name of the environment to retrieve AWS resource usage data.
    --
    -- Condition: You must specify either this or an EnvironmentId, or both. If
    -- you do not specify either, AWS Elastic Beanstalk returns
    -- @MissingRequiredParameter@ error.
    environmentName :: Prelude.Maybe Prelude.Text,
    -- | The ID of the environment to retrieve AWS resource usage data.
    --
    -- Condition: You must specify either this or an EnvironmentName, or both.
    -- If you do not specify either, AWS Elastic Beanstalk returns
    -- @MissingRequiredParameter@ error.
    environmentId :: Prelude.Maybe Prelude.Text
  }
  deriving (Prelude.Eq, Prelude.Read, Prelude.Show, Prelude.Generic)

-- |
-- Create a value of 'DescribeEnvironmentResources' with all optional fields omitted.
--
-- Use <https://hackage.haskell.org/package/generic-lens generic-lens> or <https://hackage.haskell.org/package/optics optics> to modify other optional fields.
--
-- The following record fields are available, with the corresponding lenses provided
-- for backwards compatibility:
--
-- 'environmentName', 'describeEnvironmentResources_environmentName' - The name of the environment to retrieve AWS resource usage data.
--
-- Condition: You must specify either this or an EnvironmentId, or both. If
-- you do not specify either, AWS Elastic Beanstalk returns
-- @MissingRequiredParameter@ error.
--
-- 'environmentId', 'describeEnvironmentResources_environmentId' - The ID of the environment to retrieve AWS resource usage data.
--
-- Condition: You must specify either this or an EnvironmentName, or both.
-- If you do not specify either, AWS Elastic Beanstalk returns
-- @MissingRequiredParameter@ error.
newDescribeEnvironmentResources ::
  DescribeEnvironmentResources
newDescribeEnvironmentResources =
  DescribeEnvironmentResources'
    { environmentName =
        Prelude.Nothing,
      environmentId = Prelude.Nothing
    }

-- | The name of the environment to retrieve AWS resource usage data.
--
-- Condition: You must specify either this or an EnvironmentId, or both. If
-- you do not specify either, AWS Elastic Beanstalk returns
-- @MissingRequiredParameter@ error.
describeEnvironmentResources_environmentName :: Lens.Lens' DescribeEnvironmentResources (Prelude.Maybe Prelude.Text)
describeEnvironmentResources_environmentName = Lens.lens (\DescribeEnvironmentResources' {environmentName} -> environmentName) (\s@DescribeEnvironmentResources' {} a -> s {environmentName = a} :: DescribeEnvironmentResources)

-- | The ID of the environment to retrieve AWS resource usage data.
--
-- Condition: You must specify either this or an EnvironmentName, or both.
-- If you do not specify either, AWS Elastic Beanstalk returns
-- @MissingRequiredParameter@ error.
describeEnvironmentResources_environmentId :: Lens.Lens' DescribeEnvironmentResources (Prelude.Maybe Prelude.Text)
describeEnvironmentResources_environmentId = Lens.lens (\DescribeEnvironmentResources' {environmentId} -> environmentId) (\s@DescribeEnvironmentResources' {} a -> s {environmentId = a} :: DescribeEnvironmentResources)

instance Core.AWSRequest DescribeEnvironmentResources where
  type
    AWSResponse DescribeEnvironmentResources =
      DescribeEnvironmentResourcesResponse
  request = Request.postQuery defaultService
  response =
    Response.receiveXMLWrapper
      "DescribeEnvironmentResourcesResult"
      ( \s h x ->
          DescribeEnvironmentResourcesResponse'
            Prelude.<$> (x Core..@? "EnvironmentResources")
            Prelude.<*> (Prelude.pure (Prelude.fromEnum s))
      )

instance
  Prelude.Hashable
    DescribeEnvironmentResources
  where
  hashWithSalt _salt DescribeEnvironmentResources' {..} =
    _salt `Prelude.hashWithSalt` environmentName
      `Prelude.hashWithSalt` environmentId

instance Prelude.NFData DescribeEnvironmentResources where
  rnf DescribeEnvironmentResources' {..} =
    Prelude.rnf environmentName
      `Prelude.seq` Prelude.rnf environmentId

instance Core.ToHeaders DescribeEnvironmentResources where
  toHeaders = Prelude.const Prelude.mempty

instance Core.ToPath DescribeEnvironmentResources where
  toPath = Prelude.const "/"

instance Core.ToQuery DescribeEnvironmentResources where
  toQuery DescribeEnvironmentResources' {..} =
    Prelude.mconcat
      [ "Action"
          Core.=: ( "DescribeEnvironmentResources" ::
                      Prelude.ByteString
                  ),
        "Version"
          Core.=: ("2010-12-01" :: Prelude.ByteString),
        "EnvironmentName" Core.=: environmentName,
        "EnvironmentId" Core.=: environmentId
      ]

-- | Result message containing a list of environment resource descriptions.
--
-- /See:/ 'newDescribeEnvironmentResourcesResponse' smart constructor.
data DescribeEnvironmentResourcesResponse = DescribeEnvironmentResourcesResponse'
  { -- | A list of EnvironmentResourceDescription.
    environmentResources :: Prelude.Maybe EnvironmentResourceDescription,
    -- | The response's http status code.
    httpStatus :: Prelude.Int
  }
  deriving (Prelude.Eq, Prelude.Read, Prelude.Show, Prelude.Generic)

-- |
-- Create a value of 'DescribeEnvironmentResourcesResponse' with all optional fields omitted.
--
-- Use <https://hackage.haskell.org/package/generic-lens generic-lens> or <https://hackage.haskell.org/package/optics optics> to modify other optional fields.
--
-- The following record fields are available, with the corresponding lenses provided
-- for backwards compatibility:
--
-- 'environmentResources', 'describeEnvironmentResourcesResponse_environmentResources' - A list of EnvironmentResourceDescription.
--
-- 'httpStatus', 'describeEnvironmentResourcesResponse_httpStatus' - The response's http status code.
newDescribeEnvironmentResourcesResponse ::
  -- | 'httpStatus'
  Prelude.Int ->
  DescribeEnvironmentResourcesResponse
newDescribeEnvironmentResourcesResponse pHttpStatus_ =
  DescribeEnvironmentResourcesResponse'
    { environmentResources =
        Prelude.Nothing,
      httpStatus = pHttpStatus_
    }

-- | A list of EnvironmentResourceDescription.
describeEnvironmentResourcesResponse_environmentResources :: Lens.Lens' DescribeEnvironmentResourcesResponse (Prelude.Maybe EnvironmentResourceDescription)
describeEnvironmentResourcesResponse_environmentResources = Lens.lens (\DescribeEnvironmentResourcesResponse' {environmentResources} -> environmentResources) (\s@DescribeEnvironmentResourcesResponse' {} a -> s {environmentResources = a} :: DescribeEnvironmentResourcesResponse)

-- | The response's http status code.
describeEnvironmentResourcesResponse_httpStatus :: Lens.Lens' DescribeEnvironmentResourcesResponse Prelude.Int
describeEnvironmentResourcesResponse_httpStatus = Lens.lens (\DescribeEnvironmentResourcesResponse' {httpStatus} -> httpStatus) (\s@DescribeEnvironmentResourcesResponse' {} a -> s {httpStatus = a} :: DescribeEnvironmentResourcesResponse)

instance
  Prelude.NFData
    DescribeEnvironmentResourcesResponse
  where
  rnf DescribeEnvironmentResourcesResponse' {..} =
    Prelude.rnf environmentResources
      `Prelude.seq` Prelude.rnf httpStatus
