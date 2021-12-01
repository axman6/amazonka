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
-- Module      : Amazonka.Route53RecoveryControlConfig.DescribeRoutingControl
-- Copyright   : (c) 2013-2021 Brendan Hay
-- License     : Mozilla Public License, v. 2.0.
-- Maintainer  : Brendan Hay <brendan.g.hay+amazonka@gmail.com>
-- Stability   : auto-generated
-- Portability : non-portable (GHC extensions)
--
-- Displays details about a routing control. A routing control has one of
-- two states: ON and OFF. You can map the routing control state to the
-- state of an Amazon Route 53 health check, which can be used to control
-- routing.
--
-- To get or update the routing control state, see the Recovery Cluster
-- (data plane) API actions for Amazon Route 53 Application Recovery
-- Controller.
module Amazonka.Route53RecoveryControlConfig.DescribeRoutingControl
  ( -- * Creating a Request
    DescribeRoutingControl (..),
    newDescribeRoutingControl,

    -- * Request Lenses
    describeRoutingControl_routingControlArn,

    -- * Destructuring the Response
    DescribeRoutingControlResponse (..),
    newDescribeRoutingControlResponse,

    -- * Response Lenses
    describeRoutingControlResponse_routingControl,
    describeRoutingControlResponse_httpStatus,
  )
where

import qualified Amazonka.Core as Core
import qualified Amazonka.Lens as Lens
import qualified Amazonka.Prelude as Prelude
import qualified Amazonka.Request as Request
import qualified Amazonka.Response as Response
import Amazonka.Route53RecoveryControlConfig.Types

-- | /See:/ 'newDescribeRoutingControl' smart constructor.
data DescribeRoutingControl = DescribeRoutingControl'
  { -- | The Amazon Resource Name (ARN) of the routing control that you\'re
    -- getting details for.
    routingControlArn :: Prelude.Text
  }
  deriving (Prelude.Eq, Prelude.Read, Prelude.Show, Prelude.Generic)

-- |
-- Create a value of 'DescribeRoutingControl' with all optional fields omitted.
--
-- Use <https://hackage.haskell.org/package/generic-lens generic-lens> or <https://hackage.haskell.org/package/optics optics> to modify other optional fields.
--
-- The following record fields are available, with the corresponding lenses provided
-- for backwards compatibility:
--
-- 'routingControlArn', 'describeRoutingControl_routingControlArn' - The Amazon Resource Name (ARN) of the routing control that you\'re
-- getting details for.
newDescribeRoutingControl ::
  -- | 'routingControlArn'
  Prelude.Text ->
  DescribeRoutingControl
newDescribeRoutingControl pRoutingControlArn_ =
  DescribeRoutingControl'
    { routingControlArn =
        pRoutingControlArn_
    }

-- | The Amazon Resource Name (ARN) of the routing control that you\'re
-- getting details for.
describeRoutingControl_routingControlArn :: Lens.Lens' DescribeRoutingControl Prelude.Text
describeRoutingControl_routingControlArn = Lens.lens (\DescribeRoutingControl' {routingControlArn} -> routingControlArn) (\s@DescribeRoutingControl' {} a -> s {routingControlArn = a} :: DescribeRoutingControl)

instance Core.AWSRequest DescribeRoutingControl where
  type
    AWSResponse DescribeRoutingControl =
      DescribeRoutingControlResponse
  request = Request.get defaultService
  response =
    Response.receiveJSON
      ( \s h x ->
          DescribeRoutingControlResponse'
            Prelude.<$> (x Core..?> "RoutingControl")
            Prelude.<*> (Prelude.pure (Prelude.fromEnum s))
      )

instance Prelude.Hashable DescribeRoutingControl where
  hashWithSalt salt' DescribeRoutingControl' {..} =
    salt' `Prelude.hashWithSalt` routingControlArn

instance Prelude.NFData DescribeRoutingControl where
  rnf DescribeRoutingControl' {..} =
    Prelude.rnf routingControlArn

instance Core.ToHeaders DescribeRoutingControl where
  toHeaders =
    Prelude.const
      ( Prelude.mconcat
          [ "Content-Type"
              Core.=# ( "application/x-amz-json-1.1" ::
                          Prelude.ByteString
                      )
          ]
      )

instance Core.ToPath DescribeRoutingControl where
  toPath DescribeRoutingControl' {..} =
    Prelude.mconcat
      ["/routingcontrol/", Core.toBS routingControlArn]

instance Core.ToQuery DescribeRoutingControl where
  toQuery = Prelude.const Prelude.mempty

-- | /See:/ 'newDescribeRoutingControlResponse' smart constructor.
data DescribeRoutingControlResponse = DescribeRoutingControlResponse'
  { -- | Information about the routing control.
    routingControl :: Prelude.Maybe RoutingControl,
    -- | The response's http status code.
    httpStatus :: Prelude.Int
  }
  deriving (Prelude.Eq, Prelude.Read, Prelude.Show, Prelude.Generic)

-- |
-- Create a value of 'DescribeRoutingControlResponse' with all optional fields omitted.
--
-- Use <https://hackage.haskell.org/package/generic-lens generic-lens> or <https://hackage.haskell.org/package/optics optics> to modify other optional fields.
--
-- The following record fields are available, with the corresponding lenses provided
-- for backwards compatibility:
--
-- 'routingControl', 'describeRoutingControlResponse_routingControl' - Information about the routing control.
--
-- 'httpStatus', 'describeRoutingControlResponse_httpStatus' - The response's http status code.
newDescribeRoutingControlResponse ::
  -- | 'httpStatus'
  Prelude.Int ->
  DescribeRoutingControlResponse
newDescribeRoutingControlResponse pHttpStatus_ =
  DescribeRoutingControlResponse'
    { routingControl =
        Prelude.Nothing,
      httpStatus = pHttpStatus_
    }

-- | Information about the routing control.
describeRoutingControlResponse_routingControl :: Lens.Lens' DescribeRoutingControlResponse (Prelude.Maybe RoutingControl)
describeRoutingControlResponse_routingControl = Lens.lens (\DescribeRoutingControlResponse' {routingControl} -> routingControl) (\s@DescribeRoutingControlResponse' {} a -> s {routingControl = a} :: DescribeRoutingControlResponse)

-- | The response's http status code.
describeRoutingControlResponse_httpStatus :: Lens.Lens' DescribeRoutingControlResponse Prelude.Int
describeRoutingControlResponse_httpStatus = Lens.lens (\DescribeRoutingControlResponse' {httpStatus} -> httpStatus) (\s@DescribeRoutingControlResponse' {} a -> s {httpStatus = a} :: DescribeRoutingControlResponse)

instance
  Prelude.NFData
    DescribeRoutingControlResponse
  where
  rnf DescribeRoutingControlResponse' {..} =
    Prelude.rnf routingControl
      `Prelude.seq` Prelude.rnf httpStatus
