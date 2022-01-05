{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE StrictData #-}
{-# LANGUAGE NoImplicitPrelude #-}
{-# OPTIONS_GHC -fno-warn-unused-imports #-}
{-# OPTIONS_GHC -fno-warn-unused-matches #-}

-- Derived from AWS service descriptions, licensed under Apache 2.0.

-- |
-- Module      : Amazonka.ELBV2.Types.LoadBalancerState
-- Copyright   : (c) 2013-2021 Brendan Hay
-- License     : Mozilla Public License, v. 2.0.
-- Maintainer  : Brendan Hay <brendan.g.hay+amazonka@gmail.com>
-- Stability   : auto-generated
-- Portability : non-portable (GHC extensions)
module Amazonka.ELBV2.Types.LoadBalancerState where

import qualified Amazonka.Core as Core
import Amazonka.ELBV2.Types.LoadBalancerStateEnum
import qualified Amazonka.Lens as Lens
import qualified Amazonka.Prelude as Prelude

-- | Information about the state of the load balancer.
--
-- /See:/ 'newLoadBalancerState' smart constructor.
data LoadBalancerState = LoadBalancerState'
  { -- | A description of the state.
    reason :: Prelude.Maybe Prelude.Text,
    -- | The state code. The initial state of the load balancer is
    -- @provisioning@. After the load balancer is fully set up and ready to
    -- route traffic, its state is @active@. If load balancer is routing
    -- traffic but does not have the resources it needs to scale, its state
    -- is@active_impaired@. If the load balancer could not be set up, its state
    -- is @failed@.
    code :: Prelude.Maybe LoadBalancerStateEnum
  }
  deriving (Prelude.Eq, Prelude.Read, Prelude.Show, Prelude.Generic)

-- |
-- Create a value of 'LoadBalancerState' with all optional fields omitted.
--
-- Use <https://hackage.haskell.org/package/generic-lens generic-lens> or <https://hackage.haskell.org/package/optics optics> to modify other optional fields.
--
-- The following record fields are available, with the corresponding lenses provided
-- for backwards compatibility:
--
-- 'reason', 'loadBalancerState_reason' - A description of the state.
--
-- 'code', 'loadBalancerState_code' - The state code. The initial state of the load balancer is
-- @provisioning@. After the load balancer is fully set up and ready to
-- route traffic, its state is @active@. If load balancer is routing
-- traffic but does not have the resources it needs to scale, its state
-- is@active_impaired@. If the load balancer could not be set up, its state
-- is @failed@.
newLoadBalancerState ::
  LoadBalancerState
newLoadBalancerState =
  LoadBalancerState'
    { reason = Prelude.Nothing,
      code = Prelude.Nothing
    }

-- | A description of the state.
loadBalancerState_reason :: Lens.Lens' LoadBalancerState (Prelude.Maybe Prelude.Text)
loadBalancerState_reason = Lens.lens (\LoadBalancerState' {reason} -> reason) (\s@LoadBalancerState' {} a -> s {reason = a} :: LoadBalancerState)

-- | The state code. The initial state of the load balancer is
-- @provisioning@. After the load balancer is fully set up and ready to
-- route traffic, its state is @active@. If load balancer is routing
-- traffic but does not have the resources it needs to scale, its state
-- is@active_impaired@. If the load balancer could not be set up, its state
-- is @failed@.
loadBalancerState_code :: Lens.Lens' LoadBalancerState (Prelude.Maybe LoadBalancerStateEnum)
loadBalancerState_code = Lens.lens (\LoadBalancerState' {code} -> code) (\s@LoadBalancerState' {} a -> s {code = a} :: LoadBalancerState)

instance Core.FromXML LoadBalancerState where
  parseXML x =
    LoadBalancerState'
      Prelude.<$> (x Core..@? "Reason") Prelude.<*> (x Core..@? "Code")

instance Prelude.Hashable LoadBalancerState where
  hashWithSalt _salt LoadBalancerState' {..} =
    _salt `Prelude.hashWithSalt` reason
      `Prelude.hashWithSalt` code

instance Prelude.NFData LoadBalancerState where
  rnf LoadBalancerState' {..} =
    Prelude.rnf reason `Prelude.seq` Prelude.rnf code
