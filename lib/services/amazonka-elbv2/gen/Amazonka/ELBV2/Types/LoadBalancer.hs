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
-- Module      : Amazonka.ELBV2.Types.LoadBalancer
-- Copyright   : (c) 2013-2022 Brendan Hay
-- License     : Mozilla Public License, v. 2.0.
-- Maintainer  : Brendan Hay <brendan.g.hay+amazonka@gmail.com>
-- Stability   : auto-generated
-- Portability : non-portable (GHC extensions)
module Amazonka.ELBV2.Types.LoadBalancer where

import qualified Amazonka.Core as Core
import Amazonka.ELBV2.Types.AvailabilityZone
import Amazonka.ELBV2.Types.IpAddressType
import Amazonka.ELBV2.Types.LoadBalancerSchemeEnum
import Amazonka.ELBV2.Types.LoadBalancerState
import Amazonka.ELBV2.Types.LoadBalancerTypeEnum
import qualified Amazonka.Lens as Lens
import qualified Amazonka.Prelude as Prelude

-- | Information about a load balancer.
--
-- /See:/ 'newLoadBalancer' smart constructor.
data LoadBalancer = LoadBalancer'
  { -- | The nodes of an Internet-facing load balancer have public IP addresses.
    -- The DNS name of an Internet-facing load balancer is publicly resolvable
    -- to the public IP addresses of the nodes. Therefore, Internet-facing load
    -- balancers can route requests from clients over the internet.
    --
    -- The nodes of an internal load balancer have only private IP addresses.
    -- The DNS name of an internal load balancer is publicly resolvable to the
    -- private IP addresses of the nodes. Therefore, internal load balancers
    -- can route requests only from clients with access to the VPC for the load
    -- balancer.
    scheme :: Prelude.Maybe LoadBalancerSchemeEnum,
    -- | The type of load balancer.
    type' :: Prelude.Maybe LoadBalancerTypeEnum,
    -- | The date and time the load balancer was created.
    createdTime :: Prelude.Maybe Core.ISO8601,
    -- | The name of the load balancer.
    loadBalancerName :: Prelude.Maybe Prelude.Text,
    -- | The subnets for the load balancer.
    availabilityZones :: Prelude.Maybe [AvailabilityZone],
    -- | The state of the load balancer.
    state :: Prelude.Maybe LoadBalancerState,
    -- | The Amazon Resource Name (ARN) of the load balancer.
    loadBalancerArn :: Prelude.Maybe Prelude.Text,
    -- | [Application Load Balancers on Outposts] The ID of the customer-owned
    -- address pool.
    customerOwnedIpv4Pool :: Prelude.Maybe Prelude.Text,
    -- | The IDs of the security groups for the load balancer.
    securityGroups :: Prelude.Maybe [Prelude.Text],
    -- | The public DNS name of the load balancer.
    dNSName :: Prelude.Maybe Prelude.Text,
    -- | The ID of the VPC for the load balancer.
    vpcId :: Prelude.Maybe Prelude.Text,
    -- | The ID of the Amazon Route 53 hosted zone associated with the load
    -- balancer.
    canonicalHostedZoneId :: Prelude.Maybe Prelude.Text,
    -- | The type of IP addresses used by the subnets for your load balancer. The
    -- possible values are @ipv4@ (for IPv4 addresses) and @dualstack@ (for
    -- IPv4 and IPv6 addresses).
    ipAddressType :: Prelude.Maybe IpAddressType
  }
  deriving (Prelude.Eq, Prelude.Read, Prelude.Show, Prelude.Generic)

-- |
-- Create a value of 'LoadBalancer' with all optional fields omitted.
--
-- Use <https://hackage.haskell.org/package/generic-lens generic-lens> or <https://hackage.haskell.org/package/optics optics> to modify other optional fields.
--
-- The following record fields are available, with the corresponding lenses provided
-- for backwards compatibility:
--
-- 'scheme', 'loadBalancer_scheme' - The nodes of an Internet-facing load balancer have public IP addresses.
-- The DNS name of an Internet-facing load balancer is publicly resolvable
-- to the public IP addresses of the nodes. Therefore, Internet-facing load
-- balancers can route requests from clients over the internet.
--
-- The nodes of an internal load balancer have only private IP addresses.
-- The DNS name of an internal load balancer is publicly resolvable to the
-- private IP addresses of the nodes. Therefore, internal load balancers
-- can route requests only from clients with access to the VPC for the load
-- balancer.
--
-- 'type'', 'loadBalancer_type' - The type of load balancer.
--
-- 'createdTime', 'loadBalancer_createdTime' - The date and time the load balancer was created.
--
-- 'loadBalancerName', 'loadBalancer_loadBalancerName' - The name of the load balancer.
--
-- 'availabilityZones', 'loadBalancer_availabilityZones' - The subnets for the load balancer.
--
-- 'state', 'loadBalancer_state' - The state of the load balancer.
--
-- 'loadBalancerArn', 'loadBalancer_loadBalancerArn' - The Amazon Resource Name (ARN) of the load balancer.
--
-- 'customerOwnedIpv4Pool', 'loadBalancer_customerOwnedIpv4Pool' - [Application Load Balancers on Outposts] The ID of the customer-owned
-- address pool.
--
-- 'securityGroups', 'loadBalancer_securityGroups' - The IDs of the security groups for the load balancer.
--
-- 'dNSName', 'loadBalancer_dNSName' - The public DNS name of the load balancer.
--
-- 'vpcId', 'loadBalancer_vpcId' - The ID of the VPC for the load balancer.
--
-- 'canonicalHostedZoneId', 'loadBalancer_canonicalHostedZoneId' - The ID of the Amazon Route 53 hosted zone associated with the load
-- balancer.
--
-- 'ipAddressType', 'loadBalancer_ipAddressType' - The type of IP addresses used by the subnets for your load balancer. The
-- possible values are @ipv4@ (for IPv4 addresses) and @dualstack@ (for
-- IPv4 and IPv6 addresses).
newLoadBalancer ::
  LoadBalancer
newLoadBalancer =
  LoadBalancer'
    { scheme = Prelude.Nothing,
      type' = Prelude.Nothing,
      createdTime = Prelude.Nothing,
      loadBalancerName = Prelude.Nothing,
      availabilityZones = Prelude.Nothing,
      state = Prelude.Nothing,
      loadBalancerArn = Prelude.Nothing,
      customerOwnedIpv4Pool = Prelude.Nothing,
      securityGroups = Prelude.Nothing,
      dNSName = Prelude.Nothing,
      vpcId = Prelude.Nothing,
      canonicalHostedZoneId = Prelude.Nothing,
      ipAddressType = Prelude.Nothing
    }

-- | The nodes of an Internet-facing load balancer have public IP addresses.
-- The DNS name of an Internet-facing load balancer is publicly resolvable
-- to the public IP addresses of the nodes. Therefore, Internet-facing load
-- balancers can route requests from clients over the internet.
--
-- The nodes of an internal load balancer have only private IP addresses.
-- The DNS name of an internal load balancer is publicly resolvable to the
-- private IP addresses of the nodes. Therefore, internal load balancers
-- can route requests only from clients with access to the VPC for the load
-- balancer.
loadBalancer_scheme :: Lens.Lens' LoadBalancer (Prelude.Maybe LoadBalancerSchemeEnum)
loadBalancer_scheme = Lens.lens (\LoadBalancer' {scheme} -> scheme) (\s@LoadBalancer' {} a -> s {scheme = a} :: LoadBalancer)

-- | The type of load balancer.
loadBalancer_type :: Lens.Lens' LoadBalancer (Prelude.Maybe LoadBalancerTypeEnum)
loadBalancer_type = Lens.lens (\LoadBalancer' {type'} -> type') (\s@LoadBalancer' {} a -> s {type' = a} :: LoadBalancer)

-- | The date and time the load balancer was created.
loadBalancer_createdTime :: Lens.Lens' LoadBalancer (Prelude.Maybe Prelude.UTCTime)
loadBalancer_createdTime = Lens.lens (\LoadBalancer' {createdTime} -> createdTime) (\s@LoadBalancer' {} a -> s {createdTime = a} :: LoadBalancer) Prelude.. Lens.mapping Core._Time

-- | The name of the load balancer.
loadBalancer_loadBalancerName :: Lens.Lens' LoadBalancer (Prelude.Maybe Prelude.Text)
loadBalancer_loadBalancerName = Lens.lens (\LoadBalancer' {loadBalancerName} -> loadBalancerName) (\s@LoadBalancer' {} a -> s {loadBalancerName = a} :: LoadBalancer)

-- | The subnets for the load balancer.
loadBalancer_availabilityZones :: Lens.Lens' LoadBalancer (Prelude.Maybe [AvailabilityZone])
loadBalancer_availabilityZones = Lens.lens (\LoadBalancer' {availabilityZones} -> availabilityZones) (\s@LoadBalancer' {} a -> s {availabilityZones = a} :: LoadBalancer) Prelude.. Lens.mapping Lens.coerced

-- | The state of the load balancer.
loadBalancer_state :: Lens.Lens' LoadBalancer (Prelude.Maybe LoadBalancerState)
loadBalancer_state = Lens.lens (\LoadBalancer' {state} -> state) (\s@LoadBalancer' {} a -> s {state = a} :: LoadBalancer)

-- | The Amazon Resource Name (ARN) of the load balancer.
loadBalancer_loadBalancerArn :: Lens.Lens' LoadBalancer (Prelude.Maybe Prelude.Text)
loadBalancer_loadBalancerArn = Lens.lens (\LoadBalancer' {loadBalancerArn} -> loadBalancerArn) (\s@LoadBalancer' {} a -> s {loadBalancerArn = a} :: LoadBalancer)

-- | [Application Load Balancers on Outposts] The ID of the customer-owned
-- address pool.
loadBalancer_customerOwnedIpv4Pool :: Lens.Lens' LoadBalancer (Prelude.Maybe Prelude.Text)
loadBalancer_customerOwnedIpv4Pool = Lens.lens (\LoadBalancer' {customerOwnedIpv4Pool} -> customerOwnedIpv4Pool) (\s@LoadBalancer' {} a -> s {customerOwnedIpv4Pool = a} :: LoadBalancer)

-- | The IDs of the security groups for the load balancer.
loadBalancer_securityGroups :: Lens.Lens' LoadBalancer (Prelude.Maybe [Prelude.Text])
loadBalancer_securityGroups = Lens.lens (\LoadBalancer' {securityGroups} -> securityGroups) (\s@LoadBalancer' {} a -> s {securityGroups = a} :: LoadBalancer) Prelude.. Lens.mapping Lens.coerced

-- | The public DNS name of the load balancer.
loadBalancer_dNSName :: Lens.Lens' LoadBalancer (Prelude.Maybe Prelude.Text)
loadBalancer_dNSName = Lens.lens (\LoadBalancer' {dNSName} -> dNSName) (\s@LoadBalancer' {} a -> s {dNSName = a} :: LoadBalancer)

-- | The ID of the VPC for the load balancer.
loadBalancer_vpcId :: Lens.Lens' LoadBalancer (Prelude.Maybe Prelude.Text)
loadBalancer_vpcId = Lens.lens (\LoadBalancer' {vpcId} -> vpcId) (\s@LoadBalancer' {} a -> s {vpcId = a} :: LoadBalancer)

-- | The ID of the Amazon Route 53 hosted zone associated with the load
-- balancer.
loadBalancer_canonicalHostedZoneId :: Lens.Lens' LoadBalancer (Prelude.Maybe Prelude.Text)
loadBalancer_canonicalHostedZoneId = Lens.lens (\LoadBalancer' {canonicalHostedZoneId} -> canonicalHostedZoneId) (\s@LoadBalancer' {} a -> s {canonicalHostedZoneId = a} :: LoadBalancer)

-- | The type of IP addresses used by the subnets for your load balancer. The
-- possible values are @ipv4@ (for IPv4 addresses) and @dualstack@ (for
-- IPv4 and IPv6 addresses).
loadBalancer_ipAddressType :: Lens.Lens' LoadBalancer (Prelude.Maybe IpAddressType)
loadBalancer_ipAddressType = Lens.lens (\LoadBalancer' {ipAddressType} -> ipAddressType) (\s@LoadBalancer' {} a -> s {ipAddressType = a} :: LoadBalancer)

instance Core.FromXML LoadBalancer where
  parseXML x =
    LoadBalancer'
      Prelude.<$> (x Core..@? "Scheme")
      Prelude.<*> (x Core..@? "Type")
      Prelude.<*> (x Core..@? "CreatedTime")
      Prelude.<*> (x Core..@? "LoadBalancerName")
      Prelude.<*> ( x Core..@? "AvailabilityZones"
                      Core..!@ Prelude.mempty
                      Prelude.>>= Core.may (Core.parseXMLList "member")
                  )
      Prelude.<*> (x Core..@? "State")
      Prelude.<*> (x Core..@? "LoadBalancerArn")
      Prelude.<*> (x Core..@? "CustomerOwnedIpv4Pool")
      Prelude.<*> ( x Core..@? "SecurityGroups" Core..!@ Prelude.mempty
                      Prelude.>>= Core.may (Core.parseXMLList "member")
                  )
      Prelude.<*> (x Core..@? "DNSName")
      Prelude.<*> (x Core..@? "VpcId")
      Prelude.<*> (x Core..@? "CanonicalHostedZoneId")
      Prelude.<*> (x Core..@? "IpAddressType")

instance Prelude.Hashable LoadBalancer where
  hashWithSalt _salt LoadBalancer' {..} =
    _salt `Prelude.hashWithSalt` scheme
      `Prelude.hashWithSalt` type'
      `Prelude.hashWithSalt` createdTime
      `Prelude.hashWithSalt` loadBalancerName
      `Prelude.hashWithSalt` availabilityZones
      `Prelude.hashWithSalt` state
      `Prelude.hashWithSalt` loadBalancerArn
      `Prelude.hashWithSalt` customerOwnedIpv4Pool
      `Prelude.hashWithSalt` securityGroups
      `Prelude.hashWithSalt` dNSName
      `Prelude.hashWithSalt` vpcId
      `Prelude.hashWithSalt` canonicalHostedZoneId
      `Prelude.hashWithSalt` ipAddressType

instance Prelude.NFData LoadBalancer where
  rnf LoadBalancer' {..} =
    Prelude.rnf scheme
      `Prelude.seq` Prelude.rnf type'
      `Prelude.seq` Prelude.rnf createdTime
      `Prelude.seq` Prelude.rnf loadBalancerName
      `Prelude.seq` Prelude.rnf availabilityZones
      `Prelude.seq` Prelude.rnf state
      `Prelude.seq` Prelude.rnf loadBalancerArn
      `Prelude.seq` Prelude.rnf customerOwnedIpv4Pool
      `Prelude.seq` Prelude.rnf securityGroups
      `Prelude.seq` Prelude.rnf dNSName
      `Prelude.seq` Prelude.rnf vpcId
      `Prelude.seq` Prelude.rnf canonicalHostedZoneId
      `Prelude.seq` Prelude.rnf ipAddressType
