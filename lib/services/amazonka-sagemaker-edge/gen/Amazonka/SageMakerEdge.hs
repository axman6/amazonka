{-# OPTIONS_GHC -fno-warn-duplicate-exports #-}
{-# OPTIONS_GHC -fno-warn-unused-imports #-}

-- |
-- Module      : Amazonka.SageMakerEdge
-- Copyright   : (c) 2013-2021 Brendan Hay
-- License     : Mozilla Public License, v. 2.0.
-- Maintainer  : Brendan Hay <brendan.g.hay+amazonka@gmail.com>
-- Stability   : auto-generated
-- Portability : non-portable (GHC extensions)
--
-- Derived from API version @2020-09-23@ of the AWS service descriptions, licensed under Apache 2.0.
--
-- SageMaker Edge Manager dataplane service for communicating with active
-- agents.
module Amazonka.SageMakerEdge
  ( -- * Service Configuration
    defaultService,

    -- * Errors
    -- $errors

    -- ** InternalServiceException
    _InternalServiceException,

    -- * Waiters
    -- $waiters

    -- * Operations
    -- $operations

    -- ** SendHeartbeat
    SendHeartbeat (SendHeartbeat'),
    newSendHeartbeat,
    SendHeartbeatResponse (SendHeartbeatResponse'),
    newSendHeartbeatResponse,

    -- ** GetDeviceRegistration
    GetDeviceRegistration (GetDeviceRegistration'),
    newGetDeviceRegistration,
    GetDeviceRegistrationResponse (GetDeviceRegistrationResponse'),
    newGetDeviceRegistrationResponse,

    -- * Types

    -- ** EdgeMetric
    EdgeMetric (EdgeMetric'),
    newEdgeMetric,

    -- ** Model
    Model (Model'),
    newModel,
  )
where

import Amazonka.SageMakerEdge.GetDeviceRegistration
import Amazonka.SageMakerEdge.Lens
import Amazonka.SageMakerEdge.SendHeartbeat
import Amazonka.SageMakerEdge.Types
import Amazonka.SageMakerEdge.Waiters

-- $errors
-- Error matchers are designed for use with the functions provided by
-- <http://hackage.haskell.org/package/lens/docs/Control-Exception-Lens.html Control.Exception.Lens>.
-- This allows catching (and rethrowing) service specific errors returned
-- by 'SageMakerEdge'.

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
