{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE StrictData #-}
{-# LANGUAGE NoImplicitPrelude #-}
{-# OPTIONS_GHC -fno-warn-unused-matches #-}

-- Derived from AWS service descriptions, licensed under Apache 2.0.

-- |
-- Module      : Amazonka.MediaConnect.Types
-- Copyright   : (c) 2013-2021 Brendan Hay
-- License     : Mozilla Public License, v. 2.0.
-- Maintainer  : Brendan Hay <brendan.g.hay+amazonka@gmail.com>
-- Stability   : auto-generated
-- Portability : non-portable (GHC extensions)
module Amazonka.MediaConnect.Types
  ( -- * Service Configuration
    defaultService,

    -- * Errors
    _GrantFlowEntitlements420Exception,
    _ForbiddenException,
    _NotFoundException,
    _CreateFlow420Exception,
    _TooManyRequestsException,
    _InternalServerErrorException,
    _ServiceUnavailableException,
    _AddFlowOutputs420Exception,
    _BadRequestException,

    -- * Algorithm
    Algorithm (..),

    -- * Colorimetry
    Colorimetry (..),

    -- * DurationUnits
    DurationUnits (..),

    -- * EncoderProfile
    EncoderProfile (..),

    -- * EncodingName
    EncodingName (..),

    -- * EntitlementStatus
    EntitlementStatus (..),

    -- * FailoverMode
    FailoverMode (..),

    -- * KeyType
    KeyType (..),

    -- * MediaStreamType
    MediaStreamType (..),

    -- * NetworkInterfaceType
    NetworkInterfaceType (..),

    -- * PriceUnits
    PriceUnits (..),

    -- * Protocol
    Protocol (..),

    -- * Range
    Range (..),

    -- * ReservationState
    ReservationState (..),

    -- * ResourceType
    ResourceType (..),

    -- * ScanMode
    ScanMode (..),

    -- * SourceType
    SourceType (..),

    -- * State
    State (..),

    -- * Status
    Status (..),

    -- * Tcs
    Tcs (..),

    -- * AddMediaStreamRequest
    AddMediaStreamRequest (..),
    newAddMediaStreamRequest,
    addMediaStreamRequest_videoFormat,
    addMediaStreamRequest_attributes,
    addMediaStreamRequest_clockRate,
    addMediaStreamRequest_description,
    addMediaStreamRequest_mediaStreamType,
    addMediaStreamRequest_mediaStreamId,
    addMediaStreamRequest_mediaStreamName,

    -- * AddOutputRequest
    AddOutputRequest (..),
    newAddOutputRequest,
    addOutputRequest_destination,
    addOutputRequest_maxLatency,
    addOutputRequest_mediaStreamOutputConfigurations,
    addOutputRequest_encryption,
    addOutputRequest_name,
    addOutputRequest_cidrAllowList,
    addOutputRequest_smoothingLatency,
    addOutputRequest_minLatency,
    addOutputRequest_description,
    addOutputRequest_port,
    addOutputRequest_streamId,
    addOutputRequest_remoteId,
    addOutputRequest_vpcInterfaceAttachment,
    addOutputRequest_protocol,

    -- * DestinationConfiguration
    DestinationConfiguration (..),
    newDestinationConfiguration,
    destinationConfiguration_destinationIp,
    destinationConfiguration_destinationPort,
    destinationConfiguration_interface,
    destinationConfiguration_outboundIp,

    -- * DestinationConfigurationRequest
    DestinationConfigurationRequest (..),
    newDestinationConfigurationRequest,
    destinationConfigurationRequest_destinationIp,
    destinationConfigurationRequest_destinationPort,
    destinationConfigurationRequest_interface,

    -- * EncodingParameters
    EncodingParameters (..),
    newEncodingParameters,
    encodingParameters_encoderProfile,
    encodingParameters_compressionFactor,

    -- * EncodingParametersRequest
    EncodingParametersRequest (..),
    newEncodingParametersRequest,
    encodingParametersRequest_encoderProfile,
    encodingParametersRequest_compressionFactor,

    -- * Encryption
    Encryption (..),
    newEncryption,
    encryption_keyType,
    encryption_resourceId,
    encryption_url,
    encryption_algorithm,
    encryption_constantInitializationVector,
    encryption_deviceId,
    encryption_region,
    encryption_secretArn,
    encryption_roleArn,

    -- * Entitlement
    Entitlement (..),
    newEntitlement,
    entitlement_dataTransferSubscriberFeePercent,
    entitlement_encryption,
    entitlement_entitlementStatus,
    entitlement_description,
    entitlement_entitlementArn,
    entitlement_subscribers,
    entitlement_name,

    -- * FailoverConfig
    FailoverConfig (..),
    newFailoverConfig,
    failoverConfig_state,
    failoverConfig_recoveryWindow,
    failoverConfig_sourcePriority,
    failoverConfig_failoverMode,

    -- * Flow
    Flow (..),
    newFlow,
    flow_mediaStreams,
    flow_sourceFailoverConfig,
    flow_vpcInterfaces,
    flow_sources,
    flow_egressIp,
    flow_description,
    flow_status,
    flow_entitlements,
    flow_outputs,
    flow_availabilityZone,
    flow_flowArn,
    flow_source,
    flow_name,

    -- * Fmtp
    Fmtp (..),
    newFmtp,
    fmtp_tcs,
    fmtp_exactFramerate,
    fmtp_par,
    fmtp_scanMode,
    fmtp_range,
    fmtp_channelOrder,
    fmtp_colorimetry,

    -- * FmtpRequest
    FmtpRequest (..),
    newFmtpRequest,
    fmtpRequest_tcs,
    fmtpRequest_exactFramerate,
    fmtpRequest_par,
    fmtpRequest_scanMode,
    fmtpRequest_range,
    fmtpRequest_channelOrder,
    fmtpRequest_colorimetry,

    -- * GrantEntitlementRequest
    GrantEntitlementRequest (..),
    newGrantEntitlementRequest,
    grantEntitlementRequest_dataTransferSubscriberFeePercent,
    grantEntitlementRequest_encryption,
    grantEntitlementRequest_name,
    grantEntitlementRequest_entitlementStatus,
    grantEntitlementRequest_description,
    grantEntitlementRequest_subscribers,

    -- * InputConfiguration
    InputConfiguration (..),
    newInputConfiguration,
    inputConfiguration_inputPort,
    inputConfiguration_inputIp,
    inputConfiguration_interface,

    -- * InputConfigurationRequest
    InputConfigurationRequest (..),
    newInputConfigurationRequest,
    inputConfigurationRequest_inputPort,
    inputConfigurationRequest_interface,

    -- * Interface
    Interface (..),
    newInterface,
    interface_name,

    -- * InterfaceRequest
    InterfaceRequest (..),
    newInterfaceRequest,
    interfaceRequest_name,

    -- * ListedEntitlement
    ListedEntitlement (..),
    newListedEntitlement,
    listedEntitlement_dataTransferSubscriberFeePercent,
    listedEntitlement_entitlementArn,
    listedEntitlement_entitlementName,

    -- * ListedFlow
    ListedFlow (..),
    newListedFlow,
    listedFlow_status,
    listedFlow_description,
    listedFlow_sourceType,
    listedFlow_availabilityZone,
    listedFlow_flowArn,
    listedFlow_name,

    -- * MediaStream
    MediaStream (..),
    newMediaStream,
    mediaStream_videoFormat,
    mediaStream_attributes,
    mediaStream_clockRate,
    mediaStream_description,
    mediaStream_mediaStreamType,
    mediaStream_mediaStreamId,
    mediaStream_mediaStreamName,
    mediaStream_fmt,

    -- * MediaStreamAttributes
    MediaStreamAttributes (..),
    newMediaStreamAttributes,
    mediaStreamAttributes_lang,
    mediaStreamAttributes_fmtp,

    -- * MediaStreamAttributesRequest
    MediaStreamAttributesRequest (..),
    newMediaStreamAttributesRequest,
    mediaStreamAttributesRequest_lang,
    mediaStreamAttributesRequest_fmtp,

    -- * MediaStreamOutputConfiguration
    MediaStreamOutputConfiguration (..),
    newMediaStreamOutputConfiguration,
    mediaStreamOutputConfiguration_destinationConfigurations,
    mediaStreamOutputConfiguration_encodingParameters,
    mediaStreamOutputConfiguration_mediaStreamName,
    mediaStreamOutputConfiguration_encodingName,

    -- * MediaStreamOutputConfigurationRequest
    MediaStreamOutputConfigurationRequest (..),
    newMediaStreamOutputConfigurationRequest,
    mediaStreamOutputConfigurationRequest_destinationConfigurations,
    mediaStreamOutputConfigurationRequest_encodingParameters,
    mediaStreamOutputConfigurationRequest_mediaStreamName,
    mediaStreamOutputConfigurationRequest_encodingName,

    -- * MediaStreamSourceConfiguration
    MediaStreamSourceConfiguration (..),
    newMediaStreamSourceConfiguration,
    mediaStreamSourceConfiguration_inputConfigurations,
    mediaStreamSourceConfiguration_mediaStreamName,
    mediaStreamSourceConfiguration_encodingName,

    -- * MediaStreamSourceConfigurationRequest
    MediaStreamSourceConfigurationRequest (..),
    newMediaStreamSourceConfigurationRequest,
    mediaStreamSourceConfigurationRequest_inputConfigurations,
    mediaStreamSourceConfigurationRequest_mediaStreamName,
    mediaStreamSourceConfigurationRequest_encodingName,

    -- * Messages
    Messages (..),
    newMessages,
    messages_errors,

    -- * Offering
    Offering (..),
    newOffering,
    offering_currencyCode,
    offering_offeringArn,
    offering_offeringDescription,
    offering_durationUnits,
    offering_duration,
    offering_pricePerUnit,
    offering_resourceSpecification,
    offering_priceUnits,

    -- * Output
    Output (..),
    newOutput,
    output_entitlementArn,
    output_dataTransferSubscriberFeePercent,
    output_destination,
    output_mediaStreamOutputConfigurations,
    output_mediaLiveInputArn,
    output_encryption,
    output_listenerAddress,
    output_transport,
    output_description,
    output_port,
    output_vpcInterfaceAttachment,
    output_outputArn,
    output_name,

    -- * Reservation
    Reservation (..),
    newReservation,
    reservation_currencyCode,
    reservation_reservationState,
    reservation_offeringArn,
    reservation_reservationArn,
    reservation_start,
    reservation_offeringDescription,
    reservation_reservationName,
    reservation_end,
    reservation_duration,
    reservation_durationUnits,
    reservation_pricePerUnit,
    reservation_resourceSpecification,
    reservation_priceUnits,

    -- * ResourceSpecification
    ResourceSpecification (..),
    newResourceSpecification,
    resourceSpecification_reservedBitrate,
    resourceSpecification_resourceType,

    -- * SetSourceRequest
    SetSourceRequest (..),
    newSetSourceRequest,
    setSourceRequest_entitlementArn,
    setSourceRequest_maxLatency,
    setSourceRequest_vpcInterfaceName,
    setSourceRequest_decryption,
    setSourceRequest_maxSyncBuffer,
    setSourceRequest_protocol,
    setSourceRequest_name,
    setSourceRequest_minLatency,
    setSourceRequest_ingestPort,
    setSourceRequest_description,
    setSourceRequest_mediaStreamSourceConfigurations,
    setSourceRequest_whitelistCidr,
    setSourceRequest_maxBitrate,
    setSourceRequest_streamId,

    -- * Source
    Source (..),
    newSource,
    source_entitlementArn,
    source_dataTransferSubscriberFeePercent,
    source_vpcInterfaceName,
    source_decryption,
    source_ingestIp,
    source_ingestPort,
    source_transport,
    source_description,
    source_mediaStreamSourceConfigurations,
    source_whitelistCidr,
    source_sourceArn,
    source_name,

    -- * SourcePriority
    SourcePriority (..),
    newSourcePriority,
    sourcePriority_primarySource,

    -- * Transport
    Transport (..),
    newTransport,
    transport_maxLatency,
    transport_maxSyncBuffer,
    transport_cidrAllowList,
    transport_smoothingLatency,
    transport_minLatency,
    transport_maxBitrate,
    transport_streamId,
    transport_remoteId,
    transport_protocol,

    -- * UpdateEncryption
    UpdateEncryption (..),
    newUpdateEncryption,
    updateEncryption_keyType,
    updateEncryption_resourceId,
    updateEncryption_url,
    updateEncryption_algorithm,
    updateEncryption_constantInitializationVector,
    updateEncryption_deviceId,
    updateEncryption_region,
    updateEncryption_secretArn,
    updateEncryption_roleArn,

    -- * UpdateFailoverConfig
    UpdateFailoverConfig (..),
    newUpdateFailoverConfig,
    updateFailoverConfig_state,
    updateFailoverConfig_recoveryWindow,
    updateFailoverConfig_sourcePriority,
    updateFailoverConfig_failoverMode,

    -- * VpcInterface
    VpcInterface (..),
    newVpcInterface,
    vpcInterface_networkInterfaceType,
    vpcInterface_networkInterfaceIds,
    vpcInterface_subnetId,
    vpcInterface_securityGroupIds,
    vpcInterface_roleArn,
    vpcInterface_name,

    -- * VpcInterfaceAttachment
    VpcInterfaceAttachment (..),
    newVpcInterfaceAttachment,
    vpcInterfaceAttachment_vpcInterfaceName,

    -- * VpcInterfaceRequest
    VpcInterfaceRequest (..),
    newVpcInterfaceRequest,
    vpcInterfaceRequest_networkInterfaceType,
    vpcInterfaceRequest_subnetId,
    vpcInterfaceRequest_securityGroupIds,
    vpcInterfaceRequest_roleArn,
    vpcInterfaceRequest_name,
  )
where

import qualified Amazonka.Core as Core
import qualified Amazonka.Lens as Lens
import Amazonka.MediaConnect.Types.AddMediaStreamRequest
import Amazonka.MediaConnect.Types.AddOutputRequest
import Amazonka.MediaConnect.Types.Algorithm
import Amazonka.MediaConnect.Types.Colorimetry
import Amazonka.MediaConnect.Types.DestinationConfiguration
import Amazonka.MediaConnect.Types.DestinationConfigurationRequest
import Amazonka.MediaConnect.Types.DurationUnits
import Amazonka.MediaConnect.Types.EncoderProfile
import Amazonka.MediaConnect.Types.EncodingName
import Amazonka.MediaConnect.Types.EncodingParameters
import Amazonka.MediaConnect.Types.EncodingParametersRequest
import Amazonka.MediaConnect.Types.Encryption
import Amazonka.MediaConnect.Types.Entitlement
import Amazonka.MediaConnect.Types.EntitlementStatus
import Amazonka.MediaConnect.Types.FailoverConfig
import Amazonka.MediaConnect.Types.FailoverMode
import Amazonka.MediaConnect.Types.Flow
import Amazonka.MediaConnect.Types.Fmtp
import Amazonka.MediaConnect.Types.FmtpRequest
import Amazonka.MediaConnect.Types.GrantEntitlementRequest
import Amazonka.MediaConnect.Types.InputConfiguration
import Amazonka.MediaConnect.Types.InputConfigurationRequest
import Amazonka.MediaConnect.Types.Interface
import Amazonka.MediaConnect.Types.InterfaceRequest
import Amazonka.MediaConnect.Types.KeyType
import Amazonka.MediaConnect.Types.ListedEntitlement
import Amazonka.MediaConnect.Types.ListedFlow
import Amazonka.MediaConnect.Types.MediaStream
import Amazonka.MediaConnect.Types.MediaStreamAttributes
import Amazonka.MediaConnect.Types.MediaStreamAttributesRequest
import Amazonka.MediaConnect.Types.MediaStreamOutputConfiguration
import Amazonka.MediaConnect.Types.MediaStreamOutputConfigurationRequest
import Amazonka.MediaConnect.Types.MediaStreamSourceConfiguration
import Amazonka.MediaConnect.Types.MediaStreamSourceConfigurationRequest
import Amazonka.MediaConnect.Types.MediaStreamType
import Amazonka.MediaConnect.Types.Messages
import Amazonka.MediaConnect.Types.NetworkInterfaceType
import Amazonka.MediaConnect.Types.Offering
import Amazonka.MediaConnect.Types.Output
import Amazonka.MediaConnect.Types.PriceUnits
import Amazonka.MediaConnect.Types.Protocol
import Amazonka.MediaConnect.Types.Range
import Amazonka.MediaConnect.Types.Reservation
import Amazonka.MediaConnect.Types.ReservationState
import Amazonka.MediaConnect.Types.ResourceSpecification
import Amazonka.MediaConnect.Types.ResourceType
import Amazonka.MediaConnect.Types.ScanMode
import Amazonka.MediaConnect.Types.SetSourceRequest
import Amazonka.MediaConnect.Types.Source
import Amazonka.MediaConnect.Types.SourcePriority
import Amazonka.MediaConnect.Types.SourceType
import Amazonka.MediaConnect.Types.State
import Amazonka.MediaConnect.Types.Status
import Amazonka.MediaConnect.Types.Tcs
import Amazonka.MediaConnect.Types.Transport
import Amazonka.MediaConnect.Types.UpdateEncryption
import Amazonka.MediaConnect.Types.UpdateFailoverConfig
import Amazonka.MediaConnect.Types.VpcInterface
import Amazonka.MediaConnect.Types.VpcInterfaceAttachment
import Amazonka.MediaConnect.Types.VpcInterfaceRequest
import qualified Amazonka.Prelude as Prelude
import qualified Amazonka.Sign.V4 as Sign

-- | API version @2018-11-14@ of the Amazon MediaConnect SDK configuration.
defaultService :: Core.Service
defaultService =
  Core.Service
    { Core._serviceAbbrev = "MediaConnect",
      Core._serviceSigner = Sign.v4,
      Core._serviceEndpointPrefix = "mediaconnect",
      Core._serviceSigningName = "mediaconnect",
      Core._serviceVersion = "2018-11-14",
      Core._serviceEndpoint =
        Core.defaultEndpoint defaultService,
      Core._serviceTimeout = Prelude.Just 70,
      Core._serviceCheck = Core.statusSuccess,
      Core._serviceError =
        Core.parseJSONError "MediaConnect",
      Core._serviceRetry = retry
    }
  where
    retry =
      Core.Exponential
        { Core._retryBase = 5.0e-2,
          Core._retryGrowth = 2,
          Core._retryAttempts = 5,
          Core._retryCheck = check
        }
    check e
      | Lens.has
          ( Core.hasCode "ThrottledException"
              Prelude.. Core.hasStatus 400
          )
          e =
        Prelude.Just "throttled_exception"
      | Lens.has (Core.hasStatus 429) e =
        Prelude.Just "too_many_requests"
      | Lens.has
          ( Core.hasCode "ThrottlingException"
              Prelude.. Core.hasStatus 400
          )
          e =
        Prelude.Just "throttling_exception"
      | Lens.has
          ( Core.hasCode "Throttling"
              Prelude.. Core.hasStatus 400
          )
          e =
        Prelude.Just "throttling"
      | Lens.has
          ( Core.hasCode
              "ProvisionedThroughputExceededException"
              Prelude.. Core.hasStatus 400
          )
          e =
        Prelude.Just "throughput_exceeded"
      | Lens.has (Core.hasStatus 504) e =
        Prelude.Just "gateway_timeout"
      | Lens.has
          ( Core.hasCode "RequestThrottledException"
              Prelude.. Core.hasStatus 400
          )
          e =
        Prelude.Just "request_throttled_exception"
      | Lens.has (Core.hasStatus 502) e =
        Prelude.Just "bad_gateway"
      | Lens.has (Core.hasStatus 503) e =
        Prelude.Just "service_unavailable"
      | Lens.has (Core.hasStatus 500) e =
        Prelude.Just "general_server_error"
      | Lens.has (Core.hasStatus 509) e =
        Prelude.Just "limit_exceeded"
      | Prelude.otherwise = Prelude.Nothing

-- | Exception raised by AWS Elemental MediaConnect. See the error message
-- and documentation for the operation for more information on the cause of
-- this exception.
_GrantFlowEntitlements420Exception :: Core.AsError a => Lens.Getting (Prelude.First Core.ServiceError) a Core.ServiceError
_GrantFlowEntitlements420Exception =
  Core._MatchServiceError
    defaultService
    "GrantFlowEntitlements420Exception"
    Prelude.. Core.hasStatus 420

-- | Exception raised by AWS Elemental MediaConnect. See the error message
-- and documentation for the operation for more information on the cause of
-- this exception.
_ForbiddenException :: Core.AsError a => Lens.Getting (Prelude.First Core.ServiceError) a Core.ServiceError
_ForbiddenException =
  Core._MatchServiceError
    defaultService
    "ForbiddenException"
    Prelude.. Core.hasStatus 403

-- | Exception raised by AWS Elemental MediaConnect. See the error message
-- and documentation for the operation for more information on the cause of
-- this exception.
_NotFoundException :: Core.AsError a => Lens.Getting (Prelude.First Core.ServiceError) a Core.ServiceError
_NotFoundException =
  Core._MatchServiceError
    defaultService
    "NotFoundException"
    Prelude.. Core.hasStatus 404

-- | Exception raised by AWS Elemental MediaConnect. See the error message
-- and documentation for the operation for more information on the cause of
-- this exception.
_CreateFlow420Exception :: Core.AsError a => Lens.Getting (Prelude.First Core.ServiceError) a Core.ServiceError
_CreateFlow420Exception =
  Core._MatchServiceError
    defaultService
    "CreateFlow420Exception"
    Prelude.. Core.hasStatus 420

-- | Exception raised by AWS Elemental MediaConnect. See the error message
-- and documentation for the operation for more information on the cause of
-- this exception.
_TooManyRequestsException :: Core.AsError a => Lens.Getting (Prelude.First Core.ServiceError) a Core.ServiceError
_TooManyRequestsException =
  Core._MatchServiceError
    defaultService
    "TooManyRequestsException"
    Prelude.. Core.hasStatus 429

-- | Exception raised by AWS Elemental MediaConnect. See the error message
-- and documentation for the operation for more information on the cause of
-- this exception.
_InternalServerErrorException :: Core.AsError a => Lens.Getting (Prelude.First Core.ServiceError) a Core.ServiceError
_InternalServerErrorException =
  Core._MatchServiceError
    defaultService
    "InternalServerErrorException"
    Prelude.. Core.hasStatus 500

-- | Exception raised by AWS Elemental MediaConnect. See the error message
-- and documentation for the operation for more information on the cause of
-- this exception.
_ServiceUnavailableException :: Core.AsError a => Lens.Getting (Prelude.First Core.ServiceError) a Core.ServiceError
_ServiceUnavailableException =
  Core._MatchServiceError
    defaultService
    "ServiceUnavailableException"
    Prelude.. Core.hasStatus 503

-- | Exception raised by AWS Elemental MediaConnect. See the error message
-- and documentation for the operation for more information on the cause of
-- this exception.
_AddFlowOutputs420Exception :: Core.AsError a => Lens.Getting (Prelude.First Core.ServiceError) a Core.ServiceError
_AddFlowOutputs420Exception =
  Core._MatchServiceError
    defaultService
    "AddFlowOutputs420Exception"
    Prelude.. Core.hasStatus 420

-- | Exception raised by AWS Elemental MediaConnect. See the error message
-- and documentation for the operation for more information on the cause of
-- this exception.
_BadRequestException :: Core.AsError a => Lens.Getting (Prelude.First Core.ServiceError) a Core.ServiceError
_BadRequestException =
  Core._MatchServiceError
    defaultService
    "BadRequestException"
    Prelude.. Core.hasStatus 400
