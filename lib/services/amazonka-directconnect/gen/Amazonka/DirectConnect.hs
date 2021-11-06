{-# OPTIONS_GHC -fno-warn-duplicate-exports #-}
{-# OPTIONS_GHC -fno-warn-unused-imports #-}

-- |
-- Module      : Amazonka.DirectConnect
-- Copyright   : (c) 2013-2021 Brendan Hay
-- License     : Mozilla Public License, v. 2.0.
-- Maintainer  : Brendan Hay <brendan.g.hay+amazonka@gmail.com>
-- Stability   : auto-generated
-- Portability : non-portable (GHC extensions)
--
-- Derived from API version @2012-10-25@ of the AWS service descriptions, licensed under Apache 2.0.
--
-- Direct Connect links your internal network to an Direct Connect location
-- over a standard Ethernet fiber-optic cable. One end of the cable is
-- connected to your router, the other to an Direct Connect router. With
-- this connection in place, you can create virtual interfaces directly to
-- the Amazon Web Services Cloud (for example, to Amazon EC2 and Amazon S3)
-- and to Amazon VPC, bypassing Internet service providers in your network
-- path. A connection provides access to all Amazon Web Services Regions
-- except the China (Beijing) and (China) Ningxia Regions. Amazon Web
-- Services resources in the China Regions can only be accessed through
-- locations associated with those Regions.
module Amazonka.DirectConnect
  ( -- * Service Configuration
    defaultService,

    -- * Errors
    -- $errors

    -- ** DirectConnectClientException
    _DirectConnectClientException,

    -- ** DuplicateTagKeysException
    _DuplicateTagKeysException,

    -- ** TooManyTagsException
    _TooManyTagsException,

    -- ** DirectConnectServerException
    _DirectConnectServerException,

    -- * Waiters
    -- $waiters

    -- * Operations
    -- $operations

    -- ** DescribeDirectConnectGatewayAssociations (Paginated)
    DescribeDirectConnectGatewayAssociations (DescribeDirectConnectGatewayAssociations'),
    newDescribeDirectConnectGatewayAssociations,
    DescribeDirectConnectGatewayAssociationsResponse (DescribeDirectConnectGatewayAssociationsResponse'),
    newDescribeDirectConnectGatewayAssociationsResponse,

    -- ** DescribeInterconnects
    DescribeInterconnects (DescribeInterconnects'),
    newDescribeInterconnects,
    DescribeInterconnectsResponse (DescribeInterconnectsResponse'),
    newDescribeInterconnectsResponse,

    -- ** DescribeTags
    DescribeTags (DescribeTags'),
    newDescribeTags,
    DescribeTagsResponse (DescribeTagsResponse'),
    newDescribeTagsResponse,

    -- ** CreateTransitVirtualInterface
    CreateTransitVirtualInterface (CreateTransitVirtualInterface'),
    newCreateTransitVirtualInterface,
    CreateTransitVirtualInterfaceResponse (CreateTransitVirtualInterfaceResponse'),
    newCreateTransitVirtualInterfaceResponse,

    -- ** DescribeLoa
    DescribeLoa (DescribeLoa'),
    newDescribeLoa,
    DescribeLoaResponse (DescribeLoaResponse'),
    newDescribeLoaResponse,

    -- ** DisassociateMacSecKey
    DisassociateMacSecKey (DisassociateMacSecKey'),
    newDisassociateMacSecKey,
    DisassociateMacSecKeyResponse (DisassociateMacSecKeyResponse'),
    newDisassociateMacSecKeyResponse,

    -- ** DeleteConnection
    DeleteConnection (DeleteConnection'),
    newDeleteConnection,
    Connection (Connection'),
    newConnection,

    -- ** UpdateConnection
    UpdateConnection (UpdateConnection'),
    newUpdateConnection,
    Connection (Connection'),
    newConnection,

    -- ** StartBgpFailoverTest
    StartBgpFailoverTest (StartBgpFailoverTest'),
    newStartBgpFailoverTest,
    StartBgpFailoverTestResponse (StartBgpFailoverTestResponse'),
    newStartBgpFailoverTestResponse,

    -- ** UpdateVirtualInterfaceAttributes
    UpdateVirtualInterfaceAttributes (UpdateVirtualInterfaceAttributes'),
    newUpdateVirtualInterfaceAttributes,
    VirtualInterface (VirtualInterface'),
    newVirtualInterface,

    -- ** AssociateConnectionWithLag
    AssociateConnectionWithLag (AssociateConnectionWithLag'),
    newAssociateConnectionWithLag,
    Connection (Connection'),
    newConnection,

    -- ** CreateDirectConnectGatewayAssociationProposal
    CreateDirectConnectGatewayAssociationProposal (CreateDirectConnectGatewayAssociationProposal'),
    newCreateDirectConnectGatewayAssociationProposal,
    CreateDirectConnectGatewayAssociationProposalResponse (CreateDirectConnectGatewayAssociationProposalResponse'),
    newCreateDirectConnectGatewayAssociationProposalResponse,

    -- ** CreateConnection
    CreateConnection (CreateConnection'),
    newCreateConnection,
    Connection (Connection'),
    newConnection,

    -- ** DescribeDirectConnectGateways (Paginated)
    DescribeDirectConnectGateways (DescribeDirectConnectGateways'),
    newDescribeDirectConnectGateways,
    DescribeDirectConnectGatewaysResponse (DescribeDirectConnectGatewaysResponse'),
    newDescribeDirectConnectGatewaysResponse,

    -- ** AssociateVirtualInterface
    AssociateVirtualInterface (AssociateVirtualInterface'),
    newAssociateVirtualInterface,
    VirtualInterface (VirtualInterface'),
    newVirtualInterface,

    -- ** DescribeConnections
    DescribeConnections (DescribeConnections'),
    newDescribeConnections,
    Connections (Connections'),
    newConnections,

    -- ** ConfirmCustomerAgreement
    ConfirmCustomerAgreement (ConfirmCustomerAgreement'),
    newConfirmCustomerAgreement,
    ConfirmCustomerAgreementResponse (ConfirmCustomerAgreementResponse'),
    newConfirmCustomerAgreementResponse,

    -- ** DeleteInterconnect
    DeleteInterconnect (DeleteInterconnect'),
    newDeleteInterconnect,
    DeleteInterconnectResponse (DeleteInterconnectResponse'),
    newDeleteInterconnectResponse,

    -- ** ConfirmPrivateVirtualInterface
    ConfirmPrivateVirtualInterface (ConfirmPrivateVirtualInterface'),
    newConfirmPrivateVirtualInterface,
    ConfirmPrivateVirtualInterfaceResponse (ConfirmPrivateVirtualInterfaceResponse'),
    newConfirmPrivateVirtualInterfaceResponse,

    -- ** UpdateDirectConnectGatewayAssociation
    UpdateDirectConnectGatewayAssociation (UpdateDirectConnectGatewayAssociation'),
    newUpdateDirectConnectGatewayAssociation,
    UpdateDirectConnectGatewayAssociationResponse (UpdateDirectConnectGatewayAssociationResponse'),
    newUpdateDirectConnectGatewayAssociationResponse,

    -- ** DeleteDirectConnectGatewayAssociation
    DeleteDirectConnectGatewayAssociation (DeleteDirectConnectGatewayAssociation'),
    newDeleteDirectConnectGatewayAssociation,
    DeleteDirectConnectGatewayAssociationResponse (DeleteDirectConnectGatewayAssociationResponse'),
    newDeleteDirectConnectGatewayAssociationResponse,

    -- ** DescribeLocations
    DescribeLocations (DescribeLocations'),
    newDescribeLocations,
    DescribeLocationsResponse (DescribeLocationsResponse'),
    newDescribeLocationsResponse,

    -- ** CreateDirectConnectGatewayAssociation
    CreateDirectConnectGatewayAssociation (CreateDirectConnectGatewayAssociation'),
    newCreateDirectConnectGatewayAssociation,
    CreateDirectConnectGatewayAssociationResponse (CreateDirectConnectGatewayAssociationResponse'),
    newCreateDirectConnectGatewayAssociationResponse,

    -- ** AcceptDirectConnectGatewayAssociationProposal
    AcceptDirectConnectGatewayAssociationProposal (AcceptDirectConnectGatewayAssociationProposal'),
    newAcceptDirectConnectGatewayAssociationProposal,
    AcceptDirectConnectGatewayAssociationProposalResponse (AcceptDirectConnectGatewayAssociationProposalResponse'),
    newAcceptDirectConnectGatewayAssociationProposalResponse,

    -- ** CreatePublicVirtualInterface
    CreatePublicVirtualInterface (CreatePublicVirtualInterface'),
    newCreatePublicVirtualInterface,
    VirtualInterface (VirtualInterface'),
    newVirtualInterface,

    -- ** AssociateMacSecKey
    AssociateMacSecKey (AssociateMacSecKey'),
    newAssociateMacSecKey,
    AssociateMacSecKeyResponse (AssociateMacSecKeyResponse'),
    newAssociateMacSecKeyResponse,

    -- ** AllocatePrivateVirtualInterface
    AllocatePrivateVirtualInterface (AllocatePrivateVirtualInterface'),
    newAllocatePrivateVirtualInterface,
    VirtualInterface (VirtualInterface'),
    newVirtualInterface,

    -- ** DescribeLags
    DescribeLags (DescribeLags'),
    newDescribeLags,
    DescribeLagsResponse (DescribeLagsResponse'),
    newDescribeLagsResponse,

    -- ** ConfirmConnection
    ConfirmConnection (ConfirmConnection'),
    newConfirmConnection,
    ConfirmConnectionResponse (ConfirmConnectionResponse'),
    newConfirmConnectionResponse,

    -- ** DescribeDirectConnectGatewayAttachments (Paginated)
    DescribeDirectConnectGatewayAttachments (DescribeDirectConnectGatewayAttachments'),
    newDescribeDirectConnectGatewayAttachments,
    DescribeDirectConnectGatewayAttachmentsResponse (DescribeDirectConnectGatewayAttachmentsResponse'),
    newDescribeDirectConnectGatewayAttachmentsResponse,

    -- ** DescribeCustomerMetadata
    DescribeCustomerMetadata (DescribeCustomerMetadata'),
    newDescribeCustomerMetadata,
    DescribeCustomerMetadataResponse (DescribeCustomerMetadataResponse'),
    newDescribeCustomerMetadataResponse,

    -- ** ConfirmPublicVirtualInterface
    ConfirmPublicVirtualInterface (ConfirmPublicVirtualInterface'),
    newConfirmPublicVirtualInterface,
    ConfirmPublicVirtualInterfaceResponse (ConfirmPublicVirtualInterfaceResponse'),
    newConfirmPublicVirtualInterfaceResponse,

    -- ** DescribeVirtualGateways
    DescribeVirtualGateways (DescribeVirtualGateways'),
    newDescribeVirtualGateways,
    DescribeVirtualGatewaysResponse (DescribeVirtualGatewaysResponse'),
    newDescribeVirtualGatewaysResponse,

    -- ** DeleteDirectConnectGatewayAssociationProposal
    DeleteDirectConnectGatewayAssociationProposal (DeleteDirectConnectGatewayAssociationProposal'),
    newDeleteDirectConnectGatewayAssociationProposal,
    DeleteDirectConnectGatewayAssociationProposalResponse (DeleteDirectConnectGatewayAssociationProposalResponse'),
    newDeleteDirectConnectGatewayAssociationProposalResponse,

    -- ** StopBgpFailoverTest
    StopBgpFailoverTest (StopBgpFailoverTest'),
    newStopBgpFailoverTest,
    StopBgpFailoverTestResponse (StopBgpFailoverTestResponse'),
    newStopBgpFailoverTestResponse,

    -- ** CreateDirectConnectGateway
    CreateDirectConnectGateway (CreateDirectConnectGateway'),
    newCreateDirectConnectGateway,
    CreateDirectConnectGatewayResponse (CreateDirectConnectGatewayResponse'),
    newCreateDirectConnectGatewayResponse,

    -- ** DeleteDirectConnectGateway
    DeleteDirectConnectGateway (DeleteDirectConnectGateway'),
    newDeleteDirectConnectGateway,
    DeleteDirectConnectGatewayResponse (DeleteDirectConnectGatewayResponse'),
    newDeleteDirectConnectGatewayResponse,

    -- ** UpdateDirectConnectGateway
    UpdateDirectConnectGateway (UpdateDirectConnectGateway'),
    newUpdateDirectConnectGateway,
    UpdateDirectConnectGatewayResponse (UpdateDirectConnectGatewayResponse'),
    newUpdateDirectConnectGatewayResponse,

    -- ** DescribeVirtualInterfaces
    DescribeVirtualInterfaces (DescribeVirtualInterfaces'),
    newDescribeVirtualInterfaces,
    DescribeVirtualInterfacesResponse (DescribeVirtualInterfacesResponse'),
    newDescribeVirtualInterfacesResponse,

    -- ** ListVirtualInterfaceTestHistory
    ListVirtualInterfaceTestHistory (ListVirtualInterfaceTestHistory'),
    newListVirtualInterfaceTestHistory,
    ListVirtualInterfaceTestHistoryResponse (ListVirtualInterfaceTestHistoryResponse'),
    newListVirtualInterfaceTestHistoryResponse,

    -- ** AllocateHostedConnection
    AllocateHostedConnection (AllocateHostedConnection'),
    newAllocateHostedConnection,
    Connection (Connection'),
    newConnection,

    -- ** DeleteVirtualInterface
    DeleteVirtualInterface (DeleteVirtualInterface'),
    newDeleteVirtualInterface,
    DeleteVirtualInterfaceResponse (DeleteVirtualInterfaceResponse'),
    newDeleteVirtualInterfaceResponse,

    -- ** CreatePrivateVirtualInterface
    CreatePrivateVirtualInterface (CreatePrivateVirtualInterface'),
    newCreatePrivateVirtualInterface,
    VirtualInterface (VirtualInterface'),
    newVirtualInterface,

    -- ** AllocatePublicVirtualInterface
    AllocatePublicVirtualInterface (AllocatePublicVirtualInterface'),
    newAllocatePublicVirtualInterface,
    VirtualInterface (VirtualInterface'),
    newVirtualInterface,

    -- ** DescribeDirectConnectGatewayAssociationProposals
    DescribeDirectConnectGatewayAssociationProposals (DescribeDirectConnectGatewayAssociationProposals'),
    newDescribeDirectConnectGatewayAssociationProposals,
    DescribeDirectConnectGatewayAssociationProposalsResponse (DescribeDirectConnectGatewayAssociationProposalsResponse'),
    newDescribeDirectConnectGatewayAssociationProposalsResponse,

    -- ** DisassociateConnectionFromLag
    DisassociateConnectionFromLag (DisassociateConnectionFromLag'),
    newDisassociateConnectionFromLag,
    Connection (Connection'),
    newConnection,

    -- ** TagResource
    TagResource (TagResource'),
    newTagResource,
    TagResourceResponse (TagResourceResponse'),
    newTagResourceResponse,

    -- ** DeleteLag
    DeleteLag (DeleteLag'),
    newDeleteLag,
    Lag (Lag'),
    newLag,

    -- ** UpdateLag
    UpdateLag (UpdateLag'),
    newUpdateLag,
    Lag (Lag'),
    newLag,

    -- ** UntagResource
    UntagResource (UntagResource'),
    newUntagResource,
    UntagResourceResponse (UntagResourceResponse'),
    newUntagResourceResponse,

    -- ** CreateBGPPeer
    CreateBGPPeer (CreateBGPPeer'),
    newCreateBGPPeer,
    CreateBGPPeerResponse (CreateBGPPeerResponse'),
    newCreateBGPPeerResponse,

    -- ** AssociateHostedConnection
    AssociateHostedConnection (AssociateHostedConnection'),
    newAssociateHostedConnection,
    Connection (Connection'),
    newConnection,

    -- ** CreateInterconnect
    CreateInterconnect (CreateInterconnect'),
    newCreateInterconnect,
    Interconnect (Interconnect'),
    newInterconnect,

    -- ** DescribeRouterConfiguration
    DescribeRouterConfiguration (DescribeRouterConfiguration'),
    newDescribeRouterConfiguration,
    DescribeRouterConfigurationResponse (DescribeRouterConfigurationResponse'),
    newDescribeRouterConfigurationResponse,

    -- ** DeleteBGPPeer
    DeleteBGPPeer (DeleteBGPPeer'),
    newDeleteBGPPeer,
    DeleteBGPPeerResponse (DeleteBGPPeerResponse'),
    newDeleteBGPPeerResponse,

    -- ** AllocateTransitVirtualInterface
    AllocateTransitVirtualInterface (AllocateTransitVirtualInterface'),
    newAllocateTransitVirtualInterface,
    AllocateTransitVirtualInterfaceResponse (AllocateTransitVirtualInterfaceResponse'),
    newAllocateTransitVirtualInterfaceResponse,

    -- ** CreateLag
    CreateLag (CreateLag'),
    newCreateLag,
    Lag (Lag'),
    newLag,

    -- ** ConfirmTransitVirtualInterface
    ConfirmTransitVirtualInterface (ConfirmTransitVirtualInterface'),
    newConfirmTransitVirtualInterface,
    ConfirmTransitVirtualInterfaceResponse (ConfirmTransitVirtualInterfaceResponse'),
    newConfirmTransitVirtualInterfaceResponse,

    -- ** DescribeHostedConnections
    DescribeHostedConnections (DescribeHostedConnections'),
    newDescribeHostedConnections,
    Connections (Connections'),
    newConnections,

    -- * Types

    -- ** AddressFamily
    AddressFamily (..),

    -- ** BGPPeerState
    BGPPeerState (..),

    -- ** BGPStatus
    BGPStatus (..),

    -- ** ConnectionState
    ConnectionState (..),

    -- ** DirectConnectGatewayAssociationProposalState
    DirectConnectGatewayAssociationProposalState (..),

    -- ** DirectConnectGatewayAssociationState
    DirectConnectGatewayAssociationState (..),

    -- ** DirectConnectGatewayAttachmentState
    DirectConnectGatewayAttachmentState (..),

    -- ** DirectConnectGatewayAttachmentType
    DirectConnectGatewayAttachmentType (..),

    -- ** DirectConnectGatewayState
    DirectConnectGatewayState (..),

    -- ** GatewayType
    GatewayType (..),

    -- ** HasLogicalRedundancy
    HasLogicalRedundancy (..),

    -- ** InterconnectState
    InterconnectState (..),

    -- ** LagState
    LagState (..),

    -- ** LoaContentType
    LoaContentType (..),

    -- ** NniPartnerType
    NniPartnerType (..),

    -- ** VirtualInterfaceState
    VirtualInterfaceState (..),

    -- ** AssociatedGateway
    AssociatedGateway (AssociatedGateway'),
    newAssociatedGateway,

    -- ** BGPPeer
    BGPPeer (BGPPeer'),
    newBGPPeer,

    -- ** Connection
    Connection (Connection'),
    newConnection,

    -- ** Connections
    Connections (Connections'),
    newConnections,

    -- ** CustomerAgreement
    CustomerAgreement (CustomerAgreement'),
    newCustomerAgreement,

    -- ** DirectConnectGateway
    DirectConnectGateway (DirectConnectGateway'),
    newDirectConnectGateway,

    -- ** DirectConnectGatewayAssociation
    DirectConnectGatewayAssociation (DirectConnectGatewayAssociation'),
    newDirectConnectGatewayAssociation,

    -- ** DirectConnectGatewayAssociationProposal
    DirectConnectGatewayAssociationProposal (DirectConnectGatewayAssociationProposal'),
    newDirectConnectGatewayAssociationProposal,

    -- ** DirectConnectGatewayAttachment
    DirectConnectGatewayAttachment (DirectConnectGatewayAttachment'),
    newDirectConnectGatewayAttachment,

    -- ** Interconnect
    Interconnect (Interconnect'),
    newInterconnect,

    -- ** Lag
    Lag (Lag'),
    newLag,

    -- ** Location
    Location (Location'),
    newLocation,

    -- ** MacSecKey
    MacSecKey (MacSecKey'),
    newMacSecKey,

    -- ** NewBGPPeer
    NewBGPPeer (NewBGPPeer'),
    newNewBGPPeer,

    -- ** NewPrivateVirtualInterface
    NewPrivateVirtualInterface (NewPrivateVirtualInterface'),
    newNewPrivateVirtualInterface,

    -- ** NewPrivateVirtualInterfaceAllocation
    NewPrivateVirtualInterfaceAllocation (NewPrivateVirtualInterfaceAllocation'),
    newNewPrivateVirtualInterfaceAllocation,

    -- ** NewPublicVirtualInterface
    NewPublicVirtualInterface (NewPublicVirtualInterface'),
    newNewPublicVirtualInterface,

    -- ** NewPublicVirtualInterfaceAllocation
    NewPublicVirtualInterfaceAllocation (NewPublicVirtualInterfaceAllocation'),
    newNewPublicVirtualInterfaceAllocation,

    -- ** NewTransitVirtualInterface
    NewTransitVirtualInterface (NewTransitVirtualInterface'),
    newNewTransitVirtualInterface,

    -- ** NewTransitVirtualInterfaceAllocation
    NewTransitVirtualInterfaceAllocation (NewTransitVirtualInterfaceAllocation'),
    newNewTransitVirtualInterfaceAllocation,

    -- ** ResourceTag
    ResourceTag (ResourceTag'),
    newResourceTag,

    -- ** RouteFilterPrefix
    RouteFilterPrefix (RouteFilterPrefix'),
    newRouteFilterPrefix,

    -- ** RouterType
    RouterType (RouterType'),
    newRouterType,

    -- ** Tag
    Tag (Tag'),
    newTag,

    -- ** VirtualGateway
    VirtualGateway (VirtualGateway'),
    newVirtualGateway,

    -- ** VirtualInterface
    VirtualInterface (VirtualInterface'),
    newVirtualInterface,

    -- ** VirtualInterfaceTestHistory
    VirtualInterfaceTestHistory (VirtualInterfaceTestHistory'),
    newVirtualInterfaceTestHistory,
  )
where

import Amazonka.DirectConnect.AcceptDirectConnectGatewayAssociationProposal
import Amazonka.DirectConnect.AllocateHostedConnection
import Amazonka.DirectConnect.AllocatePrivateVirtualInterface
import Amazonka.DirectConnect.AllocatePublicVirtualInterface
import Amazonka.DirectConnect.AllocateTransitVirtualInterface
import Amazonka.DirectConnect.AssociateConnectionWithLag
import Amazonka.DirectConnect.AssociateHostedConnection
import Amazonka.DirectConnect.AssociateMacSecKey
import Amazonka.DirectConnect.AssociateVirtualInterface
import Amazonka.DirectConnect.ConfirmConnection
import Amazonka.DirectConnect.ConfirmCustomerAgreement
import Amazonka.DirectConnect.ConfirmPrivateVirtualInterface
import Amazonka.DirectConnect.ConfirmPublicVirtualInterface
import Amazonka.DirectConnect.ConfirmTransitVirtualInterface
import Amazonka.DirectConnect.CreateBGPPeer
import Amazonka.DirectConnect.CreateConnection
import Amazonka.DirectConnect.CreateDirectConnectGateway
import Amazonka.DirectConnect.CreateDirectConnectGatewayAssociation
import Amazonka.DirectConnect.CreateDirectConnectGatewayAssociationProposal
import Amazonka.DirectConnect.CreateInterconnect
import Amazonka.DirectConnect.CreateLag
import Amazonka.DirectConnect.CreatePrivateVirtualInterface
import Amazonka.DirectConnect.CreatePublicVirtualInterface
import Amazonka.DirectConnect.CreateTransitVirtualInterface
import Amazonka.DirectConnect.DeleteBGPPeer
import Amazonka.DirectConnect.DeleteConnection
import Amazonka.DirectConnect.DeleteDirectConnectGateway
import Amazonka.DirectConnect.DeleteDirectConnectGatewayAssociation
import Amazonka.DirectConnect.DeleteDirectConnectGatewayAssociationProposal
import Amazonka.DirectConnect.DeleteInterconnect
import Amazonka.DirectConnect.DeleteLag
import Amazonka.DirectConnect.DeleteVirtualInterface
import Amazonka.DirectConnect.DescribeConnections
import Amazonka.DirectConnect.DescribeCustomerMetadata
import Amazonka.DirectConnect.DescribeDirectConnectGatewayAssociationProposals
import Amazonka.DirectConnect.DescribeDirectConnectGatewayAssociations
import Amazonka.DirectConnect.DescribeDirectConnectGatewayAttachments
import Amazonka.DirectConnect.DescribeDirectConnectGateways
import Amazonka.DirectConnect.DescribeHostedConnections
import Amazonka.DirectConnect.DescribeInterconnects
import Amazonka.DirectConnect.DescribeLags
import Amazonka.DirectConnect.DescribeLoa
import Amazonka.DirectConnect.DescribeLocations
import Amazonka.DirectConnect.DescribeRouterConfiguration
import Amazonka.DirectConnect.DescribeTags
import Amazonka.DirectConnect.DescribeVirtualGateways
import Amazonka.DirectConnect.DescribeVirtualInterfaces
import Amazonka.DirectConnect.DisassociateConnectionFromLag
import Amazonka.DirectConnect.DisassociateMacSecKey
import Amazonka.DirectConnect.Lens
import Amazonka.DirectConnect.ListVirtualInterfaceTestHistory
import Amazonka.DirectConnect.StartBgpFailoverTest
import Amazonka.DirectConnect.StopBgpFailoverTest
import Amazonka.DirectConnect.TagResource
import Amazonka.DirectConnect.Types
import Amazonka.DirectConnect.UntagResource
import Amazonka.DirectConnect.UpdateConnection
import Amazonka.DirectConnect.UpdateDirectConnectGateway
import Amazonka.DirectConnect.UpdateDirectConnectGatewayAssociation
import Amazonka.DirectConnect.UpdateLag
import Amazonka.DirectConnect.UpdateVirtualInterfaceAttributes
import Amazonka.DirectConnect.Waiters

-- $errors
-- Error matchers are designed for use with the functions provided by
-- <http://hackage.haskell.org/package/lens/docs/Control-Exception-Lens.html Control.Exception.Lens>.
-- This allows catching (and rethrowing) service specific errors returned
-- by 'DirectConnect'.

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
