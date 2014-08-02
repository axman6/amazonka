{-# LANGUAGE DeriveGeneric     #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE NoImplicitPrelude #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards   #-}
{-# LANGUAGE TemplateHaskell   #-}
{-# LANGUAGE TypeFamilies      #-}

-- Module      : Network.AWS.IAM.V2010_05_08.CreateSAMLProvider
-- Copyright   : (c) 2013-2014 Brendan Hay <brendan.g.hay@gmail.com>
-- License     : This Source Code Form is subject to the terms of
--               the Mozilla Public License, v. 2.0.
--               A copy of the MPL can be found in the LICENSE file or
--               you can obtain it at http://mozilla.org/MPL/2.0/.
-- Maintainer  : Brendan Hay <brendan.g.hay@gmail.com>
-- Stability   : experimental
-- Portability : non-portable (GHC extensions)

-- | Creates an IAM entity to describe an identity provider (IdP) that supports
-- SAML 2.0. The SAML provider that you create with this operation can be used
-- as a principal in a role's trust policy to establish a trust relationship
-- between AWS and a SAML identity provider. You can create an IAM role that
-- supports Web-based single sign-on (SSO) to the AWS Management Console or
-- one that supports API access to AWS. When you create the SAML provider, you
-- upload an a SAML metadata document that you get from your IdP and that
-- includes the issuer's name, expiration information, and keys that can be
-- used to validate the SAML authentication response (assertions) that are
-- received from the IdP. You must generate the metadata document using the
-- identity management software that is used as your organization's IdP. This
-- operation requires Signature Version 4. For more information, see Giving
-- Console Access Using SAML and Creating Temporary Security Credentials for
-- SAML Federation in the Using Temporary Credentials guide.
-- https://iam.amazonaws.com/ ?Action=CreateSAMLProvider &Name=MyUniversity
-- &SAMLProviderDocument=VGhpcyBpcyB3aGVyZSB5b3UgcHV0IHRoZSBTQU1MIHByb3ZpZGVyIG1ldGFkYXRhIGRvY3VtZW50
-- LCBCYXNlNjQtZW5jb2RlZCBpbnRvIGEgYmlnIHN0cmluZy4= &Version=2010-05-08
-- &AUTHPARAMS arn:aws:iam::123456789012:saml-metadata/MyUniversity
-- 29f47818-99f5-11e1-a4c3-27EXAMPLE804.
module Network.AWS.IAM.V2010_05_08.CreateSAMLProvider where

import Control.Lens
import Network.AWS.Request.Query
import Network.AWS.IAM.V2010_05_08.Types
import Network.AWS.Prelude

data CreateSAMLProvider = CreateSAMLProvider
    { _csamlprSAMLMetadataDocument :: Text
      -- ^ An XML document generated by an identity provider (IdP) that
      -- supports SAML 2.0. The document includes the issuer's name,
      -- expiration information, and keys that can be used to validate the
      -- SAML authentication response (assertions) that are received from
      -- the IdP. You must generate the metadata document using the
      -- identity management software that is used as your organization's
      -- IdP. For more information, see Creating Temporary Security
      -- Credentials for SAML Federation in the Using Temporary Security
      -- Credentials guide.
    , _csamlprName :: Text
      -- ^ The name of the provider to create.
    } deriving (Generic)

makeLenses ''CreateSAMLProvider

instance ToQuery CreateSAMLProvider where
    toQuery = genericToQuery def

data CreateSAMLProviderResponse = CreateSAMLProviderResponse
    { _csamlpsSAMLProviderArn :: Maybe Text
      -- ^ The Amazon Resource Name (ARN) of the SAML provider.
    } deriving (Generic)

makeLenses ''CreateSAMLProviderResponse

instance FromXML CreateSAMLProviderResponse where
    fromXMLOptions = xmlOptions

instance AWSRequest CreateSAMLProvider where
    type Sv CreateSAMLProvider = IAM
    type Rs CreateSAMLProvider = CreateSAMLProviderResponse

    request = post "CreateSAMLProvider"
    response _ = xmlResponse
