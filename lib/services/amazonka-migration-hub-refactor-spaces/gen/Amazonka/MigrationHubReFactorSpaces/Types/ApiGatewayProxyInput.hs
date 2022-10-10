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
-- Module      : Amazonka.MigrationHubReFactorSpaces.Types.ApiGatewayProxyInput
-- Copyright   : (c) 2013-2022 Brendan Hay
-- License     : Mozilla Public License, v. 2.0.
-- Maintainer  : Brendan Hay <brendan.g.hay+amazonka@gmail.com>
-- Stability   : auto-generated
-- Portability : non-portable (GHC extensions)
module Amazonka.MigrationHubReFactorSpaces.Types.ApiGatewayProxyInput where

import qualified Amazonka.Core as Core
import qualified Amazonka.Lens as Lens
import Amazonka.MigrationHubReFactorSpaces.Types.ApiGatewayEndpointType
import qualified Amazonka.Prelude as Prelude

-- | A wrapper object holding the Amazon API Gateway endpoint input.
--
-- /See:/ 'newApiGatewayProxyInput' smart constructor.
data ApiGatewayProxyInput = ApiGatewayProxyInput'
  { -- | The name of the API Gateway stage. The name defaults to @prod@.
    stageName :: Prelude.Maybe Prelude.Text,
    -- | The type of endpoint to use for the API Gateway proxy. If no value is
    -- specified in the request, the value is set to @REGIONAL@ by default.
    --
    -- If the value is set to @PRIVATE@ in the request, this creates a private
    -- API endpoint that is isolated from the public internet. The private
    -- endpoint can only be accessed by using Amazon Virtual Private Cloud
    -- (Amazon VPC) endpoints for Amazon API Gateway that have been granted
    -- access.
    endpointType :: Prelude.Maybe ApiGatewayEndpointType
  }
  deriving (Prelude.Eq, Prelude.Read, Prelude.Show, Prelude.Generic)

-- |
-- Create a value of 'ApiGatewayProxyInput' with all optional fields omitted.
--
-- Use <https://hackage.haskell.org/package/generic-lens generic-lens> or <https://hackage.haskell.org/package/optics optics> to modify other optional fields.
--
-- The following record fields are available, with the corresponding lenses provided
-- for backwards compatibility:
--
-- 'stageName', 'apiGatewayProxyInput_stageName' - The name of the API Gateway stage. The name defaults to @prod@.
--
-- 'endpointType', 'apiGatewayProxyInput_endpointType' - The type of endpoint to use for the API Gateway proxy. If no value is
-- specified in the request, the value is set to @REGIONAL@ by default.
--
-- If the value is set to @PRIVATE@ in the request, this creates a private
-- API endpoint that is isolated from the public internet. The private
-- endpoint can only be accessed by using Amazon Virtual Private Cloud
-- (Amazon VPC) endpoints for Amazon API Gateway that have been granted
-- access.
newApiGatewayProxyInput ::
  ApiGatewayProxyInput
newApiGatewayProxyInput =
  ApiGatewayProxyInput'
    { stageName = Prelude.Nothing,
      endpointType = Prelude.Nothing
    }

-- | The name of the API Gateway stage. The name defaults to @prod@.
apiGatewayProxyInput_stageName :: Lens.Lens' ApiGatewayProxyInput (Prelude.Maybe Prelude.Text)
apiGatewayProxyInput_stageName = Lens.lens (\ApiGatewayProxyInput' {stageName} -> stageName) (\s@ApiGatewayProxyInput' {} a -> s {stageName = a} :: ApiGatewayProxyInput)

-- | The type of endpoint to use for the API Gateway proxy. If no value is
-- specified in the request, the value is set to @REGIONAL@ by default.
--
-- If the value is set to @PRIVATE@ in the request, this creates a private
-- API endpoint that is isolated from the public internet. The private
-- endpoint can only be accessed by using Amazon Virtual Private Cloud
-- (Amazon VPC) endpoints for Amazon API Gateway that have been granted
-- access.
apiGatewayProxyInput_endpointType :: Lens.Lens' ApiGatewayProxyInput (Prelude.Maybe ApiGatewayEndpointType)
apiGatewayProxyInput_endpointType = Lens.lens (\ApiGatewayProxyInput' {endpointType} -> endpointType) (\s@ApiGatewayProxyInput' {} a -> s {endpointType = a} :: ApiGatewayProxyInput)

instance Core.FromJSON ApiGatewayProxyInput where
  parseJSON =
    Core.withObject
      "ApiGatewayProxyInput"
      ( \x ->
          ApiGatewayProxyInput'
            Prelude.<$> (x Core..:? "StageName")
            Prelude.<*> (x Core..:? "EndpointType")
      )

instance Prelude.Hashable ApiGatewayProxyInput where
  hashWithSalt _salt ApiGatewayProxyInput' {..} =
    _salt `Prelude.hashWithSalt` stageName
      `Prelude.hashWithSalt` endpointType

instance Prelude.NFData ApiGatewayProxyInput where
  rnf ApiGatewayProxyInput' {..} =
    Prelude.rnf stageName
      `Prelude.seq` Prelude.rnf endpointType

instance Core.ToJSON ApiGatewayProxyInput where
  toJSON ApiGatewayProxyInput' {..} =
    Core.object
      ( Prelude.catMaybes
          [ ("StageName" Core..=) Prelude.<$> stageName,
            ("EndpointType" Core..=) Prelude.<$> endpointType
          ]
      )
