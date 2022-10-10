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
-- Module      : Amazonka.ServiceCatalog.DescribeProvisioningParameters
-- Copyright   : (c) 2013-2022 Brendan Hay
-- License     : Mozilla Public License, v. 2.0.
-- Maintainer  : Brendan Hay <brendan.g.hay+amazonka@gmail.com>
-- Stability   : auto-generated
-- Portability : non-portable (GHC extensions)
--
-- Gets information about the configuration required to provision the
-- specified product using the specified provisioning artifact.
--
-- If the output contains a TagOption key with an empty list of values,
-- there is a TagOption conflict for that key. The end user cannot take
-- action to fix the conflict, and launch is not blocked. In subsequent
-- calls to ProvisionProduct, do not include conflicted TagOption keys as
-- tags, or this causes the error \"Parameter validation failed: Missing
-- required parameter in Tags[/N/]:/Value/\". Tag the provisioned product
-- with the value @sc-tagoption-conflict-portfolioId-productId@.
module Amazonka.ServiceCatalog.DescribeProvisioningParameters
  ( -- * Creating a Request
    DescribeProvisioningParameters (..),
    newDescribeProvisioningParameters,

    -- * Request Lenses
    describeProvisioningParameters_productName,
    describeProvisioningParameters_pathId,
    describeProvisioningParameters_productId,
    describeProvisioningParameters_pathName,
    describeProvisioningParameters_provisioningArtifactName,
    describeProvisioningParameters_provisioningArtifactId,
    describeProvisioningParameters_acceptLanguage,

    -- * Destructuring the Response
    DescribeProvisioningParametersResponse (..),
    newDescribeProvisioningParametersResponse,

    -- * Response Lenses
    describeProvisioningParametersResponse_constraintSummaries,
    describeProvisioningParametersResponse_usageInstructions,
    describeProvisioningParametersResponse_provisioningArtifactOutputs,
    describeProvisioningParametersResponse_tagOptions,
    describeProvisioningParametersResponse_provisioningArtifactParameters,
    describeProvisioningParametersResponse_provisioningArtifactPreferences,
    describeProvisioningParametersResponse_provisioningArtifactOutputKeys,
    describeProvisioningParametersResponse_httpStatus,
  )
where

import qualified Amazonka.Core as Core
import qualified Amazonka.Lens as Lens
import qualified Amazonka.Prelude as Prelude
import qualified Amazonka.Request as Request
import qualified Amazonka.Response as Response
import Amazonka.ServiceCatalog.Types

-- | /See:/ 'newDescribeProvisioningParameters' smart constructor.
data DescribeProvisioningParameters = DescribeProvisioningParameters'
  { -- | The name of the product. You must provide the name or ID, but not both.
    productName :: Prelude.Maybe Prelude.Text,
    -- | The path identifier of the product. This value is optional if the
    -- product has a default path, and required if the product has more than
    -- one path. To list the paths for a product, use ListLaunchPaths. You must
    -- provide the name or ID, but not both.
    pathId :: Prelude.Maybe Prelude.Text,
    -- | The product identifier. You must provide the product name or ID, but not
    -- both.
    productId :: Prelude.Maybe Prelude.Text,
    -- | The name of the path. You must provide the name or ID, but not both.
    pathName :: Prelude.Maybe Prelude.Text,
    -- | The name of the provisioning artifact. You must provide the name or ID,
    -- but not both.
    provisioningArtifactName :: Prelude.Maybe Prelude.Text,
    -- | The identifier of the provisioning artifact. You must provide the name
    -- or ID, but not both.
    provisioningArtifactId :: Prelude.Maybe Prelude.Text,
    -- | The language code.
    --
    -- -   @en@ - English (default)
    --
    -- -   @jp@ - Japanese
    --
    -- -   @zh@ - Chinese
    acceptLanguage :: Prelude.Maybe Prelude.Text
  }
  deriving (Prelude.Eq, Prelude.Read, Prelude.Show, Prelude.Generic)

-- |
-- Create a value of 'DescribeProvisioningParameters' with all optional fields omitted.
--
-- Use <https://hackage.haskell.org/package/generic-lens generic-lens> or <https://hackage.haskell.org/package/optics optics> to modify other optional fields.
--
-- The following record fields are available, with the corresponding lenses provided
-- for backwards compatibility:
--
-- 'productName', 'describeProvisioningParameters_productName' - The name of the product. You must provide the name or ID, but not both.
--
-- 'pathId', 'describeProvisioningParameters_pathId' - The path identifier of the product. This value is optional if the
-- product has a default path, and required if the product has more than
-- one path. To list the paths for a product, use ListLaunchPaths. You must
-- provide the name or ID, but not both.
--
-- 'productId', 'describeProvisioningParameters_productId' - The product identifier. You must provide the product name or ID, but not
-- both.
--
-- 'pathName', 'describeProvisioningParameters_pathName' - The name of the path. You must provide the name or ID, but not both.
--
-- 'provisioningArtifactName', 'describeProvisioningParameters_provisioningArtifactName' - The name of the provisioning artifact. You must provide the name or ID,
-- but not both.
--
-- 'provisioningArtifactId', 'describeProvisioningParameters_provisioningArtifactId' - The identifier of the provisioning artifact. You must provide the name
-- or ID, but not both.
--
-- 'acceptLanguage', 'describeProvisioningParameters_acceptLanguage' - The language code.
--
-- -   @en@ - English (default)
--
-- -   @jp@ - Japanese
--
-- -   @zh@ - Chinese
newDescribeProvisioningParameters ::
  DescribeProvisioningParameters
newDescribeProvisioningParameters =
  DescribeProvisioningParameters'
    { productName =
        Prelude.Nothing,
      pathId = Prelude.Nothing,
      productId = Prelude.Nothing,
      pathName = Prelude.Nothing,
      provisioningArtifactName = Prelude.Nothing,
      provisioningArtifactId = Prelude.Nothing,
      acceptLanguage = Prelude.Nothing
    }

-- | The name of the product. You must provide the name or ID, but not both.
describeProvisioningParameters_productName :: Lens.Lens' DescribeProvisioningParameters (Prelude.Maybe Prelude.Text)
describeProvisioningParameters_productName = Lens.lens (\DescribeProvisioningParameters' {productName} -> productName) (\s@DescribeProvisioningParameters' {} a -> s {productName = a} :: DescribeProvisioningParameters)

-- | The path identifier of the product. This value is optional if the
-- product has a default path, and required if the product has more than
-- one path. To list the paths for a product, use ListLaunchPaths. You must
-- provide the name or ID, but not both.
describeProvisioningParameters_pathId :: Lens.Lens' DescribeProvisioningParameters (Prelude.Maybe Prelude.Text)
describeProvisioningParameters_pathId = Lens.lens (\DescribeProvisioningParameters' {pathId} -> pathId) (\s@DescribeProvisioningParameters' {} a -> s {pathId = a} :: DescribeProvisioningParameters)

-- | The product identifier. You must provide the product name or ID, but not
-- both.
describeProvisioningParameters_productId :: Lens.Lens' DescribeProvisioningParameters (Prelude.Maybe Prelude.Text)
describeProvisioningParameters_productId = Lens.lens (\DescribeProvisioningParameters' {productId} -> productId) (\s@DescribeProvisioningParameters' {} a -> s {productId = a} :: DescribeProvisioningParameters)

-- | The name of the path. You must provide the name or ID, but not both.
describeProvisioningParameters_pathName :: Lens.Lens' DescribeProvisioningParameters (Prelude.Maybe Prelude.Text)
describeProvisioningParameters_pathName = Lens.lens (\DescribeProvisioningParameters' {pathName} -> pathName) (\s@DescribeProvisioningParameters' {} a -> s {pathName = a} :: DescribeProvisioningParameters)

-- | The name of the provisioning artifact. You must provide the name or ID,
-- but not both.
describeProvisioningParameters_provisioningArtifactName :: Lens.Lens' DescribeProvisioningParameters (Prelude.Maybe Prelude.Text)
describeProvisioningParameters_provisioningArtifactName = Lens.lens (\DescribeProvisioningParameters' {provisioningArtifactName} -> provisioningArtifactName) (\s@DescribeProvisioningParameters' {} a -> s {provisioningArtifactName = a} :: DescribeProvisioningParameters)

-- | The identifier of the provisioning artifact. You must provide the name
-- or ID, but not both.
describeProvisioningParameters_provisioningArtifactId :: Lens.Lens' DescribeProvisioningParameters (Prelude.Maybe Prelude.Text)
describeProvisioningParameters_provisioningArtifactId = Lens.lens (\DescribeProvisioningParameters' {provisioningArtifactId} -> provisioningArtifactId) (\s@DescribeProvisioningParameters' {} a -> s {provisioningArtifactId = a} :: DescribeProvisioningParameters)

-- | The language code.
--
-- -   @en@ - English (default)
--
-- -   @jp@ - Japanese
--
-- -   @zh@ - Chinese
describeProvisioningParameters_acceptLanguage :: Lens.Lens' DescribeProvisioningParameters (Prelude.Maybe Prelude.Text)
describeProvisioningParameters_acceptLanguage = Lens.lens (\DescribeProvisioningParameters' {acceptLanguage} -> acceptLanguage) (\s@DescribeProvisioningParameters' {} a -> s {acceptLanguage = a} :: DescribeProvisioningParameters)

instance
  Core.AWSRequest
    DescribeProvisioningParameters
  where
  type
    AWSResponse DescribeProvisioningParameters =
      DescribeProvisioningParametersResponse
  request = Request.postJSON defaultService
  response =
    Response.receiveJSON
      ( \s h x ->
          DescribeProvisioningParametersResponse'
            Prelude.<$> ( x Core..?> "ConstraintSummaries"
                            Core..!@ Prelude.mempty
                        )
            Prelude.<*> ( x Core..?> "UsageInstructions"
                            Core..!@ Prelude.mempty
                        )
            Prelude.<*> ( x Core..?> "ProvisioningArtifactOutputs"
                            Core..!@ Prelude.mempty
                        )
            Prelude.<*> (x Core..?> "TagOptions" Core..!@ Prelude.mempty)
            Prelude.<*> ( x Core..?> "ProvisioningArtifactParameters"
                            Core..!@ Prelude.mempty
                        )
            Prelude.<*> (x Core..?> "ProvisioningArtifactPreferences")
            Prelude.<*> ( x Core..?> "ProvisioningArtifactOutputKeys"
                            Core..!@ Prelude.mempty
                        )
            Prelude.<*> (Prelude.pure (Prelude.fromEnum s))
      )

instance
  Prelude.Hashable
    DescribeProvisioningParameters
  where
  hashWithSalt
    _salt
    DescribeProvisioningParameters' {..} =
      _salt `Prelude.hashWithSalt` productName
        `Prelude.hashWithSalt` pathId
        `Prelude.hashWithSalt` productId
        `Prelude.hashWithSalt` pathName
        `Prelude.hashWithSalt` provisioningArtifactName
        `Prelude.hashWithSalt` provisioningArtifactId
        `Prelude.hashWithSalt` acceptLanguage

instance
  Prelude.NFData
    DescribeProvisioningParameters
  where
  rnf DescribeProvisioningParameters' {..} =
    Prelude.rnf productName
      `Prelude.seq` Prelude.rnf pathId
      `Prelude.seq` Prelude.rnf productId
      `Prelude.seq` Prelude.rnf pathName
      `Prelude.seq` Prelude.rnf provisioningArtifactName
      `Prelude.seq` Prelude.rnf provisioningArtifactId
      `Prelude.seq` Prelude.rnf acceptLanguage

instance
  Core.ToHeaders
    DescribeProvisioningParameters
  where
  toHeaders =
    Prelude.const
      ( Prelude.mconcat
          [ "X-Amz-Target"
              Core.=# ( "AWS242ServiceCatalogService.DescribeProvisioningParameters" ::
                          Prelude.ByteString
                      ),
            "Content-Type"
              Core.=# ( "application/x-amz-json-1.1" ::
                          Prelude.ByteString
                      )
          ]
      )

instance Core.ToJSON DescribeProvisioningParameters where
  toJSON DescribeProvisioningParameters' {..} =
    Core.object
      ( Prelude.catMaybes
          [ ("ProductName" Core..=) Prelude.<$> productName,
            ("PathId" Core..=) Prelude.<$> pathId,
            ("ProductId" Core..=) Prelude.<$> productId,
            ("PathName" Core..=) Prelude.<$> pathName,
            ("ProvisioningArtifactName" Core..=)
              Prelude.<$> provisioningArtifactName,
            ("ProvisioningArtifactId" Core..=)
              Prelude.<$> provisioningArtifactId,
            ("AcceptLanguage" Core..=)
              Prelude.<$> acceptLanguage
          ]
      )

instance Core.ToPath DescribeProvisioningParameters where
  toPath = Prelude.const "/"

instance Core.ToQuery DescribeProvisioningParameters where
  toQuery = Prelude.const Prelude.mempty

-- | /See:/ 'newDescribeProvisioningParametersResponse' smart constructor.
data DescribeProvisioningParametersResponse = DescribeProvisioningParametersResponse'
  { -- | Information about the constraints used to provision the product.
    constraintSummaries :: Prelude.Maybe [ConstraintSummary],
    -- | Any additional metadata specifically related to the provisioning of the
    -- product. For example, see the @Version@ field of the CloudFormation
    -- template.
    usageInstructions :: Prelude.Maybe [UsageInstruction],
    -- | The output of the provisioning artifact.
    provisioningArtifactOutputs :: Prelude.Maybe [ProvisioningArtifactOutput],
    -- | Information about the TagOptions associated with the resource.
    tagOptions :: Prelude.Maybe [TagOptionSummary],
    -- | Information about the parameters used to provision the product.
    provisioningArtifactParameters :: Prelude.Maybe [ProvisioningArtifactParameter],
    -- | An object that contains information about preferences, such as Regions
    -- and accounts, for the provisioning artifact.
    provisioningArtifactPreferences :: Prelude.Maybe ProvisioningArtifactPreferences,
    -- | A list of the keys and descriptions of the outputs. These outputs can be
    -- referenced from a provisioned product launched from this provisioning
    -- artifact.
    provisioningArtifactOutputKeys :: Prelude.Maybe [ProvisioningArtifactOutput],
    -- | The response's http status code.
    httpStatus :: Prelude.Int
  }
  deriving (Prelude.Eq, Prelude.Read, Prelude.Show, Prelude.Generic)

-- |
-- Create a value of 'DescribeProvisioningParametersResponse' with all optional fields omitted.
--
-- Use <https://hackage.haskell.org/package/generic-lens generic-lens> or <https://hackage.haskell.org/package/optics optics> to modify other optional fields.
--
-- The following record fields are available, with the corresponding lenses provided
-- for backwards compatibility:
--
-- 'constraintSummaries', 'describeProvisioningParametersResponse_constraintSummaries' - Information about the constraints used to provision the product.
--
-- 'usageInstructions', 'describeProvisioningParametersResponse_usageInstructions' - Any additional metadata specifically related to the provisioning of the
-- product. For example, see the @Version@ field of the CloudFormation
-- template.
--
-- 'provisioningArtifactOutputs', 'describeProvisioningParametersResponse_provisioningArtifactOutputs' - The output of the provisioning artifact.
--
-- 'tagOptions', 'describeProvisioningParametersResponse_tagOptions' - Information about the TagOptions associated with the resource.
--
-- 'provisioningArtifactParameters', 'describeProvisioningParametersResponse_provisioningArtifactParameters' - Information about the parameters used to provision the product.
--
-- 'provisioningArtifactPreferences', 'describeProvisioningParametersResponse_provisioningArtifactPreferences' - An object that contains information about preferences, such as Regions
-- and accounts, for the provisioning artifact.
--
-- 'provisioningArtifactOutputKeys', 'describeProvisioningParametersResponse_provisioningArtifactOutputKeys' - A list of the keys and descriptions of the outputs. These outputs can be
-- referenced from a provisioned product launched from this provisioning
-- artifact.
--
-- 'httpStatus', 'describeProvisioningParametersResponse_httpStatus' - The response's http status code.
newDescribeProvisioningParametersResponse ::
  -- | 'httpStatus'
  Prelude.Int ->
  DescribeProvisioningParametersResponse
newDescribeProvisioningParametersResponse
  pHttpStatus_ =
    DescribeProvisioningParametersResponse'
      { constraintSummaries =
          Prelude.Nothing,
        usageInstructions = Prelude.Nothing,
        provisioningArtifactOutputs =
          Prelude.Nothing,
        tagOptions = Prelude.Nothing,
        provisioningArtifactParameters =
          Prelude.Nothing,
        provisioningArtifactPreferences =
          Prelude.Nothing,
        provisioningArtifactOutputKeys =
          Prelude.Nothing,
        httpStatus = pHttpStatus_
      }

-- | Information about the constraints used to provision the product.
describeProvisioningParametersResponse_constraintSummaries :: Lens.Lens' DescribeProvisioningParametersResponse (Prelude.Maybe [ConstraintSummary])
describeProvisioningParametersResponse_constraintSummaries = Lens.lens (\DescribeProvisioningParametersResponse' {constraintSummaries} -> constraintSummaries) (\s@DescribeProvisioningParametersResponse' {} a -> s {constraintSummaries = a} :: DescribeProvisioningParametersResponse) Prelude.. Lens.mapping Lens.coerced

-- | Any additional metadata specifically related to the provisioning of the
-- product. For example, see the @Version@ field of the CloudFormation
-- template.
describeProvisioningParametersResponse_usageInstructions :: Lens.Lens' DescribeProvisioningParametersResponse (Prelude.Maybe [UsageInstruction])
describeProvisioningParametersResponse_usageInstructions = Lens.lens (\DescribeProvisioningParametersResponse' {usageInstructions} -> usageInstructions) (\s@DescribeProvisioningParametersResponse' {} a -> s {usageInstructions = a} :: DescribeProvisioningParametersResponse) Prelude.. Lens.mapping Lens.coerced

-- | The output of the provisioning artifact.
describeProvisioningParametersResponse_provisioningArtifactOutputs :: Lens.Lens' DescribeProvisioningParametersResponse (Prelude.Maybe [ProvisioningArtifactOutput])
describeProvisioningParametersResponse_provisioningArtifactOutputs = Lens.lens (\DescribeProvisioningParametersResponse' {provisioningArtifactOutputs} -> provisioningArtifactOutputs) (\s@DescribeProvisioningParametersResponse' {} a -> s {provisioningArtifactOutputs = a} :: DescribeProvisioningParametersResponse) Prelude.. Lens.mapping Lens.coerced

-- | Information about the TagOptions associated with the resource.
describeProvisioningParametersResponse_tagOptions :: Lens.Lens' DescribeProvisioningParametersResponse (Prelude.Maybe [TagOptionSummary])
describeProvisioningParametersResponse_tagOptions = Lens.lens (\DescribeProvisioningParametersResponse' {tagOptions} -> tagOptions) (\s@DescribeProvisioningParametersResponse' {} a -> s {tagOptions = a} :: DescribeProvisioningParametersResponse) Prelude.. Lens.mapping Lens.coerced

-- | Information about the parameters used to provision the product.
describeProvisioningParametersResponse_provisioningArtifactParameters :: Lens.Lens' DescribeProvisioningParametersResponse (Prelude.Maybe [ProvisioningArtifactParameter])
describeProvisioningParametersResponse_provisioningArtifactParameters = Lens.lens (\DescribeProvisioningParametersResponse' {provisioningArtifactParameters} -> provisioningArtifactParameters) (\s@DescribeProvisioningParametersResponse' {} a -> s {provisioningArtifactParameters = a} :: DescribeProvisioningParametersResponse) Prelude.. Lens.mapping Lens.coerced

-- | An object that contains information about preferences, such as Regions
-- and accounts, for the provisioning artifact.
describeProvisioningParametersResponse_provisioningArtifactPreferences :: Lens.Lens' DescribeProvisioningParametersResponse (Prelude.Maybe ProvisioningArtifactPreferences)
describeProvisioningParametersResponse_provisioningArtifactPreferences = Lens.lens (\DescribeProvisioningParametersResponse' {provisioningArtifactPreferences} -> provisioningArtifactPreferences) (\s@DescribeProvisioningParametersResponse' {} a -> s {provisioningArtifactPreferences = a} :: DescribeProvisioningParametersResponse)

-- | A list of the keys and descriptions of the outputs. These outputs can be
-- referenced from a provisioned product launched from this provisioning
-- artifact.
describeProvisioningParametersResponse_provisioningArtifactOutputKeys :: Lens.Lens' DescribeProvisioningParametersResponse (Prelude.Maybe [ProvisioningArtifactOutput])
describeProvisioningParametersResponse_provisioningArtifactOutputKeys = Lens.lens (\DescribeProvisioningParametersResponse' {provisioningArtifactOutputKeys} -> provisioningArtifactOutputKeys) (\s@DescribeProvisioningParametersResponse' {} a -> s {provisioningArtifactOutputKeys = a} :: DescribeProvisioningParametersResponse) Prelude.. Lens.mapping Lens.coerced

-- | The response's http status code.
describeProvisioningParametersResponse_httpStatus :: Lens.Lens' DescribeProvisioningParametersResponse Prelude.Int
describeProvisioningParametersResponse_httpStatus = Lens.lens (\DescribeProvisioningParametersResponse' {httpStatus} -> httpStatus) (\s@DescribeProvisioningParametersResponse' {} a -> s {httpStatus = a} :: DescribeProvisioningParametersResponse)

instance
  Prelude.NFData
    DescribeProvisioningParametersResponse
  where
  rnf DescribeProvisioningParametersResponse' {..} =
    Prelude.rnf constraintSummaries
      `Prelude.seq` Prelude.rnf usageInstructions
      `Prelude.seq` Prelude.rnf provisioningArtifactOutputs
      `Prelude.seq` Prelude.rnf tagOptions
      `Prelude.seq` Prelude.rnf provisioningArtifactParameters
      `Prelude.seq` Prelude.rnf provisioningArtifactPreferences
      `Prelude.seq` Prelude.rnf provisioningArtifactOutputKeys
      `Prelude.seq` Prelude.rnf httpStatus
