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
-- Module      : Amazonka.Route53Resolver.ListResolverRuleAssociations
-- Copyright   : (c) 2013-2022 Brendan Hay
-- License     : Mozilla Public License, v. 2.0.
-- Maintainer  : Brendan Hay <brendan.g.hay+amazonka@gmail.com>
-- Stability   : auto-generated
-- Portability : non-portable (GHC extensions)
--
-- Lists the associations that were created between Resolver rules and VPCs
-- using the current Amazon Web Services account.
--
-- This operation returns paginated results.
module Amazonka.Route53Resolver.ListResolverRuleAssociations
  ( -- * Creating a Request
    ListResolverRuleAssociations (..),
    newListResolverRuleAssociations,

    -- * Request Lenses
    listResolverRuleAssociations_nextToken,
    listResolverRuleAssociations_filters,
    listResolverRuleAssociations_maxResults,

    -- * Destructuring the Response
    ListResolverRuleAssociationsResponse (..),
    newListResolverRuleAssociationsResponse,

    -- * Response Lenses
    listResolverRuleAssociationsResponse_nextToken,
    listResolverRuleAssociationsResponse_resolverRuleAssociations,
    listResolverRuleAssociationsResponse_maxResults,
    listResolverRuleAssociationsResponse_httpStatus,
  )
where

import qualified Amazonka.Core as Core
import qualified Amazonka.Lens as Lens
import qualified Amazonka.Prelude as Prelude
import qualified Amazonka.Request as Request
import qualified Amazonka.Response as Response
import Amazonka.Route53Resolver.Types

-- | /See:/ 'newListResolverRuleAssociations' smart constructor.
data ListResolverRuleAssociations = ListResolverRuleAssociations'
  { -- | For the first @ListResolverRuleAssociation@ request, omit this value.
    --
    -- If you have more than @MaxResults@ rule associations, you can submit
    -- another @ListResolverRuleAssociation@ request to get the next group of
    -- rule associations. In the next request, specify the value of @NextToken@
    -- from the previous response.
    nextToken :: Prelude.Maybe Prelude.Text,
    -- | An optional specification to return a subset of Resolver rules, such as
    -- Resolver rules that are associated with the same VPC ID.
    --
    -- If you submit a second or subsequent @ListResolverRuleAssociations@
    -- request and specify the @NextToken@ parameter, you must use the same
    -- values for @Filters@, if any, as in the previous request.
    filters :: Prelude.Maybe [Filter],
    -- | The maximum number of rule associations that you want to return in the
    -- response to a @ListResolverRuleAssociations@ request. If you don\'t
    -- specify a value for @MaxResults@, Resolver returns up to 100 rule
    -- associations.
    maxResults :: Prelude.Maybe Prelude.Natural
  }
  deriving (Prelude.Eq, Prelude.Read, Prelude.Show, Prelude.Generic)

-- |
-- Create a value of 'ListResolverRuleAssociations' with all optional fields omitted.
--
-- Use <https://hackage.haskell.org/package/generic-lens generic-lens> or <https://hackage.haskell.org/package/optics optics> to modify other optional fields.
--
-- The following record fields are available, with the corresponding lenses provided
-- for backwards compatibility:
--
-- 'nextToken', 'listResolverRuleAssociations_nextToken' - For the first @ListResolverRuleAssociation@ request, omit this value.
--
-- If you have more than @MaxResults@ rule associations, you can submit
-- another @ListResolverRuleAssociation@ request to get the next group of
-- rule associations. In the next request, specify the value of @NextToken@
-- from the previous response.
--
-- 'filters', 'listResolverRuleAssociations_filters' - An optional specification to return a subset of Resolver rules, such as
-- Resolver rules that are associated with the same VPC ID.
--
-- If you submit a second or subsequent @ListResolverRuleAssociations@
-- request and specify the @NextToken@ parameter, you must use the same
-- values for @Filters@, if any, as in the previous request.
--
-- 'maxResults', 'listResolverRuleAssociations_maxResults' - The maximum number of rule associations that you want to return in the
-- response to a @ListResolverRuleAssociations@ request. If you don\'t
-- specify a value for @MaxResults@, Resolver returns up to 100 rule
-- associations.
newListResolverRuleAssociations ::
  ListResolverRuleAssociations
newListResolverRuleAssociations =
  ListResolverRuleAssociations'
    { nextToken =
        Prelude.Nothing,
      filters = Prelude.Nothing,
      maxResults = Prelude.Nothing
    }

-- | For the first @ListResolverRuleAssociation@ request, omit this value.
--
-- If you have more than @MaxResults@ rule associations, you can submit
-- another @ListResolverRuleAssociation@ request to get the next group of
-- rule associations. In the next request, specify the value of @NextToken@
-- from the previous response.
listResolverRuleAssociations_nextToken :: Lens.Lens' ListResolverRuleAssociations (Prelude.Maybe Prelude.Text)
listResolverRuleAssociations_nextToken = Lens.lens (\ListResolverRuleAssociations' {nextToken} -> nextToken) (\s@ListResolverRuleAssociations' {} a -> s {nextToken = a} :: ListResolverRuleAssociations)

-- | An optional specification to return a subset of Resolver rules, such as
-- Resolver rules that are associated with the same VPC ID.
--
-- If you submit a second or subsequent @ListResolverRuleAssociations@
-- request and specify the @NextToken@ parameter, you must use the same
-- values for @Filters@, if any, as in the previous request.
listResolverRuleAssociations_filters :: Lens.Lens' ListResolverRuleAssociations (Prelude.Maybe [Filter])
listResolverRuleAssociations_filters = Lens.lens (\ListResolverRuleAssociations' {filters} -> filters) (\s@ListResolverRuleAssociations' {} a -> s {filters = a} :: ListResolverRuleAssociations) Prelude.. Lens.mapping Lens.coerced

-- | The maximum number of rule associations that you want to return in the
-- response to a @ListResolverRuleAssociations@ request. If you don\'t
-- specify a value for @MaxResults@, Resolver returns up to 100 rule
-- associations.
listResolverRuleAssociations_maxResults :: Lens.Lens' ListResolverRuleAssociations (Prelude.Maybe Prelude.Natural)
listResolverRuleAssociations_maxResults = Lens.lens (\ListResolverRuleAssociations' {maxResults} -> maxResults) (\s@ListResolverRuleAssociations' {} a -> s {maxResults = a} :: ListResolverRuleAssociations)

instance Core.AWSPager ListResolverRuleAssociations where
  page rq rs
    | Core.stop
        ( rs
            Lens.^? listResolverRuleAssociationsResponse_nextToken
              Prelude.. Lens._Just
        ) =
      Prelude.Nothing
    | Core.stop
        ( rs
            Lens.^? listResolverRuleAssociationsResponse_resolverRuleAssociations
              Prelude.. Lens._Just
        ) =
      Prelude.Nothing
    | Prelude.otherwise =
      Prelude.Just Prelude.$
        rq
          Prelude.& listResolverRuleAssociations_nextToken
          Lens..~ rs
          Lens.^? listResolverRuleAssociationsResponse_nextToken
            Prelude.. Lens._Just

instance Core.AWSRequest ListResolverRuleAssociations where
  type
    AWSResponse ListResolverRuleAssociations =
      ListResolverRuleAssociationsResponse
  request = Request.postJSON defaultService
  response =
    Response.receiveJSON
      ( \s h x ->
          ListResolverRuleAssociationsResponse'
            Prelude.<$> (x Core..?> "NextToken")
            Prelude.<*> ( x Core..?> "ResolverRuleAssociations"
                            Core..!@ Prelude.mempty
                        )
            Prelude.<*> (x Core..?> "MaxResults")
            Prelude.<*> (Prelude.pure (Prelude.fromEnum s))
      )

instance
  Prelude.Hashable
    ListResolverRuleAssociations
  where
  hashWithSalt _salt ListResolverRuleAssociations' {..} =
    _salt `Prelude.hashWithSalt` nextToken
      `Prelude.hashWithSalt` filters
      `Prelude.hashWithSalt` maxResults

instance Prelude.NFData ListResolverRuleAssociations where
  rnf ListResolverRuleAssociations' {..} =
    Prelude.rnf nextToken
      `Prelude.seq` Prelude.rnf filters
      `Prelude.seq` Prelude.rnf maxResults

instance Core.ToHeaders ListResolverRuleAssociations where
  toHeaders =
    Prelude.const
      ( Prelude.mconcat
          [ "X-Amz-Target"
              Core.=# ( "Route53Resolver.ListResolverRuleAssociations" ::
                          Prelude.ByteString
                      ),
            "Content-Type"
              Core.=# ( "application/x-amz-json-1.1" ::
                          Prelude.ByteString
                      )
          ]
      )

instance Core.ToJSON ListResolverRuleAssociations where
  toJSON ListResolverRuleAssociations' {..} =
    Core.object
      ( Prelude.catMaybes
          [ ("NextToken" Core..=) Prelude.<$> nextToken,
            ("Filters" Core..=) Prelude.<$> filters,
            ("MaxResults" Core..=) Prelude.<$> maxResults
          ]
      )

instance Core.ToPath ListResolverRuleAssociations where
  toPath = Prelude.const "/"

instance Core.ToQuery ListResolverRuleAssociations where
  toQuery = Prelude.const Prelude.mempty

-- | /See:/ 'newListResolverRuleAssociationsResponse' smart constructor.
data ListResolverRuleAssociationsResponse = ListResolverRuleAssociationsResponse'
  { -- | If more than @MaxResults@ rule associations match the specified
    -- criteria, you can submit another @ListResolverRuleAssociation@ request
    -- to get the next group of results. In the next request, specify the value
    -- of @NextToken@ from the previous response.
    nextToken :: Prelude.Maybe Prelude.Text,
    -- | The associations that were created between Resolver rules and VPCs using
    -- the current Amazon Web Services account, and that match the specified
    -- filters, if any.
    resolverRuleAssociations :: Prelude.Maybe [ResolverRuleAssociation],
    -- | The value that you specified for @MaxResults@ in the request.
    maxResults :: Prelude.Maybe Prelude.Natural,
    -- | The response's http status code.
    httpStatus :: Prelude.Int
  }
  deriving (Prelude.Eq, Prelude.Read, Prelude.Show, Prelude.Generic)

-- |
-- Create a value of 'ListResolverRuleAssociationsResponse' with all optional fields omitted.
--
-- Use <https://hackage.haskell.org/package/generic-lens generic-lens> or <https://hackage.haskell.org/package/optics optics> to modify other optional fields.
--
-- The following record fields are available, with the corresponding lenses provided
-- for backwards compatibility:
--
-- 'nextToken', 'listResolverRuleAssociationsResponse_nextToken' - If more than @MaxResults@ rule associations match the specified
-- criteria, you can submit another @ListResolverRuleAssociation@ request
-- to get the next group of results. In the next request, specify the value
-- of @NextToken@ from the previous response.
--
-- 'resolverRuleAssociations', 'listResolverRuleAssociationsResponse_resolverRuleAssociations' - The associations that were created between Resolver rules and VPCs using
-- the current Amazon Web Services account, and that match the specified
-- filters, if any.
--
-- 'maxResults', 'listResolverRuleAssociationsResponse_maxResults' - The value that you specified for @MaxResults@ in the request.
--
-- 'httpStatus', 'listResolverRuleAssociationsResponse_httpStatus' - The response's http status code.
newListResolverRuleAssociationsResponse ::
  -- | 'httpStatus'
  Prelude.Int ->
  ListResolverRuleAssociationsResponse
newListResolverRuleAssociationsResponse pHttpStatus_ =
  ListResolverRuleAssociationsResponse'
    { nextToken =
        Prelude.Nothing,
      resolverRuleAssociations =
        Prelude.Nothing,
      maxResults = Prelude.Nothing,
      httpStatus = pHttpStatus_
    }

-- | If more than @MaxResults@ rule associations match the specified
-- criteria, you can submit another @ListResolverRuleAssociation@ request
-- to get the next group of results. In the next request, specify the value
-- of @NextToken@ from the previous response.
listResolverRuleAssociationsResponse_nextToken :: Lens.Lens' ListResolverRuleAssociationsResponse (Prelude.Maybe Prelude.Text)
listResolverRuleAssociationsResponse_nextToken = Lens.lens (\ListResolverRuleAssociationsResponse' {nextToken} -> nextToken) (\s@ListResolverRuleAssociationsResponse' {} a -> s {nextToken = a} :: ListResolverRuleAssociationsResponse)

-- | The associations that were created between Resolver rules and VPCs using
-- the current Amazon Web Services account, and that match the specified
-- filters, if any.
listResolverRuleAssociationsResponse_resolverRuleAssociations :: Lens.Lens' ListResolverRuleAssociationsResponse (Prelude.Maybe [ResolverRuleAssociation])
listResolverRuleAssociationsResponse_resolverRuleAssociations = Lens.lens (\ListResolverRuleAssociationsResponse' {resolverRuleAssociations} -> resolverRuleAssociations) (\s@ListResolverRuleAssociationsResponse' {} a -> s {resolverRuleAssociations = a} :: ListResolverRuleAssociationsResponse) Prelude.. Lens.mapping Lens.coerced

-- | The value that you specified for @MaxResults@ in the request.
listResolverRuleAssociationsResponse_maxResults :: Lens.Lens' ListResolverRuleAssociationsResponse (Prelude.Maybe Prelude.Natural)
listResolverRuleAssociationsResponse_maxResults = Lens.lens (\ListResolverRuleAssociationsResponse' {maxResults} -> maxResults) (\s@ListResolverRuleAssociationsResponse' {} a -> s {maxResults = a} :: ListResolverRuleAssociationsResponse)

-- | The response's http status code.
listResolverRuleAssociationsResponse_httpStatus :: Lens.Lens' ListResolverRuleAssociationsResponse Prelude.Int
listResolverRuleAssociationsResponse_httpStatus = Lens.lens (\ListResolverRuleAssociationsResponse' {httpStatus} -> httpStatus) (\s@ListResolverRuleAssociationsResponse' {} a -> s {httpStatus = a} :: ListResolverRuleAssociationsResponse)

instance
  Prelude.NFData
    ListResolverRuleAssociationsResponse
  where
  rnf ListResolverRuleAssociationsResponse' {..} =
    Prelude.rnf nextToken
      `Prelude.seq` Prelude.rnf resolverRuleAssociations
      `Prelude.seq` Prelude.rnf maxResults
      `Prelude.seq` Prelude.rnf httpStatus
