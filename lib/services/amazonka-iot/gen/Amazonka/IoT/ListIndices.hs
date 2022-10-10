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
-- Module      : Amazonka.IoT.ListIndices
-- Copyright   : (c) 2013-2022 Brendan Hay
-- License     : Mozilla Public License, v. 2.0.
-- Maintainer  : Brendan Hay <brendan.g.hay+amazonka@gmail.com>
-- Stability   : auto-generated
-- Portability : non-portable (GHC extensions)
--
-- Lists the search indices.
--
-- Requires permission to access the
-- <https://docs.aws.amazon.com/service-authorization/latest/reference/list_awsiot.html#awsiot-actions-as-permissions ListIndices>
-- action.
--
-- This operation returns paginated results.
module Amazonka.IoT.ListIndices
  ( -- * Creating a Request
    ListIndices (..),
    newListIndices,

    -- * Request Lenses
    listIndices_nextToken,
    listIndices_maxResults,

    -- * Destructuring the Response
    ListIndicesResponse (..),
    newListIndicesResponse,

    -- * Response Lenses
    listIndicesResponse_nextToken,
    listIndicesResponse_indexNames,
    listIndicesResponse_httpStatus,
  )
where

import qualified Amazonka.Core as Core
import Amazonka.IoT.Types
import qualified Amazonka.Lens as Lens
import qualified Amazonka.Prelude as Prelude
import qualified Amazonka.Request as Request
import qualified Amazonka.Response as Response

-- | /See:/ 'newListIndices' smart constructor.
data ListIndices = ListIndices'
  { -- | The token used to get the next set of results, or @null@ if there are no
    -- additional results.
    nextToken :: Prelude.Maybe Prelude.Text,
    -- | The maximum number of results to return at one time.
    maxResults :: Prelude.Maybe Prelude.Natural
  }
  deriving (Prelude.Eq, Prelude.Read, Prelude.Show, Prelude.Generic)

-- |
-- Create a value of 'ListIndices' with all optional fields omitted.
--
-- Use <https://hackage.haskell.org/package/generic-lens generic-lens> or <https://hackage.haskell.org/package/optics optics> to modify other optional fields.
--
-- The following record fields are available, with the corresponding lenses provided
-- for backwards compatibility:
--
-- 'nextToken', 'listIndices_nextToken' - The token used to get the next set of results, or @null@ if there are no
-- additional results.
--
-- 'maxResults', 'listIndices_maxResults' - The maximum number of results to return at one time.
newListIndices ::
  ListIndices
newListIndices =
  ListIndices'
    { nextToken = Prelude.Nothing,
      maxResults = Prelude.Nothing
    }

-- | The token used to get the next set of results, or @null@ if there are no
-- additional results.
listIndices_nextToken :: Lens.Lens' ListIndices (Prelude.Maybe Prelude.Text)
listIndices_nextToken = Lens.lens (\ListIndices' {nextToken} -> nextToken) (\s@ListIndices' {} a -> s {nextToken = a} :: ListIndices)

-- | The maximum number of results to return at one time.
listIndices_maxResults :: Lens.Lens' ListIndices (Prelude.Maybe Prelude.Natural)
listIndices_maxResults = Lens.lens (\ListIndices' {maxResults} -> maxResults) (\s@ListIndices' {} a -> s {maxResults = a} :: ListIndices)

instance Core.AWSPager ListIndices where
  page rq rs
    | Core.stop
        ( rs
            Lens.^? listIndicesResponse_nextToken Prelude.. Lens._Just
        ) =
      Prelude.Nothing
    | Core.stop
        ( rs
            Lens.^? listIndicesResponse_indexNames Prelude.. Lens._Just
        ) =
      Prelude.Nothing
    | Prelude.otherwise =
      Prelude.Just Prelude.$
        rq
          Prelude.& listIndices_nextToken
          Lens..~ rs
          Lens.^? listIndicesResponse_nextToken Prelude.. Lens._Just

instance Core.AWSRequest ListIndices where
  type AWSResponse ListIndices = ListIndicesResponse
  request = Request.get defaultService
  response =
    Response.receiveJSON
      ( \s h x ->
          ListIndicesResponse'
            Prelude.<$> (x Core..?> "nextToken")
            Prelude.<*> (x Core..?> "indexNames" Core..!@ Prelude.mempty)
            Prelude.<*> (Prelude.pure (Prelude.fromEnum s))
      )

instance Prelude.Hashable ListIndices where
  hashWithSalt _salt ListIndices' {..} =
    _salt `Prelude.hashWithSalt` nextToken
      `Prelude.hashWithSalt` maxResults

instance Prelude.NFData ListIndices where
  rnf ListIndices' {..} =
    Prelude.rnf nextToken
      `Prelude.seq` Prelude.rnf maxResults

instance Core.ToHeaders ListIndices where
  toHeaders = Prelude.const Prelude.mempty

instance Core.ToPath ListIndices where
  toPath = Prelude.const "/indices"

instance Core.ToQuery ListIndices where
  toQuery ListIndices' {..} =
    Prelude.mconcat
      [ "nextToken" Core.=: nextToken,
        "maxResults" Core.=: maxResults
      ]

-- | /See:/ 'newListIndicesResponse' smart constructor.
data ListIndicesResponse = ListIndicesResponse'
  { -- | The token used to get the next set of results, or @null@ if there are no
    -- additional results.
    nextToken :: Prelude.Maybe Prelude.Text,
    -- | The index names.
    indexNames :: Prelude.Maybe [Prelude.Text],
    -- | The response's http status code.
    httpStatus :: Prelude.Int
  }
  deriving (Prelude.Eq, Prelude.Read, Prelude.Show, Prelude.Generic)

-- |
-- Create a value of 'ListIndicesResponse' with all optional fields omitted.
--
-- Use <https://hackage.haskell.org/package/generic-lens generic-lens> or <https://hackage.haskell.org/package/optics optics> to modify other optional fields.
--
-- The following record fields are available, with the corresponding lenses provided
-- for backwards compatibility:
--
-- 'nextToken', 'listIndicesResponse_nextToken' - The token used to get the next set of results, or @null@ if there are no
-- additional results.
--
-- 'indexNames', 'listIndicesResponse_indexNames' - The index names.
--
-- 'httpStatus', 'listIndicesResponse_httpStatus' - The response's http status code.
newListIndicesResponse ::
  -- | 'httpStatus'
  Prelude.Int ->
  ListIndicesResponse
newListIndicesResponse pHttpStatus_ =
  ListIndicesResponse'
    { nextToken = Prelude.Nothing,
      indexNames = Prelude.Nothing,
      httpStatus = pHttpStatus_
    }

-- | The token used to get the next set of results, or @null@ if there are no
-- additional results.
listIndicesResponse_nextToken :: Lens.Lens' ListIndicesResponse (Prelude.Maybe Prelude.Text)
listIndicesResponse_nextToken = Lens.lens (\ListIndicesResponse' {nextToken} -> nextToken) (\s@ListIndicesResponse' {} a -> s {nextToken = a} :: ListIndicesResponse)

-- | The index names.
listIndicesResponse_indexNames :: Lens.Lens' ListIndicesResponse (Prelude.Maybe [Prelude.Text])
listIndicesResponse_indexNames = Lens.lens (\ListIndicesResponse' {indexNames} -> indexNames) (\s@ListIndicesResponse' {} a -> s {indexNames = a} :: ListIndicesResponse) Prelude.. Lens.mapping Lens.coerced

-- | The response's http status code.
listIndicesResponse_httpStatus :: Lens.Lens' ListIndicesResponse Prelude.Int
listIndicesResponse_httpStatus = Lens.lens (\ListIndicesResponse' {httpStatus} -> httpStatus) (\s@ListIndicesResponse' {} a -> s {httpStatus = a} :: ListIndicesResponse)

instance Prelude.NFData ListIndicesResponse where
  rnf ListIndicesResponse' {..} =
    Prelude.rnf nextToken
      `Prelude.seq` Prelude.rnf indexNames
      `Prelude.seq` Prelude.rnf httpStatus
