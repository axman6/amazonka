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
-- Module      : Amazonka.Chime.ListPhoneNumberOrders
-- Copyright   : (c) 2013-2022 Brendan Hay
-- License     : Mozilla Public License, v. 2.0.
-- Maintainer  : Brendan Hay <brendan.g.hay+amazonka@gmail.com>
-- Stability   : auto-generated
-- Portability : non-portable (GHC extensions)
--
-- Lists the phone number orders for the administrator\'s Amazon Chime
-- account.
module Amazonka.Chime.ListPhoneNumberOrders
  ( -- * Creating a Request
    ListPhoneNumberOrders (..),
    newListPhoneNumberOrders,

    -- * Request Lenses
    listPhoneNumberOrders_nextToken,
    listPhoneNumberOrders_maxResults,

    -- * Destructuring the Response
    ListPhoneNumberOrdersResponse (..),
    newListPhoneNumberOrdersResponse,

    -- * Response Lenses
    listPhoneNumberOrdersResponse_nextToken,
    listPhoneNumberOrdersResponse_phoneNumberOrders,
    listPhoneNumberOrdersResponse_httpStatus,
  )
where

import Amazonka.Chime.Types
import qualified Amazonka.Core as Core
import qualified Amazonka.Core.Lens.Internal as Lens
import qualified Amazonka.Prelude as Prelude
import qualified Amazonka.Request as Request
import qualified Amazonka.Response as Response

-- | /See:/ 'newListPhoneNumberOrders' smart constructor.
data ListPhoneNumberOrders = ListPhoneNumberOrders'
  { -- | The token to use to retrieve the next page of results.
    nextToken :: Prelude.Maybe Prelude.Text,
    -- | The maximum number of results to return in a single call.
    maxResults :: Prelude.Maybe Prelude.Natural
  }
  deriving (Prelude.Eq, Prelude.Read, Prelude.Show, Prelude.Generic)

-- |
-- Create a value of 'ListPhoneNumberOrders' with all optional fields omitted.
--
-- Use <https://hackage.haskell.org/package/generic-lens generic-lens> or <https://hackage.haskell.org/package/optics optics> to modify other optional fields.
--
-- The following record fields are available, with the corresponding lenses provided
-- for backwards compatibility:
--
-- 'nextToken', 'listPhoneNumberOrders_nextToken' - The token to use to retrieve the next page of results.
--
-- 'maxResults', 'listPhoneNumberOrders_maxResults' - The maximum number of results to return in a single call.
newListPhoneNumberOrders ::
  ListPhoneNumberOrders
newListPhoneNumberOrders =
  ListPhoneNumberOrders'
    { nextToken = Prelude.Nothing,
      maxResults = Prelude.Nothing
    }

-- | The token to use to retrieve the next page of results.
listPhoneNumberOrders_nextToken :: Lens.Lens' ListPhoneNumberOrders (Prelude.Maybe Prelude.Text)
listPhoneNumberOrders_nextToken = Lens.lens (\ListPhoneNumberOrders' {nextToken} -> nextToken) (\s@ListPhoneNumberOrders' {} a -> s {nextToken = a} :: ListPhoneNumberOrders)

-- | The maximum number of results to return in a single call.
listPhoneNumberOrders_maxResults :: Lens.Lens' ListPhoneNumberOrders (Prelude.Maybe Prelude.Natural)
listPhoneNumberOrders_maxResults = Lens.lens (\ListPhoneNumberOrders' {maxResults} -> maxResults) (\s@ListPhoneNumberOrders' {} a -> s {maxResults = a} :: ListPhoneNumberOrders)

instance Core.AWSRequest ListPhoneNumberOrders where
  type
    AWSResponse ListPhoneNumberOrders =
      ListPhoneNumberOrdersResponse
  request overrides =
    Request.get (overrides defaultService)
  response =
    Response.receiveJSON
      ( \s h x ->
          ListPhoneNumberOrdersResponse'
            Prelude.<$> (x Core..?> "NextToken")
            Prelude.<*> ( x Core..?> "PhoneNumberOrders"
                            Core..!@ Prelude.mempty
                        )
            Prelude.<*> (Prelude.pure (Prelude.fromEnum s))
      )

instance Prelude.Hashable ListPhoneNumberOrders where
  hashWithSalt _salt ListPhoneNumberOrders' {..} =
    _salt `Prelude.hashWithSalt` nextToken
      `Prelude.hashWithSalt` maxResults

instance Prelude.NFData ListPhoneNumberOrders where
  rnf ListPhoneNumberOrders' {..} =
    Prelude.rnf nextToken
      `Prelude.seq` Prelude.rnf maxResults

instance Core.ToHeaders ListPhoneNumberOrders where
  toHeaders = Prelude.const Prelude.mempty

instance Core.ToPath ListPhoneNumberOrders where
  toPath = Prelude.const "/phone-number-orders"

instance Core.ToQuery ListPhoneNumberOrders where
  toQuery ListPhoneNumberOrders' {..} =
    Prelude.mconcat
      [ "next-token" Core.=: nextToken,
        "max-results" Core.=: maxResults
      ]

-- | /See:/ 'newListPhoneNumberOrdersResponse' smart constructor.
data ListPhoneNumberOrdersResponse = ListPhoneNumberOrdersResponse'
  { -- | The token to use to retrieve the next page of results.
    nextToken :: Prelude.Maybe Prelude.Text,
    -- | The phone number order details.
    phoneNumberOrders :: Prelude.Maybe [PhoneNumberOrder],
    -- | The response's http status code.
    httpStatus :: Prelude.Int
  }
  deriving (Prelude.Eq, Prelude.Show, Prelude.Generic)

-- |
-- Create a value of 'ListPhoneNumberOrdersResponse' with all optional fields omitted.
--
-- Use <https://hackage.haskell.org/package/generic-lens generic-lens> or <https://hackage.haskell.org/package/optics optics> to modify other optional fields.
--
-- The following record fields are available, with the corresponding lenses provided
-- for backwards compatibility:
--
-- 'nextToken', 'listPhoneNumberOrdersResponse_nextToken' - The token to use to retrieve the next page of results.
--
-- 'phoneNumberOrders', 'listPhoneNumberOrdersResponse_phoneNumberOrders' - The phone number order details.
--
-- 'httpStatus', 'listPhoneNumberOrdersResponse_httpStatus' - The response's http status code.
newListPhoneNumberOrdersResponse ::
  -- | 'httpStatus'
  Prelude.Int ->
  ListPhoneNumberOrdersResponse
newListPhoneNumberOrdersResponse pHttpStatus_ =
  ListPhoneNumberOrdersResponse'
    { nextToken =
        Prelude.Nothing,
      phoneNumberOrders = Prelude.Nothing,
      httpStatus = pHttpStatus_
    }

-- | The token to use to retrieve the next page of results.
listPhoneNumberOrdersResponse_nextToken :: Lens.Lens' ListPhoneNumberOrdersResponse (Prelude.Maybe Prelude.Text)
listPhoneNumberOrdersResponse_nextToken = Lens.lens (\ListPhoneNumberOrdersResponse' {nextToken} -> nextToken) (\s@ListPhoneNumberOrdersResponse' {} a -> s {nextToken = a} :: ListPhoneNumberOrdersResponse)

-- | The phone number order details.
listPhoneNumberOrdersResponse_phoneNumberOrders :: Lens.Lens' ListPhoneNumberOrdersResponse (Prelude.Maybe [PhoneNumberOrder])
listPhoneNumberOrdersResponse_phoneNumberOrders = Lens.lens (\ListPhoneNumberOrdersResponse' {phoneNumberOrders} -> phoneNumberOrders) (\s@ListPhoneNumberOrdersResponse' {} a -> s {phoneNumberOrders = a} :: ListPhoneNumberOrdersResponse) Prelude.. Lens.mapping Lens.coerced

-- | The response's http status code.
listPhoneNumberOrdersResponse_httpStatus :: Lens.Lens' ListPhoneNumberOrdersResponse Prelude.Int
listPhoneNumberOrdersResponse_httpStatus = Lens.lens (\ListPhoneNumberOrdersResponse' {httpStatus} -> httpStatus) (\s@ListPhoneNumberOrdersResponse' {} a -> s {httpStatus = a} :: ListPhoneNumberOrdersResponse)

instance Prelude.NFData ListPhoneNumberOrdersResponse where
  rnf ListPhoneNumberOrdersResponse' {..} =
    Prelude.rnf nextToken
      `Prelude.seq` Prelude.rnf phoneNumberOrders
      `Prelude.seq` Prelude.rnf httpStatus
