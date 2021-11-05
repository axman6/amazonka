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
-- Module      : Amazonka.AlexaBusiness.SearchRooms
-- Copyright   : (c) 2013-2021 Brendan Hay
-- License     : Mozilla Public License, v. 2.0.
-- Maintainer  : Brendan Hay <brendan.g.hay+amazonka@gmail.com>
-- Stability   : auto-generated
-- Portability : non-portable (GHC extensions)
--
-- Searches rooms and lists the ones that meet a set of filter and sort
-- criteria.
--
-- This operation returns paginated results.
module Amazonka.AlexaBusiness.SearchRooms
  ( -- * Creating a Request
    SearchRooms (..),
    newSearchRooms,

    -- * Request Lenses
    searchRooms_filters,
    searchRooms_sortCriteria,
    searchRooms_nextToken,
    searchRooms_maxResults,

    -- * Destructuring the Response
    SearchRoomsResponse (..),
    newSearchRoomsResponse,

    -- * Response Lenses
    searchRoomsResponse_rooms,
    searchRoomsResponse_nextToken,
    searchRoomsResponse_totalCount,
    searchRoomsResponse_httpStatus,
  )
where

import Amazonka.AlexaBusiness.Types
import qualified Amazonka.Core as Core
import qualified Amazonka.Lens as Lens
import qualified Amazonka.Prelude as Prelude
import qualified Amazonka.Request as Request
import qualified Amazonka.Response as Response

-- | /See:/ 'newSearchRooms' smart constructor.
data SearchRooms = SearchRooms'
  { -- | The filters to use to list a specified set of rooms. The supported
    -- filter keys are RoomName and ProfileName.
    filters :: Prelude.Maybe [Filter],
    -- | The sort order to use in listing the specified set of rooms. The
    -- supported sort keys are RoomName and ProfileName.
    sortCriteria :: Prelude.Maybe [Sort],
    -- | An optional token returned from a prior request. Use this token for
    -- pagination of results from this action. If this parameter is specified,
    -- the response includes only results beyond the token, up to the value
    -- specified by @MaxResults@.
    nextToken :: Prelude.Maybe Prelude.Text,
    -- | The maximum number of results to include in the response. If more
    -- results exist than the specified @MaxResults@ value, a token is included
    -- in the response so that the remaining results can be retrieved.
    maxResults :: Prelude.Maybe Prelude.Natural
  }
  deriving (Prelude.Eq, Prelude.Read, Prelude.Show, Prelude.Generic)

-- |
-- Create a value of 'SearchRooms' with all optional fields omitted.
--
-- Use <https://hackage.haskell.org/package/generic-lens generic-lens> or <https://hackage.haskell.org/package/optics optics> to modify other optional fields.
--
-- The following record fields are available, with the corresponding lenses provided
-- for backwards compatibility:
--
-- 'filters', 'searchRooms_filters' - The filters to use to list a specified set of rooms. The supported
-- filter keys are RoomName and ProfileName.
--
-- 'sortCriteria', 'searchRooms_sortCriteria' - The sort order to use in listing the specified set of rooms. The
-- supported sort keys are RoomName and ProfileName.
--
-- 'nextToken', 'searchRooms_nextToken' - An optional token returned from a prior request. Use this token for
-- pagination of results from this action. If this parameter is specified,
-- the response includes only results beyond the token, up to the value
-- specified by @MaxResults@.
--
-- 'maxResults', 'searchRooms_maxResults' - The maximum number of results to include in the response. If more
-- results exist than the specified @MaxResults@ value, a token is included
-- in the response so that the remaining results can be retrieved.
newSearchRooms ::
  SearchRooms
newSearchRooms =
  SearchRooms'
    { filters = Prelude.Nothing,
      sortCriteria = Prelude.Nothing,
      nextToken = Prelude.Nothing,
      maxResults = Prelude.Nothing
    }

-- | The filters to use to list a specified set of rooms. The supported
-- filter keys are RoomName and ProfileName.
searchRooms_filters :: Lens.Lens' SearchRooms (Prelude.Maybe [Filter])
searchRooms_filters = Lens.lens (\SearchRooms' {filters} -> filters) (\s@SearchRooms' {} a -> s {filters = a} :: SearchRooms) Prelude.. Lens.mapping Lens.coerced

-- | The sort order to use in listing the specified set of rooms. The
-- supported sort keys are RoomName and ProfileName.
searchRooms_sortCriteria :: Lens.Lens' SearchRooms (Prelude.Maybe [Sort])
searchRooms_sortCriteria = Lens.lens (\SearchRooms' {sortCriteria} -> sortCriteria) (\s@SearchRooms' {} a -> s {sortCriteria = a} :: SearchRooms) Prelude.. Lens.mapping Lens.coerced

-- | An optional token returned from a prior request. Use this token for
-- pagination of results from this action. If this parameter is specified,
-- the response includes only results beyond the token, up to the value
-- specified by @MaxResults@.
searchRooms_nextToken :: Lens.Lens' SearchRooms (Prelude.Maybe Prelude.Text)
searchRooms_nextToken = Lens.lens (\SearchRooms' {nextToken} -> nextToken) (\s@SearchRooms' {} a -> s {nextToken = a} :: SearchRooms)

-- | The maximum number of results to include in the response. If more
-- results exist than the specified @MaxResults@ value, a token is included
-- in the response so that the remaining results can be retrieved.
searchRooms_maxResults :: Lens.Lens' SearchRooms (Prelude.Maybe Prelude.Natural)
searchRooms_maxResults = Lens.lens (\SearchRooms' {maxResults} -> maxResults) (\s@SearchRooms' {} a -> s {maxResults = a} :: SearchRooms)

instance Core.AWSPager SearchRooms where
  page rq rs
    | Core.stop
        ( rs
            Lens.^? searchRoomsResponse_nextToken Prelude.. Lens._Just
        ) =
      Prelude.Nothing
    | Core.stop
        ( rs
            Lens.^? searchRoomsResponse_rooms Prelude.. Lens._Just
        ) =
      Prelude.Nothing
    | Prelude.otherwise =
      Prelude.Just Prelude.$
        rq
          Prelude.& searchRooms_nextToken
          Lens..~ rs
          Lens.^? searchRoomsResponse_nextToken Prelude.. Lens._Just

instance Core.AWSRequest SearchRooms where
  type AWSResponse SearchRooms = SearchRoomsResponse
  request = Request.postJSON defaultService
  response =
    Response.receiveJSON
      ( \s h x ->
          SearchRoomsResponse'
            Prelude.<$> (x Core..?> "Rooms" Core..!@ Prelude.mempty)
            Prelude.<*> (x Core..?> "NextToken")
            Prelude.<*> (x Core..?> "TotalCount")
            Prelude.<*> (Prelude.pure (Prelude.fromEnum s))
      )

instance Prelude.Hashable SearchRooms

instance Prelude.NFData SearchRooms

instance Core.ToHeaders SearchRooms where
  toHeaders =
    Prelude.const
      ( Prelude.mconcat
          [ "X-Amz-Target"
              Core.=# ( "AlexaForBusiness.SearchRooms" ::
                          Prelude.ByteString
                      ),
            "Content-Type"
              Core.=# ( "application/x-amz-json-1.1" ::
                          Prelude.ByteString
                      )
          ]
      )

instance Core.ToJSON SearchRooms where
  toJSON SearchRooms' {..} =
    Core.object
      ( Prelude.catMaybes
          [ ("Filters" Core..=) Prelude.<$> filters,
            ("SortCriteria" Core..=) Prelude.<$> sortCriteria,
            ("NextToken" Core..=) Prelude.<$> nextToken,
            ("MaxResults" Core..=) Prelude.<$> maxResults
          ]
      )

instance Core.ToPath SearchRooms where
  toPath = Prelude.const "/"

instance Core.ToQuery SearchRooms where
  toQuery = Prelude.const Prelude.mempty

-- | /See:/ 'newSearchRoomsResponse' smart constructor.
data SearchRoomsResponse = SearchRoomsResponse'
  { -- | The rooms that meet the specified set of filter criteria, in sort order.
    rooms :: Prelude.Maybe [RoomData],
    -- | The token returned to indicate that there is more data available.
    nextToken :: Prelude.Maybe Prelude.Text,
    -- | The total number of rooms returned.
    totalCount :: Prelude.Maybe Prelude.Int,
    -- | The response's http status code.
    httpStatus :: Prelude.Int
  }
  deriving (Prelude.Eq, Prelude.Read, Prelude.Show, Prelude.Generic)

-- |
-- Create a value of 'SearchRoomsResponse' with all optional fields omitted.
--
-- Use <https://hackage.haskell.org/package/generic-lens generic-lens> or <https://hackage.haskell.org/package/optics optics> to modify other optional fields.
--
-- The following record fields are available, with the corresponding lenses provided
-- for backwards compatibility:
--
-- 'rooms', 'searchRoomsResponse_rooms' - The rooms that meet the specified set of filter criteria, in sort order.
--
-- 'nextToken', 'searchRoomsResponse_nextToken' - The token returned to indicate that there is more data available.
--
-- 'totalCount', 'searchRoomsResponse_totalCount' - The total number of rooms returned.
--
-- 'httpStatus', 'searchRoomsResponse_httpStatus' - The response's http status code.
newSearchRoomsResponse ::
  -- | 'httpStatus'
  Prelude.Int ->
  SearchRoomsResponse
newSearchRoomsResponse pHttpStatus_ =
  SearchRoomsResponse'
    { rooms = Prelude.Nothing,
      nextToken = Prelude.Nothing,
      totalCount = Prelude.Nothing,
      httpStatus = pHttpStatus_
    }

-- | The rooms that meet the specified set of filter criteria, in sort order.
searchRoomsResponse_rooms :: Lens.Lens' SearchRoomsResponse (Prelude.Maybe [RoomData])
searchRoomsResponse_rooms = Lens.lens (\SearchRoomsResponse' {rooms} -> rooms) (\s@SearchRoomsResponse' {} a -> s {rooms = a} :: SearchRoomsResponse) Prelude.. Lens.mapping Lens.coerced

-- | The token returned to indicate that there is more data available.
searchRoomsResponse_nextToken :: Lens.Lens' SearchRoomsResponse (Prelude.Maybe Prelude.Text)
searchRoomsResponse_nextToken = Lens.lens (\SearchRoomsResponse' {nextToken} -> nextToken) (\s@SearchRoomsResponse' {} a -> s {nextToken = a} :: SearchRoomsResponse)

-- | The total number of rooms returned.
searchRoomsResponse_totalCount :: Lens.Lens' SearchRoomsResponse (Prelude.Maybe Prelude.Int)
searchRoomsResponse_totalCount = Lens.lens (\SearchRoomsResponse' {totalCount} -> totalCount) (\s@SearchRoomsResponse' {} a -> s {totalCount = a} :: SearchRoomsResponse)

-- | The response's http status code.
searchRoomsResponse_httpStatus :: Lens.Lens' SearchRoomsResponse Prelude.Int
searchRoomsResponse_httpStatus = Lens.lens (\SearchRoomsResponse' {httpStatus} -> httpStatus) (\s@SearchRoomsResponse' {} a -> s {httpStatus = a} :: SearchRoomsResponse)

instance Prelude.NFData SearchRoomsResponse
