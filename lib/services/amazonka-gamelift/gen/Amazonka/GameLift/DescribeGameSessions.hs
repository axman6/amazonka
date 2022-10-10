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
-- Module      : Amazonka.GameLift.DescribeGameSessions
-- Copyright   : (c) 2013-2022 Brendan Hay
-- License     : Mozilla Public License, v. 2.0.
-- Maintainer  : Brendan Hay <brendan.g.hay+amazonka@gmail.com>
-- Stability   : auto-generated
-- Portability : non-portable (GHC extensions)
--
-- Retrieves a set of one or more game sessions in a specific fleet
-- location. You can optionally filter the results by current game session
-- status. Alternatively, use SearchGameSessions to request a set of active
-- game sessions that are filtered by certain criteria. To retrieve the
-- protection policy for game sessions, use DescribeGameSessionDetails.
--
-- This operation is not designed to be continually called to track game
-- session status. This practice can cause you to exceed your API limit,
-- which results in errors. Instead, you must configure configure an Amazon
-- Simple Notification Service (SNS) topic to receive notifications from
-- FlexMatch or queues. Continuously polling with @DescribeGameSessions@
-- should only be used for games in development with low game session
-- usage.
--
-- This operation can be used in the following ways:
--
-- -   To retrieve all game sessions that are currently running on all
--     locations in a fleet, provide a fleet or alias ID, with an optional
--     status filter. This approach returns all game sessions in the
--     fleet\'s home Region and all remote locations.
--
-- -   To retrieve all game sessions that are currently running on a
--     specific fleet location, provide a fleet or alias ID and a location
--     name, with optional status filter. The location can be the fleet\'s
--     home Region or any remote location.
--
-- -   To retrieve a specific game session, provide the game session ID.
--     This approach looks for the game session ID in all fleets that
--     reside in the Amazon Web Services Region defined in the request.
--
-- Use the pagination parameters to retrieve results as a set of sequential
-- pages.
--
-- If successful, a @GameSession@ object is returned for each game session
-- that matches the request.
--
-- This operation is not designed to be continually called to track
-- matchmaking ticket status. This practice can cause you to exceed your
-- API limit, which results in errors. Instead, as a best practice, set up
-- an Amazon Simple Notification Service to receive notifications, and
-- provide the topic ARN in the matchmaking configuration. Continuously
-- poling ticket status with DescribeGameSessions should only be used for
-- games in development with low matchmaking usage.
--
-- /Available in Amazon GameLift Local./
--
-- __Learn more__
--
-- <https://docs.aws.amazon.com/gamelift/latest/developerguide/gamelift-sdk-client-api.html#gamelift-sdk-client-api-find Find a game session>
--
-- __Related actions__
--
-- CreateGameSession | DescribeGameSessions | DescribeGameSessionDetails |
-- SearchGameSessions | UpdateGameSession | GetGameSessionLogUrl |
-- StartGameSessionPlacement | DescribeGameSessionPlacement |
-- StopGameSessionPlacement |
-- <https://docs.aws.amazon.com/gamelift/latest/developerguide/reference-awssdk.html#reference-awssdk-resources-fleets All APIs by task>
--
-- This operation returns paginated results.
module Amazonka.GameLift.DescribeGameSessions
  ( -- * Creating a Request
    DescribeGameSessions (..),
    newDescribeGameSessions,

    -- * Request Lenses
    describeGameSessions_gameSessionId,
    describeGameSessions_fleetId,
    describeGameSessions_nextToken,
    describeGameSessions_aliasId,
    describeGameSessions_location,
    describeGameSessions_limit,
    describeGameSessions_statusFilter,

    -- * Destructuring the Response
    DescribeGameSessionsResponse (..),
    newDescribeGameSessionsResponse,

    -- * Response Lenses
    describeGameSessionsResponse_nextToken,
    describeGameSessionsResponse_gameSessions,
    describeGameSessionsResponse_httpStatus,
  )
where

import qualified Amazonka.Core as Core
import Amazonka.GameLift.Types
import qualified Amazonka.Lens as Lens
import qualified Amazonka.Prelude as Prelude
import qualified Amazonka.Request as Request
import qualified Amazonka.Response as Response

-- | Represents the input for a request operation.
--
-- /See:/ 'newDescribeGameSessions' smart constructor.
data DescribeGameSessions = DescribeGameSessions'
  { -- | A unique identifier for the game session to retrieve.
    gameSessionId :: Prelude.Maybe Prelude.Text,
    -- | A unique identifier for the fleet to retrieve game sessions for. You can
    -- use either the fleet ID or ARN value.
    fleetId :: Prelude.Maybe Prelude.Text,
    -- | A token that indicates the start of the next sequential page of results.
    -- Use the token that is returned with a previous call to this operation.
    -- To start at the beginning of the result set, do not specify a value.
    nextToken :: Prelude.Maybe Prelude.Text,
    -- | A unique identifier for the alias associated with the fleet to retrieve
    -- game sessions for. You can use either the alias ID or ARN value.
    aliasId :: Prelude.Maybe Prelude.Text,
    -- | A fleet location to get game session details for. You can specify a
    -- fleet\'s home Region or a remote location. Use the Amazon Web Services
    -- Region code format, such as @us-west-2@.
    location :: Prelude.Maybe Prelude.Text,
    -- | The maximum number of results to return. Use this parameter with
    -- @NextToken@ to get results as a set of sequential pages.
    limit :: Prelude.Maybe Prelude.Natural,
    -- | Game session status to filter results on. You can filter on the
    -- following states: @ACTIVE@, @TERMINATED@, @ACTIVATING@, and
    -- @TERMINATING@. The last two are transitory and used for only very brief
    -- periods of time.
    statusFilter :: Prelude.Maybe Prelude.Text
  }
  deriving (Prelude.Eq, Prelude.Read, Prelude.Show, Prelude.Generic)

-- |
-- Create a value of 'DescribeGameSessions' with all optional fields omitted.
--
-- Use <https://hackage.haskell.org/package/generic-lens generic-lens> or <https://hackage.haskell.org/package/optics optics> to modify other optional fields.
--
-- The following record fields are available, with the corresponding lenses provided
-- for backwards compatibility:
--
-- 'gameSessionId', 'describeGameSessions_gameSessionId' - A unique identifier for the game session to retrieve.
--
-- 'fleetId', 'describeGameSessions_fleetId' - A unique identifier for the fleet to retrieve game sessions for. You can
-- use either the fleet ID or ARN value.
--
-- 'nextToken', 'describeGameSessions_nextToken' - A token that indicates the start of the next sequential page of results.
-- Use the token that is returned with a previous call to this operation.
-- To start at the beginning of the result set, do not specify a value.
--
-- 'aliasId', 'describeGameSessions_aliasId' - A unique identifier for the alias associated with the fleet to retrieve
-- game sessions for. You can use either the alias ID or ARN value.
--
-- 'location', 'describeGameSessions_location' - A fleet location to get game session details for. You can specify a
-- fleet\'s home Region or a remote location. Use the Amazon Web Services
-- Region code format, such as @us-west-2@.
--
-- 'limit', 'describeGameSessions_limit' - The maximum number of results to return. Use this parameter with
-- @NextToken@ to get results as a set of sequential pages.
--
-- 'statusFilter', 'describeGameSessions_statusFilter' - Game session status to filter results on. You can filter on the
-- following states: @ACTIVE@, @TERMINATED@, @ACTIVATING@, and
-- @TERMINATING@. The last two are transitory and used for only very brief
-- periods of time.
newDescribeGameSessions ::
  DescribeGameSessions
newDescribeGameSessions =
  DescribeGameSessions'
    { gameSessionId =
        Prelude.Nothing,
      fleetId = Prelude.Nothing,
      nextToken = Prelude.Nothing,
      aliasId = Prelude.Nothing,
      location = Prelude.Nothing,
      limit = Prelude.Nothing,
      statusFilter = Prelude.Nothing
    }

-- | A unique identifier for the game session to retrieve.
describeGameSessions_gameSessionId :: Lens.Lens' DescribeGameSessions (Prelude.Maybe Prelude.Text)
describeGameSessions_gameSessionId = Lens.lens (\DescribeGameSessions' {gameSessionId} -> gameSessionId) (\s@DescribeGameSessions' {} a -> s {gameSessionId = a} :: DescribeGameSessions)

-- | A unique identifier for the fleet to retrieve game sessions for. You can
-- use either the fleet ID or ARN value.
describeGameSessions_fleetId :: Lens.Lens' DescribeGameSessions (Prelude.Maybe Prelude.Text)
describeGameSessions_fleetId = Lens.lens (\DescribeGameSessions' {fleetId} -> fleetId) (\s@DescribeGameSessions' {} a -> s {fleetId = a} :: DescribeGameSessions)

-- | A token that indicates the start of the next sequential page of results.
-- Use the token that is returned with a previous call to this operation.
-- To start at the beginning of the result set, do not specify a value.
describeGameSessions_nextToken :: Lens.Lens' DescribeGameSessions (Prelude.Maybe Prelude.Text)
describeGameSessions_nextToken = Lens.lens (\DescribeGameSessions' {nextToken} -> nextToken) (\s@DescribeGameSessions' {} a -> s {nextToken = a} :: DescribeGameSessions)

-- | A unique identifier for the alias associated with the fleet to retrieve
-- game sessions for. You can use either the alias ID or ARN value.
describeGameSessions_aliasId :: Lens.Lens' DescribeGameSessions (Prelude.Maybe Prelude.Text)
describeGameSessions_aliasId = Lens.lens (\DescribeGameSessions' {aliasId} -> aliasId) (\s@DescribeGameSessions' {} a -> s {aliasId = a} :: DescribeGameSessions)

-- | A fleet location to get game session details for. You can specify a
-- fleet\'s home Region or a remote location. Use the Amazon Web Services
-- Region code format, such as @us-west-2@.
describeGameSessions_location :: Lens.Lens' DescribeGameSessions (Prelude.Maybe Prelude.Text)
describeGameSessions_location = Lens.lens (\DescribeGameSessions' {location} -> location) (\s@DescribeGameSessions' {} a -> s {location = a} :: DescribeGameSessions)

-- | The maximum number of results to return. Use this parameter with
-- @NextToken@ to get results as a set of sequential pages.
describeGameSessions_limit :: Lens.Lens' DescribeGameSessions (Prelude.Maybe Prelude.Natural)
describeGameSessions_limit = Lens.lens (\DescribeGameSessions' {limit} -> limit) (\s@DescribeGameSessions' {} a -> s {limit = a} :: DescribeGameSessions)

-- | Game session status to filter results on. You can filter on the
-- following states: @ACTIVE@, @TERMINATED@, @ACTIVATING@, and
-- @TERMINATING@. The last two are transitory and used for only very brief
-- periods of time.
describeGameSessions_statusFilter :: Lens.Lens' DescribeGameSessions (Prelude.Maybe Prelude.Text)
describeGameSessions_statusFilter = Lens.lens (\DescribeGameSessions' {statusFilter} -> statusFilter) (\s@DescribeGameSessions' {} a -> s {statusFilter = a} :: DescribeGameSessions)

instance Core.AWSPager DescribeGameSessions where
  page rq rs
    | Core.stop
        ( rs
            Lens.^? describeGameSessionsResponse_nextToken
              Prelude.. Lens._Just
        ) =
      Prelude.Nothing
    | Core.stop
        ( rs
            Lens.^? describeGameSessionsResponse_gameSessions
              Prelude.. Lens._Just
        ) =
      Prelude.Nothing
    | Prelude.otherwise =
      Prelude.Just Prelude.$
        rq
          Prelude.& describeGameSessions_nextToken
          Lens..~ rs
          Lens.^? describeGameSessionsResponse_nextToken
            Prelude.. Lens._Just

instance Core.AWSRequest DescribeGameSessions where
  type
    AWSResponse DescribeGameSessions =
      DescribeGameSessionsResponse
  request = Request.postJSON defaultService
  response =
    Response.receiveJSON
      ( \s h x ->
          DescribeGameSessionsResponse'
            Prelude.<$> (x Core..?> "NextToken")
            Prelude.<*> (x Core..?> "GameSessions" Core..!@ Prelude.mempty)
            Prelude.<*> (Prelude.pure (Prelude.fromEnum s))
      )

instance Prelude.Hashable DescribeGameSessions where
  hashWithSalt _salt DescribeGameSessions' {..} =
    _salt `Prelude.hashWithSalt` gameSessionId
      `Prelude.hashWithSalt` fleetId
      `Prelude.hashWithSalt` nextToken
      `Prelude.hashWithSalt` aliasId
      `Prelude.hashWithSalt` location
      `Prelude.hashWithSalt` limit
      `Prelude.hashWithSalt` statusFilter

instance Prelude.NFData DescribeGameSessions where
  rnf DescribeGameSessions' {..} =
    Prelude.rnf gameSessionId
      `Prelude.seq` Prelude.rnf fleetId
      `Prelude.seq` Prelude.rnf nextToken
      `Prelude.seq` Prelude.rnf aliasId
      `Prelude.seq` Prelude.rnf location
      `Prelude.seq` Prelude.rnf limit
      `Prelude.seq` Prelude.rnf statusFilter

instance Core.ToHeaders DescribeGameSessions where
  toHeaders =
    Prelude.const
      ( Prelude.mconcat
          [ "X-Amz-Target"
              Core.=# ( "GameLift.DescribeGameSessions" ::
                          Prelude.ByteString
                      ),
            "Content-Type"
              Core.=# ( "application/x-amz-json-1.1" ::
                          Prelude.ByteString
                      )
          ]
      )

instance Core.ToJSON DescribeGameSessions where
  toJSON DescribeGameSessions' {..} =
    Core.object
      ( Prelude.catMaybes
          [ ("GameSessionId" Core..=) Prelude.<$> gameSessionId,
            ("FleetId" Core..=) Prelude.<$> fleetId,
            ("NextToken" Core..=) Prelude.<$> nextToken,
            ("AliasId" Core..=) Prelude.<$> aliasId,
            ("Location" Core..=) Prelude.<$> location,
            ("Limit" Core..=) Prelude.<$> limit,
            ("StatusFilter" Core..=) Prelude.<$> statusFilter
          ]
      )

instance Core.ToPath DescribeGameSessions where
  toPath = Prelude.const "/"

instance Core.ToQuery DescribeGameSessions where
  toQuery = Prelude.const Prelude.mempty

-- | Represents the returned data in response to a request operation.
--
-- /See:/ 'newDescribeGameSessionsResponse' smart constructor.
data DescribeGameSessionsResponse = DescribeGameSessionsResponse'
  { -- | A token that indicates where to resume retrieving results on the next
    -- call to this operation. If no token is returned, these results represent
    -- the end of the list.
    nextToken :: Prelude.Maybe Prelude.Text,
    -- | A collection of properties for each game session that matches the
    -- request.
    gameSessions :: Prelude.Maybe [GameSession],
    -- | The response's http status code.
    httpStatus :: Prelude.Int
  }
  deriving (Prelude.Eq, Prelude.Read, Prelude.Show, Prelude.Generic)

-- |
-- Create a value of 'DescribeGameSessionsResponse' with all optional fields omitted.
--
-- Use <https://hackage.haskell.org/package/generic-lens generic-lens> or <https://hackage.haskell.org/package/optics optics> to modify other optional fields.
--
-- The following record fields are available, with the corresponding lenses provided
-- for backwards compatibility:
--
-- 'nextToken', 'describeGameSessionsResponse_nextToken' - A token that indicates where to resume retrieving results on the next
-- call to this operation. If no token is returned, these results represent
-- the end of the list.
--
-- 'gameSessions', 'describeGameSessionsResponse_gameSessions' - A collection of properties for each game session that matches the
-- request.
--
-- 'httpStatus', 'describeGameSessionsResponse_httpStatus' - The response's http status code.
newDescribeGameSessionsResponse ::
  -- | 'httpStatus'
  Prelude.Int ->
  DescribeGameSessionsResponse
newDescribeGameSessionsResponse pHttpStatus_ =
  DescribeGameSessionsResponse'
    { nextToken =
        Prelude.Nothing,
      gameSessions = Prelude.Nothing,
      httpStatus = pHttpStatus_
    }

-- | A token that indicates where to resume retrieving results on the next
-- call to this operation. If no token is returned, these results represent
-- the end of the list.
describeGameSessionsResponse_nextToken :: Lens.Lens' DescribeGameSessionsResponse (Prelude.Maybe Prelude.Text)
describeGameSessionsResponse_nextToken = Lens.lens (\DescribeGameSessionsResponse' {nextToken} -> nextToken) (\s@DescribeGameSessionsResponse' {} a -> s {nextToken = a} :: DescribeGameSessionsResponse)

-- | A collection of properties for each game session that matches the
-- request.
describeGameSessionsResponse_gameSessions :: Lens.Lens' DescribeGameSessionsResponse (Prelude.Maybe [GameSession])
describeGameSessionsResponse_gameSessions = Lens.lens (\DescribeGameSessionsResponse' {gameSessions} -> gameSessions) (\s@DescribeGameSessionsResponse' {} a -> s {gameSessions = a} :: DescribeGameSessionsResponse) Prelude.. Lens.mapping Lens.coerced

-- | The response's http status code.
describeGameSessionsResponse_httpStatus :: Lens.Lens' DescribeGameSessionsResponse Prelude.Int
describeGameSessionsResponse_httpStatus = Lens.lens (\DescribeGameSessionsResponse' {httpStatus} -> httpStatus) (\s@DescribeGameSessionsResponse' {} a -> s {httpStatus = a} :: DescribeGameSessionsResponse)

instance Prelude.NFData DescribeGameSessionsResponse where
  rnf DescribeGameSessionsResponse' {..} =
    Prelude.rnf nextToken
      `Prelude.seq` Prelude.rnf gameSessions
      `Prelude.seq` Prelude.rnf httpStatus
