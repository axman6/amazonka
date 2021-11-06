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
-- Module      : Amazonka.IoT1ClickDevices.ListDeviceEvents
-- Copyright   : (c) 2013-2021 Brendan Hay
-- License     : Mozilla Public License, v. 2.0.
-- Maintainer  : Brendan Hay <brendan.g.hay+amazonka@gmail.com>
-- Stability   : auto-generated
-- Portability : non-portable (GHC extensions)
--
-- Using a device ID, returns a DeviceEventsResponse object containing an
-- array of events for the device.
--
-- This operation returns paginated results.
module Amazonka.IoT1ClickDevices.ListDeviceEvents
  ( -- * Creating a Request
    ListDeviceEvents (..),
    newListDeviceEvents,

    -- * Request Lenses
    listDeviceEvents_nextToken,
    listDeviceEvents_maxResults,
    listDeviceEvents_deviceId,
    listDeviceEvents_fromTimeStamp,
    listDeviceEvents_toTimeStamp,

    -- * Destructuring the Response
    ListDeviceEventsResponse (..),
    newListDeviceEventsResponse,

    -- * Response Lenses
    listDeviceEventsResponse_nextToken,
    listDeviceEventsResponse_events,
    listDeviceEventsResponse_httpStatus,
  )
where

import qualified Amazonka.Core as Core
import Amazonka.IoT1ClickDevices.Types
import qualified Amazonka.Lens as Lens
import qualified Amazonka.Prelude as Prelude
import qualified Amazonka.Request as Request
import qualified Amazonka.Response as Response

-- | /See:/ 'newListDeviceEvents' smart constructor.
data ListDeviceEvents = ListDeviceEvents'
  { -- | The token to retrieve the next set of results.
    nextToken :: Prelude.Maybe Prelude.Text,
    -- | The maximum number of results to return per request. If not set, a
    -- default value of 100 is used.
    maxResults :: Prelude.Maybe Prelude.Natural,
    -- | The unique identifier of the device.
    deviceId :: Prelude.Text,
    -- | The start date for the device event query, in ISO8061 format. For
    -- example, 2018-03-28T15:45:12.880Z
    fromTimeStamp :: Core.POSIX,
    -- | The end date for the device event query, in ISO8061 format. For example,
    -- 2018-03-28T15:45:12.880Z
    toTimeStamp :: Core.POSIX
  }
  deriving (Prelude.Eq, Prelude.Read, Prelude.Show, Prelude.Generic)

-- |
-- Create a value of 'ListDeviceEvents' with all optional fields omitted.
--
-- Use <https://hackage.haskell.org/package/generic-lens generic-lens> or <https://hackage.haskell.org/package/optics optics> to modify other optional fields.
--
-- The following record fields are available, with the corresponding lenses provided
-- for backwards compatibility:
--
-- 'nextToken', 'listDeviceEvents_nextToken' - The token to retrieve the next set of results.
--
-- 'maxResults', 'listDeviceEvents_maxResults' - The maximum number of results to return per request. If not set, a
-- default value of 100 is used.
--
-- 'deviceId', 'listDeviceEvents_deviceId' - The unique identifier of the device.
--
-- 'fromTimeStamp', 'listDeviceEvents_fromTimeStamp' - The start date for the device event query, in ISO8061 format. For
-- example, 2018-03-28T15:45:12.880Z
--
-- 'toTimeStamp', 'listDeviceEvents_toTimeStamp' - The end date for the device event query, in ISO8061 format. For example,
-- 2018-03-28T15:45:12.880Z
newListDeviceEvents ::
  -- | 'deviceId'
  Prelude.Text ->
  -- | 'fromTimeStamp'
  Prelude.UTCTime ->
  -- | 'toTimeStamp'
  Prelude.UTCTime ->
  ListDeviceEvents
newListDeviceEvents
  pDeviceId_
  pFromTimeStamp_
  pToTimeStamp_ =
    ListDeviceEvents'
      { nextToken = Prelude.Nothing,
        maxResults = Prelude.Nothing,
        deviceId = pDeviceId_,
        fromTimeStamp = Core._Time Lens.# pFromTimeStamp_,
        toTimeStamp = Core._Time Lens.# pToTimeStamp_
      }

-- | The token to retrieve the next set of results.
listDeviceEvents_nextToken :: Lens.Lens' ListDeviceEvents (Prelude.Maybe Prelude.Text)
listDeviceEvents_nextToken = Lens.lens (\ListDeviceEvents' {nextToken} -> nextToken) (\s@ListDeviceEvents' {} a -> s {nextToken = a} :: ListDeviceEvents)

-- | The maximum number of results to return per request. If not set, a
-- default value of 100 is used.
listDeviceEvents_maxResults :: Lens.Lens' ListDeviceEvents (Prelude.Maybe Prelude.Natural)
listDeviceEvents_maxResults = Lens.lens (\ListDeviceEvents' {maxResults} -> maxResults) (\s@ListDeviceEvents' {} a -> s {maxResults = a} :: ListDeviceEvents)

-- | The unique identifier of the device.
listDeviceEvents_deviceId :: Lens.Lens' ListDeviceEvents Prelude.Text
listDeviceEvents_deviceId = Lens.lens (\ListDeviceEvents' {deviceId} -> deviceId) (\s@ListDeviceEvents' {} a -> s {deviceId = a} :: ListDeviceEvents)

-- | The start date for the device event query, in ISO8061 format. For
-- example, 2018-03-28T15:45:12.880Z
listDeviceEvents_fromTimeStamp :: Lens.Lens' ListDeviceEvents Prelude.UTCTime
listDeviceEvents_fromTimeStamp = Lens.lens (\ListDeviceEvents' {fromTimeStamp} -> fromTimeStamp) (\s@ListDeviceEvents' {} a -> s {fromTimeStamp = a} :: ListDeviceEvents) Prelude.. Core._Time

-- | The end date for the device event query, in ISO8061 format. For example,
-- 2018-03-28T15:45:12.880Z
listDeviceEvents_toTimeStamp :: Lens.Lens' ListDeviceEvents Prelude.UTCTime
listDeviceEvents_toTimeStamp = Lens.lens (\ListDeviceEvents' {toTimeStamp} -> toTimeStamp) (\s@ListDeviceEvents' {} a -> s {toTimeStamp = a} :: ListDeviceEvents) Prelude.. Core._Time

instance Core.AWSPager ListDeviceEvents where
  page rq rs
    | Core.stop
        ( rs
            Lens.^? listDeviceEventsResponse_nextToken
              Prelude.. Lens._Just
        ) =
      Prelude.Nothing
    | Core.stop
        ( rs
            Lens.^? listDeviceEventsResponse_events Prelude.. Lens._Just
        ) =
      Prelude.Nothing
    | Prelude.otherwise =
      Prelude.Just Prelude.$
        rq
          Prelude.& listDeviceEvents_nextToken
          Lens..~ rs
          Lens.^? listDeviceEventsResponse_nextToken
            Prelude.. Lens._Just

instance Core.AWSRequest ListDeviceEvents where
  type
    AWSResponse ListDeviceEvents =
      ListDeviceEventsResponse
  request = Request.get defaultService
  response =
    Response.receiveJSON
      ( \s h x ->
          ListDeviceEventsResponse'
            Prelude.<$> (x Core..?> "nextToken")
            Prelude.<*> (x Core..?> "events" Core..!@ Prelude.mempty)
            Prelude.<*> (Prelude.pure (Prelude.fromEnum s))
      )

instance Prelude.Hashable ListDeviceEvents

instance Prelude.NFData ListDeviceEvents

instance Core.ToHeaders ListDeviceEvents where
  toHeaders =
    Prelude.const
      ( Prelude.mconcat
          [ "Content-Type"
              Core.=# ( "application/x-amz-json-1.1" ::
                          Prelude.ByteString
                      )
          ]
      )

instance Core.ToPath ListDeviceEvents where
  toPath ListDeviceEvents' {..} =
    Prelude.mconcat
      ["/devices/", Core.toBS deviceId, "/events"]

instance Core.ToQuery ListDeviceEvents where
  toQuery ListDeviceEvents' {..} =
    Prelude.mconcat
      [ "nextToken" Core.=: nextToken,
        "maxResults" Core.=: maxResults,
        "fromTimeStamp" Core.=: fromTimeStamp,
        "toTimeStamp" Core.=: toTimeStamp
      ]

-- | /See:/ 'newListDeviceEventsResponse' smart constructor.
data ListDeviceEventsResponse = ListDeviceEventsResponse'
  { -- | The token to retrieve the next set of results.
    nextToken :: Prelude.Maybe Prelude.Text,
    -- | An array of zero or more elements describing the event(s) associated
    -- with the device.
    events :: Prelude.Maybe [DeviceEvent],
    -- | The response's http status code.
    httpStatus :: Prelude.Int
  }
  deriving (Prelude.Eq, Prelude.Read, Prelude.Show, Prelude.Generic)

-- |
-- Create a value of 'ListDeviceEventsResponse' with all optional fields omitted.
--
-- Use <https://hackage.haskell.org/package/generic-lens generic-lens> or <https://hackage.haskell.org/package/optics optics> to modify other optional fields.
--
-- The following record fields are available, with the corresponding lenses provided
-- for backwards compatibility:
--
-- 'nextToken', 'listDeviceEventsResponse_nextToken' - The token to retrieve the next set of results.
--
-- 'events', 'listDeviceEventsResponse_events' - An array of zero or more elements describing the event(s) associated
-- with the device.
--
-- 'httpStatus', 'listDeviceEventsResponse_httpStatus' - The response's http status code.
newListDeviceEventsResponse ::
  -- | 'httpStatus'
  Prelude.Int ->
  ListDeviceEventsResponse
newListDeviceEventsResponse pHttpStatus_ =
  ListDeviceEventsResponse'
    { nextToken =
        Prelude.Nothing,
      events = Prelude.Nothing,
      httpStatus = pHttpStatus_
    }

-- | The token to retrieve the next set of results.
listDeviceEventsResponse_nextToken :: Lens.Lens' ListDeviceEventsResponse (Prelude.Maybe Prelude.Text)
listDeviceEventsResponse_nextToken = Lens.lens (\ListDeviceEventsResponse' {nextToken} -> nextToken) (\s@ListDeviceEventsResponse' {} a -> s {nextToken = a} :: ListDeviceEventsResponse)

-- | An array of zero or more elements describing the event(s) associated
-- with the device.
listDeviceEventsResponse_events :: Lens.Lens' ListDeviceEventsResponse (Prelude.Maybe [DeviceEvent])
listDeviceEventsResponse_events = Lens.lens (\ListDeviceEventsResponse' {events} -> events) (\s@ListDeviceEventsResponse' {} a -> s {events = a} :: ListDeviceEventsResponse) Prelude.. Lens.mapping Lens.coerced

-- | The response's http status code.
listDeviceEventsResponse_httpStatus :: Lens.Lens' ListDeviceEventsResponse Prelude.Int
listDeviceEventsResponse_httpStatus = Lens.lens (\ListDeviceEventsResponse' {httpStatus} -> httpStatus) (\s@ListDeviceEventsResponse' {} a -> s {httpStatus = a} :: ListDeviceEventsResponse)

instance Prelude.NFData ListDeviceEventsResponse
