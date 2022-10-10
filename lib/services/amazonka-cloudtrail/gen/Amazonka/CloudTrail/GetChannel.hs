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
-- Module      : Amazonka.CloudTrail.GetChannel
-- Copyright   : (c) 2013-2022 Brendan Hay
-- License     : Mozilla Public License, v. 2.0.
-- Maintainer  : Brendan Hay <brendan.g.hay+amazonka@gmail.com>
-- Stability   : auto-generated
-- Portability : non-portable (GHC extensions)
--
-- Returns the specified CloudTrail service-linked channel. Amazon Web
-- Services services create service-linked channels to view CloudTrail
-- events.
module Amazonka.CloudTrail.GetChannel
  ( -- * Creating a Request
    GetChannel (..),
    newGetChannel,

    -- * Request Lenses
    getChannel_channel,

    -- * Destructuring the Response
    GetChannelResponse (..),
    newGetChannelResponse,

    -- * Response Lenses
    getChannelResponse_name,
    getChannelResponse_sourceConfig,
    getChannelResponse_channelArn,
    getChannelResponse_source,
    getChannelResponse_destinations,
    getChannelResponse_httpStatus,
  )
where

import Amazonka.CloudTrail.Types
import qualified Amazonka.Core as Core
import qualified Amazonka.Lens as Lens
import qualified Amazonka.Prelude as Prelude
import qualified Amazonka.Request as Request
import qualified Amazonka.Response as Response

-- | /See:/ 'newGetChannel' smart constructor.
data GetChannel = GetChannel'
  { -- | The Amazon Resource Name (ARN) of the CloudTrail service-linked channel.
    channel :: Prelude.Text
  }
  deriving (Prelude.Eq, Prelude.Read, Prelude.Show, Prelude.Generic)

-- |
-- Create a value of 'GetChannel' with all optional fields omitted.
--
-- Use <https://hackage.haskell.org/package/generic-lens generic-lens> or <https://hackage.haskell.org/package/optics optics> to modify other optional fields.
--
-- The following record fields are available, with the corresponding lenses provided
-- for backwards compatibility:
--
-- 'channel', 'getChannel_channel' - The Amazon Resource Name (ARN) of the CloudTrail service-linked channel.
newGetChannel ::
  -- | 'channel'
  Prelude.Text ->
  GetChannel
newGetChannel pChannel_ =
  GetChannel' {channel = pChannel_}

-- | The Amazon Resource Name (ARN) of the CloudTrail service-linked channel.
getChannel_channel :: Lens.Lens' GetChannel Prelude.Text
getChannel_channel = Lens.lens (\GetChannel' {channel} -> channel) (\s@GetChannel' {} a -> s {channel = a} :: GetChannel)

instance Core.AWSRequest GetChannel where
  type AWSResponse GetChannel = GetChannelResponse
  request = Request.postJSON defaultService
  response =
    Response.receiveJSON
      ( \s h x ->
          GetChannelResponse'
            Prelude.<$> (x Core..?> "Name")
            Prelude.<*> (x Core..?> "SourceConfig")
            Prelude.<*> (x Core..?> "ChannelArn")
            Prelude.<*> (x Core..?> "Source")
            Prelude.<*> (x Core..?> "Destinations")
            Prelude.<*> (Prelude.pure (Prelude.fromEnum s))
      )

instance Prelude.Hashable GetChannel where
  hashWithSalt _salt GetChannel' {..} =
    _salt `Prelude.hashWithSalt` channel

instance Prelude.NFData GetChannel where
  rnf GetChannel' {..} = Prelude.rnf channel

instance Core.ToHeaders GetChannel where
  toHeaders =
    Prelude.const
      ( Prelude.mconcat
          [ "X-Amz-Target"
              Core.=# ( "com.amazonaws.cloudtrail.v20131101.CloudTrail_20131101.GetChannel" ::
                          Prelude.ByteString
                      ),
            "Content-Type"
              Core.=# ( "application/x-amz-json-1.1" ::
                          Prelude.ByteString
                      )
          ]
      )

instance Core.ToJSON GetChannel where
  toJSON GetChannel' {..} =
    Core.object
      ( Prelude.catMaybes
          [Prelude.Just ("Channel" Core..= channel)]
      )

instance Core.ToPath GetChannel where
  toPath = Prelude.const "/"

instance Core.ToQuery GetChannel where
  toQuery = Prelude.const Prelude.mempty

-- | /See:/ 'newGetChannelResponse' smart constructor.
data GetChannelResponse = GetChannelResponse'
  { -- | The name of the CloudTrail service-linked channel. For service-linked
    -- channels, the value is
    -- @aws-service-channel\/service-name\/custom-suffix@ where @service-name@
    -- represents the name of the Amazon Web Services service that created the
    -- channel and @custom-suffix@ represents the suffix generated by the
    -- Amazon Web Services service.
    name :: Prelude.Maybe Prelude.Text,
    -- | Provides information about the advanced event selectors configured for
    -- the service-linked channel, and whether the service-linked channel
    -- applies to all regions or one region.
    sourceConfig :: Prelude.Maybe SourceConfig,
    -- | The ARN of the CloudTrail service-linked channel.
    channelArn :: Prelude.Maybe Prelude.Text,
    -- | The trail or event data store for the CloudTrail service-linked channel.
    source :: Prelude.Maybe Prelude.Text,
    -- | The Amazon Web Services service that created the CloudTrail
    -- service-linked channel.
    destinations :: Prelude.Maybe (Prelude.NonEmpty Destination),
    -- | The response's http status code.
    httpStatus :: Prelude.Int
  }
  deriving (Prelude.Eq, Prelude.Read, Prelude.Show, Prelude.Generic)

-- |
-- Create a value of 'GetChannelResponse' with all optional fields omitted.
--
-- Use <https://hackage.haskell.org/package/generic-lens generic-lens> or <https://hackage.haskell.org/package/optics optics> to modify other optional fields.
--
-- The following record fields are available, with the corresponding lenses provided
-- for backwards compatibility:
--
-- 'name', 'getChannelResponse_name' - The name of the CloudTrail service-linked channel. For service-linked
-- channels, the value is
-- @aws-service-channel\/service-name\/custom-suffix@ where @service-name@
-- represents the name of the Amazon Web Services service that created the
-- channel and @custom-suffix@ represents the suffix generated by the
-- Amazon Web Services service.
--
-- 'sourceConfig', 'getChannelResponse_sourceConfig' - Provides information about the advanced event selectors configured for
-- the service-linked channel, and whether the service-linked channel
-- applies to all regions or one region.
--
-- 'channelArn', 'getChannelResponse_channelArn' - The ARN of the CloudTrail service-linked channel.
--
-- 'source', 'getChannelResponse_source' - The trail or event data store for the CloudTrail service-linked channel.
--
-- 'destinations', 'getChannelResponse_destinations' - The Amazon Web Services service that created the CloudTrail
-- service-linked channel.
--
-- 'httpStatus', 'getChannelResponse_httpStatus' - The response's http status code.
newGetChannelResponse ::
  -- | 'httpStatus'
  Prelude.Int ->
  GetChannelResponse
newGetChannelResponse pHttpStatus_ =
  GetChannelResponse'
    { name = Prelude.Nothing,
      sourceConfig = Prelude.Nothing,
      channelArn = Prelude.Nothing,
      source = Prelude.Nothing,
      destinations = Prelude.Nothing,
      httpStatus = pHttpStatus_
    }

-- | The name of the CloudTrail service-linked channel. For service-linked
-- channels, the value is
-- @aws-service-channel\/service-name\/custom-suffix@ where @service-name@
-- represents the name of the Amazon Web Services service that created the
-- channel and @custom-suffix@ represents the suffix generated by the
-- Amazon Web Services service.
getChannelResponse_name :: Lens.Lens' GetChannelResponse (Prelude.Maybe Prelude.Text)
getChannelResponse_name = Lens.lens (\GetChannelResponse' {name} -> name) (\s@GetChannelResponse' {} a -> s {name = a} :: GetChannelResponse)

-- | Provides information about the advanced event selectors configured for
-- the service-linked channel, and whether the service-linked channel
-- applies to all regions or one region.
getChannelResponse_sourceConfig :: Lens.Lens' GetChannelResponse (Prelude.Maybe SourceConfig)
getChannelResponse_sourceConfig = Lens.lens (\GetChannelResponse' {sourceConfig} -> sourceConfig) (\s@GetChannelResponse' {} a -> s {sourceConfig = a} :: GetChannelResponse)

-- | The ARN of the CloudTrail service-linked channel.
getChannelResponse_channelArn :: Lens.Lens' GetChannelResponse (Prelude.Maybe Prelude.Text)
getChannelResponse_channelArn = Lens.lens (\GetChannelResponse' {channelArn} -> channelArn) (\s@GetChannelResponse' {} a -> s {channelArn = a} :: GetChannelResponse)

-- | The trail or event data store for the CloudTrail service-linked channel.
getChannelResponse_source :: Lens.Lens' GetChannelResponse (Prelude.Maybe Prelude.Text)
getChannelResponse_source = Lens.lens (\GetChannelResponse' {source} -> source) (\s@GetChannelResponse' {} a -> s {source = a} :: GetChannelResponse)

-- | The Amazon Web Services service that created the CloudTrail
-- service-linked channel.
getChannelResponse_destinations :: Lens.Lens' GetChannelResponse (Prelude.Maybe (Prelude.NonEmpty Destination))
getChannelResponse_destinations = Lens.lens (\GetChannelResponse' {destinations} -> destinations) (\s@GetChannelResponse' {} a -> s {destinations = a} :: GetChannelResponse) Prelude.. Lens.mapping Lens.coerced

-- | The response's http status code.
getChannelResponse_httpStatus :: Lens.Lens' GetChannelResponse Prelude.Int
getChannelResponse_httpStatus = Lens.lens (\GetChannelResponse' {httpStatus} -> httpStatus) (\s@GetChannelResponse' {} a -> s {httpStatus = a} :: GetChannelResponse)

instance Prelude.NFData GetChannelResponse where
  rnf GetChannelResponse' {..} =
    Prelude.rnf name
      `Prelude.seq` Prelude.rnf sourceConfig
      `Prelude.seq` Prelude.rnf channelArn
      `Prelude.seq` Prelude.rnf source
      `Prelude.seq` Prelude.rnf destinations
      `Prelude.seq` Prelude.rnf httpStatus
