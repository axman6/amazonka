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
-- Module      : Amazonka.CloudWatchEvents.Types.EventSource
-- Copyright   : (c) 2013-2021 Brendan Hay
-- License     : Mozilla Public License, v. 2.0.
-- Maintainer  : Brendan Hay <brendan.g.hay+amazonka@gmail.com>
-- Stability   : auto-generated
-- Portability : non-portable (GHC extensions)
module Amazonka.CloudWatchEvents.Types.EventSource where

import Amazonka.CloudWatchEvents.Types.EventSourceState
import qualified Amazonka.Core as Core
import qualified Amazonka.Lens as Lens
import qualified Amazonka.Prelude as Prelude

-- | A partner event source is created by an SaaS partner. If a customer
-- creates a partner event bus that matches this event source, that Amazon
-- Web Services account can receive events from the partner\'s applications
-- or services.
--
-- /See:/ 'newEventSource' smart constructor.
data EventSource = EventSource'
  { -- | The date and time the event source was created.
    creationTime :: Prelude.Maybe Core.POSIX,
    -- | The state of the event source. If it is ACTIVE, you have already created
    -- a matching event bus for this event source, and that event bus is
    -- active. If it is PENDING, either you haven\'t yet created a matching
    -- event bus, or that event bus is deactivated. If it is DELETED, you have
    -- created a matching event bus, but the event source has since been
    -- deleted.
    state :: Prelude.Maybe EventSourceState,
    -- | The ARN of the event source.
    arn :: Prelude.Maybe Prelude.Text,
    -- | The name of the partner that created the event source.
    createdBy :: Prelude.Maybe Prelude.Text,
    -- | The name of the event source.
    name :: Prelude.Maybe Prelude.Text,
    -- | The date and time that the event source will expire, if the Amazon Web
    -- Services account doesn\'t create a matching event bus for it.
    expirationTime :: Prelude.Maybe Core.POSIX
  }
  deriving (Prelude.Eq, Prelude.Read, Prelude.Show, Prelude.Generic)

-- |
-- Create a value of 'EventSource' with all optional fields omitted.
--
-- Use <https://hackage.haskell.org/package/generic-lens generic-lens> or <https://hackage.haskell.org/package/optics optics> to modify other optional fields.
--
-- The following record fields are available, with the corresponding lenses provided
-- for backwards compatibility:
--
-- 'creationTime', 'eventSource_creationTime' - The date and time the event source was created.
--
-- 'state', 'eventSource_state' - The state of the event source. If it is ACTIVE, you have already created
-- a matching event bus for this event source, and that event bus is
-- active. If it is PENDING, either you haven\'t yet created a matching
-- event bus, or that event bus is deactivated. If it is DELETED, you have
-- created a matching event bus, but the event source has since been
-- deleted.
--
-- 'arn', 'eventSource_arn' - The ARN of the event source.
--
-- 'createdBy', 'eventSource_createdBy' - The name of the partner that created the event source.
--
-- 'name', 'eventSource_name' - The name of the event source.
--
-- 'expirationTime', 'eventSource_expirationTime' - The date and time that the event source will expire, if the Amazon Web
-- Services account doesn\'t create a matching event bus for it.
newEventSource ::
  EventSource
newEventSource =
  EventSource'
    { creationTime = Prelude.Nothing,
      state = Prelude.Nothing,
      arn = Prelude.Nothing,
      createdBy = Prelude.Nothing,
      name = Prelude.Nothing,
      expirationTime = Prelude.Nothing
    }

-- | The date and time the event source was created.
eventSource_creationTime :: Lens.Lens' EventSource (Prelude.Maybe Prelude.UTCTime)
eventSource_creationTime = Lens.lens (\EventSource' {creationTime} -> creationTime) (\s@EventSource' {} a -> s {creationTime = a} :: EventSource) Prelude.. Lens.mapping Core._Time

-- | The state of the event source. If it is ACTIVE, you have already created
-- a matching event bus for this event source, and that event bus is
-- active. If it is PENDING, either you haven\'t yet created a matching
-- event bus, or that event bus is deactivated. If it is DELETED, you have
-- created a matching event bus, but the event source has since been
-- deleted.
eventSource_state :: Lens.Lens' EventSource (Prelude.Maybe EventSourceState)
eventSource_state = Lens.lens (\EventSource' {state} -> state) (\s@EventSource' {} a -> s {state = a} :: EventSource)

-- | The ARN of the event source.
eventSource_arn :: Lens.Lens' EventSource (Prelude.Maybe Prelude.Text)
eventSource_arn = Lens.lens (\EventSource' {arn} -> arn) (\s@EventSource' {} a -> s {arn = a} :: EventSource)

-- | The name of the partner that created the event source.
eventSource_createdBy :: Lens.Lens' EventSource (Prelude.Maybe Prelude.Text)
eventSource_createdBy = Lens.lens (\EventSource' {createdBy} -> createdBy) (\s@EventSource' {} a -> s {createdBy = a} :: EventSource)

-- | The name of the event source.
eventSource_name :: Lens.Lens' EventSource (Prelude.Maybe Prelude.Text)
eventSource_name = Lens.lens (\EventSource' {name} -> name) (\s@EventSource' {} a -> s {name = a} :: EventSource)

-- | The date and time that the event source will expire, if the Amazon Web
-- Services account doesn\'t create a matching event bus for it.
eventSource_expirationTime :: Lens.Lens' EventSource (Prelude.Maybe Prelude.UTCTime)
eventSource_expirationTime = Lens.lens (\EventSource' {expirationTime} -> expirationTime) (\s@EventSource' {} a -> s {expirationTime = a} :: EventSource) Prelude.. Lens.mapping Core._Time

instance Core.FromJSON EventSource where
  parseJSON =
    Core.withObject
      "EventSource"
      ( \x ->
          EventSource'
            Prelude.<$> (x Core..:? "CreationTime")
            Prelude.<*> (x Core..:? "State")
            Prelude.<*> (x Core..:? "Arn")
            Prelude.<*> (x Core..:? "CreatedBy")
            Prelude.<*> (x Core..:? "Name")
            Prelude.<*> (x Core..:? "ExpirationTime")
      )

instance Prelude.Hashable EventSource where
  hashWithSalt _salt EventSource' {..} =
    _salt `Prelude.hashWithSalt` creationTime
      `Prelude.hashWithSalt` state
      `Prelude.hashWithSalt` arn
      `Prelude.hashWithSalt` createdBy
      `Prelude.hashWithSalt` name
      `Prelude.hashWithSalt` expirationTime

instance Prelude.NFData EventSource where
  rnf EventSource' {..} =
    Prelude.rnf creationTime
      `Prelude.seq` Prelude.rnf state
      `Prelude.seq` Prelude.rnf arn
      `Prelude.seq` Prelude.rnf createdBy
      `Prelude.seq` Prelude.rnf name
      `Prelude.seq` Prelude.rnf expirationTime
