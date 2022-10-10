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
-- Module      : Amazonka.Personalize.Types.Recommender
-- Copyright   : (c) 2013-2022 Brendan Hay
-- License     : Mozilla Public License, v. 2.0.
-- Maintainer  : Brendan Hay <brendan.g.hay+amazonka@gmail.com>
-- Stability   : auto-generated
-- Portability : non-portable (GHC extensions)
module Amazonka.Personalize.Types.Recommender where

import qualified Amazonka.Core as Core
import qualified Amazonka.Lens as Lens
import Amazonka.Personalize.Types.RecommenderConfig
import Amazonka.Personalize.Types.RecommenderUpdateSummary
import qualified Amazonka.Prelude as Prelude

-- | Describes a recommendation generator for a Domain dataset group. You
-- create a recommender in a Domain dataset group for a specific domain use
-- case (domain recipe), and specify the recommender in a
-- <https://docs.aws.amazon.com/personalize/latest/dg/API_RS_GetRecommendations.html GetRecommendations>
-- request.
--
-- /See:/ 'newRecommender' smart constructor.
data Recommender = Recommender'
  { -- | The name of the recommender.
    name :: Prelude.Maybe Prelude.Text,
    -- | The date and time (in Unix format) that the recommender was created.
    creationDateTime :: Prelude.Maybe Core.POSIX,
    -- | The Amazon Resource Name (ARN) of the recommender.
    recommenderArn :: Prelude.Maybe Prelude.Text,
    -- | The configuration details of the recommender.
    recommenderConfig :: Prelude.Maybe RecommenderConfig,
    -- | Provides a summary of the latest updates to the recommender.
    latestRecommenderUpdate :: Prelude.Maybe RecommenderUpdateSummary,
    -- | The status of the recommender.
    --
    -- A recommender can be in one of the following states:
    --
    -- -   CREATE PENDING > CREATE IN_PROGRESS > ACTIVE -or- CREATE FAILED
    --
    -- -   STOP PENDING > STOP IN_PROGRESS > INACTIVE > START PENDING > START
    --     IN_PROGRESS > ACTIVE
    --
    -- -   DELETE PENDING > DELETE IN_PROGRESS
    status :: Prelude.Maybe Prelude.Text,
    -- | Provides evaluation metrics that help you determine the performance of a
    -- recommender. For more information, see
    -- <https://docs.aws.amazon.com/personalize/latest/dg/evaluating-recommenders.html Evaluating a recommender>.
    modelMetrics :: Prelude.Maybe (Prelude.HashMap Prelude.Text Prelude.Double),
    -- | The Amazon Resource Name (ARN) of the Domain dataset group that contains
    -- the recommender.
    datasetGroupArn :: Prelude.Maybe Prelude.Text,
    -- | The Amazon Resource Name (ARN) of the recipe (Domain dataset group use
    -- case) that the recommender was created for.
    recipeArn :: Prelude.Maybe Prelude.Text,
    -- | The date and time (in Unix format) that the recommender was last
    -- updated.
    lastUpdatedDateTime :: Prelude.Maybe Core.POSIX,
    -- | If a recommender fails, the reason behind the failure.
    failureReason :: Prelude.Maybe Prelude.Text
  }
  deriving (Prelude.Eq, Prelude.Read, Prelude.Show, Prelude.Generic)

-- |
-- Create a value of 'Recommender' with all optional fields omitted.
--
-- Use <https://hackage.haskell.org/package/generic-lens generic-lens> or <https://hackage.haskell.org/package/optics optics> to modify other optional fields.
--
-- The following record fields are available, with the corresponding lenses provided
-- for backwards compatibility:
--
-- 'name', 'recommender_name' - The name of the recommender.
--
-- 'creationDateTime', 'recommender_creationDateTime' - The date and time (in Unix format) that the recommender was created.
--
-- 'recommenderArn', 'recommender_recommenderArn' - The Amazon Resource Name (ARN) of the recommender.
--
-- 'recommenderConfig', 'recommender_recommenderConfig' - The configuration details of the recommender.
--
-- 'latestRecommenderUpdate', 'recommender_latestRecommenderUpdate' - Provides a summary of the latest updates to the recommender.
--
-- 'status', 'recommender_status' - The status of the recommender.
--
-- A recommender can be in one of the following states:
--
-- -   CREATE PENDING > CREATE IN_PROGRESS > ACTIVE -or- CREATE FAILED
--
-- -   STOP PENDING > STOP IN_PROGRESS > INACTIVE > START PENDING > START
--     IN_PROGRESS > ACTIVE
--
-- -   DELETE PENDING > DELETE IN_PROGRESS
--
-- 'modelMetrics', 'recommender_modelMetrics' - Provides evaluation metrics that help you determine the performance of a
-- recommender. For more information, see
-- <https://docs.aws.amazon.com/personalize/latest/dg/evaluating-recommenders.html Evaluating a recommender>.
--
-- 'datasetGroupArn', 'recommender_datasetGroupArn' - The Amazon Resource Name (ARN) of the Domain dataset group that contains
-- the recommender.
--
-- 'recipeArn', 'recommender_recipeArn' - The Amazon Resource Name (ARN) of the recipe (Domain dataset group use
-- case) that the recommender was created for.
--
-- 'lastUpdatedDateTime', 'recommender_lastUpdatedDateTime' - The date and time (in Unix format) that the recommender was last
-- updated.
--
-- 'failureReason', 'recommender_failureReason' - If a recommender fails, the reason behind the failure.
newRecommender ::
  Recommender
newRecommender =
  Recommender'
    { name = Prelude.Nothing,
      creationDateTime = Prelude.Nothing,
      recommenderArn = Prelude.Nothing,
      recommenderConfig = Prelude.Nothing,
      latestRecommenderUpdate = Prelude.Nothing,
      status = Prelude.Nothing,
      modelMetrics = Prelude.Nothing,
      datasetGroupArn = Prelude.Nothing,
      recipeArn = Prelude.Nothing,
      lastUpdatedDateTime = Prelude.Nothing,
      failureReason = Prelude.Nothing
    }

-- | The name of the recommender.
recommender_name :: Lens.Lens' Recommender (Prelude.Maybe Prelude.Text)
recommender_name = Lens.lens (\Recommender' {name} -> name) (\s@Recommender' {} a -> s {name = a} :: Recommender)

-- | The date and time (in Unix format) that the recommender was created.
recommender_creationDateTime :: Lens.Lens' Recommender (Prelude.Maybe Prelude.UTCTime)
recommender_creationDateTime = Lens.lens (\Recommender' {creationDateTime} -> creationDateTime) (\s@Recommender' {} a -> s {creationDateTime = a} :: Recommender) Prelude.. Lens.mapping Core._Time

-- | The Amazon Resource Name (ARN) of the recommender.
recommender_recommenderArn :: Lens.Lens' Recommender (Prelude.Maybe Prelude.Text)
recommender_recommenderArn = Lens.lens (\Recommender' {recommenderArn} -> recommenderArn) (\s@Recommender' {} a -> s {recommenderArn = a} :: Recommender)

-- | The configuration details of the recommender.
recommender_recommenderConfig :: Lens.Lens' Recommender (Prelude.Maybe RecommenderConfig)
recommender_recommenderConfig = Lens.lens (\Recommender' {recommenderConfig} -> recommenderConfig) (\s@Recommender' {} a -> s {recommenderConfig = a} :: Recommender)

-- | Provides a summary of the latest updates to the recommender.
recommender_latestRecommenderUpdate :: Lens.Lens' Recommender (Prelude.Maybe RecommenderUpdateSummary)
recommender_latestRecommenderUpdate = Lens.lens (\Recommender' {latestRecommenderUpdate} -> latestRecommenderUpdate) (\s@Recommender' {} a -> s {latestRecommenderUpdate = a} :: Recommender)

-- | The status of the recommender.
--
-- A recommender can be in one of the following states:
--
-- -   CREATE PENDING > CREATE IN_PROGRESS > ACTIVE -or- CREATE FAILED
--
-- -   STOP PENDING > STOP IN_PROGRESS > INACTIVE > START PENDING > START
--     IN_PROGRESS > ACTIVE
--
-- -   DELETE PENDING > DELETE IN_PROGRESS
recommender_status :: Lens.Lens' Recommender (Prelude.Maybe Prelude.Text)
recommender_status = Lens.lens (\Recommender' {status} -> status) (\s@Recommender' {} a -> s {status = a} :: Recommender)

-- | Provides evaluation metrics that help you determine the performance of a
-- recommender. For more information, see
-- <https://docs.aws.amazon.com/personalize/latest/dg/evaluating-recommenders.html Evaluating a recommender>.
recommender_modelMetrics :: Lens.Lens' Recommender (Prelude.Maybe (Prelude.HashMap Prelude.Text Prelude.Double))
recommender_modelMetrics = Lens.lens (\Recommender' {modelMetrics} -> modelMetrics) (\s@Recommender' {} a -> s {modelMetrics = a} :: Recommender) Prelude.. Lens.mapping Lens.coerced

-- | The Amazon Resource Name (ARN) of the Domain dataset group that contains
-- the recommender.
recommender_datasetGroupArn :: Lens.Lens' Recommender (Prelude.Maybe Prelude.Text)
recommender_datasetGroupArn = Lens.lens (\Recommender' {datasetGroupArn} -> datasetGroupArn) (\s@Recommender' {} a -> s {datasetGroupArn = a} :: Recommender)

-- | The Amazon Resource Name (ARN) of the recipe (Domain dataset group use
-- case) that the recommender was created for.
recommender_recipeArn :: Lens.Lens' Recommender (Prelude.Maybe Prelude.Text)
recommender_recipeArn = Lens.lens (\Recommender' {recipeArn} -> recipeArn) (\s@Recommender' {} a -> s {recipeArn = a} :: Recommender)

-- | The date and time (in Unix format) that the recommender was last
-- updated.
recommender_lastUpdatedDateTime :: Lens.Lens' Recommender (Prelude.Maybe Prelude.UTCTime)
recommender_lastUpdatedDateTime = Lens.lens (\Recommender' {lastUpdatedDateTime} -> lastUpdatedDateTime) (\s@Recommender' {} a -> s {lastUpdatedDateTime = a} :: Recommender) Prelude.. Lens.mapping Core._Time

-- | If a recommender fails, the reason behind the failure.
recommender_failureReason :: Lens.Lens' Recommender (Prelude.Maybe Prelude.Text)
recommender_failureReason = Lens.lens (\Recommender' {failureReason} -> failureReason) (\s@Recommender' {} a -> s {failureReason = a} :: Recommender)

instance Core.FromJSON Recommender where
  parseJSON =
    Core.withObject
      "Recommender"
      ( \x ->
          Recommender'
            Prelude.<$> (x Core..:? "name")
            Prelude.<*> (x Core..:? "creationDateTime")
            Prelude.<*> (x Core..:? "recommenderArn")
            Prelude.<*> (x Core..:? "recommenderConfig")
            Prelude.<*> (x Core..:? "latestRecommenderUpdate")
            Prelude.<*> (x Core..:? "status")
            Prelude.<*> (x Core..:? "modelMetrics" Core..!= Prelude.mempty)
            Prelude.<*> (x Core..:? "datasetGroupArn")
            Prelude.<*> (x Core..:? "recipeArn")
            Prelude.<*> (x Core..:? "lastUpdatedDateTime")
            Prelude.<*> (x Core..:? "failureReason")
      )

instance Prelude.Hashable Recommender where
  hashWithSalt _salt Recommender' {..} =
    _salt `Prelude.hashWithSalt` name
      `Prelude.hashWithSalt` creationDateTime
      `Prelude.hashWithSalt` recommenderArn
      `Prelude.hashWithSalt` recommenderConfig
      `Prelude.hashWithSalt` latestRecommenderUpdate
      `Prelude.hashWithSalt` status
      `Prelude.hashWithSalt` modelMetrics
      `Prelude.hashWithSalt` datasetGroupArn
      `Prelude.hashWithSalt` recipeArn
      `Prelude.hashWithSalt` lastUpdatedDateTime
      `Prelude.hashWithSalt` failureReason

instance Prelude.NFData Recommender where
  rnf Recommender' {..} =
    Prelude.rnf name
      `Prelude.seq` Prelude.rnf creationDateTime
      `Prelude.seq` Prelude.rnf recommenderArn
      `Prelude.seq` Prelude.rnf recommenderConfig
      `Prelude.seq` Prelude.rnf latestRecommenderUpdate
      `Prelude.seq` Prelude.rnf status
      `Prelude.seq` Prelude.rnf modelMetrics
      `Prelude.seq` Prelude.rnf datasetGroupArn
      `Prelude.seq` Prelude.rnf recipeArn
      `Prelude.seq` Prelude.rnf lastUpdatedDateTime
      `Prelude.seq` Prelude.rnf failureReason
