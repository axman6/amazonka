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
-- Module      : Amazonka.ELBV2.Types.Rule
-- Copyright   : (c) 2013-2021 Brendan Hay
-- License     : Mozilla Public License, v. 2.0.
-- Maintainer  : Brendan Hay <brendan.g.hay+amazonka@gmail.com>
-- Stability   : auto-generated
-- Portability : non-portable (GHC extensions)
module Amazonka.ELBV2.Types.Rule where

import qualified Amazonka.Core as Core
import Amazonka.ELBV2.Types.Action
import Amazonka.ELBV2.Types.RuleCondition
import qualified Amazonka.Lens as Lens
import qualified Amazonka.Prelude as Prelude

-- | Information about a rule.
--
-- /See:/ 'newRule' smart constructor.
data Rule = Rule'
  { -- | The priority.
    priority :: Prelude.Maybe Prelude.Text,
    -- | The actions. Each rule must include exactly one of the following types
    -- of actions: @forward@, @redirect@, or @fixed-response@, and it must be
    -- the last action to be performed.
    actions :: Prelude.Maybe [Action],
    -- | The conditions. Each rule can include zero or one of the following
    -- conditions: @http-request-method@, @host-header@, @path-pattern@, and
    -- @source-ip@, and zero or more of the following conditions: @http-header@
    -- and @query-string@.
    conditions :: Prelude.Maybe [RuleCondition],
    -- | The Amazon Resource Name (ARN) of the rule.
    ruleArn :: Prelude.Maybe Prelude.Text,
    -- | Indicates whether this is the default rule.
    isDefault :: Prelude.Maybe Prelude.Bool
  }
  deriving (Prelude.Eq, Prelude.Read, Prelude.Show, Prelude.Generic)

-- |
-- Create a value of 'Rule' with all optional fields omitted.
--
-- Use <https://hackage.haskell.org/package/generic-lens generic-lens> or <https://hackage.haskell.org/package/optics optics> to modify other optional fields.
--
-- The following record fields are available, with the corresponding lenses provided
-- for backwards compatibility:
--
-- 'priority', 'rule_priority' - The priority.
--
-- 'actions', 'rule_actions' - The actions. Each rule must include exactly one of the following types
-- of actions: @forward@, @redirect@, or @fixed-response@, and it must be
-- the last action to be performed.
--
-- 'conditions', 'rule_conditions' - The conditions. Each rule can include zero or one of the following
-- conditions: @http-request-method@, @host-header@, @path-pattern@, and
-- @source-ip@, and zero or more of the following conditions: @http-header@
-- and @query-string@.
--
-- 'ruleArn', 'rule_ruleArn' - The Amazon Resource Name (ARN) of the rule.
--
-- 'isDefault', 'rule_isDefault' - Indicates whether this is the default rule.
newRule ::
  Rule
newRule =
  Rule'
    { priority = Prelude.Nothing,
      actions = Prelude.Nothing,
      conditions = Prelude.Nothing,
      ruleArn = Prelude.Nothing,
      isDefault = Prelude.Nothing
    }

-- | The priority.
rule_priority :: Lens.Lens' Rule (Prelude.Maybe Prelude.Text)
rule_priority = Lens.lens (\Rule' {priority} -> priority) (\s@Rule' {} a -> s {priority = a} :: Rule)

-- | The actions. Each rule must include exactly one of the following types
-- of actions: @forward@, @redirect@, or @fixed-response@, and it must be
-- the last action to be performed.
rule_actions :: Lens.Lens' Rule (Prelude.Maybe [Action])
rule_actions = Lens.lens (\Rule' {actions} -> actions) (\s@Rule' {} a -> s {actions = a} :: Rule) Prelude.. Lens.mapping Lens.coerced

-- | The conditions. Each rule can include zero or one of the following
-- conditions: @http-request-method@, @host-header@, @path-pattern@, and
-- @source-ip@, and zero or more of the following conditions: @http-header@
-- and @query-string@.
rule_conditions :: Lens.Lens' Rule (Prelude.Maybe [RuleCondition])
rule_conditions = Lens.lens (\Rule' {conditions} -> conditions) (\s@Rule' {} a -> s {conditions = a} :: Rule) Prelude.. Lens.mapping Lens.coerced

-- | The Amazon Resource Name (ARN) of the rule.
rule_ruleArn :: Lens.Lens' Rule (Prelude.Maybe Prelude.Text)
rule_ruleArn = Lens.lens (\Rule' {ruleArn} -> ruleArn) (\s@Rule' {} a -> s {ruleArn = a} :: Rule)

-- | Indicates whether this is the default rule.
rule_isDefault :: Lens.Lens' Rule (Prelude.Maybe Prelude.Bool)
rule_isDefault = Lens.lens (\Rule' {isDefault} -> isDefault) (\s@Rule' {} a -> s {isDefault = a} :: Rule)

instance Core.FromXML Rule where
  parseXML x =
    Rule'
      Prelude.<$> (x Core..@? "Priority")
      Prelude.<*> ( x Core..@? "Actions" Core..!@ Prelude.mempty
                      Prelude.>>= Core.may (Core.parseXMLList "member")
                  )
      Prelude.<*> ( x Core..@? "Conditions" Core..!@ Prelude.mempty
                      Prelude.>>= Core.may (Core.parseXMLList "member")
                  )
      Prelude.<*> (x Core..@? "RuleArn")
      Prelude.<*> (x Core..@? "IsDefault")

instance Prelude.Hashable Rule

instance Prelude.NFData Rule
