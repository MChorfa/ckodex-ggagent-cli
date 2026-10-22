//! # Execution Budget & Resource Accounting (Chapters 2, 14, 22)
//!
//! Provides strict, multidimensional resource accounting for sandboxed agent execution:
//! - Maximum execution steps / loop iterations
//! - Maximum mutating side effects
//! - Maximum token consumption
//! - Maximum wall-clock duration
//!
//! Enforces monotonicity: an attenuated or child budget MUST NOT exceed parent limits.
//! Budget exhaustion automatically blocks new mutating side effects.

use crate::error::KernelError;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionBudget {
    pub max_steps: u32,
    pub consumed_steps: u32,
    pub max_mutating_effects: u32,
    pub consumed_mutating_effects: u32,
    pub max_tokens: u64,
    pub consumed_tokens: u64,
    pub max_duration_ms: u64,
    pub consumed_duration_ms: u64,
}

impl Default for ExecutionBudget {
    fn default() -> Self {
        Self {
            max_steps: 50,
            consumed_steps: 0,
            max_mutating_effects: 10,
            consumed_mutating_effects: 0,
            max_tokens: 100_000,
            consumed_tokens: 0,
            max_duration_ms: 300_000, // 5 minutes
            consumed_duration_ms: 0,
        }
    }
}

impl ExecutionBudget {
    pub fn new(
        max_steps: u32,
        max_mutating_effects: u32,
        max_tokens: u64,
        max_duration_ms: u64,
    ) -> Self {
        Self {
            max_steps,
            consumed_steps: 0,
            max_mutating_effects,
            consumed_mutating_effects: 0,
            max_tokens,
            consumed_tokens: 0,
            max_duration_ms,
            consumed_duration_ms: 0,
        }
    }

    pub fn record_step(&mut self) -> Result<(), KernelError> {
        if self.consumed_steps >= self.max_steps {
            return Err(KernelError::BudgetExhausted {
                dimension: "steps".into(),
                limit: self.max_steps as u64,
                consumed: self.consumed_steps as u64,
            });
        }
        self.consumed_steps += 1;
        Ok(())
    }

    pub fn record_mutating_effect(&mut self) -> Result<(), KernelError> {
        if self.consumed_mutating_effects >= self.max_mutating_effects {
            return Err(KernelError::BudgetExhausted {
                dimension: "mutating_effects".into(),
                limit: self.max_mutating_effects as u64,
                consumed: self.consumed_mutating_effects as u64,
            });
        }
        self.consumed_mutating_effects += 1;
        Ok(())
    }

    pub fn record_tokens(&mut self, count: u64) -> Result<(), KernelError> {
        let next = self.consumed_tokens.saturating_add(count);
        if next > self.max_tokens {
            return Err(KernelError::BudgetExhausted {
                dimension: "tokens".into(),
                limit: self.max_tokens,
                consumed: next,
            });
        }
        self.consumed_tokens = next;
        Ok(())
    }

    pub fn record_duration_ms(&mut self, ms: u64) -> Result<(), KernelError> {
        let next = self.consumed_duration_ms.saturating_add(ms);
        if next > self.max_duration_ms {
            return Err(KernelError::BudgetExhausted {
                dimension: "duration_ms".into(),
                limit: self.max_duration_ms,
                consumed: next,
            });
        }
        self.consumed_duration_ms = next;
        Ok(())
    }

    pub fn remaining_steps(&self) -> u32 {
        self.max_steps.saturating_sub(self.consumed_steps)
    }

    pub fn remaining_effects(&self) -> u32 {
        self.max_mutating_effects
            .saturating_sub(self.consumed_mutating_effects)
    }

    pub fn remaining_tokens(&self) -> u64 {
        self.max_tokens.saturating_sub(self.consumed_tokens)
    }

    pub fn remaining_duration_ms(&self) -> u64 {
        self.max_duration_ms
            .saturating_sub(self.consumed_duration_ms)
    }

    pub fn is_exhausted(&self) -> bool {
        self.consumed_steps >= self.max_steps
            || self.consumed_mutating_effects >= self.max_mutating_effects
            || self.consumed_tokens >= self.max_tokens
            || self.consumed_duration_ms >= self.max_duration_ms
    }

    /// Attenuate budget for child subagent or delegation.
    /// Invariant: Child limits MUST NOT exceed remaining parent budget.
    pub fn attenuate(
        &self,
        child_steps: u32,
        child_effects: u32,
        child_tokens: u64,
        child_duration_ms: u64,
    ) -> Result<Self, KernelError> {
        if child_steps > self.remaining_steps() {
            return Err(KernelError::BudgetAttenuationExceeded {
                dimension: "steps".into(),
                requested: child_steps as u64,
                remaining_parent: self.remaining_steps() as u64,
            });
        }
        if child_effects > self.remaining_effects() {
            return Err(KernelError::BudgetAttenuationExceeded {
                dimension: "effects".into(),
                requested: child_effects as u64,
                remaining_parent: self.remaining_effects() as u64,
            });
        }
        if child_tokens > self.remaining_tokens() {
            return Err(KernelError::BudgetAttenuationExceeded {
                dimension: "tokens".into(),
                requested: child_tokens,
                remaining_parent: self.remaining_tokens(),
            });
        }
        if child_duration_ms > self.remaining_duration_ms() {
            return Err(KernelError::BudgetAttenuationExceeded {
                dimension: "duration_ms".into(),
                requested: child_duration_ms,
                remaining_parent: self.remaining_duration_ms(),
            });
        }

        Ok(Self::new(
            child_steps,
            child_effects,
            child_tokens,
            child_duration_ms,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_budget_consumption_and_exhaustion() {
        let mut budget = ExecutionBudget::new(2, 1, 1000, 5000);

        // Step 1
        assert!(budget.record_step().is_ok());
        assert_eq!(budget.remaining_steps(), 1);

        // Mutating effect 1
        assert!(budget.record_mutating_effect().is_ok());
        assert_eq!(budget.remaining_effects(), 0);

        // Mutating effect 2 should fail
        assert!(matches!(
            budget.record_mutating_effect(),
            Err(KernelError::BudgetExhausted { .. })
        ));

        // Step 2
        assert!(budget.record_step().is_ok());
        assert!(budget.is_exhausted());

        // Step 3 should fail
        assert!(matches!(
            budget.record_step(),
            Err(KernelError::BudgetExhausted { .. })
        ));
    }

    #[test]
    fn test_budget_attenuation_invariants() {
        let parent = ExecutionBudget::new(10, 5, 50_000, 60_000);

        // Valid child attenuation
        let child = parent.attenuate(5, 2, 20_000, 30_000);
        assert!(child.is_ok());

        // Invalid child: exceeds parent step budget
        let child_over = parent.attenuate(15, 2, 20_000, 30_000);
        assert!(matches!(
            child_over,
            Err(KernelError::BudgetAttenuationExceeded { .. })
        ));
    }
}
