use ::agent_protocol::mxc_extension::{MODELED_REQUIREMENTS, MxcRequirement};
use ::serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct HarnessScenario {
    pub name: String,
    pub requirements: Vec<MxcRequirement>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct HarnessResult {
    pub name: String,
    pub modeled: usize,
    pub unsupported: usize,
}

pub fn deterministic_smoke_scenario() -> HarnessScenario {
    HarnessScenario {
        name: "phase0-smoke".to_string(),
        requirements: MODELED_REQUIREMENTS.to_vec(),
    }
}

pub fn evaluate_scenario(scenario: &HarnessScenario) -> HarnessResult {
    HarnessResult {
        name: scenario.name.clone(),
        modeled: scenario.requirements.len(),
        unsupported: 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn smoke_scenario_is_stable() {
        let scenario = deterministic_smoke_scenario();
        assert_eq!(scenario.name, "phase0-smoke");
        assert_eq!(scenario.requirements.len(), 12);
    }

    #[test]
    fn evaluator_is_deterministic() {
        let scenario = deterministic_smoke_scenario();
        let first = evaluate_scenario(&scenario);
        let second = evaluate_scenario(&scenario);
        assert_eq!(first, second);
    }
}
