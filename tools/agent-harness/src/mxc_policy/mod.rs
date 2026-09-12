pub mod adapter;
pub mod cases;
pub mod catalog;
pub mod effects;
pub mod live;
pub mod report;
pub mod schema;

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct PolicyError {
    pub code: String,
    pub instance_path: String,
    pub message: String,
}

impl PolicyError {
    pub fn new(
        code: impl Into<String>,
        instance_path: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            code: code.into(),
            instance_path: instance_path.into(),
            message: message.into(),
        }
    }
}

pub use schema::{
    MxcPhase, schema_declares_draft7, schema_normalized_sha256, schema_raw_sha256, validate_config,
};

pub use adapter::{NvxExecPolicy, NvxPolicyPlan, NvxProvisionPolicy, adapt_policy};
pub use catalog::{CatalogEntry, EvidenceRequirement, PolicyDisposition, catalog_entries};
pub use effects::{
    CountingHostEffects, EffectCounters, HostEffects, PolicyExecutionError, PolicyRunError,
    ProductionHostEffects, run_policy_production, run_with_effects,
};
pub use report::{
    PolicyHarnessMode, PolicyHarnessOptions, PolicyHarnessRun, execute_policy_harness,
};
