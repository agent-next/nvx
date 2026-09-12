pub mod adapter;
pub mod catalog;
pub mod schema;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyError {
    pub code: String,
    pub instance_path: String,
    pub message: String,
}

pub use schema::{
    MxcPhase, schema_declares_draft7, schema_normalized_sha256, schema_raw_sha256, validate_config,
};

pub use adapter::{NvxExecPolicy, NvxPolicyPlan, NvxProvisionPolicy, adapt_policy};
pub use catalog::{CatalogEntry, EvidenceRequirement, PolicyDisposition, catalog_entries};
