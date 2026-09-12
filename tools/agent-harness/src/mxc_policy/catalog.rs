use super::schema::MxcPhase;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PolicyDisposition {
    Honored,
    AcceptedInert,
    Rejected,
    Control,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvidenceRequirement {
    UnitStatic,
    LocalLinuxRuntime,
    LiveWhpPositiveNegative,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CatalogEntry {
    pub key: &'static str,
    pub schema_path: &'static str,
    pub disposition: PolicyDisposition,
    pub phases: &'static [MxcPhase],
    pub evidence: EvidenceRequirement,
    pub reason: &'static str,
}

const PHASES_ALL: &[MxcPhase] = &[
    MxcPhase::Provision,
    MxcPhase::Start,
    MxcPhase::Exec,
    MxcPhase::Stop,
    MxcPhase::Deprovision,
];
const PHASES_NON_PROVISION: &[MxcPhase] = &[
    MxcPhase::Start,
    MxcPhase::Exec,
    MxcPhase::Stop,
    MxcPhase::Deprovision,
];
const PHASES_PROVISION: &[MxcPhase] = &[MxcPhase::Provision];
const PHASES_EXEC: &[MxcPhase] = &[MxcPhase::Exec];

const EVIDENCE_UNIT_STATIC: EvidenceRequirement = EvidenceRequirement::UnitStatic;
const EVIDENCE_LOCAL_LINUX_RUNTIME: EvidenceRequirement = EvidenceRequirement::LocalLinuxRuntime;
const EVIDENCE_LIVE_WHP_POS_NEG: EvidenceRequirement = EvidenceRequirement::LiveWhpPositiveNegative;

const REASON_ACCEPTED_INERT: &str =
    "Accepted for compatibility but ignored by backend policy application.";
const REASON_CONTROL: &str =
    "Controls request routing/identity/phase selection rather than sandbox permissions.";
const REASON_HONORED_PROVISION: &str =
    "Provision-phase state-aware field honored by planned NVX backend mapping.";
const REASON_HONORED_EXEC: &str =
    "Exec-phase state-aware field honored by planned NVX backend mapping.";
const REASON_REJECTED: &str =
    "Schema-admitted construct outside approved future-NVX state-aware support envelope.";
const REASON_CROSS_FIELD_CONTROL: &str =
    "Cross-field lifecycle invariant enforced by state-aware control-plane logic.";
const REASON_CROSS_FIELD_PROVISION: &str =
    "Cross-field provision invariant binding approved provision policy surface.";
const REASON_CROSS_FIELD_EXEC: &str =
    "Cross-field exec invariant binding approved exec policy surface.";

pub const CATALOG: &[CatalogEntry] = &[
    CatalogEntry {
        key: "$schema",
        schema_path: "/properties/$schema",
        disposition: PolicyDisposition::AcceptedInert,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_ACCEPTED_INERT,
    },
    CatalogEntry {
        key: "$schema#absent",
        schema_path: "/properties/$schema",
        disposition: PolicyDisposition::AcceptedInert,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_ACCEPTED_INERT,
    },
    CatalogEntry {
        key: "$schema#nullable",
        schema_path: "/properties/$schema",
        disposition: PolicyDisposition::AcceptedInert,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_ACCEPTED_INERT,
    },
    CatalogEntry {
        key: "_comment",
        schema_path: "/properties/_comment",
        disposition: PolicyDisposition::AcceptedInert,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_ACCEPTED_INERT,
    },
    CatalogEntry {
        key: "_comment#absent",
        schema_path: "/properties/_comment",
        disposition: PolicyDisposition::AcceptedInert,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_ACCEPTED_INERT,
    },
    CatalogEntry {
        key: "containerId",
        schema_path: "/properties/containerId",
        disposition: PolicyDisposition::Control,
        phases: PHASES_ALL,
        evidence: EVIDENCE_LIVE_WHP_POS_NEG,
        reason: REASON_CONTROL,
    },
    CatalogEntry {
        key: "containerId#absent",
        schema_path: "/properties/containerId",
        disposition: PolicyDisposition::Control,
        phases: PHASES_ALL,
        evidence: EVIDENCE_LIVE_WHP_POS_NEG,
        reason: REASON_CONTROL,
    },
    CatalogEntry {
        key: "containerId#nullable",
        schema_path: "/properties/containerId",
        disposition: PolicyDisposition::Control,
        phases: PHASES_ALL,
        evidence: EVIDENCE_LIVE_WHP_POS_NEG,
        reason: REASON_CONTROL,
    },
    CatalogEntry {
        key: "containment",
        schema_path: "/properties/containment",
        disposition: PolicyDisposition::Control,
        phases: PHASES_ALL,
        evidence: EVIDENCE_LIVE_WHP_POS_NEG,
        reason: REASON_CONTROL,
    },
    CatalogEntry {
        key: "containment#absent",
        schema_path: "/properties/containment",
        disposition: PolicyDisposition::Control,
        phases: PHASES_ALL,
        evidence: EVIDENCE_LIVE_WHP_POS_NEG,
        reason: REASON_CONTROL,
    },
    CatalogEntry {
        key: "containment#nullable",
        schema_path: "/properties/containment",
        disposition: PolicyDisposition::Control,
        phases: PHASES_ALL,
        evidence: EVIDENCE_LIVE_WHP_POS_NEG,
        reason: REASON_CONTROL,
    },
    CatalogEntry {
        key: "containment#anyOf[0]=#/definitions/Containment",
        schema_path: "/properties/containment/anyOf/0",
        disposition: PolicyDisposition::Control,
        phases: PHASES_ALL,
        evidence: EVIDENCE_LIVE_WHP_POS_NEG,
        reason: REASON_CONTROL,
    },
    CatalogEntry {
        key: "containment#oneOf[0]=string",
        schema_path: "/properties/containment/anyOf/0/oneOf/0",
        disposition: PolicyDisposition::Control,
        phases: PHASES_ALL,
        evidence: EVIDENCE_LIVE_WHP_POS_NEG,
        reason: REASON_CONTROL,
    },
    CatalogEntry {
        key: "containment#enum=process",
        schema_path: "/properties/containment/anyOf/0/oneOf/0/enum/0",
        disposition: PolicyDisposition::Control,
        phases: PHASES_ALL,
        evidence: EVIDENCE_LIVE_WHP_POS_NEG,
        reason: REASON_CONTROL,
    },
    CatalogEntry {
        key: "containment#oneOf[1]=string",
        schema_path: "/properties/containment/anyOf/0/oneOf/1",
        disposition: PolicyDisposition::Control,
        phases: PHASES_ALL,
        evidence: EVIDENCE_LIVE_WHP_POS_NEG,
        reason: REASON_CONTROL,
    },
    CatalogEntry {
        key: "containment#enum=processcontainer",
        schema_path: "/properties/containment/anyOf/0/oneOf/1/enum/0",
        disposition: PolicyDisposition::Control,
        phases: PHASES_ALL,
        evidence: EVIDENCE_LIVE_WHP_POS_NEG,
        reason: REASON_CONTROL,
    },
    CatalogEntry {
        key: "containment#oneOf[2]=string",
        schema_path: "/properties/containment/anyOf/0/oneOf/2",
        disposition: PolicyDisposition::Control,
        phases: PHASES_ALL,
        evidence: EVIDENCE_LIVE_WHP_POS_NEG,
        reason: REASON_CONTROL,
    },
    CatalogEntry {
        key: "containment#enum=vm",
        schema_path: "/properties/containment/anyOf/0/oneOf/2/enum/0",
        disposition: PolicyDisposition::Control,
        phases: PHASES_ALL,
        evidence: EVIDENCE_LIVE_WHP_POS_NEG,
        reason: REASON_CONTROL,
    },
    CatalogEntry {
        key: "containment#oneOf[3]=string",
        schema_path: "/properties/containment/anyOf/0/oneOf/3",
        disposition: PolicyDisposition::Control,
        phases: PHASES_ALL,
        evidence: EVIDENCE_LIVE_WHP_POS_NEG,
        reason: REASON_CONTROL,
    },
    CatalogEntry {
        key: "containment#enum=windows_sandbox",
        schema_path: "/properties/containment/anyOf/0/oneOf/3/enum/0",
        disposition: PolicyDisposition::Control,
        phases: PHASES_ALL,
        evidence: EVIDENCE_LIVE_WHP_POS_NEG,
        reason: REASON_CONTROL,
    },
    CatalogEntry {
        key: "containment#oneOf[4]=string",
        schema_path: "/properties/containment/anyOf/0/oneOf/4",
        disposition: PolicyDisposition::Control,
        phases: PHASES_ALL,
        evidence: EVIDENCE_LIVE_WHP_POS_NEG,
        reason: REASON_CONTROL,
    },
    CatalogEntry {
        key: "containment#enum=lxc",
        schema_path: "/properties/containment/anyOf/0/oneOf/4/enum/0",
        disposition: PolicyDisposition::Control,
        phases: PHASES_ALL,
        evidence: EVIDENCE_LIVE_WHP_POS_NEG,
        reason: REASON_CONTROL,
    },
    CatalogEntry {
        key: "containment#oneOf[5]=string",
        schema_path: "/properties/containment/anyOf/0/oneOf/5",
        disposition: PolicyDisposition::Control,
        phases: PHASES_ALL,
        evidence: EVIDENCE_LIVE_WHP_POS_NEG,
        reason: REASON_CONTROL,
    },
    CatalogEntry {
        key: "containment#enum=microvm",
        schema_path: "/properties/containment/anyOf/0/oneOf/5/enum/0",
        disposition: PolicyDisposition::Control,
        phases: PHASES_ALL,
        evidence: EVIDENCE_LIVE_WHP_POS_NEG,
        reason: REASON_CONTROL,
    },
    CatalogEntry {
        key: "containment#oneOf[6]=string",
        schema_path: "/properties/containment/anyOf/0/oneOf/6",
        disposition: PolicyDisposition::Control,
        phases: PHASES_ALL,
        evidence: EVIDENCE_LIVE_WHP_POS_NEG,
        reason: REASON_CONTROL,
    },
    CatalogEntry {
        key: "containment#enum=hyperlight",
        schema_path: "/properties/containment/anyOf/0/oneOf/6/enum/0",
        disposition: PolicyDisposition::Control,
        phases: PHASES_ALL,
        evidence: EVIDENCE_LIVE_WHP_POS_NEG,
        reason: REASON_CONTROL,
    },
    CatalogEntry {
        key: "containment#oneOf[7]=string",
        schema_path: "/properties/containment/anyOf/0/oneOf/7",
        disposition: PolicyDisposition::Control,
        phases: PHASES_ALL,
        evidence: EVIDENCE_LIVE_WHP_POS_NEG,
        reason: REASON_CONTROL,
    },
    CatalogEntry {
        key: "containment#enum=wslc",
        schema_path: "/properties/containment/anyOf/0/oneOf/7/enum/0",
        disposition: PolicyDisposition::Control,
        phases: PHASES_ALL,
        evidence: EVIDENCE_LIVE_WHP_POS_NEG,
        reason: REASON_CONTROL,
    },
    CatalogEntry {
        key: "containment#oneOf[8]=string",
        schema_path: "/properties/containment/anyOf/0/oneOf/8",
        disposition: PolicyDisposition::Control,
        phases: PHASES_ALL,
        evidence: EVIDENCE_LIVE_WHP_POS_NEG,
        reason: REASON_CONTROL,
    },
    CatalogEntry {
        key: "containment#enum=seatbelt",
        schema_path: "/properties/containment/anyOf/0/oneOf/8/enum/0",
        disposition: PolicyDisposition::Control,
        phases: PHASES_ALL,
        evidence: EVIDENCE_LIVE_WHP_POS_NEG,
        reason: REASON_CONTROL,
    },
    CatalogEntry {
        key: "containment#oneOf[9]=string",
        schema_path: "/properties/containment/anyOf/0/oneOf/9",
        disposition: PolicyDisposition::Control,
        phases: PHASES_ALL,
        evidence: EVIDENCE_LIVE_WHP_POS_NEG,
        reason: REASON_CONTROL,
    },
    CatalogEntry {
        key: "containment#enum=isolation_session",
        schema_path: "/properties/containment/anyOf/0/oneOf/9/enum/0",
        disposition: PolicyDisposition::Control,
        phases: PHASES_ALL,
        evidence: EVIDENCE_LIVE_WHP_POS_NEG,
        reason: REASON_CONTROL,
    },
    CatalogEntry {
        key: "containment#oneOf[10]=string",
        schema_path: "/properties/containment/anyOf/0/oneOf/10",
        disposition: PolicyDisposition::Control,
        phases: PHASES_ALL,
        evidence: EVIDENCE_LIVE_WHP_POS_NEG,
        reason: REASON_CONTROL,
    },
    CatalogEntry {
        key: "containment#enum=bubblewrap",
        schema_path: "/properties/containment/anyOf/0/oneOf/10/enum/0",
        disposition: PolicyDisposition::Control,
        phases: PHASES_ALL,
        evidence: EVIDENCE_LIVE_WHP_POS_NEG,
        reason: REASON_CONTROL,
    },
    CatalogEntry {
        key: "containment#anyOf[1]=null",
        schema_path: "/properties/containment/anyOf/1",
        disposition: PolicyDisposition::Control,
        phases: PHASES_ALL,
        evidence: EVIDENCE_LIVE_WHP_POS_NEG,
        reason: REASON_CONTROL,
    },
    CatalogEntry {
        key: "experimental",
        schema_path: "/properties/experimental",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "experimental#absent",
        schema_path: "/properties/experimental",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "experimental#nullable",
        schema_path: "/properties/experimental",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "experimental#anyOf[0]=#/definitions/Experimental",
        schema_path: "/properties/experimental/anyOf/0",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "experimental.isolation_session",
        schema_path: "/properties/experimental/anyOf/0/properties/isolation_session",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "experimental.isolation_session#absent",
        schema_path: "/properties/experimental/anyOf/0/properties/isolation_session",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "experimental.isolation_session#nullable",
        schema_path: "/properties/experimental/anyOf/0/properties/isolation_session",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "experimental.isolation_session#anyOf[0]=#/definitions/IsolationSession",
        schema_path: "/properties/experimental/anyOf/0/properties/isolation_session/anyOf/0",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "experimental.isolation_session.provision",
        schema_path: "/properties/experimental/anyOf/0/properties/isolation_session/anyOf/0/properties/provision",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "experimental.isolation_session.provision#absent",
        schema_path: "/properties/experimental/anyOf/0/properties/isolation_session/anyOf/0/properties/provision",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "experimental.isolation_session.provision#nullable",
        schema_path: "/properties/experimental/anyOf/0/properties/isolation_session/anyOf/0/properties/provision",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "experimental.isolation_session.provision#anyOf[0]=#/definitions/IsolationSessionProvisionPhase",
        schema_path: "/properties/experimental/anyOf/0/properties/isolation_session/anyOf/0/properties/provision/anyOf/0",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "experimental.isolation_session.provision.appId",
        schema_path: "/properties/experimental/anyOf/0/properties/isolation_session/anyOf/0/properties/provision/anyOf/0/properties/appId",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "experimental.isolation_session.provision.appId#absent",
        schema_path: "/properties/experimental/anyOf/0/properties/isolation_session/anyOf/0/properties/provision/anyOf/0/properties/appId",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "experimental.isolation_session.provision.appId#nullable",
        schema_path: "/properties/experimental/anyOf/0/properties/isolation_session/anyOf/0/properties/provision/anyOf/0/properties/appId",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "experimental.isolation_session.provision#anyOf[1]=null",
        schema_path: "/properties/experimental/anyOf/0/properties/isolation_session/anyOf/0/properties/provision/anyOf/1",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "experimental.isolation_session#anyOf[1]=null",
        schema_path: "/properties/experimental/anyOf/0/properties/isolation_session/anyOf/1",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "experimental.seatbelt",
        schema_path: "/properties/experimental/anyOf/0/properties/seatbelt",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "experimental.seatbelt#absent",
        schema_path: "/properties/experimental/anyOf/0/properties/seatbelt",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "experimental.seatbelt#nullable",
        schema_path: "/properties/experimental/anyOf/0/properties/seatbelt",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "experimental.seatbelt#anyOf[0]=#/definitions/Seatbelt",
        schema_path: "/properties/experimental/anyOf/0/properties/seatbelt/anyOf/0",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "experimental.seatbelt.extraMachLookups",
        schema_path: "/properties/experimental/anyOf/0/properties/seatbelt/anyOf/0/properties/extraMachLookups",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "experimental.seatbelt.extraMachLookups#absent",
        schema_path: "/properties/experimental/anyOf/0/properties/seatbelt/anyOf/0/properties/extraMachLookups",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "experimental.seatbelt.extraMachLookups#nullable",
        schema_path: "/properties/experimental/anyOf/0/properties/seatbelt/anyOf/0/properties/extraMachLookups",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "experimental.seatbelt.extraMachLookups[]",
        schema_path: "/properties/experimental/anyOf/0/properties/seatbelt/anyOf/0/properties/extraMachLookups/items",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "experimental.seatbelt.guiAccess",
        schema_path: "/properties/experimental/anyOf/0/properties/seatbelt/anyOf/0/properties/guiAccess",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "experimental.seatbelt.guiAccess#absent",
        schema_path: "/properties/experimental/anyOf/0/properties/seatbelt/anyOf/0/properties/guiAccess",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "experimental.seatbelt.guiAccess#nullable",
        schema_path: "/properties/experimental/anyOf/0/properties/seatbelt/anyOf/0/properties/guiAccess",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "experimental.seatbelt.keychainAccess",
        schema_path: "/properties/experimental/anyOf/0/properties/seatbelt/anyOf/0/properties/keychainAccess",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "experimental.seatbelt.keychainAccess#absent",
        schema_path: "/properties/experimental/anyOf/0/properties/seatbelt/anyOf/0/properties/keychainAccess",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "experimental.seatbelt.keychainAccess#nullable",
        schema_path: "/properties/experimental/anyOf/0/properties/seatbelt/anyOf/0/properties/keychainAccess",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "experimental.seatbelt.launchMethod",
        schema_path: "/properties/experimental/anyOf/0/properties/seatbelt/anyOf/0/properties/launchMethod",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "experimental.seatbelt.launchMethod#absent",
        schema_path: "/properties/experimental/anyOf/0/properties/seatbelt/anyOf/0/properties/launchMethod",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "experimental.seatbelt.launchMethod#nullable",
        schema_path: "/properties/experimental/anyOf/0/properties/seatbelt/anyOf/0/properties/launchMethod",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "experimental.seatbelt.launchMethod#anyOf[0]=#/definitions/LaunchMethod",
        schema_path: "/properties/experimental/anyOf/0/properties/seatbelt/anyOf/0/properties/launchMethod/anyOf/0",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "experimental.seatbelt.launchMethod#oneOf[0]=string",
        schema_path: "/properties/experimental/anyOf/0/properties/seatbelt/anyOf/0/properties/launchMethod/anyOf/0/oneOf/0",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "experimental.seatbelt.launchMethod#enum=exec",
        schema_path: "/properties/experimental/anyOf/0/properties/seatbelt/anyOf/0/properties/launchMethod/anyOf/0/oneOf/0/enum/0",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "experimental.seatbelt.launchMethod#default=exec",
        schema_path: "/properties/experimental/anyOf/0/properties/seatbelt/anyOf/0/properties/launchMethod/anyOf/0/oneOf/0",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "experimental.seatbelt.launchMethod#oneOf[1]=string",
        schema_path: "/properties/experimental/anyOf/0/properties/seatbelt/anyOf/0/properties/launchMethod/anyOf/0/oneOf/1",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "experimental.seatbelt.launchMethod#enum=open",
        schema_path: "/properties/experimental/anyOf/0/properties/seatbelt/anyOf/0/properties/launchMethod/anyOf/0/oneOf/1/enum/0",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "experimental.seatbelt.launchMethod#anyOf[1]=null",
        schema_path: "/properties/experimental/anyOf/0/properties/seatbelt/anyOf/0/properties/launchMethod/anyOf/1",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "experimental.seatbelt.nestedPty",
        schema_path: "/properties/experimental/anyOf/0/properties/seatbelt/anyOf/0/properties/nestedPty",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "experimental.seatbelt.nestedPty#absent",
        schema_path: "/properties/experimental/anyOf/0/properties/seatbelt/anyOf/0/properties/nestedPty",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "experimental.seatbelt.nestedPty#nullable",
        schema_path: "/properties/experimental/anyOf/0/properties/seatbelt/anyOf/0/properties/nestedPty",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "experimental.seatbelt.nestedPty#default=true",
        schema_path: "/properties/experimental/anyOf/0/properties/seatbelt/anyOf/0/properties/nestedPty",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "experimental.seatbelt.profileOverride",
        schema_path: "/properties/experimental/anyOf/0/properties/seatbelt/anyOf/0/properties/profileOverride",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "experimental.seatbelt.profileOverride#absent",
        schema_path: "/properties/experimental/anyOf/0/properties/seatbelt/anyOf/0/properties/profileOverride",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "experimental.seatbelt.profileOverride#nullable",
        schema_path: "/properties/experimental/anyOf/0/properties/seatbelt/anyOf/0/properties/profileOverride",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "experimental.seatbelt#anyOf[1]=null",
        schema_path: "/properties/experimental/anyOf/0/properties/seatbelt/anyOf/1",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "experimental.test",
        schema_path: "/properties/experimental/anyOf/0/properties/test",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "experimental.test#absent",
        schema_path: "/properties/experimental/anyOf/0/properties/test",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "experimental.test#nullable",
        schema_path: "/properties/experimental/anyOf/0/properties/test",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "experimental.test#anyOf[0]=#/definitions/TestFeature",
        schema_path: "/properties/experimental/anyOf/0/properties/test/anyOf/0",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "experimental.test.message",
        schema_path: "/properties/experimental/anyOf/0/properties/test/anyOf/0/properties/message",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "experimental.test.message#absent",
        schema_path: "/properties/experimental/anyOf/0/properties/test/anyOf/0/properties/message",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "experimental.test.message#nullable",
        schema_path: "/properties/experimental/anyOf/0/properties/test/anyOf/0/properties/message",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "experimental.test#anyOf[1]=null",
        schema_path: "/properties/experimental/anyOf/0/properties/test/anyOf/1",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "experimental.windows_sandbox",
        schema_path: "/properties/experimental/anyOf/0/properties/windows_sandbox",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "experimental.windows_sandbox#absent",
        schema_path: "/properties/experimental/anyOf/0/properties/windows_sandbox",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "experimental.windows_sandbox#nullable",
        schema_path: "/properties/experimental/anyOf/0/properties/windows_sandbox",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "experimental.windows_sandbox#anyOf[0]=#/definitions/WindowsSandbox",
        schema_path: "/properties/experimental/anyOf/0/properties/windows_sandbox/anyOf/0",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "experimental.windows_sandbox.daemonPipeName",
        schema_path: "/properties/experimental/anyOf/0/properties/windows_sandbox/anyOf/0/properties/daemonPipeName",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "experimental.windows_sandbox.daemonPipeName#absent",
        schema_path: "/properties/experimental/anyOf/0/properties/windows_sandbox/anyOf/0/properties/daemonPipeName",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "experimental.windows_sandbox.daemonPipeName#nullable",
        schema_path: "/properties/experimental/anyOf/0/properties/windows_sandbox/anyOf/0/properties/daemonPipeName",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "experimental.windows_sandbox.idleTimeout",
        schema_path: "/properties/experimental/anyOf/0/properties/windows_sandbox/anyOf/0/properties/idleTimeout",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "experimental.windows_sandbox.idleTimeout#absent",
        schema_path: "/properties/experimental/anyOf/0/properties/windows_sandbox/anyOf/0/properties/idleTimeout",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "experimental.windows_sandbox.idleTimeout#nullable",
        schema_path: "/properties/experimental/anyOf/0/properties/windows_sandbox/anyOf/0/properties/idleTimeout",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "experimental.windows_sandbox.idleTimeoutMs",
        schema_path: "/properties/experimental/anyOf/0/properties/windows_sandbox/anyOf/0/properties/idleTimeoutMs",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "experimental.windows_sandbox.idleTimeoutMs#absent",
        schema_path: "/properties/experimental/anyOf/0/properties/windows_sandbox/anyOf/0/properties/idleTimeoutMs",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "experimental.windows_sandbox.idleTimeoutMs#nullable",
        schema_path: "/properties/experimental/anyOf/0/properties/windows_sandbox/anyOf/0/properties/idleTimeoutMs",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "experimental.windows_sandbox#anyOf[1]=null",
        schema_path: "/properties/experimental/anyOf/0/properties/windows_sandbox/anyOf/1",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "experimental.wslc",
        schema_path: "/properties/experimental/anyOf/0/properties/wslc",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "experimental.wslc#absent",
        schema_path: "/properties/experimental/anyOf/0/properties/wslc",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "experimental.wslc#nullable",
        schema_path: "/properties/experimental/anyOf/0/properties/wslc",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "experimental.wslc#anyOf[0]=#/definitions/Wslc",
        schema_path: "/properties/experimental/anyOf/0/properties/wslc/anyOf/0",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "experimental.wslc.cpuCount",
        schema_path: "/properties/experimental/anyOf/0/properties/wslc/anyOf/0/properties/cpuCount",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "experimental.wslc.cpuCount#absent",
        schema_path: "/properties/experimental/anyOf/0/properties/wslc/anyOf/0/properties/cpuCount",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "experimental.wslc.cpuCount#nullable",
        schema_path: "/properties/experimental/anyOf/0/properties/wslc/anyOf/0/properties/cpuCount",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "experimental.wslc.gpu",
        schema_path: "/properties/experimental/anyOf/0/properties/wslc/anyOf/0/properties/gpu",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "experimental.wslc.gpu#absent",
        schema_path: "/properties/experimental/anyOf/0/properties/wslc/anyOf/0/properties/gpu",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "experimental.wslc.gpu#nullable",
        schema_path: "/properties/experimental/anyOf/0/properties/wslc/anyOf/0/properties/gpu",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "experimental.wslc.image",
        schema_path: "/properties/experimental/anyOf/0/properties/wslc/anyOf/0/properties/image",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "experimental.wslc.image#absent",
        schema_path: "/properties/experimental/anyOf/0/properties/wslc/anyOf/0/properties/image",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "experimental.wslc.image#nullable",
        schema_path: "/properties/experimental/anyOf/0/properties/wslc/anyOf/0/properties/image",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "experimental.wslc.imageTarPath",
        schema_path: "/properties/experimental/anyOf/0/properties/wslc/anyOf/0/properties/imageTarPath",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "experimental.wslc.imageTarPath#absent",
        schema_path: "/properties/experimental/anyOf/0/properties/wslc/anyOf/0/properties/imageTarPath",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "experimental.wslc.imageTarPath#nullable",
        schema_path: "/properties/experimental/anyOf/0/properties/wslc/anyOf/0/properties/imageTarPath",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "experimental.wslc.memoryMb",
        schema_path: "/properties/experimental/anyOf/0/properties/wslc/anyOf/0/properties/memoryMb",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "experimental.wslc.memoryMb#absent",
        schema_path: "/properties/experimental/anyOf/0/properties/wslc/anyOf/0/properties/memoryMb",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "experimental.wslc.memoryMb#nullable",
        schema_path: "/properties/experimental/anyOf/0/properties/wslc/anyOf/0/properties/memoryMb",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "experimental.wslc.portMappings",
        schema_path: "/properties/experimental/anyOf/0/properties/wslc/anyOf/0/properties/portMappings",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "experimental.wslc.portMappings#absent",
        schema_path: "/properties/experimental/anyOf/0/properties/wslc/anyOf/0/properties/portMappings",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "experimental.wslc.portMappings#nullable",
        schema_path: "/properties/experimental/anyOf/0/properties/wslc/anyOf/0/properties/portMappings",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "experimental.wslc.portMappings[]",
        schema_path: "/properties/experimental/anyOf/0/properties/wslc/anyOf/0/properties/portMappings/items",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "experimental.wslc.portMappings[].containerPort",
        schema_path: "/properties/experimental/anyOf/0/properties/wslc/anyOf/0/properties/portMappings/items/properties/containerPort",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "experimental.wslc.portMappings[].protocol",
        schema_path: "/properties/experimental/anyOf/0/properties/wslc/anyOf/0/properties/portMappings/items/properties/protocol",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "experimental.wslc.portMappings[].protocol#absent",
        schema_path: "/properties/experimental/anyOf/0/properties/wslc/anyOf/0/properties/portMappings/items/properties/protocol",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "experimental.wslc.portMappings[].protocol#nullable",
        schema_path: "/properties/experimental/anyOf/0/properties/wslc/anyOf/0/properties/portMappings/items/properties/protocol",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "experimental.wslc.portMappings[].protocol#anyOf[0]=#/definitions/TransportProtocol",
        schema_path: "/properties/experimental/anyOf/0/properties/wslc/anyOf/0/properties/portMappings/items/properties/protocol/anyOf/0",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "experimental.wslc.portMappings[].protocol#enum=tcp",
        schema_path: "/properties/experimental/anyOf/0/properties/wslc/anyOf/0/properties/portMappings/items/properties/protocol/anyOf/0/enum/0",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "experimental.wslc.portMappings[].protocol#anyOf[1]=null",
        schema_path: "/properties/experimental/anyOf/0/properties/wslc/anyOf/0/properties/portMappings/items/properties/protocol/anyOf/1",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "experimental.wslc.portMappings[].windowsPort",
        schema_path: "/properties/experimental/anyOf/0/properties/wslc/anyOf/0/properties/portMappings/items/properties/windowsPort",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "experimental.wslc.provision",
        schema_path: "/properties/experimental/anyOf/0/properties/wslc/anyOf/0/properties/provision",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "experimental.wslc.provision#absent",
        schema_path: "/properties/experimental/anyOf/0/properties/wslc/anyOf/0/properties/provision",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "experimental.wslc.provision#nullable",
        schema_path: "/properties/experimental/anyOf/0/properties/wslc/anyOf/0/properties/provision",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "experimental.wslc.provision#anyOf[0]=#/definitions/WslcProvisionPhase",
        schema_path: "/properties/experimental/anyOf/0/properties/wslc/anyOf/0/properties/provision/anyOf/0",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "experimental.wslc.provision.image",
        schema_path: "/properties/experimental/anyOf/0/properties/wslc/anyOf/0/properties/provision/anyOf/0/properties/image",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "experimental.wslc.provision.image#absent",
        schema_path: "/properties/experimental/anyOf/0/properties/wslc/anyOf/0/properties/provision/anyOf/0/properties/image",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "experimental.wslc.provision.image#nullable",
        schema_path: "/properties/experimental/anyOf/0/properties/wslc/anyOf/0/properties/provision/anyOf/0/properties/image",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "experimental.wslc.provision.image#default=alpine:latest",
        schema_path: "/properties/experimental/anyOf/0/properties/wslc/anyOf/0/properties/provision/anyOf/0/properties/image",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "experimental.wslc.provision.imageTarPath",
        schema_path: "/properties/experimental/anyOf/0/properties/wslc/anyOf/0/properties/provision/anyOf/0/properties/imageTarPath",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "experimental.wslc.provision.imageTarPath#absent",
        schema_path: "/properties/experimental/anyOf/0/properties/wslc/anyOf/0/properties/provision/anyOf/0/properties/imageTarPath",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "experimental.wslc.provision.imageTarPath#nullable",
        schema_path: "/properties/experimental/anyOf/0/properties/wslc/anyOf/0/properties/provision/anyOf/0/properties/imageTarPath",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "experimental.wslc.provision#anyOf[1]=null",
        schema_path: "/properties/experimental/anyOf/0/properties/wslc/anyOf/0/properties/provision/anyOf/1",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "experimental.wslc.storagePath",
        schema_path: "/properties/experimental/anyOf/0/properties/wslc/anyOf/0/properties/storagePath",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "experimental.wslc.storagePath#absent",
        schema_path: "/properties/experimental/anyOf/0/properties/wslc/anyOf/0/properties/storagePath",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "experimental.wslc.storagePath#nullable",
        schema_path: "/properties/experimental/anyOf/0/properties/wslc/anyOf/0/properties/storagePath",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "experimental.wslc.targetOs",
        schema_path: "/properties/experimental/anyOf/0/properties/wslc/anyOf/0/properties/targetOs",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "experimental.wslc.targetOs#absent",
        schema_path: "/properties/experimental/anyOf/0/properties/wslc/anyOf/0/properties/targetOs",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "experimental.wslc.targetOs#nullable",
        schema_path: "/properties/experimental/anyOf/0/properties/wslc/anyOf/0/properties/targetOs",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "experimental.wslc#anyOf[1]=null",
        schema_path: "/properties/experimental/anyOf/0/properties/wslc/anyOf/1",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "experimental#anyOf[1]=null",
        schema_path: "/properties/experimental/anyOf/1",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "fallback",
        schema_path: "/properties/fallback",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "fallback#absent",
        schema_path: "/properties/fallback",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "fallback#nullable",
        schema_path: "/properties/fallback",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "fallback#anyOf[0]=#/definitions/Fallback",
        schema_path: "/properties/fallback/anyOf/0",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "fallback.allowDaclMutation",
        schema_path: "/properties/fallback/anyOf/0/properties/allowDaclMutation",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "fallback.allowDaclMutation#absent",
        schema_path: "/properties/fallback/anyOf/0/properties/allowDaclMutation",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "fallback.allowDaclMutation#nullable",
        schema_path: "/properties/fallback/anyOf/0/properties/allowDaclMutation",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "fallback#anyOf[1]=null",
        schema_path: "/properties/fallback/anyOf/1",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "filesystem",
        schema_path: "/properties/filesystem",
        disposition: PolicyDisposition::Honored,
        phases: PHASES_PROVISION,
        evidence: EVIDENCE_LOCAL_LINUX_RUNTIME,
        reason: REASON_HONORED_PROVISION,
    },
    CatalogEntry {
        key: "filesystem#absent",
        schema_path: "/properties/filesystem",
        disposition: PolicyDisposition::Honored,
        phases: PHASES_PROVISION,
        evidence: EVIDENCE_LOCAL_LINUX_RUNTIME,
        reason: REASON_HONORED_PROVISION,
    },
    CatalogEntry {
        key: "filesystem#nullable",
        schema_path: "/properties/filesystem",
        disposition: PolicyDisposition::Honored,
        phases: PHASES_PROVISION,
        evidence: EVIDENCE_LOCAL_LINUX_RUNTIME,
        reason: REASON_HONORED_PROVISION,
    },
    CatalogEntry {
        key: "filesystem#anyOf[0]=#/definitions/Filesystem",
        schema_path: "/properties/filesystem/anyOf/0",
        disposition: PolicyDisposition::Honored,
        phases: PHASES_PROVISION,
        evidence: EVIDENCE_LOCAL_LINUX_RUNTIME,
        reason: REASON_HONORED_PROVISION,
    },
    CatalogEntry {
        key: "filesystem.deniedPaths",
        schema_path: "/properties/filesystem/anyOf/0/properties/deniedPaths",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "filesystem.deniedPaths#absent",
        schema_path: "/properties/filesystem/anyOf/0/properties/deniedPaths",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "filesystem.deniedPaths#nullable",
        schema_path: "/properties/filesystem/anyOf/0/properties/deniedPaths",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "filesystem.deniedPaths[]",
        schema_path: "/properties/filesystem/anyOf/0/properties/deniedPaths/items",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "filesystem.readonlyPaths",
        schema_path: "/properties/filesystem/anyOf/0/properties/readonlyPaths",
        disposition: PolicyDisposition::Honored,
        phases: PHASES_PROVISION,
        evidence: EVIDENCE_LOCAL_LINUX_RUNTIME,
        reason: REASON_HONORED_PROVISION,
    },
    CatalogEntry {
        key: "filesystem.readonlyPaths#absent",
        schema_path: "/properties/filesystem/anyOf/0/properties/readonlyPaths",
        disposition: PolicyDisposition::Honored,
        phases: PHASES_PROVISION,
        evidence: EVIDENCE_LOCAL_LINUX_RUNTIME,
        reason: REASON_HONORED_PROVISION,
    },
    CatalogEntry {
        key: "filesystem.readonlyPaths#nullable",
        schema_path: "/properties/filesystem/anyOf/0/properties/readonlyPaths",
        disposition: PolicyDisposition::Honored,
        phases: PHASES_PROVISION,
        evidence: EVIDENCE_LOCAL_LINUX_RUNTIME,
        reason: REASON_HONORED_PROVISION,
    },
    CatalogEntry {
        key: "filesystem.readonlyPaths[]",
        schema_path: "/properties/filesystem/anyOf/0/properties/readonlyPaths/items",
        disposition: PolicyDisposition::Honored,
        phases: PHASES_PROVISION,
        evidence: EVIDENCE_LOCAL_LINUX_RUNTIME,
        reason: REASON_HONORED_PROVISION,
    },
    CatalogEntry {
        key: "filesystem.readwritePaths",
        schema_path: "/properties/filesystem/anyOf/0/properties/readwritePaths",
        disposition: PolicyDisposition::Honored,
        phases: PHASES_PROVISION,
        evidence: EVIDENCE_LOCAL_LINUX_RUNTIME,
        reason: REASON_HONORED_PROVISION,
    },
    CatalogEntry {
        key: "filesystem.readwritePaths#absent",
        schema_path: "/properties/filesystem/anyOf/0/properties/readwritePaths",
        disposition: PolicyDisposition::Honored,
        phases: PHASES_PROVISION,
        evidence: EVIDENCE_LOCAL_LINUX_RUNTIME,
        reason: REASON_HONORED_PROVISION,
    },
    CatalogEntry {
        key: "filesystem.readwritePaths#nullable",
        schema_path: "/properties/filesystem/anyOf/0/properties/readwritePaths",
        disposition: PolicyDisposition::Honored,
        phases: PHASES_PROVISION,
        evidence: EVIDENCE_LOCAL_LINUX_RUNTIME,
        reason: REASON_HONORED_PROVISION,
    },
    CatalogEntry {
        key: "filesystem.readwritePaths[]",
        schema_path: "/properties/filesystem/anyOf/0/properties/readwritePaths/items",
        disposition: PolicyDisposition::Honored,
        phases: PHASES_PROVISION,
        evidence: EVIDENCE_LOCAL_LINUX_RUNTIME,
        reason: REASON_HONORED_PROVISION,
    },
    CatalogEntry {
        key: "filesystem#anyOf[1]=null",
        schema_path: "/properties/filesystem/anyOf/1",
        disposition: PolicyDisposition::Honored,
        phases: PHASES_PROVISION,
        evidence: EVIDENCE_LOCAL_LINUX_RUNTIME,
        reason: REASON_HONORED_PROVISION,
    },
    CatalogEntry {
        key: "lifecycle",
        schema_path: "/properties/lifecycle",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "lifecycle#absent",
        schema_path: "/properties/lifecycle",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "lifecycle#nullable",
        schema_path: "/properties/lifecycle",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "lifecycle#anyOf[0]=#/definitions/Lifecycle",
        schema_path: "/properties/lifecycle/anyOf/0",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "lifecycle.destroyOnExit",
        schema_path: "/properties/lifecycle/anyOf/0/properties/destroyOnExit",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "lifecycle.destroyOnExit#absent",
        schema_path: "/properties/lifecycle/anyOf/0/properties/destroyOnExit",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "lifecycle.destroyOnExit#nullable",
        schema_path: "/properties/lifecycle/anyOf/0/properties/destroyOnExit",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "lifecycle.destroyOnExit#default=true",
        schema_path: "/properties/lifecycle/anyOf/0/properties/destroyOnExit",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "lifecycle.preservePolicy",
        schema_path: "/properties/lifecycle/anyOf/0/properties/preservePolicy",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "lifecycle.preservePolicy#absent",
        schema_path: "/properties/lifecycle/anyOf/0/properties/preservePolicy",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "lifecycle.preservePolicy#nullable",
        schema_path: "/properties/lifecycle/anyOf/0/properties/preservePolicy",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "lifecycle.preservePolicy#default=false",
        schema_path: "/properties/lifecycle/anyOf/0/properties/preservePolicy",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "lifecycle#anyOf[1]=null",
        schema_path: "/properties/lifecycle/anyOf/1",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "lxc",
        schema_path: "/properties/lxc",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "lxc#absent",
        schema_path: "/properties/lxc",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "lxc#nullable",
        schema_path: "/properties/lxc",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "lxc#anyOf[0]=#/definitions/Lxc",
        schema_path: "/properties/lxc/anyOf/0",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "lxc.distribution",
        schema_path: "/properties/lxc/anyOf/0/properties/distribution",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "lxc.distribution#absent",
        schema_path: "/properties/lxc/anyOf/0/properties/distribution",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "lxc.distribution#nullable",
        schema_path: "/properties/lxc/anyOf/0/properties/distribution",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "lxc.release",
        schema_path: "/properties/lxc/anyOf/0/properties/release",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "lxc.release#absent",
        schema_path: "/properties/lxc/anyOf/0/properties/release",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "lxc.release#nullable",
        schema_path: "/properties/lxc/anyOf/0/properties/release",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "lxc#anyOf[1]=null",
        schema_path: "/properties/lxc/anyOf/1",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "network",
        schema_path: "/properties/network",
        disposition: PolicyDisposition::Honored,
        phases: PHASES_PROVISION,
        evidence: EVIDENCE_LIVE_WHP_POS_NEG,
        reason: REASON_HONORED_PROVISION,
    },
    CatalogEntry {
        key: "network#absent",
        schema_path: "/properties/network",
        disposition: PolicyDisposition::Honored,
        phases: PHASES_PROVISION,
        evidence: EVIDENCE_LIVE_WHP_POS_NEG,
        reason: REASON_HONORED_PROVISION,
    },
    CatalogEntry {
        key: "network#nullable",
        schema_path: "/properties/network",
        disposition: PolicyDisposition::Honored,
        phases: PHASES_PROVISION,
        evidence: EVIDENCE_LIVE_WHP_POS_NEG,
        reason: REASON_HONORED_PROVISION,
    },
    CatalogEntry {
        key: "network#anyOf[0]=#/definitions/Network",
        schema_path: "/properties/network/anyOf/0",
        disposition: PolicyDisposition::Honored,
        phases: PHASES_PROVISION,
        evidence: EVIDENCE_LIVE_WHP_POS_NEG,
        reason: REASON_HONORED_PROVISION,
    },
    CatalogEntry {
        key: "network.allowLocalNetwork",
        schema_path: "/properties/network/anyOf/0/properties/allowLocalNetwork",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "network.allowLocalNetwork#absent",
        schema_path: "/properties/network/anyOf/0/properties/allowLocalNetwork",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "network.allowLocalNetwork#nullable",
        schema_path: "/properties/network/anyOf/0/properties/allowLocalNetwork",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "network.allowedHosts",
        schema_path: "/properties/network/anyOf/0/properties/allowedHosts",
        disposition: PolicyDisposition::Honored,
        phases: PHASES_PROVISION,
        evidence: EVIDENCE_LIVE_WHP_POS_NEG,
        reason: REASON_HONORED_PROVISION,
    },
    CatalogEntry {
        key: "network.allowedHosts#absent",
        schema_path: "/properties/network/anyOf/0/properties/allowedHosts",
        disposition: PolicyDisposition::Honored,
        phases: PHASES_PROVISION,
        evidence: EVIDENCE_LIVE_WHP_POS_NEG,
        reason: REASON_HONORED_PROVISION,
    },
    CatalogEntry {
        key: "network.allowedHosts#nullable",
        schema_path: "/properties/network/anyOf/0/properties/allowedHosts",
        disposition: PolicyDisposition::Honored,
        phases: PHASES_PROVISION,
        evidence: EVIDENCE_LIVE_WHP_POS_NEG,
        reason: REASON_HONORED_PROVISION,
    },
    CatalogEntry {
        key: "network.allowedHosts[]",
        schema_path: "/properties/network/anyOf/0/properties/allowedHosts/items",
        disposition: PolicyDisposition::Honored,
        phases: PHASES_PROVISION,
        evidence: EVIDENCE_LIVE_WHP_POS_NEG,
        reason: REASON_HONORED_PROVISION,
    },
    CatalogEntry {
        key: "network.blockedHosts",
        schema_path: "/properties/network/anyOf/0/properties/blockedHosts",
        disposition: PolicyDisposition::Honored,
        phases: PHASES_PROVISION,
        evidence: EVIDENCE_LIVE_WHP_POS_NEG,
        reason: REASON_HONORED_PROVISION,
    },
    CatalogEntry {
        key: "network.blockedHosts#absent",
        schema_path: "/properties/network/anyOf/0/properties/blockedHosts",
        disposition: PolicyDisposition::Honored,
        phases: PHASES_PROVISION,
        evidence: EVIDENCE_LIVE_WHP_POS_NEG,
        reason: REASON_HONORED_PROVISION,
    },
    CatalogEntry {
        key: "network.blockedHosts#nullable",
        schema_path: "/properties/network/anyOf/0/properties/blockedHosts",
        disposition: PolicyDisposition::Honored,
        phases: PHASES_PROVISION,
        evidence: EVIDENCE_LIVE_WHP_POS_NEG,
        reason: REASON_HONORED_PROVISION,
    },
    CatalogEntry {
        key: "network.blockedHosts[]",
        schema_path: "/properties/network/anyOf/0/properties/blockedHosts/items",
        disposition: PolicyDisposition::Honored,
        phases: PHASES_PROVISION,
        evidence: EVIDENCE_LIVE_WHP_POS_NEG,
        reason: REASON_HONORED_PROVISION,
    },
    CatalogEntry {
        key: "network.defaultPolicy",
        schema_path: "/properties/network/anyOf/0/properties/defaultPolicy",
        disposition: PolicyDisposition::Honored,
        phases: PHASES_PROVISION,
        evidence: EVIDENCE_LIVE_WHP_POS_NEG,
        reason: REASON_HONORED_PROVISION,
    },
    CatalogEntry {
        key: "network.defaultPolicy#absent",
        schema_path: "/properties/network/anyOf/0/properties/defaultPolicy",
        disposition: PolicyDisposition::Honored,
        phases: PHASES_PROVISION,
        evidence: EVIDENCE_LIVE_WHP_POS_NEG,
        reason: REASON_HONORED_PROVISION,
    },
    CatalogEntry {
        key: "network.defaultPolicy#nullable",
        schema_path: "/properties/network/anyOf/0/properties/defaultPolicy",
        disposition: PolicyDisposition::Honored,
        phases: PHASES_PROVISION,
        evidence: EVIDENCE_LIVE_WHP_POS_NEG,
        reason: REASON_HONORED_PROVISION,
    },
    CatalogEntry {
        key: "network.defaultPolicy#anyOf[0]=#/definitions/NetworkPolicy",
        schema_path: "/properties/network/anyOf/0/properties/defaultPolicy/anyOf/0",
        disposition: PolicyDisposition::Honored,
        phases: PHASES_PROVISION,
        evidence: EVIDENCE_LIVE_WHP_POS_NEG,
        reason: REASON_HONORED_PROVISION,
    },
    CatalogEntry {
        key: "network.defaultPolicy#enum=allow",
        schema_path: "/properties/network/anyOf/0/properties/defaultPolicy/anyOf/0/enum/0",
        disposition: PolicyDisposition::Honored,
        phases: PHASES_PROVISION,
        evidence: EVIDENCE_LIVE_WHP_POS_NEG,
        reason: REASON_HONORED_PROVISION,
    },
    CatalogEntry {
        key: "network.defaultPolicy#enum=block",
        schema_path: "/properties/network/anyOf/0/properties/defaultPolicy/anyOf/0/enum/1",
        disposition: PolicyDisposition::Honored,
        phases: PHASES_PROVISION,
        evidence: EVIDENCE_LIVE_WHP_POS_NEG,
        reason: REASON_HONORED_PROVISION,
    },
    CatalogEntry {
        key: "network.defaultPolicy#anyOf[1]=null",
        schema_path: "/properties/network/anyOf/0/properties/defaultPolicy/anyOf/1",
        disposition: PolicyDisposition::Honored,
        phases: PHASES_PROVISION,
        evidence: EVIDENCE_LIVE_WHP_POS_NEG,
        reason: REASON_HONORED_PROVISION,
    },
    CatalogEntry {
        key: "network.egress",
        schema_path: "/properties/network/anyOf/0/properties/egress",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "network.egress#absent",
        schema_path: "/properties/network/anyOf/0/properties/egress",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "network.egress#nullable",
        schema_path: "/properties/network/anyOf/0/properties/egress",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "network.egress#anyOf[0]=#/definitions/NetworkEgress",
        schema_path: "/properties/network/anyOf/0/properties/egress/anyOf/0",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "network.egress.allow",
        schema_path: "/properties/network/anyOf/0/properties/egress/anyOf/0/properties/allow",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "network.egress.allow#absent",
        schema_path: "/properties/network/anyOf/0/properties/egress/anyOf/0/properties/allow",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "network.egress.allow#nullable",
        schema_path: "/properties/network/anyOf/0/properties/egress/anyOf/0/properties/allow",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "network.egress.allow[]",
        schema_path: "/properties/network/anyOf/0/properties/egress/anyOf/0/properties/allow/items",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "network.egress.allow[].ports",
        schema_path: "/properties/network/anyOf/0/properties/egress/anyOf/0/properties/allow/items/properties/ports",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "network.egress.allow[].ports#absent",
        schema_path: "/properties/network/anyOf/0/properties/egress/anyOf/0/properties/allow/items/properties/ports",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "network.egress.allow[].ports#nullable",
        schema_path: "/properties/network/anyOf/0/properties/egress/anyOf/0/properties/allow/items/properties/ports",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "network.egress.allow[].ports[]",
        schema_path: "/properties/network/anyOf/0/properties/egress/anyOf/0/properties/allow/items/properties/ports/items",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "network.egress.allow[].ports[].endPort",
        schema_path: "/properties/network/anyOf/0/properties/egress/anyOf/0/properties/allow/items/properties/ports/items/properties/endPort",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "network.egress.allow[].ports[].endPort#absent",
        schema_path: "/properties/network/anyOf/0/properties/egress/anyOf/0/properties/allow/items/properties/ports/items/properties/endPort",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "network.egress.allow[].ports[].endPort#nullable",
        schema_path: "/properties/network/anyOf/0/properties/egress/anyOf/0/properties/allow/items/properties/ports/items/properties/endPort",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "network.egress.allow[].ports[].port",
        schema_path: "/properties/network/anyOf/0/properties/egress/anyOf/0/properties/allow/items/properties/ports/items/properties/port",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "network.egress.allow[].ports[].port#absent",
        schema_path: "/properties/network/anyOf/0/properties/egress/anyOf/0/properties/allow/items/properties/ports/items/properties/port",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "network.egress.allow[].ports[].port#nullable",
        schema_path: "/properties/network/anyOf/0/properties/egress/anyOf/0/properties/allow/items/properties/ports/items/properties/port",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "network.egress.allow[].ports[].protocol",
        schema_path: "/properties/network/anyOf/0/properties/egress/anyOf/0/properties/allow/items/properties/ports/items/properties/protocol",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "network.egress.allow[].ports[].protocol#absent",
        schema_path: "/properties/network/anyOf/0/properties/egress/anyOf/0/properties/allow/items/properties/ports/items/properties/protocol",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "network.egress.allow[].ports[].protocol#nullable",
        schema_path: "/properties/network/anyOf/0/properties/egress/anyOf/0/properties/allow/items/properties/ports/items/properties/protocol",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "network.egress.allow[].ports[].protocol#anyOf[0]=#/definitions/NetworkProtocol",
        schema_path: "/properties/network/anyOf/0/properties/egress/anyOf/0/properties/allow/items/properties/ports/items/properties/protocol/anyOf/0",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "network.egress.allow[].ports[].protocol#enum=tcp",
        schema_path: "/properties/network/anyOf/0/properties/egress/anyOf/0/properties/allow/items/properties/ports/items/properties/protocol/anyOf/0/enum/0",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "network.egress.allow[].ports[].protocol#enum=udp",
        schema_path: "/properties/network/anyOf/0/properties/egress/anyOf/0/properties/allow/items/properties/ports/items/properties/protocol/anyOf/0/enum/1",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "network.egress.allow[].ports[].protocol#enum=icmp",
        schema_path: "/properties/network/anyOf/0/properties/egress/anyOf/0/properties/allow/items/properties/ports/items/properties/protocol/anyOf/0/enum/2",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "network.egress.allow[].ports[].protocol#enum=any",
        schema_path: "/properties/network/anyOf/0/properties/egress/anyOf/0/properties/allow/items/properties/ports/items/properties/protocol/anyOf/0/enum/3",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "network.egress.allow[].ports[].protocol#anyOf[1]=null",
        schema_path: "/properties/network/anyOf/0/properties/egress/anyOf/0/properties/allow/items/properties/ports/items/properties/protocol/anyOf/1",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "network.egress.allow[].ports[].protocol#default=any",
        schema_path: "/properties/network/anyOf/0/properties/egress/anyOf/0/properties/allow/items/properties/ports/items/properties/protocol",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "network.egress.allow[].to",
        schema_path: "/properties/network/anyOf/0/properties/egress/anyOf/0/properties/allow/items/properties/to",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "network.egress.allow[].to#absent",
        schema_path: "/properties/network/anyOf/0/properties/egress/anyOf/0/properties/allow/items/properties/to",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "network.egress.allow[].to#nullable",
        schema_path: "/properties/network/anyOf/0/properties/egress/anyOf/0/properties/allow/items/properties/to",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "network.egress.allow[].to[]",
        schema_path: "/properties/network/anyOf/0/properties/egress/anyOf/0/properties/allow/items/properties/to/items",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "network.egress.allow[].to[].cidr",
        schema_path: "/properties/network/anyOf/0/properties/egress/anyOf/0/properties/allow/items/properties/to/items/properties/cidr",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "network.egress.allow[].to[].except",
        schema_path: "/properties/network/anyOf/0/properties/egress/anyOf/0/properties/allow/items/properties/to/items/properties/except",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "network.egress.allow[].to[].except#absent",
        schema_path: "/properties/network/anyOf/0/properties/egress/anyOf/0/properties/allow/items/properties/to/items/properties/except",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "network.egress.allow[].to[].except#nullable",
        schema_path: "/properties/network/anyOf/0/properties/egress/anyOf/0/properties/allow/items/properties/to/items/properties/except",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "network.egress.allow[].to[].except[]",
        schema_path: "/properties/network/anyOf/0/properties/egress/anyOf/0/properties/allow/items/properties/to/items/properties/except/items",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "network.egress.default",
        schema_path: "/properties/network/anyOf/0/properties/egress/anyOf/0/properties/default",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "network.egress.default#absent",
        schema_path: "/properties/network/anyOf/0/properties/egress/anyOf/0/properties/default",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "network.egress.default#nullable",
        schema_path: "/properties/network/anyOf/0/properties/egress/anyOf/0/properties/default",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "network.egress.default#anyOf[0]=#/definitions/NetworkAction",
        schema_path: "/properties/network/anyOf/0/properties/egress/anyOf/0/properties/default/anyOf/0",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "network.egress.default#enum=allow",
        schema_path: "/properties/network/anyOf/0/properties/egress/anyOf/0/properties/default/anyOf/0/enum/0",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "network.egress.default#enum=deny",
        schema_path: "/properties/network/anyOf/0/properties/egress/anyOf/0/properties/default/anyOf/0/enum/1",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "network.egress.default#anyOf[1]=null",
        schema_path: "/properties/network/anyOf/0/properties/egress/anyOf/0/properties/default/anyOf/1",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "network.egress.default#default=deny",
        schema_path: "/properties/network/anyOf/0/properties/egress/anyOf/0/properties/default",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "network.egress.deny",
        schema_path: "/properties/network/anyOf/0/properties/egress/anyOf/0/properties/deny",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "network.egress.deny#absent",
        schema_path: "/properties/network/anyOf/0/properties/egress/anyOf/0/properties/deny",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "network.egress.deny#nullable",
        schema_path: "/properties/network/anyOf/0/properties/egress/anyOf/0/properties/deny",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "network.egress.deny[]",
        schema_path: "/properties/network/anyOf/0/properties/egress/anyOf/0/properties/deny/items",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "network.egress.deny[].ports",
        schema_path: "/properties/network/anyOf/0/properties/egress/anyOf/0/properties/deny/items/properties/ports",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "network.egress.deny[].ports#absent",
        schema_path: "/properties/network/anyOf/0/properties/egress/anyOf/0/properties/deny/items/properties/ports",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "network.egress.deny[].ports#nullable",
        schema_path: "/properties/network/anyOf/0/properties/egress/anyOf/0/properties/deny/items/properties/ports",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "network.egress.deny[].ports[]",
        schema_path: "/properties/network/anyOf/0/properties/egress/anyOf/0/properties/deny/items/properties/ports/items",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "network.egress.deny[].ports[].endPort",
        schema_path: "/properties/network/anyOf/0/properties/egress/anyOf/0/properties/deny/items/properties/ports/items/properties/endPort",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "network.egress.deny[].ports[].endPort#absent",
        schema_path: "/properties/network/anyOf/0/properties/egress/anyOf/0/properties/deny/items/properties/ports/items/properties/endPort",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "network.egress.deny[].ports[].endPort#nullable",
        schema_path: "/properties/network/anyOf/0/properties/egress/anyOf/0/properties/deny/items/properties/ports/items/properties/endPort",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "network.egress.deny[].ports[].port",
        schema_path: "/properties/network/anyOf/0/properties/egress/anyOf/0/properties/deny/items/properties/ports/items/properties/port",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "network.egress.deny[].ports[].port#absent",
        schema_path: "/properties/network/anyOf/0/properties/egress/anyOf/0/properties/deny/items/properties/ports/items/properties/port",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "network.egress.deny[].ports[].port#nullable",
        schema_path: "/properties/network/anyOf/0/properties/egress/anyOf/0/properties/deny/items/properties/ports/items/properties/port",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "network.egress.deny[].ports[].protocol",
        schema_path: "/properties/network/anyOf/0/properties/egress/anyOf/0/properties/deny/items/properties/ports/items/properties/protocol",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "network.egress.deny[].ports[].protocol#absent",
        schema_path: "/properties/network/anyOf/0/properties/egress/anyOf/0/properties/deny/items/properties/ports/items/properties/protocol",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "network.egress.deny[].ports[].protocol#nullable",
        schema_path: "/properties/network/anyOf/0/properties/egress/anyOf/0/properties/deny/items/properties/ports/items/properties/protocol",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "network.egress.deny[].ports[].protocol#anyOf[0]=#/definitions/NetworkProtocol",
        schema_path: "/properties/network/anyOf/0/properties/egress/anyOf/0/properties/deny/items/properties/ports/items/properties/protocol/anyOf/0",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "network.egress.deny[].ports[].protocol#enum=tcp",
        schema_path: "/properties/network/anyOf/0/properties/egress/anyOf/0/properties/deny/items/properties/ports/items/properties/protocol/anyOf/0/enum/0",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "network.egress.deny[].ports[].protocol#enum=udp",
        schema_path: "/properties/network/anyOf/0/properties/egress/anyOf/0/properties/deny/items/properties/ports/items/properties/protocol/anyOf/0/enum/1",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "network.egress.deny[].ports[].protocol#enum=icmp",
        schema_path: "/properties/network/anyOf/0/properties/egress/anyOf/0/properties/deny/items/properties/ports/items/properties/protocol/anyOf/0/enum/2",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "network.egress.deny[].ports[].protocol#enum=any",
        schema_path: "/properties/network/anyOf/0/properties/egress/anyOf/0/properties/deny/items/properties/ports/items/properties/protocol/anyOf/0/enum/3",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "network.egress.deny[].ports[].protocol#anyOf[1]=null",
        schema_path: "/properties/network/anyOf/0/properties/egress/anyOf/0/properties/deny/items/properties/ports/items/properties/protocol/anyOf/1",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "network.egress.deny[].ports[].protocol#default=any",
        schema_path: "/properties/network/anyOf/0/properties/egress/anyOf/0/properties/deny/items/properties/ports/items/properties/protocol",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "network.egress.deny[].to",
        schema_path: "/properties/network/anyOf/0/properties/egress/anyOf/0/properties/deny/items/properties/to",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "network.egress.deny[].to#absent",
        schema_path: "/properties/network/anyOf/0/properties/egress/anyOf/0/properties/deny/items/properties/to",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "network.egress.deny[].to#nullable",
        schema_path: "/properties/network/anyOf/0/properties/egress/anyOf/0/properties/deny/items/properties/to",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "network.egress.deny[].to[]",
        schema_path: "/properties/network/anyOf/0/properties/egress/anyOf/0/properties/deny/items/properties/to/items",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "network.egress.deny[].to[].cidr",
        schema_path: "/properties/network/anyOf/0/properties/egress/anyOf/0/properties/deny/items/properties/to/items/properties/cidr",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "network.egress.deny[].to[].except",
        schema_path: "/properties/network/anyOf/0/properties/egress/anyOf/0/properties/deny/items/properties/to/items/properties/except",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "network.egress.deny[].to[].except#absent",
        schema_path: "/properties/network/anyOf/0/properties/egress/anyOf/0/properties/deny/items/properties/to/items/properties/except",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "network.egress.deny[].to[].except#nullable",
        schema_path: "/properties/network/anyOf/0/properties/egress/anyOf/0/properties/deny/items/properties/to/items/properties/except",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "network.egress.deny[].to[].except[]",
        schema_path: "/properties/network/anyOf/0/properties/egress/anyOf/0/properties/deny/items/properties/to/items/properties/except/items",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "network.egress#anyOf[1]=null",
        schema_path: "/properties/network/anyOf/0/properties/egress/anyOf/1",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "network.enforcementMode",
        schema_path: "/properties/network/anyOf/0/properties/enforcementMode",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "network.enforcementMode#absent",
        schema_path: "/properties/network/anyOf/0/properties/enforcementMode",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "network.enforcementMode#nullable",
        schema_path: "/properties/network/anyOf/0/properties/enforcementMode",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "network.enforcementMode#anyOf[0]=#/definitions/NetworkEnforcement",
        schema_path: "/properties/network/anyOf/0/properties/enforcementMode/anyOf/0",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "network.enforcementMode#oneOf[0]=string",
        schema_path: "/properties/network/anyOf/0/properties/enforcementMode/anyOf/0/oneOf/0",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "network.enforcementMode#enum=capabilities",
        schema_path: "/properties/network/anyOf/0/properties/enforcementMode/anyOf/0/oneOf/0/enum/0",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "network.enforcementMode#oneOf[1]=string",
        schema_path: "/properties/network/anyOf/0/properties/enforcementMode/anyOf/0/oneOf/1",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "network.enforcementMode#enum=firewall",
        schema_path: "/properties/network/anyOf/0/properties/enforcementMode/anyOf/0/oneOf/1/enum/0",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "network.enforcementMode#oneOf[2]=string",
        schema_path: "/properties/network/anyOf/0/properties/enforcementMode/anyOf/0/oneOf/2",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "network.enforcementMode#enum=both",
        schema_path: "/properties/network/anyOf/0/properties/enforcementMode/anyOf/0/oneOf/2/enum/0",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "network.enforcementMode#anyOf[1]=null",
        schema_path: "/properties/network/anyOf/0/properties/enforcementMode/anyOf/1",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "network.ingress",
        schema_path: "/properties/network/anyOf/0/properties/ingress",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "network.ingress#absent",
        schema_path: "/properties/network/anyOf/0/properties/ingress",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "network.ingress#nullable",
        schema_path: "/properties/network/anyOf/0/properties/ingress",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "network.ingress#anyOf[0]=#/definitions/NetworkIngress",
        schema_path: "/properties/network/anyOf/0/properties/ingress/anyOf/0",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "network.ingress.default",
        schema_path: "/properties/network/anyOf/0/properties/ingress/anyOf/0/properties/default",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "network.ingress.default#absent",
        schema_path: "/properties/network/anyOf/0/properties/ingress/anyOf/0/properties/default",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "network.ingress.default#nullable",
        schema_path: "/properties/network/anyOf/0/properties/ingress/anyOf/0/properties/default",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "network.ingress.default#anyOf[0]=#/definitions/NetworkAction",
        schema_path: "/properties/network/anyOf/0/properties/ingress/anyOf/0/properties/default/anyOf/0",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "network.ingress.default#enum=allow",
        schema_path: "/properties/network/anyOf/0/properties/ingress/anyOf/0/properties/default/anyOf/0/enum/0",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "network.ingress.default#enum=deny",
        schema_path: "/properties/network/anyOf/0/properties/ingress/anyOf/0/properties/default/anyOf/0/enum/1",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "network.ingress.default#anyOf[1]=null",
        schema_path: "/properties/network/anyOf/0/properties/ingress/anyOf/0/properties/default/anyOf/1",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "network.ingress.hostLoopback",
        schema_path: "/properties/network/anyOf/0/properties/ingress/anyOf/0/properties/hostLoopback",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "network.ingress.hostLoopback#absent",
        schema_path: "/properties/network/anyOf/0/properties/ingress/anyOf/0/properties/hostLoopback",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "network.ingress.hostLoopback#nullable",
        schema_path: "/properties/network/anyOf/0/properties/ingress/anyOf/0/properties/hostLoopback",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "network.ingress.hostLoopback#anyOf[0]=#/definitions/NetworkAction",
        schema_path: "/properties/network/anyOf/0/properties/ingress/anyOf/0/properties/hostLoopback/anyOf/0",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "network.ingress.hostLoopback#enum=allow",
        schema_path: "/properties/network/anyOf/0/properties/ingress/anyOf/0/properties/hostLoopback/anyOf/0/enum/0",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "network.ingress.hostLoopback#enum=deny",
        schema_path: "/properties/network/anyOf/0/properties/ingress/anyOf/0/properties/hostLoopback/anyOf/0/enum/1",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "network.ingress.hostLoopback#anyOf[1]=null",
        schema_path: "/properties/network/anyOf/0/properties/ingress/anyOf/0/properties/hostLoopback/anyOf/1",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "network.ingress#anyOf[1]=null",
        schema_path: "/properties/network/anyOf/0/properties/ingress/anyOf/1",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "network.proxy",
        schema_path: "/properties/network/anyOf/0/properties/proxy",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "network.proxy#absent",
        schema_path: "/properties/network/anyOf/0/properties/proxy",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "network.proxy#nullable",
        schema_path: "/properties/network/anyOf/0/properties/proxy",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "network.proxy#anyOf[0]=#/definitions/Proxy",
        schema_path: "/properties/network/anyOf/0/properties/proxy/anyOf/0",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "network.proxy.builtinTestServer",
        schema_path: "/properties/network/anyOf/0/properties/proxy/anyOf/0/properties/builtinTestServer",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "network.proxy.builtinTestServer#absent",
        schema_path: "/properties/network/anyOf/0/properties/proxy/anyOf/0/properties/builtinTestServer",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "network.proxy.builtinTestServer#nullable",
        schema_path: "/properties/network/anyOf/0/properties/proxy/anyOf/0/properties/builtinTestServer",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "network.proxy.localhost",
        schema_path: "/properties/network/anyOf/0/properties/proxy/anyOf/0/properties/localhost",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "network.proxy.localhost#absent",
        schema_path: "/properties/network/anyOf/0/properties/proxy/anyOf/0/properties/localhost",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "network.proxy.localhost#nullable",
        schema_path: "/properties/network/anyOf/0/properties/proxy/anyOf/0/properties/localhost",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "network.proxy.url",
        schema_path: "/properties/network/anyOf/0/properties/proxy/anyOf/0/properties/url",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "network.proxy.url#absent",
        schema_path: "/properties/network/anyOf/0/properties/proxy/anyOf/0/properties/url",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "network.proxy.url#nullable",
        schema_path: "/properties/network/anyOf/0/properties/proxy/anyOf/0/properties/url",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "network.proxy#anyOf[1]=null",
        schema_path: "/properties/network/anyOf/0/properties/proxy/anyOf/1",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "network#anyOf[1]=null",
        schema_path: "/properties/network/anyOf/1",
        disposition: PolicyDisposition::Honored,
        phases: PHASES_PROVISION,
        evidence: EVIDENCE_LIVE_WHP_POS_NEG,
        reason: REASON_HONORED_PROVISION,
    },
    CatalogEntry {
        key: "phase",
        schema_path: "/properties/phase",
        disposition: PolicyDisposition::Control,
        phases: PHASES_ALL,
        evidence: EVIDENCE_LIVE_WHP_POS_NEG,
        reason: REASON_CONTROL,
    },
    CatalogEntry {
        key: "phase#absent",
        schema_path: "/properties/phase",
        disposition: PolicyDisposition::Control,
        phases: PHASES_ALL,
        evidence: EVIDENCE_LIVE_WHP_POS_NEG,
        reason: REASON_CONTROL,
    },
    CatalogEntry {
        key: "phase#nullable",
        schema_path: "/properties/phase",
        disposition: PolicyDisposition::Control,
        phases: PHASES_ALL,
        evidence: EVIDENCE_LIVE_WHP_POS_NEG,
        reason: REASON_CONTROL,
    },
    CatalogEntry {
        key: "phase#anyOf[0]=#/definitions/Phase",
        schema_path: "/properties/phase/anyOf/0",
        disposition: PolicyDisposition::Control,
        phases: PHASES_ALL,
        evidence: EVIDENCE_LIVE_WHP_POS_NEG,
        reason: REASON_CONTROL,
    },
    CatalogEntry {
        key: "phase#enum=provision",
        schema_path: "/properties/phase/anyOf/0/enum/0",
        disposition: PolicyDisposition::Control,
        phases: PHASES_ALL,
        evidence: EVIDENCE_LIVE_WHP_POS_NEG,
        reason: REASON_CONTROL,
    },
    CatalogEntry {
        key: "phase#enum=start",
        schema_path: "/properties/phase/anyOf/0/enum/1",
        disposition: PolicyDisposition::Control,
        phases: PHASES_ALL,
        evidence: EVIDENCE_LIVE_WHP_POS_NEG,
        reason: REASON_CONTROL,
    },
    CatalogEntry {
        key: "phase#enum=exec",
        schema_path: "/properties/phase/anyOf/0/enum/2",
        disposition: PolicyDisposition::Control,
        phases: PHASES_ALL,
        evidence: EVIDENCE_LIVE_WHP_POS_NEG,
        reason: REASON_CONTROL,
    },
    CatalogEntry {
        key: "phase#enum=stop",
        schema_path: "/properties/phase/anyOf/0/enum/3",
        disposition: PolicyDisposition::Control,
        phases: PHASES_ALL,
        evidence: EVIDENCE_LIVE_WHP_POS_NEG,
        reason: REASON_CONTROL,
    },
    CatalogEntry {
        key: "phase#enum=deprovision",
        schema_path: "/properties/phase/anyOf/0/enum/4",
        disposition: PolicyDisposition::Control,
        phases: PHASES_ALL,
        evidence: EVIDENCE_LIVE_WHP_POS_NEG,
        reason: REASON_CONTROL,
    },
    CatalogEntry {
        key: "phase#anyOf[1]=null",
        schema_path: "/properties/phase/anyOf/1",
        disposition: PolicyDisposition::Control,
        phases: PHASES_ALL,
        evidence: EVIDENCE_LIVE_WHP_POS_NEG,
        reason: REASON_CONTROL,
    },
    CatalogEntry {
        key: "process",
        schema_path: "/properties/process",
        disposition: PolicyDisposition::Honored,
        phases: PHASES_EXEC,
        evidence: EVIDENCE_LOCAL_LINUX_RUNTIME,
        reason: REASON_HONORED_EXEC,
    },
    CatalogEntry {
        key: "process#absent",
        schema_path: "/properties/process",
        disposition: PolicyDisposition::Honored,
        phases: PHASES_EXEC,
        evidence: EVIDENCE_LOCAL_LINUX_RUNTIME,
        reason: REASON_HONORED_EXEC,
    },
    CatalogEntry {
        key: "process#nullable",
        schema_path: "/properties/process",
        disposition: PolicyDisposition::Honored,
        phases: PHASES_EXEC,
        evidence: EVIDENCE_LOCAL_LINUX_RUNTIME,
        reason: REASON_HONORED_EXEC,
    },
    CatalogEntry {
        key: "process#anyOf[0]=#/definitions/Process",
        schema_path: "/properties/process/anyOf/0",
        disposition: PolicyDisposition::Honored,
        phases: PHASES_EXEC,
        evidence: EVIDENCE_LOCAL_LINUX_RUNTIME,
        reason: REASON_HONORED_EXEC,
    },
    CatalogEntry {
        key: "process.commandLine",
        schema_path: "/properties/process/anyOf/0/properties/commandLine",
        disposition: PolicyDisposition::Honored,
        phases: PHASES_EXEC,
        evidence: EVIDENCE_LOCAL_LINUX_RUNTIME,
        reason: REASON_HONORED_EXEC,
    },
    CatalogEntry {
        key: "process.commandLine#absent",
        schema_path: "/properties/process/anyOf/0/properties/commandLine",
        disposition: PolicyDisposition::Honored,
        phases: PHASES_EXEC,
        evidence: EVIDENCE_LOCAL_LINUX_RUNTIME,
        reason: REASON_HONORED_EXEC,
    },
    CatalogEntry {
        key: "process.commandLine#nullable",
        schema_path: "/properties/process/anyOf/0/properties/commandLine",
        disposition: PolicyDisposition::Honored,
        phases: PHASES_EXEC,
        evidence: EVIDENCE_LOCAL_LINUX_RUNTIME,
        reason: REASON_HONORED_EXEC,
    },
    CatalogEntry {
        key: "process.cwd",
        schema_path: "/properties/process/anyOf/0/properties/cwd",
        disposition: PolicyDisposition::Honored,
        phases: PHASES_EXEC,
        evidence: EVIDENCE_LOCAL_LINUX_RUNTIME,
        reason: REASON_HONORED_EXEC,
    },
    CatalogEntry {
        key: "process.cwd#absent",
        schema_path: "/properties/process/anyOf/0/properties/cwd",
        disposition: PolicyDisposition::Honored,
        phases: PHASES_EXEC,
        evidence: EVIDENCE_LOCAL_LINUX_RUNTIME,
        reason: REASON_HONORED_EXEC,
    },
    CatalogEntry {
        key: "process.cwd#nullable",
        schema_path: "/properties/process/anyOf/0/properties/cwd",
        disposition: PolicyDisposition::Honored,
        phases: PHASES_EXEC,
        evidence: EVIDENCE_LOCAL_LINUX_RUNTIME,
        reason: REASON_HONORED_EXEC,
    },
    CatalogEntry {
        key: "process.env",
        schema_path: "/properties/process/anyOf/0/properties/env",
        disposition: PolicyDisposition::Honored,
        phases: PHASES_EXEC,
        evidence: EVIDENCE_LOCAL_LINUX_RUNTIME,
        reason: REASON_HONORED_EXEC,
    },
    CatalogEntry {
        key: "process.env#absent",
        schema_path: "/properties/process/anyOf/0/properties/env",
        disposition: PolicyDisposition::Honored,
        phases: PHASES_EXEC,
        evidence: EVIDENCE_LOCAL_LINUX_RUNTIME,
        reason: REASON_HONORED_EXEC,
    },
    CatalogEntry {
        key: "process.env#nullable",
        schema_path: "/properties/process/anyOf/0/properties/env",
        disposition: PolicyDisposition::Honored,
        phases: PHASES_EXEC,
        evidence: EVIDENCE_LOCAL_LINUX_RUNTIME,
        reason: REASON_HONORED_EXEC,
    },
    CatalogEntry {
        key: "process.env[]",
        schema_path: "/properties/process/anyOf/0/properties/env/items",
        disposition: PolicyDisposition::Honored,
        phases: PHASES_EXEC,
        evidence: EVIDENCE_LOCAL_LINUX_RUNTIME,
        reason: REASON_HONORED_EXEC,
    },
    CatalogEntry {
        key: "process.timeout",
        schema_path: "/properties/process/anyOf/0/properties/timeout",
        disposition: PolicyDisposition::Honored,
        phases: PHASES_EXEC,
        evidence: EVIDENCE_LOCAL_LINUX_RUNTIME,
        reason: REASON_HONORED_EXEC,
    },
    CatalogEntry {
        key: "process.timeout#absent",
        schema_path: "/properties/process/anyOf/0/properties/timeout",
        disposition: PolicyDisposition::Honored,
        phases: PHASES_EXEC,
        evidence: EVIDENCE_LOCAL_LINUX_RUNTIME,
        reason: REASON_HONORED_EXEC,
    },
    CatalogEntry {
        key: "process.timeout#nullable",
        schema_path: "/properties/process/anyOf/0/properties/timeout",
        disposition: PolicyDisposition::Honored,
        phases: PHASES_EXEC,
        evidence: EVIDENCE_LOCAL_LINUX_RUNTIME,
        reason: REASON_HONORED_EXEC,
    },
    CatalogEntry {
        key: "process#anyOf[1]=null",
        schema_path: "/properties/process/anyOf/1",
        disposition: PolicyDisposition::Honored,
        phases: PHASES_EXEC,
        evidence: EVIDENCE_LOCAL_LINUX_RUNTIME,
        reason: REASON_HONORED_EXEC,
    },
    CatalogEntry {
        key: "processContainer",
        schema_path: "/properties/processContainer",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "processContainer#absent",
        schema_path: "/properties/processContainer",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "processContainer#nullable",
        schema_path: "/properties/processContainer",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "processContainer#anyOf[0]=#/definitions/ProcessContainer",
        schema_path: "/properties/processContainer/anyOf/0",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "processContainer.capabilities",
        schema_path: "/properties/processContainer/anyOf/0/properties/capabilities",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "processContainer.capabilities#absent",
        schema_path: "/properties/processContainer/anyOf/0/properties/capabilities",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "processContainer.capabilities#nullable",
        schema_path: "/properties/processContainer/anyOf/0/properties/capabilities",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "processContainer.capabilities[]",
        schema_path: "/properties/processContainer/anyOf/0/properties/capabilities/items",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "processContainer.captureDenials",
        schema_path: "/properties/processContainer/anyOf/0/properties/captureDenials",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "processContainer.captureDenials#absent",
        schema_path: "/properties/processContainer/anyOf/0/properties/captureDenials",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "processContainer.captureDenials#nullable",
        schema_path: "/properties/processContainer/anyOf/0/properties/captureDenials",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "processContainer.captureDenials#anyOf[0]=#/definitions/CaptureDenials",
        schema_path: "/properties/processContainer/anyOf/0/properties/captureDenials/anyOf/0",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "processContainer.captureDenials.mode",
        schema_path: "/properties/processContainer/anyOf/0/properties/captureDenials/anyOf/0/properties/mode",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "processContainer.captureDenials.mode#absent",
        schema_path: "/properties/processContainer/anyOf/0/properties/captureDenials/anyOf/0/properties/mode",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "processContainer.captureDenials.mode#nullable",
        schema_path: "/properties/processContainer/anyOf/0/properties/captureDenials/anyOf/0/properties/mode",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "processContainer.captureDenials.mode#anyOf[0]=#/definitions/CaptureDenialsMode",
        schema_path: "/properties/processContainer/anyOf/0/properties/captureDenials/anyOf/0/properties/mode/anyOf/0",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "processContainer.captureDenials.mode#oneOf[0]=string",
        schema_path: "/properties/processContainer/anyOf/0/properties/captureDenials/anyOf/0/properties/mode/anyOf/0/oneOf/0",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "processContainer.captureDenials.mode#enum=block",
        schema_path: "/properties/processContainer/anyOf/0/properties/captureDenials/anyOf/0/properties/mode/anyOf/0/oneOf/0/enum/0",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "processContainer.captureDenials.mode#oneOf[1]=string",
        schema_path: "/properties/processContainer/anyOf/0/properties/captureDenials/anyOf/0/properties/mode/anyOf/0/oneOf/1",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "processContainer.captureDenials.mode#enum=allow",
        schema_path: "/properties/processContainer/anyOf/0/properties/captureDenials/anyOf/0/properties/mode/anyOf/0/oneOf/1/enum/0",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "processContainer.captureDenials.mode#anyOf[1]=null",
        schema_path: "/properties/processContainer/anyOf/0/properties/captureDenials/anyOf/0/properties/mode/anyOf/1",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "processContainer.captureDenials.mode#default=block",
        schema_path: "/properties/processContainer/anyOf/0/properties/captureDenials/anyOf/0/properties/mode",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "processContainer.captureDenials.outputPath",
        schema_path: "/properties/processContainer/anyOf/0/properties/captureDenials/anyOf/0/properties/outputPath",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "processContainer.captureDenials.outputPath#absent",
        schema_path: "/properties/processContainer/anyOf/0/properties/captureDenials/anyOf/0/properties/outputPath",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "processContainer.captureDenials.outputPath#nullable",
        schema_path: "/properties/processContainer/anyOf/0/properties/captureDenials/anyOf/0/properties/outputPath",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "processContainer.captureDenials.retainEtl",
        schema_path: "/properties/processContainer/anyOf/0/properties/captureDenials/anyOf/0/properties/retainEtl",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "processContainer.captureDenials.retainEtl#absent",
        schema_path: "/properties/processContainer/anyOf/0/properties/captureDenials/anyOf/0/properties/retainEtl",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "processContainer.captureDenials.retainEtl#nullable",
        schema_path: "/properties/processContainer/anyOf/0/properties/captureDenials/anyOf/0/properties/retainEtl",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "processContainer.captureDenials.retainEtl#default=false",
        schema_path: "/properties/processContainer/anyOf/0/properties/captureDenials/anyOf/0/properties/retainEtl",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "processContainer.captureDenials#anyOf[1]=null",
        schema_path: "/properties/processContainer/anyOf/0/properties/captureDenials/anyOf/1",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "processContainer.learningMode",
        schema_path: "/properties/processContainer/anyOf/0/properties/learningMode",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "processContainer.learningMode#absent",
        schema_path: "/properties/processContainer/anyOf/0/properties/learningMode",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "processContainer.learningMode#nullable",
        schema_path: "/properties/processContainer/anyOf/0/properties/learningMode",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "processContainer.leastPrivilege",
        schema_path: "/properties/processContainer/anyOf/0/properties/leastPrivilege",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "processContainer.leastPrivilege#absent",
        schema_path: "/properties/processContainer/anyOf/0/properties/leastPrivilege",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "processContainer.leastPrivilege#nullable",
        schema_path: "/properties/processContainer/anyOf/0/properties/leastPrivilege",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "processContainer.network",
        schema_path: "/properties/processContainer/anyOf/0/properties/network",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "processContainer.network#absent",
        schema_path: "/properties/processContainer/anyOf/0/properties/network",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "processContainer.network#nullable",
        schema_path: "/properties/processContainer/anyOf/0/properties/network",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "processContainer.network#anyOf[0]=#/definitions/ProcessContainerNetwork",
        schema_path: "/properties/processContainer/anyOf/0/properties/network/anyOf/0",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "processContainer.network.allowedProxyPeer",
        schema_path: "/properties/processContainer/anyOf/0/properties/network/anyOf/0/properties/allowedProxyPeer",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "processContainer.network.allowedProxyPeer#absent",
        schema_path: "/properties/processContainer/anyOf/0/properties/network/anyOf/0/properties/allowedProxyPeer",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "processContainer.network.allowedProxyPeer#nullable",
        schema_path: "/properties/processContainer/anyOf/0/properties/network/anyOf/0/properties/allowedProxyPeer",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "processContainer.network#anyOf[1]=null",
        schema_path: "/properties/processContainer/anyOf/0/properties/network/anyOf/1",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "processContainer.ui",
        schema_path: "/properties/processContainer/anyOf/0/properties/ui",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "processContainer.ui#absent",
        schema_path: "/properties/processContainer/anyOf/0/properties/ui",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "processContainer.ui#nullable",
        schema_path: "/properties/processContainer/anyOf/0/properties/ui",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "processContainer.ui#anyOf[0]=#/definitions/BaseProcessUi",
        schema_path: "/properties/processContainer/anyOf/0/properties/ui/anyOf/0",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "processContainer.ui.desktopSystemControl",
        schema_path: "/properties/processContainer/anyOf/0/properties/ui/anyOf/0/properties/desktopSystemControl",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "processContainer.ui.desktopSystemControl#absent",
        schema_path: "/properties/processContainer/anyOf/0/properties/ui/anyOf/0/properties/desktopSystemControl",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "processContainer.ui.desktopSystemControl#nullable",
        schema_path: "/properties/processContainer/anyOf/0/properties/ui/anyOf/0/properties/desktopSystemControl",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "processContainer.ui.ime",
        schema_path: "/properties/processContainer/anyOf/0/properties/ui/anyOf/0/properties/ime",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "processContainer.ui.ime#absent",
        schema_path: "/properties/processContainer/anyOf/0/properties/ui/anyOf/0/properties/ime",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "processContainer.ui.ime#nullable",
        schema_path: "/properties/processContainer/anyOf/0/properties/ui/anyOf/0/properties/ime",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "processContainer.ui.isolation",
        schema_path: "/properties/processContainer/anyOf/0/properties/ui/anyOf/0/properties/isolation",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "processContainer.ui.isolation#absent",
        schema_path: "/properties/processContainer/anyOf/0/properties/ui/anyOf/0/properties/isolation",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "processContainer.ui.isolation#nullable",
        schema_path: "/properties/processContainer/anyOf/0/properties/ui/anyOf/0/properties/isolation",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "processContainer.ui.isolation#anyOf[0]=#/definitions/UiIsolation",
        schema_path: "/properties/processContainer/anyOf/0/properties/ui/anyOf/0/properties/isolation/anyOf/0",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "processContainer.ui.isolation#enum=desktop",
        schema_path: "/properties/processContainer/anyOf/0/properties/ui/anyOf/0/properties/isolation/anyOf/0/enum/0",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "processContainer.ui.isolation#enum=handles",
        schema_path: "/properties/processContainer/anyOf/0/properties/ui/anyOf/0/properties/isolation/anyOf/0/enum/1",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "processContainer.ui.isolation#enum=atoms",
        schema_path: "/properties/processContainer/anyOf/0/properties/ui/anyOf/0/properties/isolation/anyOf/0/enum/2",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "processContainer.ui.isolation#enum=container",
        schema_path: "/properties/processContainer/anyOf/0/properties/ui/anyOf/0/properties/isolation/anyOf/0/enum/3",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "processContainer.ui.isolation#anyOf[1]=null",
        schema_path: "/properties/processContainer/anyOf/0/properties/ui/anyOf/0/properties/isolation/anyOf/1",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "processContainer.ui.systemSettings",
        schema_path: "/properties/processContainer/anyOf/0/properties/ui/anyOf/0/properties/systemSettings",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "processContainer.ui.systemSettings#absent",
        schema_path: "/properties/processContainer/anyOf/0/properties/ui/anyOf/0/properties/systemSettings",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "processContainer.ui.systemSettings#nullable",
        schema_path: "/properties/processContainer/anyOf/0/properties/ui/anyOf/0/properties/systemSettings",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "processContainer.ui#anyOf[1]=null",
        schema_path: "/properties/processContainer/anyOf/0/properties/ui/anyOf/1",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "processContainer#anyOf[1]=null",
        schema_path: "/properties/processContainer/anyOf/1",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "runtimeConfig",
        schema_path: "/properties/runtimeConfig",
        disposition: PolicyDisposition::Honored,
        phases: PHASES_EXEC,
        evidence: EVIDENCE_LOCAL_LINUX_RUNTIME,
        reason: REASON_HONORED_EXEC,
    },
    CatalogEntry {
        key: "runtimeConfig#absent",
        schema_path: "/properties/runtimeConfig",
        disposition: PolicyDisposition::Honored,
        phases: PHASES_EXEC,
        evidence: EVIDENCE_LOCAL_LINUX_RUNTIME,
        reason: REASON_HONORED_EXEC,
    },
    CatalogEntry {
        key: "runtimeConfig#nullable",
        schema_path: "/properties/runtimeConfig",
        disposition: PolicyDisposition::Honored,
        phases: PHASES_EXEC,
        evidence: EVIDENCE_LOCAL_LINUX_RUNTIME,
        reason: REASON_HONORED_EXEC,
    },
    CatalogEntry {
        key: "runtimeConfig#anyOf[0]=#/definitions/RuntimeConfig",
        schema_path: "/properties/runtimeConfig/anyOf/0",
        disposition: PolicyDisposition::Honored,
        phases: PHASES_EXEC,
        evidence: EVIDENCE_LOCAL_LINUX_RUNTIME,
        reason: REASON_HONORED_EXEC,
    },
    CatalogEntry {
        key: "runtimeConfig.networkProxy",
        schema_path: "/properties/runtimeConfig/anyOf/0/properties/networkProxy",
        disposition: PolicyDisposition::Honored,
        phases: PHASES_EXEC,
        evidence: EVIDENCE_LOCAL_LINUX_RUNTIME,
        reason: REASON_HONORED_EXEC,
    },
    CatalogEntry {
        key: "runtimeConfig.networkProxy#absent",
        schema_path: "/properties/runtimeConfig/anyOf/0/properties/networkProxy",
        disposition: PolicyDisposition::Honored,
        phases: PHASES_EXEC,
        evidence: EVIDENCE_LOCAL_LINUX_RUNTIME,
        reason: REASON_HONORED_EXEC,
    },
    CatalogEntry {
        key: "runtimeConfig.networkProxy#nullable",
        schema_path: "/properties/runtimeConfig/anyOf/0/properties/networkProxy",
        disposition: PolicyDisposition::Honored,
        phases: PHASES_EXEC,
        evidence: EVIDENCE_LOCAL_LINUX_RUNTIME,
        reason: REASON_HONORED_EXEC,
    },
    CatalogEntry {
        key: "runtimeConfig#anyOf[1]=null",
        schema_path: "/properties/runtimeConfig/anyOf/1",
        disposition: PolicyDisposition::Honored,
        phases: PHASES_EXEC,
        evidence: EVIDENCE_LOCAL_LINUX_RUNTIME,
        reason: REASON_HONORED_EXEC,
    },
    CatalogEntry {
        key: "sandboxId",
        schema_path: "/properties/sandboxId",
        disposition: PolicyDisposition::Control,
        phases: PHASES_ALL,
        evidence: EVIDENCE_LIVE_WHP_POS_NEG,
        reason: REASON_CONTROL,
    },
    CatalogEntry {
        key: "sandboxId#absent",
        schema_path: "/properties/sandboxId",
        disposition: PolicyDisposition::Control,
        phases: PHASES_ALL,
        evidence: EVIDENCE_LIVE_WHP_POS_NEG,
        reason: REASON_CONTROL,
    },
    CatalogEntry {
        key: "sandboxId#nullable",
        schema_path: "/properties/sandboxId",
        disposition: PolicyDisposition::Control,
        phases: PHASES_ALL,
        evidence: EVIDENCE_LIVE_WHP_POS_NEG,
        reason: REASON_CONTROL,
    },
    CatalogEntry {
        key: "seatbelt",
        schema_path: "/properties/seatbelt",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "seatbelt#absent",
        schema_path: "/properties/seatbelt",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "seatbelt#nullable",
        schema_path: "/properties/seatbelt",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "seatbelt#anyOf[0]=#/definitions/Seatbelt",
        schema_path: "/properties/seatbelt/anyOf/0",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "seatbelt.extraMachLookups",
        schema_path: "/properties/seatbelt/anyOf/0/properties/extraMachLookups",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "seatbelt.extraMachLookups#absent",
        schema_path: "/properties/seatbelt/anyOf/0/properties/extraMachLookups",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "seatbelt.extraMachLookups#nullable",
        schema_path: "/properties/seatbelt/anyOf/0/properties/extraMachLookups",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "seatbelt.extraMachLookups[]",
        schema_path: "/properties/seatbelt/anyOf/0/properties/extraMachLookups/items",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "seatbelt.guiAccess",
        schema_path: "/properties/seatbelt/anyOf/0/properties/guiAccess",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "seatbelt.guiAccess#absent",
        schema_path: "/properties/seatbelt/anyOf/0/properties/guiAccess",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "seatbelt.guiAccess#nullable",
        schema_path: "/properties/seatbelt/anyOf/0/properties/guiAccess",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "seatbelt.keychainAccess",
        schema_path: "/properties/seatbelt/anyOf/0/properties/keychainAccess",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "seatbelt.keychainAccess#absent",
        schema_path: "/properties/seatbelt/anyOf/0/properties/keychainAccess",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "seatbelt.keychainAccess#nullable",
        schema_path: "/properties/seatbelt/anyOf/0/properties/keychainAccess",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "seatbelt.launchMethod",
        schema_path: "/properties/seatbelt/anyOf/0/properties/launchMethod",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "seatbelt.launchMethod#absent",
        schema_path: "/properties/seatbelt/anyOf/0/properties/launchMethod",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "seatbelt.launchMethod#nullable",
        schema_path: "/properties/seatbelt/anyOf/0/properties/launchMethod",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "seatbelt.launchMethod#anyOf[0]=#/definitions/LaunchMethod",
        schema_path: "/properties/seatbelt/anyOf/0/properties/launchMethod/anyOf/0",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "seatbelt.launchMethod#oneOf[0]=string",
        schema_path: "/properties/seatbelt/anyOf/0/properties/launchMethod/anyOf/0/oneOf/0",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "seatbelt.launchMethod#enum=exec",
        schema_path: "/properties/seatbelt/anyOf/0/properties/launchMethod/anyOf/0/oneOf/0/enum/0",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "seatbelt.launchMethod#default=exec",
        schema_path: "/properties/seatbelt/anyOf/0/properties/launchMethod/anyOf/0/oneOf/0",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "seatbelt.launchMethod#oneOf[1]=string",
        schema_path: "/properties/seatbelt/anyOf/0/properties/launchMethod/anyOf/0/oneOf/1",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "seatbelt.launchMethod#enum=open",
        schema_path: "/properties/seatbelt/anyOf/0/properties/launchMethod/anyOf/0/oneOf/1/enum/0",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "seatbelt.launchMethod#anyOf[1]=null",
        schema_path: "/properties/seatbelt/anyOf/0/properties/launchMethod/anyOf/1",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "seatbelt.nestedPty",
        schema_path: "/properties/seatbelt/anyOf/0/properties/nestedPty",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "seatbelt.nestedPty#absent",
        schema_path: "/properties/seatbelt/anyOf/0/properties/nestedPty",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "seatbelt.nestedPty#nullable",
        schema_path: "/properties/seatbelt/anyOf/0/properties/nestedPty",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "seatbelt.nestedPty#default=true",
        schema_path: "/properties/seatbelt/anyOf/0/properties/nestedPty",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "seatbelt.profileOverride",
        schema_path: "/properties/seatbelt/anyOf/0/properties/profileOverride",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "seatbelt.profileOverride#absent",
        schema_path: "/properties/seatbelt/anyOf/0/properties/profileOverride",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "seatbelt.profileOverride#nullable",
        schema_path: "/properties/seatbelt/anyOf/0/properties/profileOverride",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "seatbelt#anyOf[1]=null",
        schema_path: "/properties/seatbelt/anyOf/1",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "telemetry",
        schema_path: "/properties/telemetry",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "telemetry#absent",
        schema_path: "/properties/telemetry",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "telemetry#nullable",
        schema_path: "/properties/telemetry",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "telemetry#anyOf[0]=#/definitions/Telemetry",
        schema_path: "/properties/telemetry/anyOf/0",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "telemetry.enabled",
        schema_path: "/properties/telemetry/anyOf/0/properties/enabled",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "telemetry.enabled#absent",
        schema_path: "/properties/telemetry/anyOf/0/properties/enabled",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "telemetry.enabled#nullable",
        schema_path: "/properties/telemetry/anyOf/0/properties/enabled",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "telemetry.enabled#default=off",
        schema_path: "/properties/telemetry/anyOf/0/properties/enabled",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "telemetry#anyOf[1]=null",
        schema_path: "/properties/telemetry/anyOf/1",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "ui",
        schema_path: "/properties/ui",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "ui#absent",
        schema_path: "/properties/ui",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "ui#nullable",
        schema_path: "/properties/ui",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "ui#anyOf[0]=#/definitions/Ui",
        schema_path: "/properties/ui/anyOf/0",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "ui.clipboard",
        schema_path: "/properties/ui/anyOf/0/properties/clipboard",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "ui.clipboard#absent",
        schema_path: "/properties/ui/anyOf/0/properties/clipboard",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "ui.clipboard#nullable",
        schema_path: "/properties/ui/anyOf/0/properties/clipboard",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "ui.clipboard#anyOf[0]=#/definitions/ClipboardPolicy",
        schema_path: "/properties/ui/anyOf/0/properties/clipboard/anyOf/0",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "ui.clipboard#enum=none",
        schema_path: "/properties/ui/anyOf/0/properties/clipboard/anyOf/0/enum/0",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "ui.clipboard#enum=read",
        schema_path: "/properties/ui/anyOf/0/properties/clipboard/anyOf/0/enum/1",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "ui.clipboard#enum=write",
        schema_path: "/properties/ui/anyOf/0/properties/clipboard/anyOf/0/enum/2",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "ui.clipboard#enum=all",
        schema_path: "/properties/ui/anyOf/0/properties/clipboard/anyOf/0/enum/3",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "ui.clipboard#anyOf[1]=null",
        schema_path: "/properties/ui/anyOf/0/properties/clipboard/anyOf/1",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "ui.disable",
        schema_path: "/properties/ui/anyOf/0/properties/disable",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "ui.disable#absent",
        schema_path: "/properties/ui/anyOf/0/properties/disable",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "ui.disable#nullable",
        schema_path: "/properties/ui/anyOf/0/properties/disable",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "ui.disable#default=true",
        schema_path: "/properties/ui/anyOf/0/properties/disable",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "ui.injection",
        schema_path: "/properties/ui/anyOf/0/properties/injection",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "ui.injection#absent",
        schema_path: "/properties/ui/anyOf/0/properties/injection",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "ui.injection#nullable",
        schema_path: "/properties/ui/anyOf/0/properties/injection",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "ui#anyOf[1]=null",
        schema_path: "/properties/ui/anyOf/1",
        disposition: PolicyDisposition::Rejected,
        phases: PHASES_ALL,
        evidence: EVIDENCE_UNIT_STATIC,
        reason: REASON_REJECTED,
    },
    CatalogEntry {
        key: "version",
        schema_path: "/properties/version",
        disposition: PolicyDisposition::Control,
        phases: PHASES_ALL,
        evidence: EVIDENCE_LIVE_WHP_POS_NEG,
        reason: REASON_CONTROL,
    },
    CatalogEntry {
        key: "version#absent",
        schema_path: "/properties/version",
        disposition: PolicyDisposition::Control,
        phases: PHASES_ALL,
        evidence: EVIDENCE_LIVE_WHP_POS_NEG,
        reason: REASON_CONTROL,
    },
    CatalogEntry {
        key: "version#nullable",
        schema_path: "/properties/version",
        disposition: PolicyDisposition::Control,
        phases: PHASES_ALL,
        evidence: EVIDENCE_LIVE_WHP_POS_NEG,
        reason: REASON_CONTROL,
    },
    CatalogEntry {
        key: "cross.phase.non_provision_requires_sandbox_id",
        schema_path: "/properties/phase",
        disposition: PolicyDisposition::Control,
        phases: PHASES_NON_PROVISION,
        evidence: EVIDENCE_LIVE_WHP_POS_NEG,
        reason: REASON_CROSS_FIELD_CONTROL,
    },
    CatalogEntry {
        key: "cross.phase.exec_uses_process_fields",
        schema_path: "/properties/process",
        disposition: PolicyDisposition::Honored,
        phases: PHASES_EXEC,
        evidence: EVIDENCE_LOCAL_LINUX_RUNTIME,
        reason: REASON_CROSS_FIELD_EXEC,
    },
    CatalogEntry {
        key: "cross.phase.provision_uses_filesystem_rw_and_network_allow_block",
        schema_path: "/properties/filesystem",
        disposition: PolicyDisposition::Honored,
        phases: PHASES_PROVISION,
        evidence: EVIDENCE_LIVE_WHP_POS_NEG,
        reason: REASON_CROSS_FIELD_PROVISION,
    },
    CatalogEntry {
        key: "cross.phase.exec_uses_runtime_config_network_proxy",
        schema_path: "/properties/runtimeConfig/anyOf/0/properties/networkProxy",
        disposition: PolicyDisposition::Honored,
        phases: PHASES_EXEC,
        evidence: EVIDENCE_LOCAL_LINUX_RUNTIME,
        reason: REASON_CROSS_FIELD_EXEC,
    },
];

pub fn catalog_entries() -> &'static [CatalogEntry] {
    CATALOG
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeMap, BTreeSet};

    use serde_json::Value;

    const SCHEMA_BYTES: &[u8] = include_bytes!("../../schemas/mxc-config.schema.0.9.0-dev.json");

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum InventoryKind {
        Path,
        Enum,
        Union,
        PresenceOrDefault,
    }

    #[derive(Clone, Debug)]
    struct InventoryEntry {
        key: String,
        schema_path: String,
        kind: InventoryKind,
    }

    #[test]
    fn catalog_paths_match_schema_inventory() {
        let inventory = derive_schema_inventory();
        assert_catalog_subset_matches(
            inventory
                .iter()
                .filter(|entry| entry.kind == InventoryKind::Path),
            "path",
        );
    }

    #[test]
    fn catalog_enums_and_unions_match_schema_inventory() {
        let inventory = derive_schema_inventory();
        assert_catalog_subset_matches(
            inventory.iter().filter(|entry| {
                entry.kind == InventoryKind::Enum || entry.kind == InventoryKind::Union
            }),
            "enum/union",
        );
    }

    #[test]
    fn catalog_presence_and_defaults_match_schema_inventory() {
        let inventory = derive_schema_inventory();
        assert_catalog_subset_matches(
            inventory
                .iter()
                .filter(|entry| entry.kind == InventoryKind::PresenceOrDefault),
            "presence/default",
        );
    }

    #[test]
    fn catalog_contains_required_cross_field_rules() {
        let required = BTreeSet::from([
            "cross.phase.non_provision_requires_sandbox_id",
            "cross.phase.exec_uses_process_fields",
            "cross.phase.provision_uses_filesystem_rw_and_network_allow_block",
            "cross.phase.exec_uses_runtime_config_network_proxy",
        ]);
        let actual = CATALOG
            .iter()
            .filter(|entry| entry.key.starts_with("cross."))
            .map(|entry| entry.key)
            .collect::<BTreeSet<_>>();
        assert_missing_unexpected(&required, &actual, "cross-field");
    }

    #[test]
    fn catalog_keys_are_unique() {
        collect_catalog_map(
            CATALOG
                .iter()
                .map(|entry| (entry.key.to_string(), entry.schema_path.to_string())),
            "complete",
        );
    }

    #[test]
    fn semantic_contract_inert_annotations_is_exact() {
        assert_group_contract(
            "inert annotations",
            string_set([
                "$schema",
                "$schema#absent",
                "$schema#nullable",
                "_comment",
                "_comment#absent",
            ]),
            |key| {
                key == "$schema"
                    || key.starts_with("$schema#")
                    || key == "_comment"
                    || key.starts_with("_comment#")
            },
            PolicyDisposition::AcceptedInert,
            PHASES_ALL,
            EVIDENCE_UNIT_STATIC,
            REASON_ACCEPTED_INERT,
        );
    }

    #[test]
    fn semantic_contract_control_fields_is_exact() {
        let expected_keys = schema_inventory_keys_for_prefixes(&[
            "containerId",
            "containment",
            "phase",
            "sandboxId",
            "version",
        ]);
        assert_group_contract(
            "control fields",
            expected_keys,
            |key| {
                key == "containerId"
                    || key.starts_with("containerId#")
                    || key == "containment"
                    || key.starts_with("containment#")
                    || key == "phase"
                    || key.starts_with("phase#")
                    || key == "sandboxId"
                    || key.starts_with("sandboxId#")
                    || key == "version"
                    || key.starts_with("version#")
            },
            PolicyDisposition::Control,
            PHASES_ALL,
            EVIDENCE_LIVE_WHP_POS_NEG,
            REASON_CONTROL,
        );
        assert_group_contract(
            "cross control",
            string_set(["cross.phase.non_provision_requires_sandbox_id"]),
            |key| key == "cross.phase.non_provision_requires_sandbox_id",
            PolicyDisposition::Control,
            PHASES_NON_PROVISION,
            EVIDENCE_LIVE_WHP_POS_NEG,
            REASON_CROSS_FIELD_CONTROL,
        );
    }

    #[test]
    fn semantic_contract_honored_provision_filesystem_and_network_allow_block_is_exact() {
        assert_group_contract(
            "honored provision structural filesystem",
            string_set([
                "filesystem",
                "filesystem#absent",
                "filesystem#nullable",
                "filesystem#anyOf[0]=#/definitions/Filesystem",
                "filesystem#anyOf[1]=null",
            ]),
            |key| {
                key == "filesystem"
                    || key == "filesystem#absent"
                    || key == "filesystem#nullable"
                    || key == "filesystem#anyOf[0]=#/definitions/Filesystem"
                    || key == "filesystem#anyOf[1]=null"
            },
            PolicyDisposition::Honored,
            PHASES_PROVISION,
            EVIDENCE_LOCAL_LINUX_RUNTIME,
            REASON_HONORED_PROVISION,
        );
        assert_group_contract(
            "honored provision filesystem ro-rw",
            string_set([
                "filesystem.readonlyPaths",
                "filesystem.readonlyPaths#absent",
                "filesystem.readonlyPaths#nullable",
                "filesystem.readonlyPaths[]",
                "filesystem.readwritePaths",
                "filesystem.readwritePaths#absent",
                "filesystem.readwritePaths#nullable",
                "filesystem.readwritePaths[]",
            ]),
            |key| {
                key.starts_with("filesystem.readonlyPaths")
                    || key.starts_with("filesystem.readwritePaths")
            },
            PolicyDisposition::Honored,
            PHASES_PROVISION,
            EVIDENCE_LOCAL_LINUX_RUNTIME,
            REASON_HONORED_PROVISION,
        );
        assert_group_contract(
            "honored provision structural network",
            string_set([
                "network",
                "network#absent",
                "network#nullable",
                "network#anyOf[0]=#/definitions/Network",
                "network#anyOf[1]=null",
            ]),
            |key| {
                key == "network"
                    || key == "network#absent"
                    || key == "network#nullable"
                    || key == "network#anyOf[0]=#/definitions/Network"
                    || key == "network#anyOf[1]=null"
            },
            PolicyDisposition::Honored,
            PHASES_PROVISION,
            EVIDENCE_LIVE_WHP_POS_NEG,
            REASON_HONORED_PROVISION,
        );
        assert_group_contract(
            "honored provision network allow-block",
            string_set([
                "network.allowedHosts",
                "network.allowedHosts#absent",
                "network.allowedHosts#nullable",
                "network.allowedHosts[]",
                "network.blockedHosts",
                "network.blockedHosts#absent",
                "network.blockedHosts#nullable",
                "network.blockedHosts[]",
                "network.defaultPolicy",
                "network.defaultPolicy#absent",
                "network.defaultPolicy#nullable",
                "network.defaultPolicy#anyOf[0]=#/definitions/NetworkPolicy",
                "network.defaultPolicy#enum=allow",
                "network.defaultPolicy#enum=block",
                "network.defaultPolicy#anyOf[1]=null",
            ]),
            |key| {
                key.starts_with("network.allowedHosts")
                    || key.starts_with("network.blockedHosts")
                    || key.starts_with("network.defaultPolicy")
            },
            PolicyDisposition::Honored,
            PHASES_PROVISION,
            EVIDENCE_LIVE_WHP_POS_NEG,
            REASON_HONORED_PROVISION,
        );
        assert_group_contract(
            "cross provision",
            string_set(["cross.phase.provision_uses_filesystem_rw_and_network_allow_block"]),
            |key| key == "cross.phase.provision_uses_filesystem_rw_and_network_allow_block",
            PolicyDisposition::Honored,
            PHASES_PROVISION,
            EVIDENCE_LIVE_WHP_POS_NEG,
            REASON_CROSS_FIELD_PROVISION,
        );
    }

    #[test]
    fn semantic_contract_honored_exec_surface_is_exact() {
        assert_group_contract(
            "honored exec structural process/runtimeConfig",
            string_set([
                "process",
                "process#absent",
                "process#nullable",
                "process#anyOf[0]=#/definitions/Process",
                "process#anyOf[1]=null",
                "runtimeConfig",
                "runtimeConfig#absent",
                "runtimeConfig#nullable",
                "runtimeConfig#anyOf[0]=#/definitions/RuntimeConfig",
                "runtimeConfig#anyOf[1]=null",
            ]),
            |key| {
                key == "process"
                    || key == "process#absent"
                    || key == "process#nullable"
                    || key == "process#anyOf[0]=#/definitions/Process"
                    || key == "process#anyOf[1]=null"
                    || key == "runtimeConfig"
                    || key == "runtimeConfig#absent"
                    || key == "runtimeConfig#nullable"
                    || key == "runtimeConfig#anyOf[0]=#/definitions/RuntimeConfig"
                    || key == "runtimeConfig#anyOf[1]=null"
            },
            PolicyDisposition::Honored,
            PHASES_EXEC,
            EVIDENCE_LOCAL_LINUX_RUNTIME,
            REASON_HONORED_EXEC,
        );
        assert_group_contract(
            "honored exec surface",
            string_set([
                "process.commandLine",
                "process.commandLine#absent",
                "process.commandLine#nullable",
                "process.cwd",
                "process.cwd#absent",
                "process.cwd#nullable",
                "process.env",
                "process.env#absent",
                "process.env#nullable",
                "process.env[]",
                "process.timeout",
                "process.timeout#absent",
                "process.timeout#nullable",
                "runtimeConfig.networkProxy",
                "runtimeConfig.networkProxy#absent",
                "runtimeConfig.networkProxy#nullable",
            ]),
            |key| {
                key.starts_with("process.commandLine")
                    || key.starts_with("process.cwd")
                    || key.starts_with("process.env")
                    || key.starts_with("process.timeout")
                    || key == "runtimeConfig.networkProxy"
                    || key.starts_with("runtimeConfig.networkProxy#")
            },
            PolicyDisposition::Honored,
            PHASES_EXEC,
            EVIDENCE_LOCAL_LINUX_RUNTIME,
            REASON_HONORED_EXEC,
        );
        assert_group_contract(
            "cross exec",
            string_set([
                "cross.phase.exec_uses_process_fields",
                "cross.phase.exec_uses_runtime_config_network_proxy",
            ]),
            |key| {
                key == "cross.phase.exec_uses_process_fields"
                    || key == "cross.phase.exec_uses_runtime_config_network_proxy"
            },
            PolicyDisposition::Honored,
            PHASES_EXEC,
            EVIDENCE_LOCAL_LINUX_RUNTIME,
            REASON_CROSS_FIELD_EXEC,
        );
    }

    #[test]
    fn semantic_contract_rejected_surfaces_are_exact() {
        assert_group_contract(
            "rejected filesystem deniedPaths",
            string_set([
                "filesystem.deniedPaths",
                "filesystem.deniedPaths#absent",
                "filesystem.deniedPaths#nullable",
                "filesystem.deniedPaths[]",
            ]),
            |key| {
                key == "filesystem.deniedPaths"
                    || key.starts_with("filesystem.deniedPaths#")
                    || key == "filesystem.deniedPaths[]"
            },
            PolicyDisposition::Rejected,
            PHASES_ALL,
            EVIDENCE_UNIT_STATIC,
            REASON_REJECTED,
        );
        let expected_rejected_directional_network =
            schema_inventory_keys_for_prefixes(&["network.egress", "network.ingress"]);
        assert_group_contract(
            "rejected directional network ingress-egress",
            expected_rejected_directional_network,
            |key| {
                key == "network.egress"
                    || key.starts_with("network.egress.")
                    || key.starts_with("network.egress#")
                    || key == "network.ingress"
                    || key.starts_with("network.ingress.")
                    || key.starts_with("network.ingress#")
            },
            PolicyDisposition::Rejected,
            PHASES_ALL,
            EVIDENCE_UNIT_STATIC,
            REASON_REJECTED,
        );
        let expected_rejected_network_backend_specific = schema_inventory_keys_for_prefixes(&[
            "network.allowLocalNetwork",
            "network.enforcementMode",
            "processContainer.network",
        ]);
        assert_group_contract(
            "rejected network container-backend-specific",
            expected_rejected_network_backend_specific,
            |key| {
                key == "network.allowLocalNetwork"
                    || key.starts_with("network.allowLocalNetwork#")
                    || key == "network.enforcementMode"
                    || key.starts_with("network.enforcementMode#")
                    || key == "processContainer.network"
                    || key.starts_with("processContainer.network.")
                    || key.starts_with("processContainer.network#")
            },
            PolicyDisposition::Rejected,
            PHASES_ALL,
            EVIDENCE_UNIT_STATIC,
            REASON_REJECTED,
        );
        assert_group_contract(
            "rejected network.proxy",
            string_set([
                "network.proxy",
                "network.proxy#absent",
                "network.proxy#nullable",
                "network.proxy#anyOf[0]=#/definitions/Proxy",
                "network.proxy.builtinTestServer",
                "network.proxy.builtinTestServer#absent",
                "network.proxy.builtinTestServer#nullable",
                "network.proxy.localhost",
                "network.proxy.localhost#absent",
                "network.proxy.localhost#nullable",
                "network.proxy.url",
                "network.proxy.url#absent",
                "network.proxy.url#nullable",
                "network.proxy#anyOf[1]=null",
            ]),
            |key| {
                key == "network.proxy"
                    || key.starts_with("network.proxy.")
                    || key.starts_with("network.proxy#")
            },
            PolicyDisposition::Rejected,
            PHASES_ALL,
            EVIDENCE_UNIT_STATIC,
            REASON_REJECTED,
        );
        assert_group_contract(
            "rejected telemetry",
            string_set([
                "telemetry",
                "telemetry#absent",
                "telemetry#nullable",
                "telemetry#anyOf[0]=#/definitions/Telemetry",
                "telemetry.enabled",
                "telemetry.enabled#absent",
                "telemetry.enabled#nullable",
                "telemetry.enabled#default=off",
                "telemetry#anyOf[1]=null",
            ]),
            |key| {
                key == "telemetry" || key.starts_with("telemetry.") || key.starts_with("telemetry#")
            },
            PolicyDisposition::Rejected,
            PHASES_ALL,
            EVIDENCE_UNIT_STATIC,
            REASON_REJECTED,
        );
        assert_group_contract(
            "rejected lifecycle",
            string_set([
                "lifecycle",
                "lifecycle#absent",
                "lifecycle#nullable",
                "lifecycle#anyOf[0]=#/definitions/Lifecycle",
                "lifecycle.destroyOnExit",
                "lifecycle.destroyOnExit#absent",
                "lifecycle.destroyOnExit#nullable",
                "lifecycle.destroyOnExit#default=true",
                "lifecycle.preservePolicy",
                "lifecycle.preservePolicy#absent",
                "lifecycle.preservePolicy#nullable",
                "lifecycle.preservePolicy#default=false",
                "lifecycle#anyOf[1]=null",
            ]),
            |key| {
                key == "lifecycle" || key.starts_with("lifecycle.") || key.starts_with("lifecycle#")
            },
            PolicyDisposition::Rejected,
            PHASES_ALL,
            EVIDENCE_UNIT_STATIC,
            REASON_REJECTED,
        );
        let expected_rejected_unsupported_backend = schema_inventory_keys_for_prefixes(&[
            "experimental",
            "fallback",
            "lxc",
            "processContainer",
            "seatbelt",
            "ui",
        ])
        .into_iter()
        .filter(|key| !is_process_container_network_key(key))
        .collect::<BTreeSet<_>>();
        assert_group_contract(
            "rejected unsupported/backend",
            expected_rejected_unsupported_backend,
            |key| {
                key == "experimental"
                    || key.starts_with("experimental.")
                    || key.starts_with("experimental#")
                    || key == "fallback"
                    || key.starts_with("fallback.")
                    || key.starts_with("fallback#")
                    || key == "lxc"
                    || key.starts_with("lxc.")
                    || key.starts_with("lxc#")
                    || key == "processContainer"
                    || (key.starts_with("processContainer.")
                        && !is_process_container_network_key(key))
                    || (key.starts_with("processContainer#")
                        && !is_process_container_network_key(key))
                    || key == "seatbelt"
                    || key.starts_with("seatbelt.")
                    || key.starts_with("seatbelt#")
                    || key == "ui"
                    || key.starts_with("ui.")
                    || key.starts_with("ui#")
            },
            PolicyDisposition::Rejected,
            PHASES_ALL,
            EVIDENCE_UNIT_STATIC,
            REASON_REJECTED,
        );
    }

    #[test]
    fn semantic_contract_groups_are_exhaustive_and_disjoint() {
        type GroupMatcher = (&'static str, fn(&str) -> bool);
        let groups: [GroupMatcher; 18] = [
            ("inert annotations", |key| {
                key == "$schema"
                    || key.starts_with("$schema#")
                    || key == "_comment"
                    || key.starts_with("_comment#")
            }),
            ("control fields", |key| {
                key == "containerId"
                    || key.starts_with("containerId#")
                    || key == "containment"
                    || key.starts_with("containment#")
                    || key == "phase"
                    || key.starts_with("phase#")
                    || key == "sandboxId"
                    || key.starts_with("sandboxId#")
                    || key == "version"
                    || key.starts_with("version#")
            }),
            ("cross control", |key| {
                key == "cross.phase.non_provision_requires_sandbox_id"
            }),
            ("honored provision structural filesystem", |key| {
                key == "filesystem"
                    || key == "filesystem#absent"
                    || key == "filesystem#nullable"
                    || key == "filesystem#anyOf[0]=#/definitions/Filesystem"
                    || key == "filesystem#anyOf[1]=null"
            }),
            ("honored provision filesystem ro-rw", |key| {
                key.starts_with("filesystem.readonlyPaths")
                    || key.starts_with("filesystem.readwritePaths")
            }),
            ("rejected filesystem deniedPaths", |key| {
                key == "filesystem.deniedPaths"
                    || key.starts_with("filesystem.deniedPaths#")
                    || key == "filesystem.deniedPaths[]"
            }),
            ("honored provision structural network", |key| {
                key == "network"
                    || key == "network#absent"
                    || key == "network#nullable"
                    || key == "network#anyOf[0]=#/definitions/Network"
                    || key == "network#anyOf[1]=null"
            }),
            ("honored provision network allow-block", |key| {
                key.starts_with("network.allowedHosts")
                    || key.starts_with("network.blockedHosts")
                    || key.starts_with("network.defaultPolicy")
            }),
            ("cross provision", |key| {
                key == "cross.phase.provision_uses_filesystem_rw_and_network_allow_block"
            }),
            ("honored exec structural process/runtimeConfig", |key| {
                key == "process"
                    || key == "process#absent"
                    || key == "process#nullable"
                    || key == "process#anyOf[0]=#/definitions/Process"
                    || key == "process#anyOf[1]=null"
                    || key == "runtimeConfig"
                    || key == "runtimeConfig#absent"
                    || key == "runtimeConfig#nullable"
                    || key == "runtimeConfig#anyOf[0]=#/definitions/RuntimeConfig"
                    || key == "runtimeConfig#anyOf[1]=null"
            }),
            ("honored exec surface", |key| {
                key.starts_with("process.commandLine")
                    || key.starts_with("process.cwd")
                    || key.starts_with("process.env")
                    || key.starts_with("process.timeout")
                    || key == "runtimeConfig.networkProxy"
                    || key.starts_with("runtimeConfig.networkProxy#")
            }),
            ("cross exec", |key| {
                key == "cross.phase.exec_uses_process_fields"
                    || key == "cross.phase.exec_uses_runtime_config_network_proxy"
            }),
            ("rejected directional network ingress-egress", |key| {
                key == "network.egress"
                    || key.starts_with("network.egress.")
                    || key.starts_with("network.egress#")
                    || key == "network.ingress"
                    || key.starts_with("network.ingress.")
                    || key.starts_with("network.ingress#")
            }),
            ("rejected network container-backend-specific", |key| {
                key == "network.allowLocalNetwork"
                    || key.starts_with("network.allowLocalNetwork#")
                    || key == "network.enforcementMode"
                    || key.starts_with("network.enforcementMode#")
                    || key == "processContainer.network"
                    || key.starts_with("processContainer.network.")
                    || key.starts_with("processContainer.network#")
            }),
            ("rejected network.proxy", |key| {
                key == "network.proxy"
                    || key.starts_with("network.proxy.")
                    || key.starts_with("network.proxy#")
            }),
            ("rejected telemetry", |key| {
                key == "telemetry" || key.starts_with("telemetry.") || key.starts_with("telemetry#")
            }),
            ("rejected lifecycle", |key| {
                key == "lifecycle" || key.starts_with("lifecycle.") || key.starts_with("lifecycle#")
            }),
            ("rejected unsupported/backend", |key| {
                key == "experimental"
                    || key.starts_with("experimental.")
                    || key.starts_with("experimental#")
                    || key == "fallback"
                    || key.starts_with("fallback.")
                    || key.starts_with("fallback#")
                    || key == "lxc"
                    || key.starts_with("lxc.")
                    || key.starts_with("lxc#")
                    || key == "processContainer"
                    || (key.starts_with("processContainer.")
                        && !is_process_container_network_key(key))
                    || (key.starts_with("processContainer#")
                        && !is_process_container_network_key(key))
                    || key == "seatbelt"
                    || key.starts_with("seatbelt.")
                    || key.starts_with("seatbelt#")
                    || key == "ui"
                    || key.starts_with("ui.")
                    || key.starts_with("ui#")
            }),
        ];

        for entry in CATALOG {
            let matching = groups
                .iter()
                .filter_map(|(label, belongs_to_group)| {
                    belongs_to_group(entry.key).then_some(*label)
                })
                .collect::<Vec<_>>();
            assert_eq!(
                matching.len(),
                1,
                "semantic coverage drift for {}: expected exactly one group, got [{}]",
                entry.key,
                matching.join(", ")
            );
        }
    }

    fn assert_group_contract(
        label: &str,
        expected_keys: BTreeSet<String>,
        belongs_to_group: impl Fn(&str) -> bool,
        expected_disposition: PolicyDisposition,
        expected_phases: &'static [MxcPhase],
        expected_evidence: EvidenceRequirement,
        expected_reason: &'static str,
    ) {
        let actual_keys = CATALOG
            .iter()
            .filter(|entry| belongs_to_group(entry.key))
            .map(|entry| entry.key.to_string())
            .collect::<BTreeSet<_>>();
        assert_missing_unexpected(&expected_keys, &actual_keys, label);

        for key in expected_keys {
            let entry = CATALOG
                .iter()
                .find(|entry| entry.key == key.as_str())
                .expect("expected key exists");
            assert_eq!(
                entry.disposition, expected_disposition,
                "{label}: {key} disposition drifted"
            );
            assert_eq!(
                entry.phases, expected_phases,
                "{label}: {key} phases drifted"
            );
            assert_eq!(
                entry.evidence, expected_evidence,
                "{label}: {key} evidence drifted"
            );
            assert_eq!(
                entry.reason, expected_reason,
                "{label}: {key} reason drifted"
            );
        }
    }

    fn schema_inventory_keys_for_prefixes(prefixes: &[&str]) -> BTreeSet<String> {
        derive_schema_inventory()
            .into_iter()
            .map(|entry| entry.key)
            .filter(|key| {
                prefixes.iter().any(|prefix| {
                    key == prefix
                        || key.starts_with(&format!("{prefix}."))
                        || key.starts_with(&format!("{prefix}#"))
                })
            })
            .collect::<BTreeSet<_>>()
    }

    fn string_set<const N: usize>(values: [&str; N]) -> BTreeSet<String> {
        values
            .into_iter()
            .map(str::to_string)
            .collect::<BTreeSet<_>>()
    }

    fn assert_catalog_subset_matches<'a>(
        expected: impl Iterator<Item = &'a InventoryEntry>,
        label: &str,
    ) {
        let expected_map = collect_inventory_map(
            expected.map(|entry| (entry.key.clone(), entry.schema_path.clone(), entry.kind)),
            label,
        );
        let actual_map = collect_catalog_map(
            CATALOG
                .iter()
                .filter(|entry| !entry.key.starts_with("cross."))
                .filter(|entry| match label {
                    "path" => !entry.key.contains('#'),
                    "enum/union" => {
                        entry.key.contains("#enum=")
                            || entry.key.contains("#anyOf[")
                            || entry.key.contains("#oneOf[")
                    }
                    "presence/default" => {
                        entry.key.contains("#absent")
                            || entry.key.contains("#nullable")
                            || entry.key.contains("#default=")
                    }
                    _ => false,
                })
                .map(|entry| (entry.key.to_string(), entry.schema_path.to_string())),
            label,
        );

        let expected_keys = expected_map.keys().cloned().collect::<BTreeSet<_>>();
        let actual_keys = actual_map.keys().cloned().collect::<BTreeSet<_>>();
        assert_missing_unexpected(&expected_keys, &actual_keys, label);

        let pointer_mismatches = expected_map
            .iter()
            .filter_map(|(key, expected_path)| {
                let actual_path = actual_map.get(key)?;
                if actual_path == expected_path {
                    return None;
                }
                Some(format!("{key} expected {expected_path} got {actual_path}"))
            })
            .collect::<Vec<_>>();
        assert!(
            pointer_mismatches.is_empty(),
            "{label} schema path mismatches ({}):\n{}",
            pointer_mismatches.len(),
            pointer_mismatches.join("\n")
        );
    }

    fn assert_missing_unexpected(
        expected: &BTreeSet<impl AsRef<str>>,
        actual: &BTreeSet<impl AsRef<str>>,
        label: &str,
    ) {
        let expected_keys = expected.iter().map(AsRef::as_ref).collect::<BTreeSet<_>>();
        let actual_keys = actual.iter().map(AsRef::as_ref).collect::<BTreeSet<_>>();
        let missing = expected_keys
            .difference(&actual_keys)
            .copied()
            .collect::<Vec<_>>();
        let unexpected = actual_keys
            .difference(&expected_keys)
            .copied()
            .collect::<Vec<_>>();
        assert!(
            missing.is_empty() && unexpected.is_empty(),
            "{label} inventory drift detected. missing: [{}] unexpected: [{}]",
            missing.join(", "),
            unexpected.join(", ")
        );
    }

    fn derive_schema_inventory() -> Vec<InventoryEntry> {
        let schema: Value = serde_json::from_slice(SCHEMA_BYTES).expect("schema JSON parses");
        let definitions = schema
            .get("definitions")
            .and_then(Value::as_object)
            .expect("definitions object");

        let mut out = Vec::new();
        let mut seen = BTreeMap::new();
        walk_node(&schema, "", "", definitions, &mut out, &mut seen);
        out
    }

    fn walk_node(
        node: &Value,
        key_prefix: &str,
        schema_path: &str,
        definitions: &serde_json::Map<String, Value>,
        out: &mut Vec<InventoryEntry>,
        seen: &mut BTreeMap<String, (String, InventoryKind)>,
    ) {
        let mut object = match node.as_object() {
            Some(object) => object,
            None => return,
        };
        if let Some(name) = object
            .get("$ref")
            .and_then(Value::as_str)
            .and_then(|reference| reference.strip_prefix("#/definitions/"))
        {
            object = definitions
                .get(name)
                .and_then(Value::as_object)
                .expect("definition exists");
        }
        let resolved_node = Value::Object(object.clone());

        let required = object
            .get("required")
            .and_then(Value::as_array)
            .map(|values| {
                values
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect::<BTreeSet<_>>()
            })
            .unwrap_or_default();

        if let Some(properties) = object.get("properties").and_then(Value::as_object) {
            for (name, property) in properties {
                let key = join_key(key_prefix, name);
                let property_schema_path =
                    join_schema_path(schema_path, &format!("/properties/{name}"));

                push_inventory(out, seen, &key, &property_schema_path, InventoryKind::Path);

                if !required.contains(name) {
                    push_inventory(
                        out,
                        seen,
                        &format!("{key}#absent"),
                        &property_schema_path,
                        InventoryKind::PresenceOrDefault,
                    );
                }

                if allows_null(property) {
                    push_inventory(
                        out,
                        seen,
                        &format!("{key}#nullable"),
                        &property_schema_path,
                        InventoryKind::PresenceOrDefault,
                    );
                }

                if let Some(description) = property.get("description").and_then(Value::as_str) {
                    for default_value in description_defaults(description) {
                        push_inventory(
                            out,
                            seen,
                            &format!("{key}#default={default_value}"),
                            &property_schema_path,
                            InventoryKind::PresenceOrDefault,
                        );
                    }
                }

                if let Some(items) = property.get("items") {
                    let item_key = format!("{key}[]");
                    let item_schema_path = format!("{property_schema_path}/items");
                    push_inventory(out, seen, &item_key, &item_schema_path, InventoryKind::Path);
                    walk_node(items, &item_key, &item_schema_path, definitions, out, seen);
                }

                walk_node(
                    property,
                    &key,
                    &property_schema_path,
                    definitions,
                    out,
                    seen,
                );
            }
        }

        collect_union_entries(
            &resolved_node,
            key_prefix,
            schema_path,
            definitions,
            out,
            seen,
        );
        collect_enum_entries(&resolved_node, key_prefix, schema_path, out, seen);
        collect_default_entries(&resolved_node, key_prefix, schema_path, out, seen);
    }

    fn collect_union_entries(
        node: &Value,
        key_prefix: &str,
        schema_path: &str,
        definitions: &serde_json::Map<String, Value>,
        out: &mut Vec<InventoryEntry>,
        seen: &mut BTreeMap<String, (String, InventoryKind)>,
    ) {
        for union_key in ["anyOf", "oneOf"] {
            let Some(branches) = node.get(union_key).and_then(Value::as_array) else {
                continue;
            };
            for (index, branch) in branches.iter().enumerate() {
                let branch_label = branch
                    .get("$ref")
                    .and_then(Value::as_str)
                    .map(str::to_string)
                    .or_else(|| {
                        branch
                            .get("type")
                            .and_then(Value::as_str)
                            .map(str::to_string)
                    })
                    .unwrap_or_else(|| "unknown".to_string());
                let key = if key_prefix.is_empty() {
                    format!("<root>#{union_key}[{index}]={branch_label}")
                } else {
                    format!("{key_prefix}#{union_key}[{index}]={branch_label}")
                };
                let branch_schema_path =
                    join_schema_path(schema_path, &format!("/{union_key}/{index}"));
                push_inventory(out, seen, &key, &branch_schema_path, InventoryKind::Union);

                walk_node(
                    branch,
                    key_prefix,
                    &branch_schema_path,
                    definitions,
                    out,
                    seen,
                );
            }
        }
    }

    fn collect_enum_entries(
        node: &Value,
        key_prefix: &str,
        schema_path: &str,
        out: &mut Vec<InventoryEntry>,
        seen: &mut BTreeMap<String, (String, InventoryKind)>,
    ) {
        let Some(values) = node.get("enum").and_then(Value::as_array) else {
            return;
        };
        for (index, value) in values.iter().enumerate() {
            let Some(enum_value) = value.as_str() else {
                continue;
            };
            let key = if key_prefix.is_empty() {
                format!("<root>#enum={enum_value}")
            } else {
                format!("{key_prefix}#enum={enum_value}")
            };
            let enum_schema_path = join_schema_path(schema_path, &format!("/enum/{index}"));
            push_inventory(out, seen, &key, &enum_schema_path, InventoryKind::Enum);
        }
    }

    fn collect_default_entries(
        node: &Value,
        key_prefix: &str,
        schema_path: &str,
        out: &mut Vec<InventoryEntry>,
        seen: &mut BTreeMap<String, (String, InventoryKind)>,
    ) {
        let Some(description) = node.get("description").and_then(Value::as_str) else {
            return;
        };
        if !description.contains("(default)") {
            return;
        }
        let Some(default_value) = node
            .get("enum")
            .and_then(Value::as_array)
            .filter(|values| values.len() == 1)
            .and_then(|values| values[0].as_str())
        else {
            return;
        };
        let key = if key_prefix.is_empty() {
            format!("<root>#default={default_value}")
        } else {
            format!("{key_prefix}#default={default_value}")
        };
        push_inventory(
            out,
            seen,
            &key,
            schema_path,
            InventoryKind::PresenceOrDefault,
        );
    }

    fn push_inventory(
        out: &mut Vec<InventoryEntry>,
        seen: &mut BTreeMap<String, (String, InventoryKind)>,
        key: &str,
        schema_path: &str,
        kind: InventoryKind,
    ) {
        if let Some((existing_schema_path, existing_kind)) =
            seen.insert(key.to_string(), (schema_path.to_string(), kind))
        {
            panic!(
                "duplicate schema inventory key {key}: existing path={existing_schema_path} kind={existing_kind:?}, new path={schema_path} kind={kind:?}"
            );
        }
        out.push(InventoryEntry {
            key: key.to_string(),
            schema_path: schema_path.to_string(),
            kind,
        });
    }

    fn join_key(parent: &str, child: &str) -> String {
        if parent.is_empty() {
            return child.to_string();
        }
        format!("{parent}.{child}")
    }

    fn join_schema_path(parent: &str, suffix: &str) -> String {
        if parent.is_empty() {
            return suffix.to_string();
        }
        format!("{parent}{suffix}")
    }

    fn allows_null(node: &Value) -> bool {
        if let Some(types) = node.get("type").and_then(Value::as_array)
            && types.iter().any(|value| value.as_str() == Some("null"))
        {
            return true;
        }

        for union_key in ["anyOf", "oneOf"] {
            let Some(branches) = node.get(union_key).and_then(Value::as_array) else {
                continue;
            };
            if branches
                .iter()
                .any(|branch| branch.get("type").and_then(Value::as_str) == Some("null"))
            {
                return true;
            }
        }
        false
    }

    fn collect_inventory_map(
        entries: impl Iterator<Item = (String, String, InventoryKind)>,
        label: &str,
    ) -> BTreeMap<String, String> {
        let mut out = BTreeMap::new();
        let mut seen_pairs = BTreeSet::new();
        for (key, schema_path, kind) in entries {
            let pair = format!("{key} -> {schema_path}");
            assert!(
                seen_pairs.insert(pair.clone()),
                "{label} inventory duplicate key/path pair {pair} kind={kind:?}",
            );
            let previous = out.insert(key.clone(), schema_path.clone());
            assert!(
                previous.is_none(),
                "{label} inventory duplicate key {key}: previous path={} new path={schema_path} kind={kind:?}",
                previous.expect("checked above"),
            );
        }
        out
    }

    fn is_process_container_network_key(key: &str) -> bool {
        key == "processContainer.network"
            || key.starts_with("processContainer.network.")
            || key.starts_with("processContainer.network#")
    }

    fn collect_catalog_map(
        entries: impl Iterator<Item = (String, String)>,
        label: &str,
    ) -> BTreeMap<String, String> {
        let mut out = BTreeMap::new();
        for (key, schema_path) in entries {
            let previous = out.insert(key.clone(), schema_path.clone());
            assert!(
                previous.is_none(),
                "{label} catalog duplicate key {key}: previous path={} new path={schema_path}",
                previous.expect("checked above"),
            );
        }
        out
    }

    fn description_defaults(description: &str) -> Vec<String> {
        let mut out = Vec::new();

        let mut cursor = 0;
        while cursor < description.len() {
            let Some(found) = description[cursor..].find("Defaults to `") else {
                break;
            };
            let start = cursor + found + "Defaults to `".len();
            let Some(end_rel) = description[start..].find('`') else {
                break;
            };
            out.push(description[start..start + end_rel].to_string());
            cursor = start + end_rel + 1;
        }

        if let Some(start) = description.find("(default ") {
            let value_start = start + "(default ".len();
            if let Some(end) = description[value_start..].find(')') {
                out.push(
                    description[value_start..value_start + end]
                        .trim()
                        .to_string(),
                );
            }
        }

        if description.contains("omitted = off") {
            out.push("off".to_string());
        }

        out
    }
}
