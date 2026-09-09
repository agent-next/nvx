// Copyright(c) The microvm authors.
// Licensed under the MIT License.

//! Phase-0 NVX PID-1 agent prototype.

mod config;
mod error;

use ::std::process::ExitCode;

use ::agent_protocol::mxc_extension::{
    MODELED_REQUIREMENTS, MXC_EXTENSION_VERSION, MxcExtensionService, MxcRequest,
    UnsupportedAciAdapter,
};

use crate::error::Result;

fn run() -> Result<()> {
    let adapter = UnsupportedAciAdapter;
    for requirement in MODELED_REQUIREMENTS {
        let response = adapter.call(MxcRequest {
            version: MXC_EXTENSION_VERSION,
            requirement,
        });
        if let Err(error) = response {
            eprintln!("NVX-AGENT: {:?}: {}", error.code, error.message);
        }
    }
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("NVX-AGENT-ERROR: [{:?}] {error}", error.code());
            ExitCode::FAILURE
        }
    }
}
