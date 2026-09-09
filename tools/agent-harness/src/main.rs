use ::agent_harness::{deterministic_smoke_scenario, evaluate_scenario};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let scenario = deterministic_smoke_scenario();
    let result = evaluate_scenario(&scenario);
    println!("{}", serde_json::to_string_pretty(&result)?);
    Ok(())
}
